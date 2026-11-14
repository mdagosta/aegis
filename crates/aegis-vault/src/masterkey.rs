//! Where the master key comes from, and `keygen`.
//!
//! In production, systemd decrypts it (`LoadCredentialEncrypted=aegis-master-key:...`) into
//! `$CREDENTIALS_DIRECTORY/aegis-master-key`, readable only by the service. In dev, `--master-key <file>`.
//! Either way the file must not be readable or writable by group or others.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::crypto::MasterKey;

/// A key file's text: 64 hex characters (then a newline).
const MASTER_KEY_HEX_LEN: usize = 64;

/// The credential name in the systemd unit.
pub const CREDENTIAL_NAME: &str = "aegis-master-key";

#[derive(Debug)]
pub struct KeyFileError(String);

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyFileError {}

/// The key file to read: `--master-key` if given, else the systemd credential.
pub fn key_path(
    flag: Option<&Path>,
    credentials_directory: Option<&Path>,
) -> Result<PathBuf, KeyFileError> {
    match (flag, credentials_directory) {
        (Some(path), _) => Ok(path.to_owned()),
        (None, Some(dir)) => Ok(dir.join(CREDENTIAL_NAME)),
        (None, None) => Err(KeyFileError(format!(
            "no master key: pass --master-key <file>, or run under systemd with \
             LoadCredentialEncrypted={CREDENTIAL_NAME}:..."
        ))),
    }
}

/// Read a master key file: 64 hex characters, mode 0600 or tighter.
pub fn read_key_file(path: &Path) -> Result<MasterKey, KeyFileError> {
    let fail = |what: String| KeyFileError(format!("master key {}: {what}", path.display()));
    let mut file = std::fs::File::open(path).map_err(|e| fail(e.to_string()))?;
    let meta = file.metadata().map_err(|e| fail(e.to_string()))?;
    if !meta.is_file() {
        return Err(fail("not a file".to_owned()));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(fail(format!(
            "mode is {mode:o}; it must not be readable or writable by group or others (chmod 600)"
        )));
    }
    // A key file is 65 bytes; refuse anything much bigger before reading it.
    if meta.len() > 1024 {
        return Err(fail("too large to be a master key".to_owned()));
    }
    let mut text = Zeroizing::new(String::with_capacity(128));
    file.read_to_string(&mut text)
        .map_err(|e| fail(e.to_string()))?;
    MasterKey::from_hex(&text).map_err(|e| fail(e.to_string()))
}

/// Make a new master key and write it to `path` (mode 0600). Never overwrites.
pub fn keygen(path: &Path) -> Result<(), KeyFileError> {
    let fail = |what: String| KeyFileError(format!("{}: {what}", path.display()));
    let key = MasterKey::generate().map_err(|e| fail(e.to_string()))?;
    // Sized up front: growing a string to add the newline would free a copy of the key unwiped.
    let mut text = Zeroizing::new(String::with_capacity(MASTER_KEY_HEX_LEN + 1));
    text.push_str(&key.to_hex());
    text.push('\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                fail("already exists; refusing to overwrite a master key".to_owned())
            } else {
                fail(e.to_string())
            }
        })?;
    // create_new with mode 0600 is narrowed further by the umask, never widened; check anyway.
    let mode = file
        .metadata()
        .map_err(|e| fail(e.to_string()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(fail(format!("created with mode {mode:o}; removed it")));
    }
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| fail(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keys;
    use crate::testutil::TempDir;

    #[test]
    fn keygen_then_read() {
        let dir = TempDir::new("keygen");
        let path = dir.path().join("master.key");
        keygen(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), 65);
        let a = read_key_file(&path).unwrap();
        let b = read_key_file(&path).unwrap();
        assert_eq!(Keys::derive(&a).kek_id(), Keys::derive(&b).kek_id());
        let again = keygen(&path).unwrap_err();
        assert!(again.0.contains("refusing to overwrite"), "{again}");
        // The refused keygen left the key alone.
        let c = read_key_file(&path).unwrap();
        assert_eq!(Keys::derive(&a).kek_id(), Keys::derive(&c).kek_id());
    }

    #[test]
    fn loose_modes_are_refused() {
        let dir = TempDir::new("keymode");
        let path = dir.path().join("master.key");
        keygen(&path).unwrap();
        for mode in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read_key_file(&path).unwrap_err();
            assert!(err.0.contains("must not be readable"), "{mode:o}: {err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_key_file(&path).is_ok());
    }

    #[test]
    fn bad_contents_are_refused() {
        let dir = TempDir::new("keybad");
        let path = dir.path().join("master.key");
        std::fs::write(&path, "not a key\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_key_file(&path).unwrap_err();
        assert!(err.0.contains("64 hex"), "{err}");
        // The error never contains the file's contents.
        assert!(!err.0.contains("not a key"));
        assert!(read_key_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn path_choice() {
        let flag = Path::new("/dev/key");
        let creds = Path::new("/run/credentials/aegis-vault.service");
        assert_eq!(key_path(Some(flag), Some(creds)).unwrap(), flag);
        assert_eq!(
            key_path(None, Some(creds)).unwrap(),
            creds.join("aegis-master-key")
        );
        assert!(key_path(None, None).is_err());
    }
}
