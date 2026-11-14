//! Checks on the files and directories the vault trusts.
//!
//! Whoever can write to the policy, or to the directory holding a socket, the store or the policy, can
//! replace it: a fake `admin.sock` would collect the values admins set, a swapped policy would grant
//! reads. So each must be owned by root or by the vault's own user, and not writable by group or others.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// This process's effective uid, from `/proc/self/status` (Linux; `None` elsewhere, where the owner
/// check is skipped: those are dev machines).
pub fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid: real effective saved filesystem
    line.split_whitespace().nth(2)?.parse().ok()
}

fn owner_ok(owner: u32, effective: Option<u32>) -> bool {
    owner == 0 || effective.is_none_or(|uid| uid == owner)
}

/// Error unless `path` exists, is owned by root or this process's user, and neither its group nor
/// others may write to it.
pub fn check_trusted(path: &Path, what: &str) -> io::Result<()> {
    let meta = std::fs::metadata(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{what} {}: {e}", path.display())))?;
    let refuse = |message: String| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{what} {}: {message}", path.display()),
        ))
    };
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return refuse(format!(
            "writable by group or others (mode {mode:o}); chmod go-w it"
        ));
    }
    let effective = effective_uid();
    if !owner_ok(meta.uid(), effective) {
        return refuse(format!(
            "owned by uid {}; it must be owned by root{}",
            meta.uid(),
            effective.map_or_else(String::new, |uid| format!(
                " or uid {uid} (the vault's user)"
            ))
        ));
    }
    Ok(())
}

/// The directory a file lives in (`.` for a bare file name).
pub fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, current_uid};

    #[test]
    fn modes() {
        let dir = TempDir::new("paths");
        let set = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for ok in [0o700, 0o755, 0o711, 0o1755] {
            set(ok);
            assert!(check_trusted(dir.path(), "dir").is_ok(), "{ok:o}");
        }
        for bad in [0o775, 0o757, 0o777, 0o1777] {
            set(bad);
            let err = check_trusted(dir.path(), "run dir").unwrap_err();
            assert!(err.to_string().contains("run dir"), "{err}");
        }
        set(0o700);
        assert!(check_trusted(&dir.path().join("missing"), "x").is_err());
    }

    #[test]
    fn owners() {
        assert!(owner_ok(0, Some(1000)));
        assert!(owner_ok(1000, Some(1000)));
        assert!(!owner_ok(33, Some(1000)));
        assert!(!owner_ok(1000, Some(0)));
        assert!(owner_ok(33, None));
        if cfg!(target_os = "linux") {
            assert_eq!(effective_uid(), Some(current_uid()));
        }
    }

    #[test]
    fn parents() {
        assert_eq!(parent_dir(Path::new("vault.db")), Path::new("."));
        assert_eq!(parent_dir(Path::new("dev/vault.db")), Path::new("dev"));
        assert_eq!(
            parent_dir(Path::new("/var/lib/aegis-vault/vault.db")),
            Path::new("/var/lib/aegis-vault")
        );
    }
}
