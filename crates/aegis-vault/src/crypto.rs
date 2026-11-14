//! Keys and sealing. See docs/plan.md, "aegis-vault", Storage.
//!
//! - The master key is 32 random bytes. HKDF-SHA256 derives from it an encryption key, a fingerprint key
//!   and a short public key id (`kek_id`), each under its own label.
//! - Values are sealed with XChaCha20-Poly1305 under a random 24-byte nonce. The associated data is a
//!   purpose label, the scope, the key and the version, each length-prefixed so no choice of names can
//!   make two different rows share it: ciphertext copied to another row (or version) fails to open.
//! - A canary, sealed at first start, tells a wrong master key apart from a damaged row.
//! - A fingerprint is a short HMAC of the value under the fingerprint key: equal values have equal
//!   fingerprints, and without the master key it says nothing about the value.

use std::fmt;

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::encoding::{hex_decode, hex_encode};

pub const MASTER_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
/// Bytes of HMAC kept as a fingerprint (shown as 12 hex characters).
const FINGERPRINT_LEN: usize = 6;
/// Bytes of key id (shown as 16 hex characters).
const KEK_ID_LEN: usize = 8;

const HKDF_SALT: &[u8] = b"aegis-vault v1";
const INFO_ENCRYPTION: &[u8] = b"aegis-vault v1 encryption key";
const INFO_FINGERPRINT: &[u8] = b"aegis-vault v1 fingerprint key";
const INFO_KEK_ID: &[u8] = b"aegis-vault v1 key id";

const PURPOSE_SECRET: &[u8] = b"aegis-vault v1 secret";
const PURPOSE_CANARY: &[u8] = b"aegis-vault v1 canary";
const CANARY_PLAINTEXT: &[u8] = b"aegis-vault canary: the master key matches this store";

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The master key text is not 64 hex characters.
    BadMasterKey,
    /// The system random source failed.
    Random,
    /// Encryption failed (only for absurd sizes).
    Seal,
    /// Authentication failed: wrong key, wrong row, or damaged data.
    Open,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CryptoError::BadMasterKey => "master key must be 64 hex characters (32 bytes)",
            CryptoError::Random => "the system random source failed",
            CryptoError::Seal => "encryption failed",
            CryptoError::Open => "decryption failed: wrong key, moved row or damaged data",
        })
    }
}

impl std::error::Error for CryptoError {}

/// Fill `buf` from the operating system's random source.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

/// The 32-byte master key. Wiped on drop; `Debug` never shows it.
pub struct MasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl MasterKey {
    /// 64 hex characters, with surrounding whitespace (a trailing newline) ignored.
    pub fn from_hex(text: &str) -> Result<Self, CryptoError> {
        let text = text.trim();
        if text.len() != MASTER_KEY_LEN * 2 {
            return Err(CryptoError::BadMasterKey);
        }
        let bytes = hex_decode(text).ok_or(CryptoError::BadMasterKey)?;
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        key.copy_from_slice(&bytes);
        Ok(MasterKey(key))
    }

    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        random_bytes(key.as_mut())?;
        Ok(MasterKey(key))
    }

    /// The key as 64 lowercase hex characters, for `keygen` to write to its file.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex_encode(self.0.as_ref()))
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

/// A sealed value as stored: nonce and ciphertext (which ends in the 16-byte tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Keys derived from the master key, held for the daemon's lifetime.
pub struct Keys {
    cipher: XChaCha20Poly1305,
    fingerprint_key: Zeroizing<[u8; 32]>,
    kek_id: String,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("kek_id", &self.kek_id)
            .finish_non_exhaustive()
    }
}

/// Length-prefixed concatenation: each part is its 4-byte big-endian length, then its bytes.
fn associated_data(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for part in parts {
        let len = u32::try_from(part.len()).expect("associated data part under 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn secret_aad(scope: &str, key: &str, version: i64) -> Vec<u8> {
    associated_data(&[
        PURPOSE_SECRET,
        scope.as_bytes(),
        key.as_bytes(),
        &version.to_be_bytes(),
    ])
}

impl Keys {
    pub fn derive(master: &MasterKey) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), master.0.as_ref());
        let mut encryption_key = Zeroizing::new([0u8; 32]);
        let mut fingerprint_key = Zeroizing::new([0u8; 32]);
        let mut kek_id = [0u8; KEK_ID_LEN];
        // 32 and 8 bytes are far below HKDF-SHA256's 8160-byte limit, so expand cannot fail.
        hkdf.expand(INFO_ENCRYPTION, encryption_key.as_mut())
            .expect("valid HKDF length");
        hkdf.expand(INFO_FINGERPRINT, fingerprint_key.as_mut())
            .expect("valid HKDF length");
        hkdf.expand(INFO_KEK_ID, &mut kek_id)
            .expect("valid HKDF length");
        let cipher =
            XChaCha20Poly1305::new_from_slice(encryption_key.as_ref()).expect("32-byte key");
        Keys {
            cipher,
            fingerprint_key,
            kek_id: hex_encode(&kek_id),
        }
    }

    /// Short public id of the master key, stored with each row and the canary.
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Seal)?;
        Ok(Sealed { nonce, ciphertext })
    }

    fn open(&self, aad: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.cipher
            .decrypt(
                &sealed.nonce.into(),
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Open)
    }

    /// Seal a value for row (scope, key, version).
    pub fn seal_secret(
        &self,
        scope: &str,
        key: &str,
        version: i64,
        plaintext: &[u8],
    ) -> Result<Sealed, CryptoError> {
        self.seal(&secret_aad(scope, key, version), plaintext)
    }

    /// Open the value of row (scope, key, version). Fails if the ciphertext belongs to any other row.
    pub fn open_secret(
        &self,
        scope: &str,
        key: &str,
        version: i64,
        sealed: &Sealed,
    ) -> Result<Zeroizing<String>, CryptoError> {
        let mut bytes = self.open(&secret_aad(scope, key, version), sealed)?;
        // Move the bytes out without copying, so the only plaintext left is wiped on drop either way.
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(text) => Ok(Zeroizing::new(text)),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
                Err(CryptoError::Open)
            }
        }
    }

    fn canary_aad(&self) -> Vec<u8> {
        associated_data(&[PURPOSE_CANARY, self.kek_id.as_bytes()])
    }

    pub fn seal_canary(&self) -> Result<Sealed, CryptoError> {
        self.seal(&self.canary_aad(), CANARY_PLAINTEXT)
    }

    /// Ok if the canary was sealed by this master key.
    pub fn check_canary(&self, sealed: &Sealed) -> Result<(), CryptoError> {
        let plaintext = self.open(&self.canary_aad(), sealed)?;
        if plaintext.as_slice() == CANARY_PLAINTEXT {
            Ok(())
        } else {
            Err(CryptoError::Open)
        }
    }

    /// Short keyed fingerprint of a value (12 hex characters).
    pub fn fingerprint(&self, value: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.fingerprint_key.as_ref())
            .expect("HMAC takes any key length");
        mac.update(value);
        let tag = mac.finalize().into_bytes();
        hex_encode(&tag[..FINGERPRINT_LEN])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> MasterKey {
        MasterKey::from_hex(&hex_encode(&[byte; 32])).unwrap()
    }

    #[test]
    fn master_key_parsing() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
        let parsed = MasterKey::from_hex(&format!("{hex}\n")).unwrap();
        assert_eq!(parsed.to_hex().as_str(), hex.to_lowercase());
        assert_eq!(
            MasterKey::from_hex(&hex[..62]).unwrap_err(),
            CryptoError::BadMasterKey
        );
        assert_eq!(
            MasterKey::from_hex(&format!("{hex}00")).unwrap_err(),
            CryptoError::BadMasterKey
        );
        assert_eq!(
            MasterKey::from_hex(&hex.replace('a', "g")).unwrap_err(),
            CryptoError::BadMasterKey
        );
        assert!(!format!("{parsed:?}").contains("0011"));
    }

    #[test]
    fn generated_keys_differ() {
        let a = MasterKey::generate().unwrap().to_hex();
        let b = MasterKey::generate().unwrap().to_hex();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn derivation_is_stable_and_separated() {
        let a = Keys::derive(&key(1));
        let a_again = Keys::derive(&key(1));
        let b = Keys::derive(&key(2));
        assert_eq!(a.kek_id(), a_again.kek_id());
        assert_ne!(a.kek_id(), b.kek_id());
        assert_eq!(a.kek_id().len(), 16);
        assert_eq!(a.fingerprint(b"v"), a_again.fingerprint(b"v"));
        assert_ne!(a.fingerprint(b"v"), b.fingerprint(b"v"));
        // The fingerprint key is not the encryption key or the key id.
        assert_ne!(*a.fingerprint_key, [0u8; 32]);
        assert!(!hex_encode(a.fingerprint_key.as_ref()).starts_with(a.kek_id()));
    }

    #[test]
    fn seal_open_round_trip() {
        let keys = Keys::derive(&key(7));
        let sealed = keys
            .seal_secret("epiphyte/prod", "DB", 3, b"hunter2")
            .unwrap();
        assert_eq!(sealed.ciphertext.len(), b"hunter2".len() + 16);
        assert!(!sealed.ciphertext.windows(7).any(|w| w == b"hunter2"));
        let opened = keys.open_secret("epiphyte/prod", "DB", 3, &sealed).unwrap();
        assert_eq!(opened.as_str(), "hunter2");
    }

    #[test]
    fn nonces_are_fresh() {
        let keys = Keys::derive(&key(7));
        let a = keys.seal_secret("s", "k", 1, b"same").unwrap();
        let b = keys.seal_secret("s", "k", 1, b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn ciphertext_is_bound_to_its_row() {
        let keys = Keys::derive(&key(7));
        let sealed = keys.seal_secret("a/b", "c", 1, b"value").unwrap();
        for (scope, key, version) in [
            ("a/b", "c", 2), // another version
            ("a/b", "d", 1), // another key
            ("a/x", "c", 1), // another scope
            ("a", "b/c", 1), // same bytes, split differently
            ("a/bc", "", 1), // separator games
        ] {
            assert_eq!(
                keys.open_secret(scope, key, version, &sealed).unwrap_err(),
                CryptoError::Open,
                "{scope} {key} {version}"
            );
        }
    }

    #[test]
    fn tampering_and_wrong_key_fail() {
        let keys = Keys::derive(&key(7));
        let sealed = keys.seal_secret("s", "k", 1, b"value").unwrap();
        let mut flipped = sealed.clone();
        flipped.ciphertext[0] ^= 1;
        assert!(keys.open_secret("s", "k", 1, &flipped).is_err());
        let mut nonce = sealed.clone();
        nonce.nonce[0] ^= 1;
        assert!(keys.open_secret("s", "k", 1, &nonce).is_err());
        let other = Keys::derive(&key(8));
        assert!(other.open_secret("s", "k", 1, &sealed).is_err());
    }

    #[test]
    fn canary() {
        let keys = Keys::derive(&key(7));
        let canary = keys.seal_canary().unwrap();
        assert_eq!(keys.check_canary(&canary), Ok(()));
        let other = Keys::derive(&key(8));
        assert_eq!(other.check_canary(&canary), Err(CryptoError::Open));
        // A secret sealed with the canary's text is still not a canary.
        let fake = keys.seal_secret("s", "k", 1, CANARY_PLAINTEXT).unwrap();
        assert!(keys.check_canary(&fake).is_err());
    }

    #[test]
    fn associated_data_is_unambiguous() {
        assert_ne!(
            associated_data(&[b"ab", b"c"]),
            associated_data(&[b"a", b"bc"])
        );
        assert_eq!(associated_data(&[b"ab"]), [0, 0, 0, 2, b'a', b'b']);
    }
}
