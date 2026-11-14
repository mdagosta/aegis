//! Scope and key names, and secret values: checked before anything touches the store.
//!
//! A scope is one or more segments of `[a-z0-9._-]` joined by `/` (`epiphyte/prod`), a key is one segment
//! of `[A-Za-z0-9._-]` (`DATABASE_URL`), each at most 128 bytes. A segment may not be `.` or `..`, since
//! names travel in URL paths and HTTP clients collapse those. Values are UTF-8 text, 1 byte to 64 KiB.

use std::fmt;

use zeroize::Zeroizing;

/// Longest scope or key name, in bytes.
pub const MAX_NAME_LEN: usize = 128;

/// Largest secret value, in bytes.
pub const MAX_VALUE_LEN: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    BadCharacter,
    EmptySegment,
    DotSegment,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "name is empty",
            NameError::TooLong => "name is longer than 128 bytes",
            NameError::BadCharacter => "name has a character outside the allowed set",
            NameError::EmptySegment => "scope has an empty segment",
            NameError::DotSegment => "name segment may not be . or ..",
        })
    }
}

impl std::error::Error for NameError {}

fn check_segment(segment: &str, allowed: fn(u8) -> bool) -> Result<(), NameError> {
    if segment.is_empty() {
        return Err(NameError::EmptySegment);
    }
    if !segment.bytes().all(allowed) {
        return Err(NameError::BadCharacter);
    }
    if segment == "." || segment == ".." {
        return Err(NameError::DotSegment);
    }
    Ok(())
}

fn scope_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
}

fn key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// A checked scope name, e.g. `epiphyte/prod`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeName(String);

impl ScopeName {
    pub fn parse(name: &str) -> Result<Self, NameError> {
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        for segment in name.split('/') {
            check_segment(segment, scope_byte)?;
        }
        Ok(ScopeName(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A checked key name, e.g. `DATABASE_URL`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyName(String);

impl KeyName {
    pub fn parse(name: &str) -> Result<Self, NameError> {
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_NAME_LEN {
            return Err(NameError::TooLong);
        }
        check_segment(name, key_byte).map_err(|e| match e {
            NameError::EmptySegment => NameError::Empty,
            other => other,
        })?;
        Ok(KeyName(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueError {
    Empty,
    TooLong,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ValueError::Empty => "value is empty",
            ValueError::TooLong => "value is longer than 64 KiB",
        })
    }
}

impl std::error::Error for ValueError {}

/// A secret value: checked, wiped from memory on drop, and never shown by `Debug`.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: Zeroizing<String>) -> Result<Self, ValueError> {
        if value.is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(ValueError::TooLong);
        }
        Ok(SecretValue(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn good_scopes() {
        for name in [
            "epiphyte/prod",
            "a",
            "cloudflare/deploy",
            "a.b_c-d/0/z",
            "x/key/y",
        ] {
            assert_eq!(ScopeName::parse(name).unwrap().as_str(), name);
        }
        assert!(ScopeName::parse(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn bad_scopes() {
        let cases = [
            ("", NameError::Empty),
            ("Epiphyte/prod", NameError::BadCharacter),
            ("a b", NameError::BadCharacter),
            ("a/", NameError::EmptySegment),
            ("/a", NameError::EmptySegment),
            ("a//b", NameError::EmptySegment),
            ("a/../b", NameError::DotSegment),
            ("./a", NameError::DotSegment),
            ("a%2fb", NameError::BadCharacter),
            ("a?b", NameError::BadCharacter),
            ("é", NameError::BadCharacter),
        ];
        for (name, error) in cases {
            assert_eq!(ScopeName::parse(name), Err(error), "{name:?}");
        }
        assert_eq!(ScopeName::parse(&"a".repeat(129)), Err(NameError::TooLong));
    }

    #[test]
    fn good_keys() {
        for name in ["DATABASE_URL", "a", "x.y-z_0", "versions", "key", "...x"] {
            assert_eq!(KeyName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn bad_keys() {
        let cases = [
            ("", NameError::Empty),
            ("a/b", NameError::BadCharacter),
            ("a b", NameError::BadCharacter),
            (".", NameError::DotSegment),
            ("..", NameError::DotSegment),
            ("a\n", NameError::BadCharacter),
            ("a\0", NameError::BadCharacter),
        ];
        for (name, error) in cases {
            assert_eq!(KeyName::parse(name), Err(error), "{name:?}");
        }
        assert_eq!(KeyName::parse(&"K".repeat(129)), Err(NameError::TooLong));
    }

    #[test]
    fn values() {
        let ok = |s: &str| SecretValue::new(Zeroizing::new(s.to_owned()));
        assert_eq!(ok("").unwrap_err(), ValueError::Empty);
        assert_eq!(
            ok(&"x".repeat(MAX_VALUE_LEN + 1)).unwrap_err(),
            ValueError::TooLong
        );
        assert!(ok(&"x".repeat(MAX_VALUE_LEN)).is_ok());
        let value = ok("hunter2").unwrap();
        assert_eq!(value.as_str(), "hunter2");
        assert!(!format!("{value:?}").contains("hunter2"));
    }
}
