//! Local users and groups, read from `/etc/passwd` and `/etc/group` at startup.
//!
//! Reading the files rather than calling `getpwnam` keeps the vault free of `unsafe` and of NSS modules
//! (LDAP and the like have no business deciding who reads secrets). Only local accounts count: the
//! system users the policy names (`www-data`, `aegis`, ...) are always in these files.

use std::collections::HashMap;
use std::io;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct Accounts {
    uids: HashMap<String, u32>,
    names: HashMap<u32, String>,
    gids: HashMap<String, u32>,
}

/// `name:password:id:...` lines; the first entry for a name (or an id) wins, as with `getpwnam`.
fn parse_entries(text: &str) -> impl Iterator<Item = (&str, u32)> {
    text.lines().filter_map(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || line.starts_with(['+', '-']) {
            return None;
        }
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let id = fields.next()?.parse().ok()?;
        (!name.is_empty()).then_some((name, id))
    })
}

impl Accounts {
    /// From the text of a passwd file and a group file.
    pub fn parse(passwd: &str, group: &str) -> Self {
        let mut accounts = Accounts::default();
        for (name, uid) in parse_entries(passwd) {
            accounts.uids.entry(name.to_owned()).or_insert(uid);
            accounts.names.entry(uid).or_insert_with(|| name.to_owned());
        }
        for (name, gid) in parse_entries(group) {
            accounts.gids.entry(name.to_owned()).or_insert(gid);
        }
        accounts
    }

    /// From `/etc/passwd` and `/etc/group`.
    pub fn load() -> io::Result<Self> {
        Self::load_from(Path::new("/etc/passwd"), Path::new("/etc/group"))
    }

    pub fn load_from(passwd: &Path, group: &Path) -> io::Result<Self> {
        let passwd = std::fs::read_to_string(passwd)?;
        let group = std::fs::read_to_string(group)?;
        Ok(Self::parse(&passwd, &group))
    }

    pub fn uid(&self, user: &str) -> Option<u32> {
        self.uids.get(user).copied()
    }

    pub fn user_name(&self, uid: u32) -> Option<&str> {
        self.names.get(&uid).map(String::as_str)
    }

    pub fn gid(&self, group: &str) -> Option<u32> {
        self.gids.get(group).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
# a comment
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

aegis:x:998:998::/var/lib/aegis:/usr/sbin/nologin
toor:x:0:0:second root:/root:/bin/sh
root:x:5000:5000:shadowed duplicate:/:/bin/sh
+nisuser::::::
broken line
bad:x:notanumber:0::/:/bin/sh
";
    const GROUP: &str = "\
root:x:0:
aegis-clients:x:990:www-data,aegis
aegis-admin:x:991:aegis
";

    #[test]
    fn users_and_groups() {
        let accounts = Accounts::parse(PASSWD, GROUP);
        assert_eq!(accounts.uid("root"), Some(0));
        assert_eq!(accounts.uid("www-data"), Some(33));
        assert_eq!(accounts.uid("aegis"), Some(998));
        assert_eq!(accounts.uid("toor"), Some(0));
        assert_eq!(accounts.uid("nobody"), None);
        assert_eq!(accounts.uid("+nisuser"), None);
        assert_eq!(accounts.uid("broken line"), None);
        assert_eq!(accounts.uid("bad"), None);
        assert_eq!(accounts.user_name(0), Some("root"));
        assert_eq!(accounts.user_name(33), Some("www-data"));
        assert_eq!(accounts.user_name(5000), Some("root"));
        assert_eq!(accounts.gid("aegis-clients"), Some(990));
        assert_eq!(accounts.gid("aegis-admin"), Some(991));
        assert_eq!(accounts.gid("www-data"), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn loads_this_system() {
        let accounts = Accounts::load().unwrap();
        assert_eq!(accounts.uid("root"), Some(0));
    }
}
