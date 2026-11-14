//! Who may do what: `/etc/aegis/policy.toml`, with user names resolved to uids once at startup.
//!
//! ```toml
//! [sockets]                       # optional: group owners for the socket files (the outer fence)
//! read_group = "aegis-clients"
//! admin_group = "aegis-admin"
//!
//! [admin]
//! full = ["aegis", "root"]        # everything on admin.sock (which never returns a value)
//! write_only = ["aegis-infra"]    # PUT and generate only, onto new keys or keys they set last
//!
//! [scope."epiphyte/prod"]
//! allow_users = ["www-data"]      # GET /v1/scope/epiphyte/prod on read.sock
//! ```
//!
//! Anything unknown or unresolvable is an error, so the daemon refuses to start rather than run with a
//! policy that doesn't say what its author meant.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::accounts::Accounts;
use crate::names::ScopeName;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    sockets: SocketsFile,
    #[serde(default)]
    admin: AdminFile,
    #[serde(default)]
    scope: BTreeMap<String, ScopeFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SocketsFile {
    read_group: Option<String>,
    admin_group: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminFile {
    #[serde(default)]
    full: Vec<String>,
    #[serde(default)]
    write_only: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFile {
    allow_users: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

fn error(message: impl Into<String>) -> PolicyError {
    PolicyError(message.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminRole {
    /// Every admin route.
    Full,
    /// `PUT` and `generate` only, onto keys that don't exist yet or that the caller set last.
    WriteOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeGrant {
    /// User names as written in the policy, for listings.
    pub users: Vec<String>,
    uids: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct Policy {
    admin: HashMap<u32, AdminRole>,
    scopes: BTreeMap<ScopeName, ScopeGrant>,
    pub read_gid: Option<u32>,
    pub admin_gid: Option<u32>,
}

impl Policy {
    /// Read the policy file, refusing one that anyone but its owner can change.
    pub fn load(path: &Path, accounts: &Accounts) -> Result<Policy, PolicyError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| error(format!("policy {}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(error(format!("policy {}: not a file", path.display())));
        }
        crate::paths::check_trusted(path, "policy").map_err(|e| error(e.to_string()))?;
        crate::paths::check_trusted(crate::paths::parent_dir(path), "policy directory")
            .map_err(|e| error(e.to_string()))?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| error(format!("policy {}: {e}", path.display())))?;
        Policy::parse(&text, accounts).map_err(|e| error(format!("policy {}: {e}", path.display())))
    }

    pub fn parse(text: &str, accounts: &Accounts) -> Result<Policy, PolicyError> {
        let file: PolicyFile = toml::from_str(text).map_err(|e| error(e.to_string()))?;
        let uid = |user: &str, place: &str| {
            accounts
                .uid(user)
                .ok_or_else(|| error(format!("{place}: no local user {user:?}")))
        };

        let mut admin = HashMap::new();
        for (list, role, place) in [
            (&file.admin.full, AdminRole::Full, "[admin] full"),
            (
                &file.admin.write_only,
                AdminRole::WriteOnly,
                "[admin] write_only",
            ),
        ] {
            for user in list {
                let id = uid(user, place)?;
                if let Some(previous) = admin.insert(id, role) {
                    return Err(error(format!(
                        "{place}: {user:?} (uid {id}) is already listed{}",
                        if previous == role {
                            String::new()
                        } else {
                            " with another role".to_owned()
                        }
                    )));
                }
            }
        }

        let mut scopes = BTreeMap::new();
        for (name, grant) in file.scope {
            let scope =
                ScopeName::parse(&name).map_err(|e| error(format!("[scope.{name:?}]: {e}")))?;
            let place = format!("[scope.{name:?}] allow_users");
            let mut uids = Vec::new();
            for user in &grant.allow_users {
                let id = uid(user, &place)?;
                if uids.contains(&id) {
                    return Err(error(format!(
                        "{place}: {user:?} (uid {id}) is listed twice"
                    )));
                }
                uids.push(id);
            }
            scopes.insert(
                scope,
                ScopeGrant {
                    users: grant.allow_users,
                    uids,
                },
            );
        }

        let gid = |group: &Option<String>, place: &str| -> Result<Option<u32>, PolicyError> {
            group
                .as_deref()
                .map(|g| {
                    accounts
                        .gid(g)
                        .ok_or_else(|| error(format!("[sockets] {place}: no local group {g:?}")))
                })
                .transpose()
        };

        Ok(Policy {
            admin,
            scopes,
            read_gid: gid(&file.sockets.read_group, "read_group")?,
            admin_gid: gid(&file.sockets.admin_group, "admin_group")?,
        })
    }

    pub fn admin_role(&self, uid: u32) -> Option<AdminRole> {
        self.admin.get(&uid).copied()
    }

    /// Whether `uid` may fetch `scope` from read.sock.
    pub fn may_read(&self, uid: u32, scope: &ScopeName) -> bool {
        self.scopes
            .get(scope)
            .is_some_and(|grant| grant.uids.contains(&uid))
    }

    /// Whether `uid` may read any scope at all.
    pub fn is_reader(&self, uid: u32) -> bool {
        self.scopes.values().any(|grant| grant.uids.contains(&uid))
    }

    /// Every admin uid and its role, by uid.
    pub fn admins(&self) -> Vec<(u32, AdminRole)> {
        let mut admins: Vec<_> = self.admin.iter().map(|(&uid, &role)| (uid, role)).collect();
        admins.sort_unstable_by_key(|&(uid, _)| uid);
        admins
    }

    /// Every scope the policy names, with who may read it.
    pub fn scopes(&self) -> impl Iterator<Item = (&ScopeName, &ScopeGrant)> {
        self.scopes.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn accounts() -> Accounts {
        Accounts::parse(
            "root:x:0:0::/:/bin/sh\nwww-data:x:33:33::/:/bin/sh\naegis:x:998:998::/:/bin/sh\n\
             aegis-infra:x:997:997::/:/bin/sh\naegis-run:x:996:996::/:/bin/sh\n",
            "aegis-clients:x:990:\naegis-admin:x:991:\n",
        )
    }

    const EXAMPLE: &str = r#"
[sockets]
read_group = "aegis-clients"
admin_group = "aegis-admin"

[admin]
full = ["aegis", "root"]
write_only = ["aegis-infra"]

[scope."epiphyte/prod"]
allow_users = ["www-data"]

[scope."cloudflare/deploy"]
allow_users = ["aegis-run"]
"#;

    #[test]
    fn example_policy() {
        let policy = Policy::parse(EXAMPLE, &accounts()).unwrap();
        assert_eq!(policy.admin_role(998), Some(AdminRole::Full));
        assert_eq!(policy.admin_role(0), Some(AdminRole::Full));
        assert_eq!(policy.admin_role(997), Some(AdminRole::WriteOnly));
        assert_eq!(policy.admin_role(33), None);
        let prod = ScopeName::parse("epiphyte/prod").unwrap();
        let deploy = ScopeName::parse("cloudflare/deploy").unwrap();
        assert!(policy.may_read(33, &prod));
        assert!(!policy.may_read(33, &deploy));
        assert!(policy.may_read(996, &deploy));
        // Root administers but reads nothing unless a scope names it.
        assert!(!policy.may_read(0, &prod));
        assert!(!policy.is_reader(0));
        assert!(policy.is_reader(33));
        assert!(!policy.may_read(33, &ScopeName::parse("epiphyte").unwrap()));
        assert_eq!(policy.read_gid, Some(990));
        assert_eq!(policy.admin_gid, Some(991));
        let listed: Vec<_> = policy
            .scopes()
            .map(|(s, g)| (s.as_str(), g.users.clone()))
            .collect();
        assert_eq!(
            listed,
            [
                ("cloudflare/deploy", vec!["aegis-run".to_owned()]),
                ("epiphyte/prod", vec!["www-data".to_owned()]),
            ]
        );
    }

    #[test]
    fn shipped_example_is_valid() {
        let text = include_str!("../../../etc/aegis/policy.toml");
        let policy = Policy::parse(text, &accounts()).unwrap();
        assert_eq!(policy.admin_role(998), Some(AdminRole::Full));
        assert_eq!(policy.admin_role(997), Some(AdminRole::WriteOnly));
        assert!(policy.may_read(33, &ScopeName::parse("epiphyte/prod").unwrap()));
        assert_eq!(policy.read_gid, Some(990));
    }

    #[test]
    fn empty_policy_allows_nothing() {
        let policy = Policy::parse("", &accounts()).unwrap();
        assert_eq!(policy.admin_role(0), None);
        assert!(!policy.is_reader(33));
        assert_eq!(policy.read_gid, None);
    }

    #[test]
    fn mistakes_are_errors() {
        let cases = [
            ("[admin]\nfull = [\"nobody\"]", "no local user \"nobody\""),
            (
                "[admin]\nfull = [\"aegis\"]\nwrite_only = [\"aegis\"]",
                "with another role",
            ),
            ("[admin]\nfull = [\"aegis\", \"aegis\"]", "already listed"),
            (
                "[scope.\"Bad/Name\"]\nallow_users = []",
                "character outside",
            ),
            (
                "[scope.\"a\"]\nallow_users = [\"ghost\"]",
                "no local user \"ghost\"",
            ),
            (
                "[scope.\"a\"]\nallow_users = [\"www-data\", \"www-data\"]",
                "listed twice",
            ),
            (
                "[scope.\"a\"]\nallow_user = [\"www-data\"]",
                "unknown field",
            ),
            ("[admin]\nfulll = [\"aegis\"]", "unknown field"),
            ("[scopes.\"a\"]\nallow_users = []", "unknown field"),
            ("[sockets]\nread_group = \"nogroup\"", "no local group"),
            ("[scope.\"a\"]", "missing field"),
            ("not toml", ""),
        ];
        for (text, expected) in cases {
            let err = Policy::parse(text, &accounts()).unwrap_err();
            assert!(err.0.contains(expected), "{text:?}: {err}");
        }
    }

    #[test]
    fn load_refuses_writable_file() {
        let dir = crate::testutil::TempDir::new("policy");
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, EXAMPLE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Policy::load(&path, &accounts()).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let err = Policy::load(&path, &accounts()).unwrap_err();
        assert!(err.0.contains("writable by group or others"), "{err}");
        // A directory others can write is as bad: they could swap the file.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = Policy::load(&path, &accounts()).unwrap_err();
        assert!(err.0.contains("policy directory"), "{err}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
