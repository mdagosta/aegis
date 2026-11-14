//! The encrypted store: one SQLite file holding versioned, sealed values and the audit log.
//!
//! - `secret` keeps every version of every key. The current version is the highest one. Set, generate,
//!   delete (a tombstone row with no value) and rollback (a copy of an old value, re-sealed for its new
//!   version) each add a version, so every change can be undone without anyone seeing a value.
//! - `audit` gets a row for every request, in the same transaction as the change it describes, and each
//!   row is echoed to stderr (the journal). Never a value.
//! - `meta` holds the master key's id and the canary: a store opened with the wrong master key refuses
//!   to start instead of writing rows nobody can read.
//!
//! SQLite is synchronous: the daemon keeps one `Store` behind a mutex and calls it from
//! `spawn_blocking`.

use std::fmt;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, Keys, MasterKey, NONCE_LEN, Sealed, random_bytes};
use crate::encoding::{base64url_encode, format_utc, now_unix};
use crate::names::{KeyName, ScopeName, SecretValue};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE meta (
    name TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE secret (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    action TEXT NOT NULL CHECK (action IN ('set', 'generate', 'rollback', 'delete')),
    nonce BLOB CHECK (nonce IS NULL OR length(nonce) = 24),
    ciphertext BLOB,
    kek_id TEXT,
    fingerprint TEXT,
    rollback_of INTEGER,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_by_uid INTEGER NOT NULL,
    PRIMARY KEY (scope, key, version),
    CHECK ((action = 'delete') = (ciphertext IS NULL)),
    CHECK ((ciphertext IS NULL) = (nonce IS NULL)),
    CHECK ((ciphertext IS NULL) = (kek_id IS NULL)),
    CHECK ((ciphertext IS NULL) = (fingerprint IS NULL)),
    CHECK ((action = 'rollback') = (rollback_of IS NOT NULL))
) STRICT, WITHOUT ROWID;

CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    uid INTEGER,
    user TEXT,
    pid INTEGER,
    cmdline TEXT,
    socket TEXT NOT NULL,
    action TEXT NOT NULL,
    scope TEXT,
    key TEXT,
    version INTEGER,
    outcome TEXT NOT NULL,
    detail TEXT
) STRICT;
";

/// Random bytes for `generate`: at least 16, at most 1024, 32 when not given.
pub const GENERATE_MIN_BYTES: usize = 16;
pub const GENERATE_MAX_BYTES: usize = 1024;
pub const GENERATE_DEFAULT_BYTES: usize = 32;

/// Audit rows returned at most, and by default.
pub const AUDIT_MAX_LIMIT: u32 = 1000;
pub const AUDIT_DEFAULT_LIMIT: u32 = 100;

#[derive(Debug)]
pub enum StoreError {
    /// No such key, version, or (for delete) no live value.
    NotFound(String),
    /// The caller's role doesn't allow this change.
    Forbidden(String),
    /// A well-formed request the store can't carry out (e.g. rolling back to a delete).
    Invalid(String),
    /// The master key doesn't match the store. Only from `open`.
    WrongMasterKey(String),
    /// A row fails to open or is malformed: the file was changed outside the vault.
    Corrupt(String),
    Crypto(CryptoError),
    Db(rusqlite::Error),
    Io(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound(m)
            | StoreError::Forbidden(m)
            | StoreError::Invalid(m)
            | StoreError::WrongMasterKey(m)
            | StoreError::Corrupt(m) => f.write_str(m),
            StoreError::Crypto(e) => write!(f, "{e}"),
            StoreError::Db(e) => write!(f, "database: {e}"),
            StoreError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e)
    }
}

impl From<CryptoError> for StoreError {
    fn from(e: CryptoError) -> Self {
        StoreError::Crypto(e)
    }
}

impl StoreError {
    pub fn outcome(&self) -> Outcome {
        match self {
            StoreError::NotFound(_) => Outcome::NotFound,
            StoreError::Forbidden(_) => Outcome::Denied,
            StoreError::Invalid(_) => Outcome::Invalid,
            _ => Outcome::Error,
        }
    }
}

/// Which socket a request came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socket {
    Read,
    Admin,
}

impl Socket {
    pub fn as_str(self) -> &'static str {
        match self {
            Socket::Read => "read",
            Socket::Admin => "admin",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Fetch,
    ListScopes,
    Versions,
    Set,
    Generate,
    Delete,
    Rollback,
    Audit,
    /// A request that matched no route.
    Unknown,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Fetch => "fetch",
            Action::ListScopes => "list",
            Action::Versions => "versions",
            Action::Set => "set",
            Action::Generate => "generate",
            Action::Delete => "delete",
            Action::Rollback => "rollback",
            Action::Audit => "audit",
            Action::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Denied,
    Invalid,
    NotFound,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Denied => "denied",
            Outcome::Invalid => "invalid",
            Outcome::NotFound => "not_found",
            Outcome::Error => "error",
        }
    }
}

/// Who is asking, from the socket's peer credentials.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    /// `None` if the kernel didn't report peer credentials; such a caller is refused everything.
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub pid: Option<i32>,
    pub cmdline: Option<String>,
}

impl Caller {
    fn created_by(&self) -> String {
        match (&self.user, self.uid) {
            (Some(user), _) => user.clone(),
            (None, Some(uid)) => format!("uid:{uid}"),
            (None, None) => "unknown".to_owned(),
        }
    }
}

/// What an audit row says about a request, apart from its outcome.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    pub caller: &'a Caller,
    pub socket: Socket,
    pub action: Action,
    pub scope: Option<&'a ScopeName>,
    pub key: Option<&'a KeyName>,
}

/// Version and detail an operation adds to its audit row.
#[derive(Default)]
struct Note {
    version: Option<i64>,
    detail: Option<String>,
}

/// Which keys a write may touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteGuard {
    Any,
    /// Only keys with no versions yet, or whose current version this uid wrote (`write_only` admins).
    NewOrOwn(u32),
}

/// The current version of one key, as listed by `GET /v1/scopes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyMeta {
    pub scope: String,
    pub key: String,
    pub version: i64,
    pub action: String,
    pub deleted: bool,
    pub fingerprint: Option<String>,
    pub set_at: String,
    pub set_by: String,
}

/// One version of a key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VersionMeta {
    pub version: i64,
    pub action: String,
    pub deleted: bool,
    pub fingerprint: Option<String>,
    pub rollback_of: Option<i64>,
    pub set_at: String,
    pub set_by: String,
}

/// What a write produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WriteResult {
    pub scope: String,
    pub key: String,
    pub version: i64,
    pub action: String,
    pub fingerprint: Option<String>,
    pub rollback_of: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub pid: Option<i32>,
    pub cmdline: Option<String>,
    pub socket: String,
    pub action: String,
    pub scope: Option<String>,
    pub key: Option<String>,
    pub version: Option<i64>,
    pub outcome: String,
    pub detail: Option<String>,
}

/// One journal line for an audit row. Strings are quoted and escaped, so a caller's command line can't
/// forge a second line.
pub fn journal_line(row: &AuditRow) -> String {
    fn text(value: Option<&str>) -> String {
        value.map_or_else(|| "-".to_owned(), |v| format!("{v:?}"))
    }
    fn number(value: Option<impl fmt::Display>) -> String {
        value.map_or_else(|| "-".to_owned(), |v| v.to_string())
    }
    format!(
        "audit socket={} action={} outcome={} uid={} user={} pid={} scope={} key={} version={} detail={} cmdline={}",
        row.socket,
        row.action,
        row.outcome,
        number(row.uid),
        text(row.user.as_deref()),
        number(row.pid),
        text(row.scope.as_deref()),
        text(row.key.as_deref()),
        number(row.version),
        text(row.detail.as_deref()),
        text(row.cmdline.as_deref()),
    )
}

pub struct Store {
    conn: Connection,
    keys: Keys,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("kek_id", &self.keys.kek_id())
            .finish_non_exhaustive()
    }
}

/// Create the database file 0600 if it's missing; tighten it to 0600 if it's looser.
fn prepare_file(path: &Path) -> Result<(), StoreError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let meta = std::fs::metadata(path).map_err(StoreError::Io)?;
            if !meta.is_file() {
                return Err(StoreError::Invalid(format!(
                    "{} is not a file",
                    path.display()
                )));
            }
            let mode = meta.permissions().mode() & 0o7777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "warning: {} was mode {mode:o}; setting it to 600",
                    path.display()
                );
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .map_err(StoreError::Io)?;
            }
            Ok(())
        }
        Err(e) => Err(StoreError::Io(e)),
    }
}

fn sealed_from_row(
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    what: impl Fn() -> String,
) -> Result<Sealed, StoreError> {
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{}: nonce is not 24 bytes", what())))?;
    Ok(Sealed { nonce, ciphertext })
}

/// The stored row of a value, as read: nonce, ciphertext and the id of the key that sealed it.
struct SealedRow {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    kek_id: String,
}

/// Open row (scope, key, version). Any failure means the file was changed outside the vault.
fn open_row(
    keys: &Keys,
    scope: &str,
    key: &str,
    version: i64,
    row: SealedRow,
) -> Result<Zeroizing<String>, StoreError> {
    let what = || format!("{scope} {key} version {version}");
    if row.kek_id != keys.kek_id() {
        return Err(StoreError::Corrupt(format!(
            "{} is sealed under master key id {}, not {}",
            what(),
            row.kek_id,
            keys.kek_id()
        )));
    }
    let sealed = sealed_from_row(row.nonce, row.ciphertext, what)?;
    keys.open_secret(scope, key, version, &sealed)
        .map_err(|_| StoreError::Corrupt(format!("{} does not open", what())))
}

struct Latest {
    version: i64,
    deleted: bool,
    created_by_uid: u32,
}

fn latest(
    tx: &Transaction,
    scope: &ScopeName,
    key: &KeyName,
) -> Result<Option<Latest>, StoreError> {
    Ok(tx
        .query_row(
            "SELECT version, ciphertext IS NULL, created_by_uid FROM secret
             WHERE scope = ?1 AND key = ?2 ORDER BY version DESC LIMIT 1",
            params![scope.as_str(), key.as_str()],
            |row| {
                Ok(Latest {
                    version: row.get(0)?,
                    deleted: row.get(1)?,
                    created_by_uid: row.get(2)?,
                })
            },
        )
        .optional()?)
}

fn check_guard(
    guard: WriteGuard,
    current: Option<&Latest>,
    scope: &ScopeName,
    key: &KeyName,
) -> Result<(), StoreError> {
    match (guard, current) {
        (WriteGuard::Any, _) | (WriteGuard::NewOrOwn(_), None) => Ok(()),
        (WriteGuard::NewOrOwn(uid), Some(latest)) if latest.created_by_uid == uid => Ok(()),
        (WriteGuard::NewOrOwn(_), Some(_)) => Err(StoreError::Forbidden(format!(
            "{scope} {key} was last set by someone else; write_only callers may only write new keys or \
             keys they set last"
        ))),
    }
}

impl Store {
    /// Open (or create) the store at `path`. Refuses a master key that doesn't match the store.
    pub fn open(path: &Path, master: &MasterKey) -> Result<Store, StoreError> {
        crate::paths::check_trusted(crate::paths::parent_dir(path), "store directory")
            .map_err(StoreError::Io)?;
        prepare_file(path)?;
        let conn = Connection::open(path)?;
        Store::init(conn, Keys::derive(master))
    }

    /// A store in memory, for tests.
    pub fn open_in_memory(master: &MasterKey) -> Result<Store, StoreError> {
        Store::init(Connection::open_in_memory()?, Keys::derive(master))
    }

    fn init(mut conn: Connection, keys: Keys) -> Result<Store, StoreError> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL;")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => {
                let objects: i64 =
                    tx.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
                if objects != 0 {
                    return Err(StoreError::Corrupt(
                        "the database has tables but isn't an aegis-vault store".to_owned(),
                    ));
                }
                tx.execute_batch(SCHEMA)?;
                let canary = keys.seal_canary()?;
                let mut canary_blob = canary.nonce.to_vec();
                canary_blob.extend_from_slice(&canary.ciphertext);
                tx.execute(
                    "INSERT INTO meta (name, value) VALUES ('kek_id', ?1), ('canary', ?2)",
                    params![keys.kek_id().as_bytes(), canary_blob],
                )?;
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            }
            SCHEMA_VERSION => {
                let meta = |name: &str| -> Result<Vec<u8>, StoreError> {
                    tx.query_row("SELECT value FROM meta WHERE name = ?1", [name], |row| {
                        row.get(0)
                    })
                    .optional()?
                    .ok_or_else(|| StoreError::Corrupt(format!("meta row {name:?} is missing")))
                };
                let kek_id = String::from_utf8_lossy(&meta("kek_id")?).into_owned();
                if kek_id != keys.kek_id() {
                    return Err(StoreError::WrongMasterKey(format!(
                        "this store was created with master key id {kek_id}, but the key given has id {}",
                        keys.kek_id()
                    )));
                }
                let blob = meta("canary")?;
                if blob.len() <= NONCE_LEN {
                    return Err(StoreError::Corrupt("canary is too short".to_owned()));
                }
                let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
                let canary =
                    sealed_from_row(nonce.to_vec(), ciphertext.to_vec(), || "canary".to_owned())?;
                keys.check_canary(&canary).map_err(|_| {
                    StoreError::WrongMasterKey(
                        "the canary doesn't open with this master key".to_owned(),
                    )
                })?;
            }
            newer => {
                return Err(StoreError::Corrupt(format!(
                    "store schema version {newer} is newer than this aegis-vault ({SCHEMA_VERSION})"
                )));
            }
        }
        tx.commit()?;
        Ok(Store { conn, keys })
    }

    pub fn kek_id(&self) -> &str {
        self.keys.kek_id()
    }

    fn insert_audit(
        conn: &Connection,
        event: &Event,
        outcome: Outcome,
        note: &Note,
    ) -> Result<AuditRow, StoreError> {
        let at = now_unix();
        let caller = event.caller;
        conn.execute(
            "INSERT INTO audit (at, uid, user, pid, cmdline, socket, action, scope, key, version, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                at,
                caller.uid,
                caller.user,
                caller.pid,
                caller.cmdline,
                event.socket.as_str(),
                event.action.as_str(),
                event.scope.map(ScopeName::as_str),
                event.key.map(KeyName::as_str),
                note.version,
                outcome.as_str(),
                note.detail,
            ],
        )?;
        Ok(AuditRow {
            id: conn.last_insert_rowid(),
            at: format_utc(at),
            uid: caller.uid,
            user: caller.user.clone(),
            pid: caller.pid,
            cmdline: caller.cmdline.clone(),
            socket: event.socket.as_str().to_owned(),
            action: event.action.as_str().to_owned(),
            scope: event.scope.map(|s| s.as_str().to_owned()),
            key: event.key.map(|k| k.as_str().to_owned()),
            version: note.version,
            outcome: outcome.as_str().to_owned(),
            detail: note.detail.clone(),
        })
    }

    /// Record a request that was refused before reaching the store (denied, malformed, no route).
    pub fn record(&mut self, event: &Event, outcome: Outcome, detail: Option<String>) {
        let note = Note {
            version: None,
            detail,
        };
        match Store::insert_audit(&self.conn, event, outcome, &note) {
            Ok(row) => eprintln!("{}", journal_line(&row)),
            Err(e) => eprintln!(
                "error: audit row not written ({e}): socket={} action={} outcome={} uid={:?}",
                event.socket.as_str(),
                event.action.as_str(),
                outcome.as_str(),
                event.caller.uid
            ),
        }
    }

    /// Run `op` in a transaction that also writes its audit row, so a change and its audit row are
    /// committed together or not at all. A failure is audited after the rollback.
    fn audited<T>(
        &mut self,
        event: &Event,
        op: impl FnOnce(&Transaction, &Keys) -> Result<(T, Note), StoreError>,
    ) -> Result<T, StoreError> {
        let Store { conn, keys } = self;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match op(&tx, keys) {
            Ok((value, note)) => {
                let row = Store::insert_audit(&tx, event, Outcome::Ok, &note)?;
                tx.commit()?;
                eprintln!("{}", journal_line(&row));
                Ok(value)
            }
            Err(e) => {
                drop(tx);
                let detail = match &e {
                    // Internal errors may carry details meant for the operator; they go to the
                    // journal line, never to the caller.
                    StoreError::NotFound(_) | StoreError::Forbidden(_) | StoreError::Invalid(_) => {
                        None
                    }
                    other => Some(other.to_string()),
                };
                self.record(event, e.outcome(), detail);
                Err(e)
            }
        }
    }

    /// Every live value in `scope`, by key. Fails as a whole if any value fails to open.
    pub fn fetch_scope(
        &mut self,
        event: &Event,
        scope: &ScopeName,
    ) -> Result<Vec<(String, Zeroizing<String>)>, StoreError> {
        self.audited(event, |tx, keys| {
            let mut statement = tx.prepare(
                "SELECT s.key, s.version, s.nonce, s.ciphertext, s.kek_id FROM secret s
                 WHERE s.scope = ?1
                   AND s.version = (SELECT max(version) FROM secret WHERE scope = s.scope AND key = s.key)
                   AND s.ciphertext IS NOT NULL
                 ORDER BY s.key",
            )?;
            let rows = statement.query_map([scope.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            let mut values = Vec::new();
            for row in rows {
                let (key, version, nonce, ciphertext, kek_id) = row?;
                let row = SealedRow {
                    nonce,
                    ciphertext,
                    kek_id,
                };
                let value = open_row(keys, scope.as_str(), &key, version, row)?;
                values.push((key, value));
            }
            let note = Note {
                version: None,
                detail: Some(format!("{} keys", values.len())),
            };
            Ok((values, note))
        })
    }

    /// The current version of every key in every scope, deleted ones included.
    pub fn list(&mut self, event: &Event) -> Result<Vec<KeyMeta>, StoreError> {
        self.audited(event, |tx, _| {
            let mut statement = tx.prepare(
                "SELECT s.scope, s.key, s.version, s.action, s.fingerprint, s.created_at, s.created_by
                 FROM secret s
                 WHERE s.version = (SELECT max(version) FROM secret WHERE scope = s.scope AND key = s.key)
                 ORDER BY s.scope, s.key",
            )?;
            let rows = statement.query_map([], |row| {
                let action: String = row.get(3)?;
                Ok(KeyMeta {
                    scope: row.get(0)?,
                    key: row.get(1)?,
                    version: row.get(2)?,
                    deleted: action == "delete",
                    action,
                    fingerprint: row.get(4)?,
                    set_at: format_utc(row.get(5)?),
                    set_by: row.get(6)?,
                })
            })?;
            let keys = rows.collect::<Result<Vec<_>, _>>()?;
            Ok((keys, Note::default()))
        })
    }

    /// Every version of one key, newest first.
    pub fn versions(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
    ) -> Result<Vec<VersionMeta>, StoreError> {
        self.audited(event, |tx, _| {
            let mut statement = tx.prepare(
                "SELECT version, action, fingerprint, rollback_of, created_at, created_by FROM secret
                 WHERE scope = ?1 AND key = ?2 ORDER BY version DESC",
            )?;
            let rows = statement.query_map(params![scope.as_str(), key.as_str()], |row| {
                let action: String = row.get(1)?;
                Ok(VersionMeta {
                    version: row.get(0)?,
                    deleted: action == "delete",
                    action,
                    fingerprint: row.get(2)?,
                    rollback_of: row.get(3)?,
                    set_at: format_utc(row.get(4)?),
                    set_by: row.get(5)?,
                })
            })?;
            let versions = rows.collect::<Result<Vec<_>, _>>()?;
            if versions.is_empty() {
                return Err(StoreError::NotFound(format!("no key {scope} {key}")));
            }
            Ok((versions, Note::default()))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_version(
        tx: &Transaction,
        keys: &Keys,
        caller: &Caller,
        scope: &ScopeName,
        key: &KeyName,
        version: i64,
        action: Action,
        value: Option<&str>,
        rollback_of: Option<i64>,
    ) -> Result<WriteResult, StoreError> {
        let uid = caller
            .uid
            .ok_or_else(|| StoreError::Forbidden("caller has no uid".to_owned()))?;
        let (sealed, fingerprint) = match value {
            Some(value) => (
                Some(keys.seal_secret(scope.as_str(), key.as_str(), version, value.as_bytes())?),
                Some(keys.fingerprint(value.as_bytes())),
            ),
            None => (None, None),
        };
        tx.execute(
            "INSERT INTO secret (scope, key, version, action, nonce, ciphertext, kek_id, fingerprint,
                                 rollback_of, created_at, created_by, created_by_uid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                scope.as_str(),
                key.as_str(),
                version,
                action.as_str(),
                sealed.as_ref().map(|s| s.nonce.to_vec()),
                sealed.as_ref().map(|s| s.ciphertext.as_slice()),
                sealed.as_ref().map(|_| keys.kek_id()),
                fingerprint,
                rollback_of,
                now_unix(),
                caller.created_by(),
                uid,
            ],
        )?;
        Ok(WriteResult {
            scope: scope.as_str().to_owned(),
            key: key.as_str().to_owned(),
            version,
            action: action.as_str().to_owned(),
            fingerprint,
            rollback_of,
        })
    }

    fn write_value(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
        guard: WriteGuard,
        action: Action,
        value: &str,
    ) -> Result<WriteResult, StoreError> {
        let caller = event.caller;
        self.audited(event, |tx, keys| {
            let current = latest(tx, scope, key)?;
            check_guard(guard, current.as_ref(), scope, key)?;
            let version = current.map_or(1, |c| c.version + 1);
            let result = Store::insert_version(
                tx,
                keys,
                caller,
                scope,
                key,
                version,
                action,
                Some(value),
                None,
            )?;
            let note = Note {
                version: Some(version),
                detail: None,
            };
            Ok((result, note))
        })
    }

    /// Set a value: a new version.
    pub fn set(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
        value: &SecretValue,
        guard: WriteGuard,
    ) -> Result<WriteResult, StoreError> {
        self.write_value(event, scope, key, guard, Action::Set, value.as_str())
    }

    /// Set a random value (`bytes` random bytes, base64url) that is never returned.
    pub fn generate(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
        bytes: usize,
        guard: WriteGuard,
    ) -> Result<WriteResult, StoreError> {
        if !(GENERATE_MIN_BYTES..=GENERATE_MAX_BYTES).contains(&bytes) {
            let e = StoreError::Invalid(format!(
                "bytes must be from {GENERATE_MIN_BYTES} to {GENERATE_MAX_BYTES}"
            ));
            self.record(event, e.outcome(), None);
            return Err(e);
        }
        let mut random = Zeroizing::new(vec![0u8; bytes]);
        if let Err(e) = random_bytes(&mut random) {
            let e = StoreError::Crypto(e);
            self.record(event, e.outcome(), Some(e.to_string()));
            return Err(e);
        }
        let value = base64url_encode(&random);
        self.write_value(event, scope, key, guard, Action::Generate, &value)
    }

    /// Delete: a tombstone version, which a rollback can undo.
    pub fn delete(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
    ) -> Result<WriteResult, StoreError> {
        let caller = event.caller;
        self.audited(event, |tx, keys| {
            let current = latest(tx, scope, key)?;
            let current = match current {
                Some(c) if !c.deleted => c,
                Some(_) => {
                    return Err(StoreError::NotFound(format!(
                        "{scope} {key} is already deleted"
                    )));
                }
                None => return Err(StoreError::NotFound(format!("no key {scope} {key}"))),
            };
            let version = current.version + 1;
            let result = Store::insert_version(
                tx,
                keys,
                caller,
                scope,
                key,
                version,
                Action::Delete,
                None,
                None,
            )?;
            let note = Note {
                version: Some(version),
                detail: None,
            };
            Ok((result, note))
        })
    }

    /// Restore version `target`'s value as a new version, re-sealed for that new version.
    pub fn rollback(
        &mut self,
        event: &Event,
        scope: &ScopeName,
        key: &KeyName,
        target: i64,
    ) -> Result<WriteResult, StoreError> {
        let caller = event.caller;
        self.audited(event, |tx, keys| {
            let row = tx
                .query_row(
                    "SELECT nonce, ciphertext, kek_id FROM secret
                     WHERE scope = ?1 AND key = ?2 AND version = ?3",
                    params![scope.as_str(), key.as_str(), target],
                    |row| {
                        Ok((
                            row.get::<_, Option<Vec<u8>>>(0)?,
                            row.get::<_, Option<Vec<u8>>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .optional()?;
            let what = || format!("{scope} {key} version {target}");
            let row = match row {
                None => return Err(StoreError::NotFound(format!("no {}", what()))),
                Some((Some(nonce), Some(ciphertext), Some(kek_id))) => SealedRow {
                    nonce,
                    ciphertext,
                    kek_id,
                },
                Some(_) => {
                    return Err(StoreError::Invalid(format!(
                        "{} is a delete; to delete, use DELETE",
                        what()
                    )));
                }
            };
            let value = open_row(keys, scope.as_str(), key.as_str(), target, row)?;
            let current = latest(tx, scope, key)?
                .ok_or_else(|| StoreError::Corrupt(format!("{} vanished", what())))?;
            let version = current.version + 1;
            let result = Store::insert_version(
                tx,
                keys,
                caller,
                scope,
                key,
                version,
                Action::Rollback,
                Some(&value),
                Some(target),
            )?;
            let note = Note {
                version: Some(version),
                detail: Some(format!("rollback to version {target}")),
            };
            Ok((result, note))
        })
    }

    /// The most recent audit rows, newest first. Audited itself.
    pub fn audit(&mut self, event: &Event, limit: u32) -> Result<Vec<AuditRow>, StoreError> {
        let limit = limit.clamp(1, AUDIT_MAX_LIMIT);
        self.audited(event, |tx, _| {
            let mut statement = tx.prepare(
                "SELECT id, at, uid, user, pid, cmdline, socket, action, scope, key, version, outcome, detail
                 FROM audit ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = statement.query_map([limit], |row| {
                Ok(AuditRow {
                    id: row.get(0)?,
                    at: format_utc(row.get(1)?),
                    uid: row.get(2)?,
                    user: row.get(3)?,
                    pid: row.get(4)?,
                    cmdline: row.get(5)?,
                    socket: row.get(6)?,
                    action: row.get(7)?,
                    scope: row.get(8)?,
                    key: row.get(9)?,
                    version: row.get(10)?,
                    outcome: row.get(11)?,
                    detail: row.get(12)?,
                })
            })?;
            let rows = rows.collect::<Result<Vec<_>, _>>()?;
            Ok((rows, Note::default()))
        })
    }

    /// Direct access for tests that tamper with the file.
    #[doc(hidden)]
    pub fn connection_for_tests(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;
    use crate::testutil::TempDir;

    fn master(byte: u8) -> MasterKey {
        MasterKey::from_hex(&hex_encode(&[byte; 32])).unwrap()
    }

    fn admin() -> Caller {
        Caller {
            uid: Some(998),
            user: Some("aegis".to_owned()),
            pid: Some(4242),
            cmdline: Some("aegis-web".to_owned()),
        }
    }

    fn infra() -> Caller {
        Caller {
            uid: Some(997),
            user: Some("aegis-infra".to_owned()),
            ..Caller::default()
        }
    }

    fn event<'a>(caller: &'a Caller, action: Action) -> Event<'a> {
        Event {
            caller,
            socket: Socket::Admin,
            action,
            scope: None,
            key: None,
        }
    }

    fn names(scope: &str, key: &str) -> (ScopeName, KeyName) {
        (
            ScopeName::parse(scope).unwrap(),
            KeyName::parse(key).unwrap(),
        )
    }

    fn value(text: &str) -> SecretValue {
        SecretValue::new(Zeroizing::new(text.to_owned())).unwrap()
    }

    fn fetch(store: &mut Store, scope: &ScopeName) -> Vec<(String, String)> {
        let caller = Caller {
            uid: Some(33),
            ..Caller::default()
        };
        let mut e = event(&caller, Action::Fetch);
        e.socket = Socket::Read;
        e.scope = Some(scope);
        store
            .fetch_scope(&e, scope)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }

    #[test]
    fn set_fetch_and_versions() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("epiphyte/prod", "DB");
        let (_, other) = names("epiphyte/prod", "API");
        let first = store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &key,
                &value("one"),
                WriteGuard::Any,
            )
            .unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.fingerprint.as_deref().map(str::len), Some(12));
        let second = store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &key,
                &value("two"),
                WriteGuard::Any,
            )
            .unwrap();
        assert_eq!(second.version, 2);
        assert_ne!(first.fingerprint, second.fingerprint);
        store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &other,
                &value("api"),
                WriteGuard::Any,
            )
            .unwrap();
        assert_eq!(
            fetch(&mut store, &scope),
            [
                ("API".to_owned(), "api".to_owned()),
                ("DB".to_owned(), "two".to_owned())
            ]
        );
        assert!(fetch(&mut store, &ScopeName::parse("epiphyte").unwrap()).is_empty());

        let versions = store
            .versions(&event(&caller, Action::Versions), &scope, &key)
            .unwrap();
        assert_eq!(
            versions.iter().map(|v| v.version).collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(versions[0].set_by, "aegis");
        assert!(versions.iter().all(|v| !v.deleted && v.action == "set"));

        let listed = store.list(&event(&caller, Action::ListScopes)).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].key, "DB");
        assert_eq!(listed[1].version, 2);
        assert_eq!(listed[1].fingerprint, second.fingerprint);
    }

    #[test]
    fn equal_values_have_equal_fingerprints() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, a) = names("s", "A");
        let (_, b) = names("s", "B");
        let fa = store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &a,
                &value("same"),
                WriteGuard::Any,
            )
            .unwrap()
            .fingerprint;
        let fb = store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &b,
                &value("same"),
                WriteGuard::Any,
            )
            .unwrap()
            .fingerprint;
        assert_eq!(fa, fb);
    }

    #[test]
    fn delete_then_rollback_restores_the_value() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("s", "K");
        let set = store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &key,
                &value("keep me"),
                WriteGuard::Any,
            )
            .unwrap();
        let deleted = store
            .delete(&event(&caller, Action::Delete), &scope, &key)
            .unwrap();
        assert_eq!(deleted.version, 2);
        assert_eq!(deleted.fingerprint, None);
        assert!(fetch(&mut store, &scope).is_empty());
        let again = store.delete(&event(&caller, Action::Delete), &scope, &key);
        assert!(matches!(again, Err(StoreError::NotFound(_))));

        let rolled = store
            .rollback(&event(&caller, Action::Rollback), &scope, &key, 1)
            .unwrap();
        assert_eq!(rolled.version, 3);
        assert_eq!(rolled.rollback_of, Some(1));
        assert_eq!(rolled.fingerprint, set.fingerprint);
        assert_eq!(
            fetch(&mut store, &scope),
            [("K".to_owned(), "keep me".to_owned())]
        );

        // The restored row is sealed for version 3, not a copy of version 1's ciphertext.
        let conn = store.connection_for_tests();
        let blob = |v: i64| -> Vec<u8> {
            conn.query_row(
                "SELECT ciphertext FROM secret WHERE scope = 's' AND key = 'K' AND version = ?1",
                [v],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_ne!(blob(1), blob(3));

        let to_delete = store.rollback(&event(&caller, Action::Rollback), &scope, &key, 2);
        assert!(matches!(to_delete, Err(StoreError::Invalid(_))));
        let missing = store.rollback(&event(&caller, Action::Rollback), &scope, &key, 9);
        assert!(matches!(missing, Err(StoreError::NotFound(_))));
        let versions = store
            .versions(&event(&caller, Action::Versions), &scope, &key)
            .unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|v| v.action.as_str())
                .collect::<Vec<_>>(),
            ["rollback", "delete", "set"]
        );
    }

    #[test]
    fn missing_keys() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("s", "K");
        assert!(matches!(
            store.versions(&event(&caller, Action::Versions), &scope, &key),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.delete(&event(&caller, Action::Delete), &scope, &key),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.rollback(&event(&caller, Action::Rollback), &scope, &key, 1),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn generate_makes_a_hidden_random_value() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("s", "TOKEN");
        let result = store
            .generate(
                &event(&caller, Action::Generate),
                &scope,
                &key,
                32,
                WriteGuard::Any,
            )
            .unwrap();
        assert_eq!(result.action, "generate");
        let fetched = fetch(&mut store, &scope);
        assert_eq!(fetched[0].1.len(), 43); // 32 bytes as unpadded base64url
        assert!(
            fetched[0]
                .1
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        store
            .generate(
                &event(&caller, Action::Generate),
                &scope,
                &key,
                32,
                WriteGuard::Any,
            )
            .unwrap();
        assert_ne!(fetch(&mut store, &scope)[0].1, fetched[0].1);
        for bad in [0, 15, 1025] {
            assert!(matches!(
                store.generate(
                    &event(&caller, Action::Generate),
                    &scope,
                    &key,
                    bad,
                    WriteGuard::Any
                ),
                Err(StoreError::Invalid(_))
            ));
        }
    }

    #[test]
    fn write_only_guard() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let (scope, new_key) = names("db/prod", "PASSWORD");
        let (_, admins_key) = names("db/prod", "ADMIN_SET");
        let infra = infra();
        let admin = admin();
        let guard = WriteGuard::NewOrOwn(997);

        // New key: allowed. Their own key: allowed again.
        store
            .set(
                &event(&infra, Action::Set),
                &scope,
                &new_key,
                &value("p1"),
                guard,
            )
            .unwrap();
        store
            .generate(
                &event(&infra, Action::Generate),
                &scope,
                &new_key,
                32,
                guard,
            )
            .unwrap();
        // Someone else's key: refused, and nothing written.
        store
            .set(
                &event(&admin, Action::Set),
                &scope,
                &admins_key,
                &value("a"),
                WriteGuard::Any,
            )
            .unwrap();
        let refused = store.set(
            &event(&infra, Action::Set),
            &scope,
            &admins_key,
            &value("x"),
            guard,
        );
        assert!(matches!(refused, Err(StoreError::Forbidden(_))));
        let refused = store.generate(
            &event(&infra, Action::Generate),
            &scope,
            &admins_key,
            32,
            guard,
        );
        assert!(matches!(refused, Err(StoreError::Forbidden(_))));
        // Their key, after an admin changed it: refused.
        store
            .set(
                &event(&admin, Action::Set),
                &scope,
                &new_key,
                &value("p2"),
                WriteGuard::Any,
            )
            .unwrap();
        let refused = store.set(
            &event(&infra, Action::Set),
            &scope,
            &new_key,
            &value("p3"),
            guard,
        );
        assert!(matches!(refused, Err(StoreError::Forbidden(_))));
        assert_eq!(
            fetch(&mut store, &scope),
            [
                ("ADMIN_SET".to_owned(), "a".to_owned()),
                ("PASSWORD".to_owned(), "p2".to_owned())
            ]
        );
    }

    #[test]
    fn ciphertext_moved_to_another_row_fails() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, a) = names("s", "A");
        let (_, b) = names("s", "B");
        store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &a,
                &value("value of A"),
                WriteGuard::Any,
            )
            .unwrap();
        store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &b,
                &value("value of B"),
                WriteGuard::Any,
            )
            .unwrap();
        store
            .connection_for_tests()
            .execute(
                "UPDATE secret SET (nonce, ciphertext) =
                   (SELECT nonce, ciphertext FROM secret WHERE key = 'A')
                 WHERE key = 'B'",
                [],
            )
            .unwrap();
        let reader = Caller::default();
        let mut e = event(&reader, Action::Fetch);
        e.scope = Some(&scope);
        let result = store.fetch_scope(&e, &scope);
        assert!(matches!(result, Err(StoreError::Corrupt(_))), "{result:?}");
        // The failure is audited, without the value.
        let rows = store.audit(&event(&caller, Action::Audit), 1).unwrap();
        let audit: Vec<String> = store
            .connection_for_tests()
            .prepare("SELECT coalesce(detail, '') || outcome FROM audit")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(audit.iter().any(|row| row.contains("does not open")));
        assert!(!audit.iter().any(|row| row.contains("value of")));
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn version_moved_to_another_version_fails() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("s", "K");
        store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &key,
                &value("old"),
                WriteGuard::Any,
            )
            .unwrap();
        store
            .set(
                &event(&caller, Action::Set),
                &scope,
                &key,
                &value("new"),
                WriteGuard::Any,
            )
            .unwrap();
        // Replay the old version's ciphertext as the current one.
        store
            .connection_for_tests()
            .execute(
                "UPDATE secret SET (nonce, ciphertext) =
                   (SELECT nonce, ciphertext FROM secret WHERE version = 1)
                 WHERE version = 2",
                [],
            )
            .unwrap();
        let reader = Caller::default();
        let e = event(&reader, Action::Fetch);
        assert!(matches!(
            store.fetch_scope(&e, &scope),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn audit_rows_for_every_request() {
        let mut store = Store::open_in_memory(&master(1)).unwrap();
        let caller = admin();
        let (scope, key) = names("s", "K");
        let mut e = event(&caller, Action::Set);
        e.scope = Some(&scope);
        e.key = Some(&key);
        store
            .set(&e, &scope, &key, &value("secret text"), WriteGuard::Any)
            .unwrap();
        let mut denied = event(&caller, Action::Delete);
        denied.scope = Some(&scope);
        store.record(&denied, Outcome::Denied, None);
        let rows = store.audit(&event(&caller, Action::Audit), 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].outcome, "denied");
        assert_eq!(rows[1].action, "set");
        assert_eq!(rows[1].scope.as_deref(), Some("s"));
        assert_eq!(rows[1].key.as_deref(), Some("K"));
        assert_eq!(rows[1].version, Some(1));
        assert_eq!(rows[1].uid, Some(998));
        assert_eq!(rows[1].pid, Some(4242));
        assert_eq!(rows[1].cmdline.as_deref(), Some("aegis-web"));
        // The audit request itself is the newest row now.
        let rows = store.audit(&event(&caller, Action::Audit), 1).unwrap();
        assert_eq!(rows[0].action, "audit");
        for row in store.audit(&event(&caller, Action::Audit), 100).unwrap() {
            assert!(!journal_line(&row).contains("secret text"));
        }
    }

    #[test]
    fn journal_lines_escape_caller_text() {
        let row = AuditRow {
            id: 1,
            at: format_utc(0),
            uid: Some(33),
            user: Some("www-data".to_owned()),
            pid: None,
            cmdline: Some("evil\naudit outcome=ok \"x\"".to_owned()),
            socket: "read".to_owned(),
            action: "fetch".to_owned(),
            scope: Some("a/b".to_owned()),
            key: None,
            version: None,
            outcome: "denied".to_owned(),
            detail: None,
        };
        let line = journal_line(&row);
        assert!(!line.contains('\n'));
        assert!(
            line.contains(r#"cmdline="evil\naudit outcome=ok \"x\"""#),
            "{line}"
        );
        assert!(line.contains("pid=- "));
    }

    #[test]
    fn file_store_reopens_and_refuses_a_wrong_key() {
        let dir = TempDir::new("store");
        let path = dir.path().join("vault.db");
        {
            let mut store = Store::open(&path, &master(1)).unwrap();
            let caller = admin();
            let (scope, key) = names("s", "K");
            store
                .set(
                    &event(&caller, Action::Set),
                    &scope,
                    &key,
                    &value("persisted"),
                    WriteGuard::Any,
                )
                .unwrap();
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mut store = Store::open(&path, &master(1)).unwrap();
        assert_eq!(
            fetch(&mut store, &ScopeName::parse("s").unwrap()),
            [("K".to_owned(), "persisted".to_owned())]
        );
        drop(store);
        let wrong = Store::open(&path, &master(2));
        assert!(
            matches!(wrong, Err(StoreError::WrongMasterKey(_))),
            "{wrong:?}"
        );
        // The file was not changed by the refused open.
        let mut store = Store::open(&path, &master(1)).unwrap();
        assert_eq!(fetch(&mut store, &ScopeName::parse("s").unwrap()).len(), 1);
    }

    #[test]
    fn damaged_canary_refuses_to_start() {
        let dir = TempDir::new("canary");
        let path = dir.path().join("vault.db");
        drop(Store::open(&path, &master(1)).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE meta SET value = zeroblob(64) WHERE name = 'canary'",
            [],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            Store::open(&path, &master(1)),
            Err(StoreError::WrongMasterKey(_))
        ));
    }

    #[test]
    fn foreign_database_is_refused() {
        let dir = TempDir::new("foreign");
        let path = dir.path().join("other.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t (x)").unwrap();
        drop(conn);
        assert!(matches!(
            Store::open(&path, &master(1)),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn shared_directory_is_refused() {
        let dir = TempDir::new("shared");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let result = Store::open(&dir.path().join("vault.db"), &master(1));
        assert!(matches!(result, Err(StoreError::Io(_))), "{result:?}");
        assert!(!dir.path().join("vault.db").exists());
    }

    #[test]
    fn loose_file_mode_is_tightened() {
        let dir = TempDir::new("mode");
        let path = dir.path().join("vault.db");
        drop(Store::open(&path, &master(1)).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(Store::open(&path, &master(1)).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
