//! The daemon: two Unix sockets, peer-uid checks, and the handlers behind them.
//!
//! Every request is checked against the policy using the uid the kernel reports for the connection
//! (`SO_PEERCRED`), then audited. A caller that isn't allowed on a socket at all gets 403 whatever it
//! asks for, so it learns nothing about routes or names. The socket file modes are only the outer fence.
//!
//! Request handling is synchronous (`Vault::read_request`, `Vault::admin_request`) and runs on tokio's
//! blocking pool, since SQLite is synchronous; axum only carries bytes and peer credentials.

use std::fs;
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{
    UnixDatagram, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::serve::IncomingStream;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use zeroize::Zeroizing;

use crate::accounts::Accounts;
use crate::listener::LimitedListener;
pub use crate::listener::{Limits, Peer};
use crate::names::{KeyName, ScopeName, SecretValue};
use crate::policy::{AdminRole, Policy};
use crate::routes::{AdminRoute, ReadRoute, RouteError, parse_admin, parse_read};
use crate::store::{
    AUDIT_DEFAULT_LIMIT, AUDIT_MAX_LIMIT, Action, Caller, Event, GENERATE_DEFAULT_BYTES, KeyMeta,
    Outcome, Socket, Store, StoreError, WriteGuard,
};

pub const READ_SOCKET: &str = "read.sock";
pub const ADMIN_SOCKET: &str = "admin.sock";

/// Largest request body: a 64 KiB value, JSON-escaped (up to 6 bytes per byte), plus room.
pub const MAX_BODY: usize = 512 * 1024;

/// Longest caller command line kept in the audit log, in characters.
const MAX_CMDLINE: usize = 512;

impl Connected<IncomingStream<'_, LimitedListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, LimitedListener>) -> Self {
        stream.io().peer()
    }
}

/// The caller's command line, best effort: Linux only, and the process may be gone already.
fn cmdline(pid: Option<i32>) -> Option<String> {
    let pid = pid.filter(|&p| p > 0)?;
    if !cfg!(target_os = "linux") {
        return None;
    }
    let file = fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
    let mut bytes = Vec::with_capacity(1024);
    file.take(4096).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes).replace('\0', " ");
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    Some(text.chars().take(MAX_CMDLINE).collect())
}

/// A finished response: status and JSON body.
pub struct Reply {
    pub status: StatusCode,
    pub body: Bytes,
}

impl Reply {
    fn json(status: StatusCode, value: &impl Serialize) -> Reply {
        match serde_json::to_vec(value) {
            Ok(body) => Reply {
                status,
                body: Bytes::from(body),
            },
            Err(_) => Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    fn error(status: StatusCode, message: &str) -> Reply {
        #[derive(Serialize)]
        struct ErrorBody<'a> {
            error: &'a str,
        }
        let body = serde_json::to_vec(&ErrorBody { error: message })
            .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec());
        Reply {
            status,
            body: Bytes::from(body),
        }
    }

    fn forbidden() -> Reply {
        Reply::error(StatusCode::FORBIDDEN, "not allowed")
    }

    /// Map a store error. Internal details stay in the journal (written by the store), not the reply.
    fn store_error(e: &StoreError) -> Reply {
        match e {
            StoreError::NotFound(m) => Reply::error(StatusCode::NOT_FOUND, m),
            StoreError::Forbidden(m) => Reply::error(StatusCode::FORBIDDEN, m),
            StoreError::Invalid(m) => Reply::error(StatusCode::BAD_REQUEST, m),
            _ => Reply::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error; see the vault's journal",
            ),
        }
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

/// The JSON for a fetched scope, built in a buffer sized up front (so it never reallocates and leaves
/// copies behind) and wiped when the response body is dropped. Copies hyper makes are out of reach.
fn secrets_reply(scope: &ScopeName, values: &[(String, Zeroizing<String>)]) -> Reply {
    #[derive(Serialize)]
    struct Body<'a> {
        scope: &'a str,
        secrets: std::collections::BTreeMap<&'a str, &'a str>,
    }
    let secrets = values
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    // JSON escaping at most sextuples a byte (\u00XX).
    let capacity = 64
        + 6 * scope.as_str().len()
        + values
            .iter()
            .map(|(k, v)| 6 * (k.len() + v.len()) + 8)
            .sum::<usize>();
    let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
    let body = Body {
        scope: scope.as_str(),
        secrets,
    };
    if serde_json::to_writer(&mut *buffer, &body).is_err() {
        return Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    Reply {
        status: StatusCode::OK,
        body: Bytes::from_owner(buffer),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBody {
    value: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackBody {
    version: i64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateBody {
    bytes: Option<usize>,
}

/// Parse a JSON body. The error never quotes the body: serde's messages can include the values in it.
fn parse_body<'a, T: Deserialize<'a>>(body: &'a [u8], expected: &str) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| {
        format!(
            "body must be JSON {expected} (problem at line {}, column {})",
            e.line(),
            e.column()
        )
    })
}

fn audit_limit(query: Option<&str>) -> Result<u32, String> {
    let mut limit = AUDIT_DEFAULT_LIMIT;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("limit", n)) => {
                limit = n
                    .parse()
                    .ok()
                    .filter(|n| (1..=AUDIT_MAX_LIMIT).contains(n))
                    .ok_or_else(|| format!("limit must be from 1 to {AUDIT_MAX_LIMIT}"))?;
            }
            _ => return Err("the only query parameter is limit".to_owned()),
        }
    }
    Ok(limit)
}

#[derive(Serialize)]
struct ScopeListing<'a> {
    scope: &'a str,
    /// Who may read it, per policy; empty for a scope the policy doesn't name.
    allow_users: Vec<&'a str>,
    in_policy: bool,
    keys: Vec<&'a KeyMeta>,
}

/// The vault: store, policy and accounts, shared by both sockets.
pub struct Vault {
    store: Mutex<Store>,
    policy: Policy,
    accounts: Accounts,
}

impl Vault {
    pub fn new(store: Store, policy: Policy, accounts: Accounts) -> Vault {
        Vault {
            store: Mutex::new(store),
            policy,
            accounts,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        // A panic mid-request rolled its transaction back on unwind; the connection is still good.
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn caller(&self, peer: Peer) -> Caller {
        Caller {
            uid: peer.uid,
            user: peer
                .uid
                .and_then(|uid| self.accounts.user_name(uid))
                .map(str::to_owned),
            pid: peer.pid,
            cmdline: cmdline(peer.pid),
        }
    }

    /// Handle one request on read.sock.
    pub fn read_request(&self, peer: Peer, method: &Method, path: &str) -> Reply {
        let caller = self.caller(peer);
        let route = parse_read(method, path);
        let scope = match &route {
            Ok(ReadRoute::Fetch(scope)) => Some(scope.clone()),
            Err(_) => None,
        };
        let event = Event {
            caller: &caller,
            socket: Socket::Read,
            action: if route.is_ok() {
                Action::Fetch
            } else {
                Action::Unknown
            },
            scope: scope.as_ref(),
            key: None,
        };
        let mut store = self.store();

        // Not a reader of anything: refused before the route says anything.
        let Some(uid) = caller.uid.filter(|&uid| self.policy.is_reader(uid)) else {
            store.record(&event, Outcome::Denied, None);
            return Reply::forbidden();
        };
        let route = match route {
            Ok(route) => route,
            Err(e) => return route_error(&mut store, &event, e),
        };
        match route {
            ReadRoute::Fetch(scope) => {
                if !self.policy.may_read(uid, &scope) {
                    store.record(&event, Outcome::Denied, None);
                    return Reply::forbidden();
                }
                match store.fetch_scope(&event, &scope) {
                    Ok(values) => secrets_reply(&scope, &values),
                    Err(e) => Reply::store_error(&e),
                }
            }
        }
    }

    /// Handle one request on admin.sock. No branch returns a value. `body` is `None` when it was over
    /// `MAX_BODY`.
    pub fn admin_request(
        &self,
        peer: Peer,
        method: &Method,
        path: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
    ) -> Reply {
        let caller = self.caller(peer);
        let route = parse_admin(method, path);
        let names = |s: &ScopeName, k: &KeyName| (Some(s.clone()), Some(k.clone()));
        let (action, (scope, key)): (Action, (Option<ScopeName>, Option<KeyName>)) = match &route {
            Ok(AdminRoute::ListScopes) => (Action::ListScopes, (None, None)),
            Ok(AdminRoute::Audit) => (Action::Audit, (None, None)),
            Ok(AdminRoute::Versions(s, k)) => (Action::Versions, names(s, k)),
            Ok(AdminRoute::Set(s, k)) => (Action::Set, names(s, k)),
            Ok(AdminRoute::Delete(s, k)) => (Action::Delete, names(s, k)),
            Ok(AdminRoute::Rollback(s, k)) => (Action::Rollback, names(s, k)),
            Ok(AdminRoute::Generate(s, k)) => (Action::Generate, names(s, k)),
            Err(_) => (Action::Unknown, (None, None)),
        };
        let event = Event {
            caller: &caller,
            socket: Socket::Admin,
            action,
            scope: scope.as_ref(),
            key: key.as_ref(),
        };
        let mut store = self.store();

        let Some((uid, role)) = caller
            .uid
            .and_then(|uid| self.policy.admin_role(uid).map(|role| (uid, role)))
        else {
            store.record(&event, Outcome::Denied, None);
            return Reply::forbidden();
        };
        let Some(body) = body else {
            store.record(&event, Outcome::Invalid, Some("body too large".to_owned()));
            return Reply::error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        };
        let route = match route {
            Ok(route) => route,
            Err(e) => return route_error(&mut store, &event, e),
        };
        let guard = match (role, &route) {
            (AdminRole::Full, _) => WriteGuard::Any,
            (AdminRole::WriteOnly, AdminRoute::Set(..) | AdminRoute::Generate(..)) => {
                WriteGuard::NewOrOwn(uid)
            }
            (AdminRole::WriteOnly, _) => {
                store.record(&event, Outcome::Denied, Some("write_only".to_owned()));
                return Reply::forbidden();
            }
        };
        let invalid = |store: &mut Store, message: String| {
            store.record(&event, Outcome::Invalid, None);
            Reply::error(StatusCode::BAD_REQUEST, &message)
        };

        match route {
            AdminRoute::ListScopes => match store.list(&event) {
                Ok(keys) => Reply::json(StatusCode::OK, &self.listing(&keys)),
                Err(e) => Reply::store_error(&e),
            },
            AdminRoute::Versions(scope, key) => match store.versions(&event, &scope, &key) {
                Ok(versions) => {
                    #[derive(Serialize)]
                    struct Versions<'a> {
                        scope: &'a str,
                        key: &'a str,
                        versions: Vec<crate::store::VersionMeta>,
                    }
                    Reply::json(
                        StatusCode::OK,
                        &Versions {
                            scope: scope.as_str(),
                            key: key.as_str(),
                            versions,
                        },
                    )
                }
                Err(e) => Reply::store_error(&e),
            },
            AdminRoute::Set(scope, key) => {
                let parsed: SetBody = match parse_body(body, r#"{"value": "<text>"}"#) {
                    Ok(parsed) => parsed,
                    Err(message) => return invalid(&mut store, message),
                };
                let value = match SecretValue::new(parsed.value) {
                    Ok(value) => value,
                    Err(e) => return invalid(&mut store, e.to_string()),
                };
                write_reply(store.set(&event, &scope, &key, &value, guard))
            }
            AdminRoute::Delete(scope, key) => write_reply(store.delete(&event, &scope, &key)),
            AdminRoute::Rollback(scope, key) => {
                let parsed: RollbackBody = match parse_body(body, r#"{"version": <n>}"#) {
                    Ok(parsed) => parsed,
                    Err(message) => return invalid(&mut store, message),
                };
                if parsed.version < 1 {
                    return invalid(&mut store, "version must be 1 or more".to_owned());
                }
                write_reply(store.rollback(&event, &scope, &key, parsed.version))
            }
            AdminRoute::Generate(scope, key) => {
                let parsed: GenerateBody = if body.iter().all(u8::is_ascii_whitespace) {
                    GenerateBody::default()
                } else {
                    match parse_body(body, r#"{"bytes": <n>}"#) {
                        Ok(parsed) => parsed,
                        Err(message) => return invalid(&mut store, message),
                    }
                };
                let bytes = parsed.bytes.unwrap_or(GENERATE_DEFAULT_BYTES);
                write_reply(store.generate(&event, &scope, &key, bytes, guard))
            }
            AdminRoute::Audit => {
                let limit = match audit_limit(query) {
                    Ok(limit) => limit,
                    Err(message) => return invalid(&mut store, message),
                };
                match store.audit(&event, limit) {
                    Ok(rows) => {
                        #[derive(Serialize)]
                        struct AuditBody {
                            audit: Vec<crate::store::AuditRow>,
                        }
                        Reply::json(StatusCode::OK, &AuditBody { audit: rows })
                    }
                    Err(e) => Reply::store_error(&e),
                }
            }
        }
    }

    /// Scopes from the store and the policy together: a scope the policy names but that has no keys
    /// yet still shows, with who may read it.
    fn listing<'a>(&'a self, keys: &'a [KeyMeta]) -> serde_json::Value {
        let mut scopes: std::collections::BTreeMap<&str, ScopeListing<'a>> = self
            .policy
            .scopes()
            .map(|(scope, grant)| {
                (
                    scope.as_str(),
                    ScopeListing {
                        scope: scope.as_str(),
                        allow_users: grant.users.iter().map(String::as_str).collect(),
                        in_policy: true,
                        keys: Vec::new(),
                    },
                )
            })
            .collect();
        for key in keys {
            scopes
                .entry(key.scope.as_str())
                .or_insert_with(|| ScopeListing {
                    scope: key.scope.as_str(),
                    allow_users: Vec::new(),
                    in_policy: false,
                    keys: Vec::new(),
                })
                .keys
                .push(key);
        }
        serde_json::json!({ "scopes": scopes.into_values().collect::<Vec<_>>() })
    }
}

fn write_reply(result: Result<crate::store::WriteResult, StoreError>) -> Reply {
    match result {
        Ok(written) => Reply::json(StatusCode::OK, &written),
        Err(e) => Reply::store_error(&e),
    }
}

fn route_error(store: &mut Store, event: &Event, e: RouteError) -> Reply {
    match e {
        RouteError::NotFound => {
            store.record(event, Outcome::NotFound, None);
            Reply::error(StatusCode::NOT_FOUND, "no such route")
        }
        RouteError::MethodNotAllowed => {
            store.record(
                event,
                Outcome::Invalid,
                Some("method not allowed".to_owned()),
            );
            Reply::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        RouteError::BadName(e) => {
            store.record(event, Outcome::Invalid, Some(e.to_string()));
            Reply::error(StatusCode::BAD_REQUEST, &e.to_string())
        }
    }
}

async fn read_handler(
    State(vault): State<Arc<Vault>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    method: Method,
    uri: Uri,
) -> Reply {
    let path = uri.path().to_owned();
    tokio::task::spawn_blocking(move || vault.read_request(peer, &method, &path))
        .await
        .unwrap_or_else(|_| Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
}

async fn admin_handler(
    State(vault): State<Arc<Vault>>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    method: Method,
    uri: Uri,
    body: Body,
) -> Reply {
    let path = uri.path().to_owned();
    let query = uri.query().map(str::to_owned);
    // Read here, but judged in admin_request: an oversized body is refused there, after the caller
    // check and with an audit row.
    let body = axum::body::to_bytes(body, MAX_BODY).await.ok();
    tokio::task::spawn_blocking(move || {
        vault.admin_request(peer, &method, &path, query.as_deref(), body.as_deref())
    })
    .await
    .unwrap_or_else(|_| Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
}

/// read.sock: every request goes to `Vault::read_request`.
pub fn read_router(vault: Arc<Vault>) -> Router {
    Router::new().fallback(read_handler).with_state(vault)
}

/// admin.sock: every request goes to `Vault::admin_request`.
pub fn admin_router(vault: Arc<Vault>) -> Router {
    Router::new().fallback(admin_handler).with_state(vault)
}

/// The two bound sockets, created before the runtime starts serving.
pub struct Listeners {
    read: StdUnixListener,
    admin: StdUnixListener,
    paths: [PathBuf; 2],
}

impl Listeners {
    pub fn paths(&self) -> &[PathBuf; 2] {
        &self.paths
    }
}

/// Create `path` as a listening socket: mode 0660, group `gid` if given. A stale socket file from a
/// previous run is replaced; a live one (another vault answering) or any other file is an error.
fn bind_socket(path: &Path, gid: Option<u32>) -> io::Result<StdUnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if StdUnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    format!("{}: another process is serving it", path.display()),
                ));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = StdUnixListener::bind(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    if let Some(gid) = gid {
        std::os::unix::fs::lchown(path, None, Some(gid)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}: chgrp to gid {gid}: {e} (is the vault's user in that group?)",
                    path.display()
                ),
            )
        })?;
    }
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Bind `read.sock` and `admin.sock` in `run_dir` (created 0755 if missing). Refuses a run directory
/// that group or others can write: they could swap in sockets of their own.
pub fn bind(run_dir: &Path, policy: &Policy) -> io::Result<Listeners> {
    if !run_dir.exists() {
        fs::create_dir_all(run_dir)?;
        fs::set_permissions(run_dir, fs::Permissions::from_mode(0o755))?;
    }
    crate::paths::check_trusted(run_dir, "run directory")?;
    let read_path = run_dir.join(READ_SOCKET);
    let admin_path = run_dir.join(ADMIN_SOCKET);
    let read = bind_socket(&read_path, policy.read_gid)?;
    let admin = bind_socket(&admin_path, policy.admin_gid)?;
    Ok(Listeners {
        read,
        admin,
        paths: [read_path, admin_path],
    })
}

/// Tell systemd (`Type=notify`) the sockets are up. A no-op outside systemd.
pub fn notify_ready() {
    let Some(target) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let result = (|| -> io::Result<()> {
        let socket = UnixDatagram::unbound()?;
        let bytes = target.as_encoded_bytes();
        if let Some(name) = bytes.strip_prefix(b"@") {
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                socket.send_to_addr(b"READY=1", &addr)?;
            }
            #[cfg(not(target_os = "linux"))]
            let _ = name;
        } else {
            socket.send_to(b"READY=1", &target)?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("warning: sd_notify READY=1 failed: {e}");
    }
}

/// Serve both sockets, each under `limits`, until `shutdown` completes; then finish in-flight requests
/// and remove the socket files.
pub async fn serve(
    vault: Arc<Vault>,
    listeners: Listeners,
    limits: Limits,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let read = LimitedListener::new(UnixListener::from_std(listeners.read)?, limits);
    let admin = LimitedListener::new(UnixListener::from_std(listeners.admin)?, limits);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let wait = |mut stopped: tokio::sync::watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|&stop| stop).await;
    };

    let read_server = axum::serve(
        read,
        read_router(Arc::clone(&vault)).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(wait(stopped.clone()));
    let admin_server = axum::serve(
        admin,
        admin_router(vault).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(wait(stopped));
    let signal = async move {
        shutdown.await;
        let _ = stop.send(true);
        Ok::<(), io::Error>(())
    };

    let result = tokio::try_join!(
        std::future::IntoFuture::into_future(read_server),
        std::future::IntoFuture::into_future(admin_server),
        signal
    );
    for path in listeners.paths {
        let _ = fs::remove_file(path);
    }
    result.map(|_| ())
}

/// Resolves on SIGTERM or SIGINT.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        eprintln!("warning: can't listen for signals; stop with SIGKILL");
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => eprintln!("SIGTERM: shutting down"),
        _ = int.recv() => eprintln!("SIGINT: shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_limits() {
        assert_eq!(audit_limit(None), Ok(AUDIT_DEFAULT_LIMIT));
        assert_eq!(audit_limit(Some("")), Ok(AUDIT_DEFAULT_LIMIT));
        assert_eq!(audit_limit(Some("limit=5")), Ok(5));
        assert_eq!(audit_limit(Some("limit=1000")), Ok(1000));
        assert!(audit_limit(Some("limit=0")).is_err());
        assert!(audit_limit(Some("limit=1001")).is_err());
        assert!(audit_limit(Some("limit=x")).is_err());
        assert!(audit_limit(Some("limit=5&value=1")).is_err());
    }

    #[test]
    fn body_errors_never_quote_the_body() {
        let body = br#"{"version": "hunter2"}"#;
        let err = parse_body::<RollbackBody>(body, "x").err().unwrap();
        assert!(!err.contains("hunter2"), "{err}");
        let body = br#"{"value": "hunter2", "extra": "hunter3"}"#;
        let err = parse_body::<SetBody>(body, "x").err().unwrap();
        assert!(!err.contains("hunter"), "{err}");
    }

    #[test]
    fn secrets_reply_is_json() {
        let scope = ScopeName::parse("a/b").unwrap();
        let values = vec![
            (
                "K".to_owned(),
                Zeroizing::new("line\n\"quoted\"\u{0}".to_owned()),
            ),
            ("L".to_owned(), Zeroizing::new("ü".to_owned())),
        ];
        let reply = secrets_reply(&scope, &values);
        assert_eq!(reply.status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(parsed["scope"], "a/b");
        assert_eq!(parsed["secrets"]["K"], "line\n\"quoted\"\u{0}");
        assert_eq!(parsed["secrets"]["L"], "ü");
    }

    #[test]
    fn cmdline_of_this_process() {
        if cfg!(target_os = "linux") {
            let line = cmdline(Some(i32::try_from(std::process::id()).unwrap())).unwrap();
            assert!(!line.is_empty());
            assert!(!line.contains('\0'));
        }
        assert_eq!(cmdline(None), None);
        assert_eq!(cmdline(Some(0)), None);
        assert_eq!(cmdline(Some(-1)), None);
    }
}
