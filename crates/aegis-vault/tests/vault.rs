//! The plan's "Tests that guard the promises", against a vault serving real Unix sockets.

mod common;

use aegis_vault::names::{KeyName, ScopeName, SecretValue};
use aegis_vault::routes::{AdminRoute, parse_admin};
use aegis_vault::store::{Action, Caller, Event, Socket, WriteGuard};
use aegis_vault::testutil::current_uid;
use axum::http::Method;
use common::{TestVault, body_text, json};
use zeroize::Zeroizing;

const SECRET: &str = "s3cr3t-VALUE-0xC0FFEE";

/// `me` administers and reads app/prod; www-data reads other/prod.
const POLICY: &str = r#"
[admin]
full = ["me"]

[scope."app/prod"]
allow_users = ["me"]

[scope."other/prod"]
allow_users = ["www-data"]

[scope."empty/scope"]
allow_users = ["me", "www-data"]
"#;

fn set(vault: &TestVault, scope: &str, key: &str, value: &str) -> serde_json::Value {
    let body = serde_json::json!({ "value": value }).to_string();
    let response = vault.admin("PUT", &format!("/v1/scope/{scope}/key/{key}"), Some(&body));
    assert_eq!(response.status, 200, "{}", body_text(&response));
    json(&response)
}

fn secrets(vault: &TestVault, scope: &str) -> serde_json::Value {
    let response = vault.get(&format!("/v1/scope/{scope}"));
    assert_eq!(response.status, 200, "{}", body_text(&response));
    json(&response)["secrets"].clone()
}

#[test]
fn allowed_uid_reads_only_its_scopes() {
    let vault = TestVault::start(POLICY);
    set(&vault, "app/prod", "DB_PASSWORD", SECRET);
    set(&vault, "app/prod", "API_KEY", "api");
    set(&vault, "other/prod", "TOKEN", "not yours");

    let response = vault.get("/v1/scope/app/prod");
    assert_eq!(response.status, 200);
    let body = json(&response);
    assert_eq!(body["scope"], "app/prod");
    assert_eq!(
        body["secrets"],
        serde_json::json!({ "API_KEY": "api", "DB_PASSWORD": SECRET })
    );

    // Another uid's scope, a scope the policy doesn't name, a parent scope: all refused alike.
    for path in [
        "/v1/scope/other/prod",
        "/v1/scope/nobody/prod",
        "/v1/scope/app",
    ] {
        let response = vault.get(path);
        assert_eq!(response.status, 403, "{path}");
        assert!(!body_text(&response).contains("not yours"));
    }
    // A scope the caller may read but that has no keys yet: empty, not an error.
    assert_eq!(secrets(&vault, "empty/scope"), serde_json::json!({}));
}

#[test]
fn uid_that_reads_nothing_is_refused_everything() {
    let vault = TestVault::start(
        r#"
[admin]
full = ["me"]

[scope."app/prod"]
allow_users = ["www-data"]
"#,
    );
    set(&vault, "app/prod", "K", SECRET);
    // Even malformed or unknown paths get 403, so a stranger learns nothing about routes or names.
    for (method, path) in [
        ("GET", "/v1/scope/app/prod"),
        ("GET", "/v1/scope/BadName"),
        ("GET", "/nonsense"),
        ("POST", "/v1/scope/app/prod"),
    ] {
        let response = aegis_vault::client::request(&vault.read, method, path, None).unwrap();
        assert_eq!(response.status, 403, "{method} {path}");
        assert_eq!(json(&response)["error"], "not allowed");
    }
}

#[test]
fn read_socket_errors_for_a_reader() {
    let vault = TestVault::start(POLICY);
    assert_eq!(vault.get("/v1/scope/Bad").status, 400);
    assert_eq!(vault.get("/v1/scope/a/../b").status, 400);
    assert_eq!(vault.get("/v1/scopes").status, 404);
    assert_eq!(vault.get("/").status, 404);
    let response =
        aegis_vault::client::request(&vault.read, "DELETE", "/v1/scope/app/prod", None).unwrap();
    assert_eq!(response.status, 405);
}

/// Names each admin route, exhaustively: adding a route to `AdminRoute` breaks this until the test
/// below covers it.
fn route_name(route: &AdminRoute) -> &'static str {
    match route {
        AdminRoute::ListScopes => "list",
        AdminRoute::Versions(..) => "versions",
        AdminRoute::Set(..) => "set",
        AdminRoute::Delete(..) => "delete",
        AdminRoute::Rollback(..) => "rollback",
        AdminRoute::Generate(..) => "generate",
        AdminRoute::Audit => "audit",
    }
}

#[test]
fn admin_socket_never_returns_a_value() {
    let vault = TestVault::start(POLICY);
    set(&vault, "app/prod", "DB_PASSWORD", SECRET);
    let generated = vault.admin("POST", "/v1/scope/app/prod/key/GEN/generate", Some("{}"));
    assert_eq!(generated.status, 200);
    let generated_value = secrets(&vault, "app/prod")["GEN"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(generated_value.len(), 43);
    assert!(!body_text(&generated).contains(&generated_value));

    // Every admin route, then everything that might look like a way to get a value.
    let routes = [
        ("GET", "/v1/scopes", None),
        ("GET", "/v1/scope/app/prod/key/DB_PASSWORD/versions", None),
        (
            "PUT",
            "/v1/scope/app/prod/key/COPY",
            Some(r#"{"value":"other"}"#),
        ),
        (
            "POST",
            "/v1/scope/app/prod/key/DB_PASSWORD/rollback",
            Some(r#"{"version":1}"#),
        ),
        (
            "POST",
            "/v1/scope/app/prod/key/GEN/generate",
            Some(r#"{"bytes":16}"#),
        ),
        ("DELETE", "/v1/scope/app/prod/key/COPY", None),
        ("GET", "/v1/audit?limit=1000", None),
    ];
    let mut covered = std::collections::BTreeSet::new();
    for (method, path, _) in &routes {
        let path_only = path.split('?').next().unwrap();
        let route =
            parse_admin(&Method::from_bytes(method.as_bytes()).unwrap(), path_only).unwrap();
        covered.insert(route_name(&route));
    }
    assert_eq!(
        covered.len(),
        7,
        "every AdminRoute variant is exercised: {covered:?}"
    );

    let probes = [
        ("GET", "/v1/scope/app/prod", None),
        ("GET", "/v1/scope/app/prod/key/DB_PASSWORD", None),
        ("GET", "/v1/scope/app/prod/key/DB_PASSWORD/value", None),
        ("POST", "/v1/scope/app/prod/key/DB_PASSWORD/reveal", None),
        (
            "GET",
            "/v1/scope/app/prod/key/DB_PASSWORD/versions?reveal=1",
            None,
        ),
        (
            "PUT",
            "/v1/scope/app/prod/key/DB_PASSWORD",
            Some(r#"{"value": 5}"#),
        ),
        (
            "POST",
            "/v1/scope/app/prod/key/DB_PASSWORD/rollback",
            Some(r#"{"version":"x"}"#),
        ),
        ("GET", "/v1/secrets", None),
    ];
    for (method, path, body) in routes.iter().chain(probes.iter()) {
        let response = vault.admin(method, path, *body);
        let text = body_text(&response);
        assert!(
            !text.contains(SECRET),
            "{method} {path} returned the value: {text}"
        );
        assert!(
            !text.contains(&generated_value),
            "{method} {path} returned the generated value"
        );
    }
    // The read route doesn't exist on admin.sock.
    assert_eq!(vault.admin("GET", "/v1/scope/app/prod", None).status, 404);
}

#[test]
fn admin_listing_and_versions() {
    let vault = TestVault::start(POLICY);
    let first = set(&vault, "app/prod", "K", "one");
    set(&vault, "app/prod", "K", "two");
    set(&vault, "unlisted/scope", "X", "x");

    let listing = json(&vault.admin("GET", "/v1/scopes", None));
    let scopes = listing["scopes"].as_array().unwrap();
    let names: Vec<&str> = scopes
        .iter()
        .map(|s| s["scope"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["app/prod", "empty/scope", "other/prod", "unlisted/scope"]
    );
    assert_eq!(scopes[0]["allow_users"], serde_json::json!(["me"]));
    assert_eq!(scopes[0]["keys"][0]["version"], 2);
    assert_eq!(scopes[0]["keys"][0]["set_by"], "me");
    assert_eq!(scopes[1]["keys"], serde_json::json!([]));
    assert_eq!(scopes[3]["in_policy"], false);

    let versions = json(&vault.admin("GET", "/v1/scope/app/prod/key/K/versions", None));
    let list = versions["versions"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[1]["fingerprint"], first["fingerprint"]);
    assert_eq!(
        vault
            .admin("GET", "/v1/scope/app/prod/key/NOPE/versions", None)
            .status,
        404
    );
}

#[test]
fn delete_then_rollback_restores_the_value() {
    let vault = TestVault::start(POLICY);
    let original = set(&vault, "app/prod", "K", SECRET);
    let deleted = vault.admin("DELETE", "/v1/scope/app/prod/key/K", None);
    assert_eq!(deleted.status, 200);
    assert_eq!(json(&deleted)["version"], 2);
    assert_eq!(secrets(&vault, "app/prod"), serde_json::json!({}));
    assert_eq!(
        vault
            .admin("DELETE", "/v1/scope/app/prod/key/K", None)
            .status,
        404
    );

    let rolled = vault.admin(
        "POST",
        "/v1/scope/app/prod/key/K/rollback",
        Some(r#"{"version": 1}"#),
    );
    assert_eq!(rolled.status, 200, "{}", body_text(&rolled));
    let rolled = json(&rolled);
    assert_eq!(rolled["version"], 3);
    assert_eq!(rolled["rollback_of"], 1);
    assert_eq!(rolled["fingerprint"], original["fingerprint"]);
    assert_eq!(secrets(&vault, "app/prod")["K"], SECRET);

    // Rolling back to the delete itself, or to nothing, is refused.
    let to_delete = vault.admin(
        "POST",
        "/v1/scope/app/prod/key/K/rollback",
        Some(r#"{"version": 2}"#),
    );
    assert_eq!(to_delete.status, 400);
    let to_nothing = vault.admin(
        "POST",
        "/v1/scope/app/prod/key/K/rollback",
        Some(r#"{"version": 99}"#),
    );
    assert_eq!(to_nothing.status, 404);
    let to_zero = vault.admin(
        "POST",
        "/v1/scope/app/prod/key/K/rollback",
        Some(r#"{"version": 0}"#),
    );
    assert_eq!(to_zero.status, 400);
}

#[test]
fn write_only_callers_may_only_store_and_generate() {
    let someone = Caller {
        uid: Some(current_uid().wrapping_add(3)),
        user: Some("someone".to_owned()),
        ..Caller::default()
    };
    let vault = TestVault::start_with(
        r#"
[admin]
write_only = ["me"]

[scope."db/prod"]
allow_users = ["www-data"]
"#,
        |store| {
            let scope = ScopeName::parse("db/prod").unwrap();
            let key = KeyName::parse("THEIRS").unwrap();
            let event = Event {
                caller: &someone,
                socket: Socket::Admin,
                action: Action::Set,
                scope: Some(&scope),
                key: Some(&key),
            };
            let value = SecretValue::new(Zeroizing::new("theirs".to_owned())).unwrap();
            store
                .set(&event, &scope, &key, &value, WriteGuard::Any)
                .unwrap();
        },
    );

    // Store and generate onto new keys, and again onto keys this caller set last.
    let stored = vault.admin(
        "PUT",
        "/v1/scope/db/prod/key/PASSWORD",
        Some(r#"{"value":"p"}"#),
    );
    assert_eq!(stored.status, 200, "{}", body_text(&stored));
    let again = vault.admin(
        "PUT",
        "/v1/scope/db/prod/key/PASSWORD",
        Some(r#"{"value":"q"}"#),
    );
    assert_eq!(again.status, 200);
    let generated = vault.admin("POST", "/v1/scope/db/prod/key/TOKEN/generate", None);
    assert_eq!(generated.status, 200, "{}", body_text(&generated));
    assert_eq!(
        vault
            .admin(
                "POST",
                "/v1/scope/db/prod/key/TOKEN/generate",
                Some(r#"{"bytes": 64}"#)
            )
            .status,
        200
    );

    // Not onto a key someone else set.
    let theirs = vault.admin(
        "PUT",
        "/v1/scope/db/prod/key/THEIRS",
        Some(r#"{"value":"x"}"#),
    );
    assert_eq!(theirs.status, 403);
    assert_eq!(
        vault
            .admin("POST", "/v1/scope/db/prod/key/THEIRS/generate", None)
            .status,
        403
    );

    // Everything else: 403.
    for (method, path, body) in [
        ("GET", "/v1/scopes", None),
        ("GET", "/v1/audit", None),
        ("GET", "/v1/scope/db/prod/key/PASSWORD/versions", None),
        ("DELETE", "/v1/scope/db/prod/key/PASSWORD", None),
        (
            "POST",
            "/v1/scope/db/prod/key/PASSWORD/rollback",
            Some(r#"{"version":1}"#),
        ),
    ] {
        let response = vault.admin(method, path, body);
        assert_eq!(response.status, 403, "{method} {path}");
    }
    // A write_only admin isn't a reader either.
    assert_eq!(vault.get("/v1/scope/db/prod").status, 403);
}

#[test]
fn non_admin_is_refused_everything_on_admin_socket() {
    let vault = TestVault::start(
        r#"
[scope."app/prod"]
allow_users = ["me"]
"#,
    );
    for (method, path, body) in [
        ("GET", "/v1/scopes", None),
        ("PUT", "/v1/scope/app/prod/key/K", Some(r#"{"value":"x"}"#)),
        ("POST", "/v1/scope/app/prod/key/K/generate", None),
        ("GET", "/nonsense", None),
        ("PUT", "/v1/scope/Bad/key/K", Some(r#"{"value":"x"}"#)),
    ] {
        let response = vault.admin(method, path, body);
        assert_eq!(response.status, 403, "{method} {path}");
    }
    assert_eq!(secrets(&vault, "app/prod"), serde_json::json!({}));
}

#[test]
fn bad_names_and_bodies_are_refused_before_the_store() {
    let vault = TestVault::start(POLICY);
    let bad = [
        ("PUT", "/v1/scope/App/key/K", Some(r#"{"value":"x"}"#)),
        ("PUT", "/v1/scope/a//b/key/K", Some(r#"{"value":"x"}"#)),
        ("PUT", "/v1/scope/a/key/K%20", Some(r#"{"value":"x"}"#)),
        ("PUT", "/v1/scope/a/../b/key/K", Some(r#"{"value":"x"}"#)),
        (
            "PUT",
            &format!("/v1/scope/a/key/{}", "K".repeat(129)),
            Some(r#"{"value":"x"}"#),
        ),
        (
            "PUT",
            &format!("/v1/scope/{}/key/K", "a".repeat(129)),
            Some(r#"{"value":"x"}"#),
        ),
        ("PUT", "/v1/scope/a/key/K", Some(r#"{"value":""}"#)),
        (
            "PUT",
            "/v1/scope/a/key/K",
            Some(r#"{"value":"x","extra":1}"#),
        ),
        ("PUT", "/v1/scope/a/key/K", Some(r#"{"valu":"x"}"#)),
        ("PUT", "/v1/scope/a/key/K", Some("not json")),
        ("PUT", "/v1/scope/a/key/K", None),
        (
            "POST",
            "/v1/scope/a/key/K/generate",
            Some(r#"{"bytes": 8}"#),
        ),
        (
            "POST",
            "/v1/scope/a/key/K/generate",
            Some(r#"{"bytes": 100000}"#),
        ),
        (
            "POST",
            "/v1/scope/a/key/K/generate",
            Some(r#"{"bytes": -1}"#),
        ),
        ("GET", "/v1/audit?limit=0", None),
        ("GET", "/v1/audit?limit=5000", None),
    ];
    for (method, path, body) in bad {
        let response = vault.admin(method, path, body);
        assert_eq!(
            response.status,
            400,
            "{method} {path} {body:?}: {}",
            body_text(&response)
        );
        assert!(json(&response)["error"].is_string());
    }
    let too_long = serde_json::json!({ "value": "x".repeat(64 * 1024 + 1) }).to_string();
    assert_eq!(
        vault
            .admin("PUT", "/v1/scope/a/key/K", Some(&too_long))
            .status,
        400
    );
    let way_too_long = serde_json::json!({ "value": "x".repeat(1024 * 1024) }).to_string();
    assert_eq!(
        vault
            .admin("PUT", "/v1/scope/a/key/K", Some(&way_too_long))
            .status,
        413
    );
    let at_limit = serde_json::json!({ "value": "x".repeat(64 * 1024) }).to_string();
    assert_eq!(
        vault
            .admin("PUT", "/v1/scope/a/key/BIG", Some(&at_limit))
            .status,
        200
    );

    // Nothing but BIG reached the secret table.
    let listing = json(&vault.admin("GET", "/v1/scopes", None));
    let keys: Vec<&str> = listing["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["keys"].as_array().unwrap())
        .map(|k| k["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["BIG"]);
}

#[test]
fn every_request_is_audited_without_values() {
    let vault = TestVault::start(POLICY);
    set(&vault, "app/prod", "K", SECRET);
    secrets(&vault, "app/prod");
    assert_eq!(vault.get("/v1/scope/other/prod").status, 403);
    assert_eq!(
        vault.admin("PUT", "/v1/scope/Bad/key/K", Some("{}")).status,
        400
    );

    let audit = json(&vault.admin("GET", "/v1/audit?limit=10", None));
    let rows = audit["audit"].as_array().unwrap();
    let summary: Vec<String> = rows
        .iter()
        .rev()
        .map(|r| format!("{} {} {}", r["socket"], r["action"], r["outcome"]).replace('"', ""))
        .collect();
    assert_eq!(
        summary,
        [
            "admin set ok",
            "read fetch ok",
            "read fetch denied",
            // A path that doesn't parse has no action; the audit request's own row comes after.
            "admin unknown invalid",
        ]
    );
    let fetch = &rows[2];
    assert_eq!(fetch["scope"], "app/prod");
    assert_eq!(fetch["uid"], current_uid());
    assert_eq!(fetch["user"], "me");
    assert!(fetch["pid"].as_i64().unwrap() > 0);
    if cfg!(target_os = "linux") {
        assert!(fetch["cmdline"].is_string());
    }
    assert!(!audit.to_string().contains(SECRET));
}

#[test]
fn sockets_are_mode_0660_and_removed_on_stop() {
    use std::os::unix::fs::PermissionsExt;
    let vault = TestVault::start(POLICY);
    for path in [&vault.read, &vault.admin] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "{}", path.display());
    }
    let (read, admin) = (vault.read.clone(), vault.admin.clone());
    vault.stop().unwrap();
    assert!(!read.exists());
    assert!(!admin.exists());
}

#[test]
fn a_second_vault_on_the_same_sockets_is_refused() {
    let vault = TestVault::start(POLICY);
    let policy = aegis_vault::policy::Policy::parse(POLICY, &common::accounts()).unwrap();
    let run_dir = vault.read.parent().unwrap();
    let err = aegis_vault::server::bind(run_dir, &policy).err().unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    // The first vault still answers.
    assert_eq!(vault.get("/v1/scope/app/prod").status, 200);
}

#[test]
fn stale_socket_files_are_replaced() {
    let dir = aegis_vault::testutil::TempDir::new("stale");
    let run_dir = dir.path().join("run");
    let policy = aegis_vault::policy::Policy::parse(POLICY, &common::accounts()).unwrap();
    // Bind and drop: the socket files stay behind with nobody listening.
    drop(aegis_vault::server::bind(&run_dir, &policy).unwrap());
    assert!(run_dir.join("read.sock").exists());
    drop(aegis_vault::server::bind(&run_dir, &policy).unwrap());
    // A regular file in the way is not removed.
    std::fs::remove_file(run_dir.join("admin.sock")).unwrap();
    std::fs::write(run_dir.join("admin.sock"), "not a socket").unwrap();
    assert!(aegis_vault::server::bind(&run_dir, &policy).is_err());
    assert_eq!(
        std::fs::read_to_string(run_dir.join("admin.sock")).unwrap(),
        "not a socket"
    );
}

#[test]
fn shared_run_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = aegis_vault::testutil::TempDir::new("shared-run");
    let run_dir = dir.path().join("run");
    std::fs::create_dir(&run_dir).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let policy = aegis_vault::policy::Policy::parse(POLICY, &common::accounts()).unwrap();
    let err = aegis_vault::server::bind(&run_dir, &policy).err().unwrap();
    assert!(err.to_string().contains("run directory"), "{err}");
    assert!(!run_dir.join("read.sock").exists());
}

#[test]
fn each_uid_gets_a_limited_number_of_connections() {
    use aegis_vault::server::Limits;
    use std::time::{Duration, Instant};
    let limits = Limits {
        per_uid: 2,
        total: 64,
        idle: Duration::from_secs(30),
    };
    let vault = TestVault::start_limited(POLICY, limits, |_| {});
    let hold: Vec<_> = (0..2)
        .map(|_| std::os::unix::net::UnixStream::connect(&vault.read).unwrap())
        .collect();
    // The two idle connections above use this uid's share: a third is closed without an answer.
    std::thread::sleep(Duration::from_millis(100));
    assert!(aegis_vault::client::request(&vault.read, "GET", "/v1/scope/app/prod", None).is_err());
    // The admin socket has its own share.
    assert_eq!(vault.admin("GET", "/v1/scopes", None).status, 200);
    drop(hold);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match aegis_vault::client::request(&vault.read, "GET", "/v1/scope/app/prod", None) {
            Ok(response) => {
                assert_eq!(response.status, 200);
                break;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("slots never came back: {e}"),
        }
    }
}

#[test]
fn idle_connections_are_closed() {
    use aegis_vault::server::Limits;
    use std::io::Read;
    use std::time::{Duration, Instant};
    let limits = Limits {
        idle: Duration::from_millis(200),
        ..Limits::default()
    };
    let vault = TestVault::start_limited(POLICY, limits, |_| {});
    let mut idle = std::os::unix::net::UnixStream::connect(&vault.read).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let started = Instant::now();
    let mut buffer = Vec::new();
    // Sends nothing; the vault hangs up.
    let _ = idle.read_to_end(&mut buffer);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert!(buffer.is_empty());
    // Requests that keep moving are unaffected.
    assert_eq!(vault.get("/v1/scope/app/prod").status, 200);
}

#[test]
fn oversized_bodies_are_audited_and_refused_after_the_caller_check() {
    let huge = serde_json::json!({ "value": "x".repeat(1024 * 1024) }).to_string();
    let vault = TestVault::start(POLICY);
    let response = vault.admin("PUT", "/v1/scope/app/prod/key/K", Some(&huge));
    assert_eq!(response.status, 413);
    assert_eq!(json(&response)["error"], "request body too large");
    let audit = json(&vault.admin("GET", "/v1/audit?limit=1", None));
    assert_eq!(audit["audit"][0]["detail"], "body too large");
    assert_eq!(audit["audit"][0]["outcome"], "invalid");

    // A caller with no admin role gets 403, as for anything else.
    let stranger = TestVault::start(
        r#"
[scope."app/prod"]
allow_users = ["me"]
"#,
    );
    let response = stranger.admin("PUT", "/v1/scope/app/prod/key/K", Some(&huge));
    assert_eq!(response.status, 403);
}

#[test]
fn concurrent_requests() {
    let vault = std::sync::Arc::new(TestVault::start(POLICY));
    set(&vault, "app/prod", "K", "0");
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let vault = std::sync::Arc::clone(&vault);
            std::thread::spawn(move || {
                for j in 0..10 {
                    let body = serde_json::json!({ "value": format!("{i}-{j}") }).to_string();
                    let response =
                        vault.admin("PUT", &format!("/v1/scope/app/prod/key/K{i}"), Some(&body));
                    assert_eq!(response.status, 200);
                    assert_eq!(vault.get("/v1/scope/app/prod").status, 200);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let all = secrets(&vault, "app/prod");
    for i in 0..8 {
        assert_eq!(all[format!("K{i}")], format!("{i}-9"));
    }
}
