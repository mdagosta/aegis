//! End to end: the real `aegis-vault` and `aegis-vault-admin` binaries and the Python client, as the
//! user running the tests (who must be in /etc/passwd; otherwise the test says so and does nothing).
//! The daemon's stderr (its journal) is captured and checked for values.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use aegis_vault::accounts::Accounts;
use aegis_vault::testutil::{TempDir, current_uid};

const VAULT: &str = env!("CARGO_BIN_EXE_aegis-vault");
const ADMIN: &str = env!("CARGO_BIN_EXE_aegis-vault-admin");
const VALUE: &str = "hunter2-end-to-end";

fn my_name() -> Option<String> {
    Accounts::load()
        .ok()?
        .user_name(current_uid())
        .map(str::to_owned)
}

fn run(command: &mut Command) -> Output {
    command.output().expect("run command")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn start(dir: &Path, key: &Path, run_dir: &Path) -> Daemon {
        let log = dir.join(format!(
            "{}.log",
            run_dir.file_name().unwrap().to_string_lossy()
        ));
        let child = Command::new(VAULT)
            .arg("serve")
            .arg("--policy")
            .arg(dir.join("policy.toml"))
            .arg("--db")
            .arg(dir.join("vault.db"))
            .arg("--run-dir")
            .arg(run_dir)
            .arg("--master-key")
            .arg(key)
            .env_remove("NOTIFY_SOCKET")
            .env_remove("CREDENTIALS_DIRECTORY")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        Daemon { child, log }
    }

    fn wait_for_sockets(&mut self, run_dir: &Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !run_dir.join("admin.sock").exists() {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("daemon exited {status}: {}", self.log());
            }
            assert!(
                Instant::now() < deadline,
                "daemon didn't start: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM, and wait for a clean exit.
    fn stop(mut self) -> String {
        let pid = self.child.id().to_string();
        assert!(
            run(Command::new("kill").args(["-TERM", &pid]))
                .status
                .success()
        );
        let status = self.child.wait().unwrap();
        assert!(status.success(), "daemon exit {status}: {}", self.log());
        self.log()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn admin(socket: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(ADMIN)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    if let Some(input) = stdin {
        pipe.write_all(input.as_bytes()).unwrap();
    }
    drop(pipe);
    child.wait_with_output().unwrap()
}

fn admin_ok(socket: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let output = admin(socket, args, stdin);
    assert!(
        output.status.success(),
        "aegis-vault-admin {args:?}: {}{}",
        text(&output.stdout),
        text(&output.stderr)
    );
    let stdout = text(&output.stdout);
    assert!(!stdout.contains(VALUE), "{args:?} printed the value");
    stdout
}

fn python3() -> Option<&'static str> {
    Command::new("python3")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "python3")
}

#[test]
fn end_to_end() {
    let Some(me) = my_name() else {
        eprintln!("skipping: uid {} is not in /etc/passwd", current_uid());
        return;
    };
    let dir = TempDir::new("e2e");
    let key = dir.path().join("master.key");
    let run_dir = dir.path().join("run");
    let admin_socket = run_dir.join("admin.sock");

    // keygen makes a 0600 key and never overwrites one.
    assert!(
        run(Command::new(VAULT).arg("keygen").arg("--out").arg(&key))
            .status
            .success()
    );
    let key_text = std::fs::read_to_string(&key).unwrap();
    assert_eq!(key_text.trim().len(), 64);
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let again = run(Command::new(VAULT).arg("keygen").arg("--out").arg(&key));
    assert!(!again.status.success());
    assert!(text(&again.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read_to_string(&key).unwrap(), key_text);

    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        format!(
            "[admin]\nfull = [\"{me}\"]\n\n[scope.\"dev/app\"]\nallow_users = [\"{me}\"]\n\n\
             [scope.\"dev/other\"]\nallow_users = []\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
    let checked = run(Command::new(VAULT)
        .arg("check-policy")
        .arg("--policy")
        .arg(&policy));
    assert!(checked.status.success(), "{}", text(&checked.stderr));
    assert!(text(&checked.stdout).contains(&format!("admin full: {me}")));
    assert!(text(&checked.stdout).contains(&format!("scope dev/app: read by {me}")));

    let mut daemon = Daemon::start(dir.path(), &key, &run_dir);
    daemon.wait_for_sockets(&run_dir);

    // The admin CLI: set from a pipe (one trailing newline dropped), generate, list, history.
    let set = admin_ok(
        &admin_socket,
        &["set", "dev/app", "DB"],
        Some(&format!("{VALUE}\n")),
    );
    assert!(
        set.contains("set dev/app DB: version 1, fingerprint "),
        "{set}"
    );
    admin_ok(
        &admin_socket,
        &["generate", "dev/app", "TOKEN", "--bytes", "24"],
        None,
    );
    let scopes = admin_ok(&admin_socket, &["scopes"], None);
    assert!(
        scopes.contains("dev/app") && scopes.contains("DB") && scopes.contains("TOKEN"),
        "{scopes}"
    );
    assert!(scopes.contains("dev/other  (read by: nobody)"), "{scopes}");
    let json = admin_ok(
        &admin_socket,
        &["--json", "versions", "dev/app", "DB"],
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["versions"][0]["version"], 1);

    // Refusals come back as errors with exit status 1, and nothing is set.
    let empty = admin(&admin_socket, &["set", "dev/app", "EMPTY"], Some("\n"));
    assert_eq!(empty.status.code(), Some(1));
    assert!(text(&empty.stderr).contains("empty value"));
    let bad = admin(&admin_socket, &["set", "Dev/App", "X"], Some("x"));
    assert_eq!(bad.status.code(), Some(1));
    let missing = admin(&admin_socket, &["delete", "dev/app", "NOPE"], None);
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        text(&missing.stderr).contains("(404)"),
        "{}",
        text(&missing.stderr)
    );
    assert_eq!(
        admin(&admin_socket, &["frobnicate"], None).status.code(),
        Some(1)
    );

    // Names that look like options or commands are still names once the command has started.
    let odd = admin_ok(&admin_socket, &["set", "help", "--json"], Some("x"));
    assert!(odd.contains("set help --json: version 1"), "{odd}");
    let long = "y".repeat(64 * 1024 + 1);
    let too_long = admin(&admin_socket, &["set", "dev/app", "LONG"], Some(&long));
    assert_eq!(too_long.status.code(), Some(1));
    assert!(text(&too_long.stderr).contains("longer than 64 KiB"));
    let at_limit = "y".repeat(64 * 1024);
    admin_ok(
        &admin_socket,
        &["set", "dev/app", "LONG"],
        Some(&format!("{at_limit}\n")),
    );
    admin_ok(&admin_socket, &["delete", "dev/app", "LONG"], None);
    let bad_flag = admin(
        &admin_socket,
        &["generate", "dev/app", "T", "--bytes"],
        None,
    );
    assert_eq!(bad_flag.status.code(), Some(1));
    let bad_flag = admin(&admin_socket, &["audit", "--limit", "x"], None);
    assert_eq!(bad_flag.status.code(), Some(1));

    // Delete and roll back.
    admin_ok(&admin_socket, &["delete", "dev/app", "DB"], None);
    let rolled = admin_ok(&admin_socket, &["rollback", "dev/app", "DB", "1"], None);
    assert!(
        rolled.contains("version 3") && rolled.contains("(value of version 1)"),
        "{rolled}"
    );

    // The Python client against the real daemon: gets the values, and checks the daemon's log for
    // both of them (the generated one it only learns here).
    if let Some(python) = python3() {
        let clients = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../clients/python");
        let script = r#"
import sys
sys.path.insert(0, sys.argv[1])
import aegis_vault
secrets = aegis_vault.fetch_scope("dev/app", socket_path=sys.argv[2])
assert sorted(secrets) == ["DB", "TOKEN"], sorted(secrets)
assert secrets["DB"] == sys.argv[3]
assert len(secrets["TOKEN"]) == 32
try:
    aegis_vault.fetch_scope("dev/other", socket_path=sys.argv[2])
    raise SystemExit("dev/other should be refused")
except aegis_vault.VaultError as e:
    assert e.status == 403, e.status
log = open(sys.argv[4]).read()
assert secrets["TOKEN"] not in log, "generated value in the log"
assert secrets["DB"] not in log, "set value in the log"
print("python ok")
"#;
        let output = run(Command::new(python)
            .arg("-I")
            .arg("-c")
            .arg(script)
            .arg(&clients)
            .arg(run_dir.join("read.sock"))
            .arg(VALUE)
            .arg(&daemon.log));
        assert!(
            output.status.success() && text(&output.stdout).contains("python ok"),
            "python: {}{}",
            text(&output.stdout),
            text(&output.stderr)
        );
    } else {
        eprintln!("python3 not found: skipped the Python client check");
    }

    let audit = admin_ok(&admin_socket, &["audit", "--limit", "50"], None);
    assert!(audit.contains("read  fetch"), "{audit}");
    assert!(audit.contains("admin set"), "{audit}");

    // A second daemon with another master key refuses the store and exits.
    let other_key = dir.path().join("other.key");
    assert!(
        run(Command::new(VAULT)
            .arg("keygen")
            .arg("--out")
            .arg(&other_key))
        .status
        .success()
    );
    let mut wrong = Daemon::start(dir.path(), &other_key, &dir.path().join("run2"));
    let status = wrong.child.wait().unwrap();
    assert_eq!(status.code(), Some(1));
    assert!(wrong.log().contains("master key id"), "{}", wrong.log());
    assert!(!dir.path().join("run2/read.sock").exists());

    // SIGTERM: clean exit, sockets removed. The journal has audit lines and no values or key.
    let log = daemon.stop();
    assert!(!admin_socket.exists());
    assert!(
        log.contains("audit socket=admin action=set outcome=ok"),
        "{log}"
    );
    assert!(log.contains("SIGTERM"), "{log}");
    assert!(!log.contains(VALUE));
    assert!(!log.contains(key_text.trim()));
}

#[test]
fn serve_refuses_bad_setups() {
    let Some(me) = my_name() else {
        return;
    };
    let dir = TempDir::new("e2e-bad");
    let key = dir.path().join("master.key");
    assert!(
        run(Command::new(VAULT).arg("keygen").arg("--out").arg(&key))
            .status
            .success()
    );
    let policy = dir.path().join("policy.toml");
    let serve = |key: &Path| {
        run(Command::new(VAULT)
            .arg("serve")
            .arg("--policy")
            .arg(&policy)
            .arg("--db")
            .arg(dir.path().join("vault.db"))
            .arg("--run-dir")
            .arg(dir.path().join("run"))
            .arg("--master-key")
            .arg(key)
            .env_remove("CREDENTIALS_DIRECTORY"))
    };

    // A policy naming a user that doesn't exist.
    std::fs::write(&policy, "[admin]\nfull = [\"no-such-user-aegis\"]\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = serve(&key);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("no local user"),
        "{}",
        text(&output.stderr)
    );

    // A policy others can write.
    std::fs::write(&policy, format!("[admin]\nfull = [\"{me}\"]\n")).unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o666)).unwrap();
    let output = serve(&key);
    assert!(text(&output.stderr).contains("writable by group or others"));
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    // A key file others can read.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = serve(&key);
    assert!(
        text(&output.stderr).contains("must not be readable"),
        "{}",
        text(&output.stderr)
    );

    // No key at all.
    let output = run(Command::new(VAULT)
        .arg("serve")
        .arg("--policy")
        .arg(&policy)
        .env_remove("CREDENTIALS_DIRECTORY"));
    assert!(
        text(&output.stderr).contains("no master key"),
        "{}",
        text(&output.stderr)
    );

    // Usage errors exit 2.
    assert_eq!(
        run(Command::new(VAULT).arg("serve").arg("--nope"))
            .status
            .code(),
        Some(2)
    );
    assert_eq!(run(&mut Command::new(VAULT)).status.code(), Some(2));
    assert_eq!(
        run(Command::new(VAULT).arg("keygen")).status.code(),
        Some(1)
    );
    assert!(!dir.path().join("vault.db").exists());
}
