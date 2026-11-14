//! aegis-vault: the secrets daemon, and `keygen` for its master key. See docs/plan.md, "aegis-vault".

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use aegis_vault::accounts::Accounts;
use aegis_vault::masterkey::{key_path, keygen, read_key_file};
use aegis_vault::policy::{AdminRole, Policy};
use aegis_vault::server::{Limits, Vault, bind, notify_ready, serve, shutdown_signal};
use aegis_vault::store::Store;

const USAGE: &str = "\
usage:
  aegis-vault serve [--policy FILE] [--db FILE] [--run-dir DIR] [--master-key FILE]
      Run the daemon. Defaults: --policy /etc/aegis/policy.toml, --db /var/lib/aegis-vault/vault.db,
      --run-dir /run/aegis-vault. The master key comes from --master-key, or else from the systemd
      credential $CREDENTIALS_DIRECTORY/aegis-master-key.
  aegis-vault keygen --out FILE
      Write a new master key (64 hex characters) to FILE, mode 0600. Never overwrites.
  aegis-vault check-policy [--policy FILE]
      Read the policy, resolve its users and groups, and print what it allows.
  aegis-vault --version
";

/// `--name value` and `--name=value` flags; anything else is a usage error.
struct Flags(Vec<(String, OsString)>);

impl Flags {
    fn parse(args: impl Iterator<Item = OsString>, allowed: &[&str]) -> Result<Flags, String> {
        let mut flags = Vec::new();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            // Flags are UTF-8; a path that isn't goes as the separate value after `--name`, which is
            // kept exactly as given.
            let Some(text) = arg.to_str() else {
                return Err(format!(
                    "{arg:?} isn't UTF-8; give a non-UTF-8 value as --name VALUE, not --name=VALUE"
                ));
            };
            let Some(stripped) = text.strip_prefix("--") else {
                return Err(format!("unexpected argument {text:?}"));
            };
            let (name, value) = match stripped.split_once('=') {
                Some((name, value)) => (name.to_owned(), OsString::from(value)),
                None => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("--{stripped} needs a value"))?;
                    (stripped.to_owned(), value)
                }
            };
            if !allowed.contains(&name.as_str()) {
                return Err(format!("unknown flag --{name}"));
            }
            if flags.iter().any(|(n, _)| *n == name) {
                return Err(format!("--{name} given twice"));
            }
            flags.push((name, value));
        }
        Ok(Flags(flags))
    }

    fn path(&self, name: &str) -> Option<PathBuf> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| PathBuf::from(v))
    }

    fn path_or(&self, name: &str, default: &str) -> PathBuf {
        self.path(name).unwrap_or_else(|| PathBuf::from(default))
    }
}

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A subcommand: the flags it takes and what it runs.
type Subcommand = (&'static [&'static str], fn(&Flags) -> AnyResult<()>);

fn load_policy(path: &Path) -> AnyResult<(Accounts, Policy)> {
    let accounts =
        Accounts::load().map_err(|e| format!("reading /etc/passwd and /etc/group: {e}"))?;
    let policy = Policy::load(path, &accounts)?;
    Ok((accounts, policy))
}

fn run_serve(flags: &Flags) -> AnyResult<()> {
    let policy_path = flags.path_or("policy", "/etc/aegis/policy.toml");
    let db = flags.path_or("db", "/var/lib/aegis-vault/vault.db");
    let run_dir = flags.path_or("run-dir", "/run/aegis-vault");
    let (accounts, policy) = load_policy(&policy_path)?;
    let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
    let key_file = key_path(flags.path("master-key").as_deref(), credentials.as_deref())?;
    let master = read_key_file(&key_file)?;
    let store = Store::open(&db, &master).map_err(|e| format!("store {}: {e}", db.display()))?;
    drop(master);
    eprintln!(
        "aegis-vault {}: store {} (master key id {}), policy {} ({} scopes, {} admins)",
        env!("CARGO_PKG_VERSION"),
        db.display(),
        store.kek_id(),
        policy_path.display(),
        policy.scopes().count(),
        policy.admins().len(),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listeners = bind(&run_dir, &policy)?;
        let vault = Arc::new(Vault::new(store, policy, accounts));
        eprintln!("listening in {}", run_dir.display());
        notify_ready();
        serve(vault, listeners, Limits::default(), shutdown_signal()).await
    })?;
    eprintln!("stopped");
    Ok(())
}

fn run_keygen(flags: &Flags) -> AnyResult<()> {
    let out = flags.path("out").ok_or("keygen needs --out FILE")?;
    keygen(&out)?;
    eprintln!(
        "wrote a new master key to {} (mode 0600). Keep a copy in the password manager; \
         the store can't be read without it.",
        out.display()
    );
    Ok(())
}

fn run_check_policy(flags: &Flags) -> AnyResult<()> {
    let path = flags.path_or("policy", "/etc/aegis/policy.toml");
    let (accounts, policy) = load_policy(&path)?;
    println!("policy {}: ok", path.display());
    let group =
        |gid: Option<u32>| gid.map_or_else(|| "(not set)".to_owned(), |g| format!("gid {g}"));
    println!("read.sock group:  {}", group(policy.read_gid));
    println!("admin.sock group: {}", group(policy.admin_gid));
    for (uid, role) in policy.admins() {
        let role = match role {
            AdminRole::Full => "full",
            AdminRole::WriteOnly => "write_only",
        };
        let name = accounts.user_name(uid).unwrap_or("?");
        println!("admin {role}: {name} (uid {uid})");
    }
    for (scope, grant) in policy.scopes() {
        println!("scope {scope}: read by {}", grant.users.join(", "));
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().map(|a| a.to_string_lossy().into_owned());
    let (allowed, run): Subcommand = match command.as_deref() {
        Some("serve") => (&["policy", "db", "run-dir", "master-key"], run_serve),
        Some("keygen") => (&["out"], run_keygen),
        Some("check-policy") => (&["policy"], run_check_policy),
        Some("--version" | "version") => {
            println!("aegis-vault {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let flags = match Flags::parse(args, allowed) {
        Ok(flags) => flags,
        Err(e) => {
            eprintln!("aegis-vault: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&flags) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-vault: {e}");
            ExitCode::FAILURE
        }
    }
}
