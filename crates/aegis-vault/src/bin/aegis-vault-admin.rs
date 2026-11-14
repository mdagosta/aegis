//! aegis-vault-admin: the break-glass CLI for admin.sock. Run as an admin user (`sudo -u aegis`, or
//! root). Values go in on stdin and are never echoed; nothing it can ask for returns one.

#![forbid(unsafe_code)]

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use aegis_vault::client::{Response, request};
use aegis_vault::names::{KeyName, MAX_VALUE_LEN, ScopeName};
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

const DEFAULT_SOCKET: &str = "/run/aegis-vault/admin.sock";

const USAGE: &str = "\
usage: aegis-vault-admin [--socket PATH] [--json] COMMAND
  scopes                            every scope and key: version, fingerprint, set at/by
  versions SCOPE KEY                version history (metadata only)
  set SCOPE KEY                     new value from stdin; at a terminal it's typed without echo
  generate SCOPE KEY [--bytes N]    random value (N random bytes, base64url), never shown
  delete SCOPE KEY                  delete (a new version; rollback undoes it)
  rollback SCOPE KEY VERSION        restore VERSION's value as a new version
  audit [--limit N]                 recent audit rows, newest first

The socket defaults to $AEGIS_VAULT_ADMIN_SOCKET, else /run/aegis-vault/admin.sock.
--json prints the vault's JSON response as is.
A value piped to `set` loses one trailing newline (so `echo` and `op read` work); values are text, up to
64 KiB. If an interrupted `set` leaves the terminal not echoing, run `stty echo`.
";

struct Options {
    socket: PathBuf,
    json: bool,
    command: Vec<String>,
}

fn usage_error(message: &str) -> Result<Options, String> {
    Err(format!("{message}\n\n{USAGE}"))
}

fn parse_args() -> Result<Options, String> {
    let mut socket = std::env::var_os("AEGIS_VAULT_ADMIN_SOCKET").map(PathBuf::from);
    let mut json = false;
    let mut args = std::env::args().skip(1);
    // Options come before the command; everything after it is the command's own, so a scope or key
    // that looks like an option (`help`, `--json`) is still a name.
    let command = loop {
        let Some(arg) = args.next() else {
            return usage_error("no command");
        };
        match arg.as_str() {
            "--socket" => match args.next() {
                Some(path) => socket = Some(PathBuf::from(path)),
                None => return usage_error("--socket needs a path"),
            },
            "--json" => json = true,
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return usage_error(&format!("unknown option {other}"));
            }
            _ => break std::iter::once(arg).chain(args).collect::<Vec<_>>(),
        }
    };
    Ok(Options {
        socket: socket.unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
        json,
        command,
    })
}

fn key_path(scope: &str, key: &str) -> Result<String, String> {
    let scope = ScopeName::parse(scope).map_err(|e| format!("scope {scope:?}: {e}"))?;
    let key = KeyName::parse(key).map_err(|e| format!("key {key:?}: {e}"))?;
    Ok(format!("/v1/scope/{scope}/key/{key}"))
}

/// Turn terminal echo off (or back on) with stty, which acts on its stdin: our terminal. By absolute
/// path, since this often runs as root.
fn set_echo(on: bool) -> bool {
    Command::new("/bin/stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The value for `set`: typed at the terminal without echo, or piped in.
fn read_value(scope: &str, key: &str) -> Result<Zeroizing<String>, String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return read_piped_value();
    }
    // Typed by a person: one line, without echo. The buffer fits any value that will be accepted.
    let mut value = Zeroizing::new(String::with_capacity(MAX_VALUE_LEN + 2));
    if !set_echo(false) {
        return Err("can't turn off terminal echo; pipe the value in instead".to_owned());
    }
    eprint!("value for {scope} {key} (not echoed): ");
    let _ = std::io::stderr().flush();
    let result = stdin.read_line(&mut value);
    set_echo(true);
    eprintln!();
    result.map_err(|e| format!("reading the value: {e}"))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err("empty value; nothing set".to_owned());
    }
    if value.len() > MAX_VALUE_LEN {
        return Err("value is longer than 64 KiB; nothing set".to_owned());
    }
    Ok(value)
}

/// A value piped to stdin: at most 64 KiB plus a line ending, read into a buffer that never has to grow
/// (growing would leave a copy of the value in freed memory).
fn read_piped_value() -> Result<Zeroizing<String>, String> {
    const LIMIT: usize = MAX_VALUE_LEN + 2;
    let mut bytes = Zeroizing::new(Vec::with_capacity(LIMIT + 2));
    std::io::stdin()
        .lock()
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading the value from stdin: {e}"))?;
    if bytes.len() > LIMIT {
        return Err("value is longer than 64 KiB; nothing set".to_owned());
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    // Moves the bytes, without copying, into a string that is wiped on drop either way.
    let value = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            return Err("value is not UTF-8 text; nothing set (binary goes in base64)".to_owned());
        }
    };
    if value.is_empty() {
        return Err("empty value; nothing set".to_owned());
    }
    if value.len() > MAX_VALUE_LEN {
        return Err("value is longer than 64 KiB; nothing set".to_owned());
    }
    Ok(value)
}

/// `{"value": ...}`, built in a buffer sized up front and wiped on drop.
fn value_body(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    #[derive(Serialize)]
    struct Body<'a> {
        value: &'a str,
    }
    let mut body = Zeroizing::new(Vec::with_capacity(6 * value.len() + 16));
    serde_json::to_writer(&mut *body, &Body { value }).map_err(|e| e.to_string())?;
    Ok(body)
}

fn call(options: &Options, method: &str, path: &str, body: Option<&[u8]>) -> Result<Value, String> {
    let Response { status, body } =
        request(&options.socket, method, path, body).map_err(|e| e.to_string())?;
    let parsed: Value = serde_json::from_slice(&body)
        .map_err(|_| format!("vault answered {status} with a body that isn't JSON"))?;
    if !(200..300).contains(&status) {
        let message = parsed["error"].as_str().unwrap_or("(no message)");
        return Err(format!("vault refused ({status}): {message}"));
    }
    Ok(parsed)
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".to_owned(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn print_scopes(response: &Value) {
    let scopes = response["scopes"].as_array().cloned().unwrap_or_default();
    if scopes.is_empty() {
        println!("no scopes");
    }
    for scope in scopes {
        let readers: Vec<String> = scope["allow_users"]
            .as_array()
            .map(|users| users.iter().map(text).collect())
            .unwrap_or_default();
        let access = if scope["in_policy"].as_bool() == Some(true) {
            format!(
                "read by: {}",
                if readers.is_empty() {
                    "nobody".to_owned()
                } else {
                    readers.join(", ")
                }
            )
        } else {
            "not in policy: nobody reads it".to_owned()
        };
        println!("{}  ({access})", text(&scope["scope"]));
        let keys = scope["keys"].as_array().cloned().unwrap_or_default();
        if keys.is_empty() {
            println!("    (no keys)");
        }
        for key in keys {
            let state = if key["deleted"].as_bool() == Some(true) {
                "deleted".to_owned()
            } else {
                format!("fp {}", text(&key["fingerprint"]))
            };
            println!(
                "    {:<32} v{:<4} {:<16} {} by {}",
                text(&key["key"]),
                text(&key["version"]),
                state,
                text(&key["set_at"]),
                text(&key["set_by"]),
            );
        }
    }
}

fn print_versions(response: &Value) {
    println!("{} {}", text(&response["scope"]), text(&response["key"]));
    for version in response["versions"].as_array().cloned().unwrap_or_default() {
        let mut what = text(&version["action"]);
        if !version["rollback_of"].is_null() {
            what = format!("rollback to v{}", text(&version["rollback_of"]));
        }
        let fingerprint = if version["deleted"].as_bool() == Some(true) {
            "-".to_owned()
        } else {
            text(&version["fingerprint"])
        };
        println!(
            "    v{:<4} {:<20} fp {:<12}  {} by {}",
            text(&version["version"]),
            what,
            fingerprint,
            text(&version["set_at"]),
            text(&version["set_by"]),
        );
    }
}

fn print_write(response: &Value) {
    let mut line = format!(
        "{} {} {}: version {}",
        text(&response["action"]),
        text(&response["scope"]),
        text(&response["key"]),
        text(&response["version"]),
    );
    if !response["fingerprint"].is_null() {
        line.push_str(&format!(", fingerprint {}", text(&response["fingerprint"])));
    }
    if !response["rollback_of"].is_null() {
        line.push_str(&format!(
            " (value of version {})",
            text(&response["rollback_of"])
        ));
    }
    println!("{line}");
}

fn print_audit(response: &Value) {
    for row in response["audit"].as_array().cloned().unwrap_or_default() {
        let who = match (&row["user"], &row["uid"]) {
            (Value::String(user), _) => user.clone(),
            (_, Value::Null) => "uid ?".to_owned(),
            (_, uid) => format!("uid {uid}"),
        };
        let mut target = String::new();
        if !row["scope"].is_null() {
            target.push_str(&text(&row["scope"]));
        }
        if !row["key"].is_null() {
            target.push(' ');
            target.push_str(&text(&row["key"]));
        }
        if !row["version"].is_null() {
            target.push_str(&format!(" v{}", text(&row["version"])));
        }
        let mut line = format!(
            "{} {:<5} {:<9} {:<9} {:<14} {}",
            text(&row["at"]),
            text(&row["socket"]),
            text(&row["action"]),
            text(&row["outcome"]),
            who,
            target.trim(),
        );
        if !row["detail"].is_null() {
            line.push_str(&format!(" ({})", text(&row["detail"])));
        }
        if !row["pid"].is_null() {
            line.push_str(&format!(" pid {}", text(&row["pid"])));
        }
        if !row["cmdline"].is_null() {
            line.push_str(&format!(" {:?}", text(&row["cmdline"])));
        }
        println!("{line}");
    }
}

/// A command's optional trailing `FLAG N`: nothing, or exactly the flag and a number.
fn number_flag(args: &[&str], flag: &str) -> Result<Option<u64>, String> {
    match args {
        [] => Ok(None),
        [name, n] if *name == flag => n
            .parse()
            .map(Some)
            .map_err(|_| format!("{flag} needs a number")),
        _ => Err(format!("unexpected arguments {args:?}\n\n{USAGE}")),
    }
}

fn run(options: &Options) -> Result<(), String> {
    let (name, args) = options.command.split_first().expect("a command");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (response, print): (Value, fn(&Value)) = match (name.as_str(), args.as_slice()) {
        ("scopes", []) => (call(options, "GET", "/v1/scopes", None)?, print_scopes),
        ("versions", [scope, key]) => {
            let path = format!("{}/versions", key_path(scope, key)?);
            (call(options, "GET", &path, None)?, print_versions)
        }
        ("set", [scope, key]) => {
            let path = key_path(scope, key)?;
            let value = read_value(scope, key)?;
            let body = value_body(&value)?;
            (call(options, "PUT", &path, Some(&body))?, print_write)
        }
        ("generate", [scope, key, flag @ ..]) => {
            let bytes = number_flag(flag, "--bytes")?;
            let path = format!("{}/generate", key_path(scope, key)?);
            let body = match bytes {
                Some(n) => serde_json::json!({ "bytes": n }).to_string(),
                None => "{}".to_owned(),
            };
            (
                call(options, "POST", &path, Some(body.as_bytes()))?,
                print_write,
            )
        }
        ("delete", [scope, key]) => {
            let path = key_path(scope, key)?;
            (call(options, "DELETE", &path, None)?, print_write)
        }
        ("rollback", [scope, key, version]) => {
            let version: i64 = version
                .parse()
                .map_err(|_| format!("version {version:?} is not a number"))?;
            let path = format!("{}/rollback", key_path(scope, key)?);
            let body = serde_json::json!({ "version": version }).to_string();
            (
                call(options, "POST", &path, Some(body.as_bytes()))?,
                print_write,
            )
        }
        ("audit", flag) => {
            let limit = number_flag(flag, "--limit")?;
            let path = match limit {
                Some(n) => format!("/v1/audit?limit={n}"),
                None => "/v1/audit".to_owned(),
            };
            (call(options, "GET", &path, None)?, print_audit)
        }
        _ => {
            return Err(format!(
                "unknown command or wrong arguments: {name}\n\n{USAGE}"
            ));
        }
    };
    if options.json {
        println!("{response}");
    } else {
        print(&response);
    }
    Ok(())
}

fn main() -> ExitCode {
    let options = match parse_args() {
        Ok(options) => options,
        Err(e) => {
            eprintln!("aegis-vault-admin: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-vault-admin: {e}");
            ExitCode::FAILURE
        }
    }
}
