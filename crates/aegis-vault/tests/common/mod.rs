//! A vault served on real Unix sockets in a temp dir, for integration tests. The test process is the
//! peer, so "this uid" is whoever runs the tests; the policy maps names to uids through a made-up
//! passwd file that puts `me` at the current uid.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

use aegis_vault::accounts::Accounts;
use aegis_vault::client::{Response, request};
use aegis_vault::crypto::MasterKey;
use aegis_vault::policy::Policy;
use aegis_vault::server::{Limits, Vault, bind, serve};
use aegis_vault::store::Store;
use aegis_vault::testutil::{TempDir, current_uid};

pub const MASTER_HEX: &str = "4f0c1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1";

/// Accounts with `me` at the current uid and a few others that aren't.
pub fn accounts() -> Accounts {
    let me = current_uid();
    let other = |n: u32| me.wrapping_add(n);
    Accounts::parse(
        &format!(
            "me:x:{me}:{me}::/:/bin/sh\nwww-data:x:{}:1::/:/bin/sh\naegis-infra:x:{}:1::/:/bin/sh\n\
             someone:x:{}:1::/:/bin/sh\n",
            other(1),
            other(2),
            other(3)
        ),
        "",
    )
}

pub fn master() -> MasterKey {
    MasterKey::from_hex(MASTER_HEX).unwrap()
}

pub struct TestVault {
    pub dir: TempDir,
    pub read: PathBuf,
    pub admin: PathBuf,
    pub db: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl TestVault {
    /// Serve a vault with this policy. `prepare` can write to the store first (as other users).
    pub fn start_with(policy: &str, prepare: impl FnOnce(&mut Store)) -> TestVault {
        TestVault::start_limited(policy, Limits::default(), prepare)
    }

    pub fn start_limited(
        policy: &str,
        limits: Limits,
        prepare: impl FnOnce(&mut Store),
    ) -> TestVault {
        let dir = TempDir::new("vault");
        let db = dir.path().join("vault.db");
        let run_dir = dir.path().join("run");
        let accounts = accounts();
        let policy = Policy::parse(policy, &accounts).unwrap();
        let mut store = Store::open(&db, &master()).unwrap();
        prepare(&mut store);
        let listeners = bind(&run_dir, &policy).unwrap();
        let vault = Arc::new(Vault::new(store, policy, accounts));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(serve(vault, listeners, limits, async {
                    let _ = stopped.await;
                }))
        });
        TestVault {
            read: run_dir.join("read.sock"),
            admin: run_dir.join("admin.sock"),
            db,
            dir,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn start(policy: &str) -> TestVault {
        TestVault::start_with(policy, |_| {})
    }

    pub fn get(&self, path: &str) -> Response {
        request(&self.read, "GET", path, None).unwrap()
    }

    pub fn admin(&self, method: &str, path: &str, body: Option<&str>) -> Response {
        request(&self.admin, method, path, body.map(str::as_bytes)).unwrap()
    }

    /// Stop the server and wait for it; returns what `serve` returned.
    pub fn stop(mut self) -> std::io::Result<()> {
        self.shutdown().unwrap()
    }

    fn shutdown(&mut self) -> Option<std::io::Result<()>> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.thread.take().map(|t| t.join().unwrap())
    }
}

impl Drop for TestVault {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn json(response: &Response) -> serde_json::Value {
    serde_json::from_slice(&response.body).unwrap_or_else(|_| {
        panic!(
            "status {} body not JSON: {:?}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )
    })
}

pub fn body_text(response: &Response) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}
