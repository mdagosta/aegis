//! aegis-vault: a secrets daemon on each box. See docs/plan.md, "aegis-vault".
//!
//! Values are sealed in an SQLite file under a key derived from the master key. Two Unix sockets serve
//! them: `read.sock` returns a scope's values to the uids the policy allows, and `admin.sock` changes
//! values and lists metadata but has no route that returns a value. The kernel's report of the peer's
//! uid is the credential.

#![forbid(unsafe_code)]

pub mod accounts;
pub mod client;
pub mod crypto;
pub mod encoding;
pub mod listener;
pub mod masterkey;
pub mod names;
pub mod paths;
pub mod policy;
pub mod routes;
pub mod server;
pub mod store;
#[doc(hidden)]
pub mod testutil;
