# aegis

Rust secrets vault, infra manager, admin UI and deploy runner. Design: `docs/plan.md` (start at "Phases"; we are at Phase 2, vault MVP).

- Cargo workspace at the root, crates in `crates/`. Toolchain pinned in `rust-toolchain.toml`; commit `Cargo.lock`.
- Use `make` targets (`make list`); `make check` before proposing a commit.
- `#![forbid(unsafe_code)]` workspace-wide. Few, small, pinned dependencies; no cloud SDKs.
- Secrets are never printed, logged or written to files. No route returns a secret value to the admin API.
- Old Python code lives on the `rough-draft` branch only. Don't touch it.
