# aegis

Rust secrets vault, infra manager, admin UI and deploy runner. Design: `docs/plan.md` (start at "Phases"; we are at Phase 2, vault MVP).

- Development happens in the dev container `aegis-dev` on orpheus (`docs/dev-container.md`). The Mac checkout is the trusted one: `make dev-*`, review, merge and push happen there.
- Cargo workspace at the root, crates in `crates/`. Toolchain pinned in `rust-toolchain.toml` (keep the Dockerfile's `RUST_VERSION` in step); commit `Cargo.lock`.
- Use `make` targets (`make list`); `make check` before proposing a commit (Rust and the Python client's tests). `make deny` and `make audit` when `Cargo.lock` changes.
- `make vault-dev` runs a vault on `dev/` for trying things; `make vault-admin ARGS=...`, `make vault-fetch`. `docs/vault.md` has the API and how it all fits.
- `#![forbid(unsafe_code)]` workspace-wide. Few, small, pinned dependencies; no cloud SDKs.
- Secrets are never printed, logged or written to files. No route returns a secret value to the admin API.
- Old Python code lives on the `rough-draft` branch only. Don't touch it.
