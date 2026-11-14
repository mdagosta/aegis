# aegis

A secrets vault, infrastructure manager, admin UI and deploy runner, in Rust. Built in that order; the
vault comes first.

- `docs/plan.md`: the design and the phases.
- `docs/vault.md`: aegis-vault, the secrets daemon: API, storage, running it.
- `docs/dev-container.md`: the dev container everything is built in.

`make list` shows the targets; `make check` runs formatting, clippy and every test.
