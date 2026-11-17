.PHONY: list build test test-python check fmt clean deny audit build-release

list: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

build: ## Debug build of the workspace
	cargo build --workspace

test: ## Run all tests (Rust, then the Python client's)
	cargo test --workspace
	$(MAKE) test-python

test-python: ## Python client tests (stdlib only)
	python3 -I -m unittest discover -s clients/python

check: ## fmt check + clippy (warnings are errors) + all tests
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	$(MAKE) test

fmt: ## Format the code
	cargo fmt --all

clean: ## Remove build output
	cargo clean

# Dependency checks: run when Cargo.lock changes. Both fetch the RustSec advisory database from GitHub.
deny: ## Dependencies: advisories, licenses, bans, sources (cargo-deny, deny.toml)
	cargo deny --locked check

audit: ## Dependencies: known vulnerabilities in Cargo.lock (cargo-audit)
	cargo audit --deny warnings

# Static binaries for icarus (x86_64, 1 CPU: too small to build Rust). zig is the C compiler and linker
# (SQLite is C), so no cross toolchain is needed. Copy them to icarus from the Mac host (make deploy, later).
RELEASE_TARGET := x86_64-unknown-linux-musl
RELEASE_BINS := aegis-vault aegis-vault-admin

build-release: ## Static x86_64 musl release binaries (cargo-zigbuild) in target/x86_64-unknown-linux-musl/release
	@command -v zig >/dev/null || { echo "zig is not installed: see the Dockerfile's zig note"; exit 1; }
	cargo zigbuild --locked --release --target $(RELEASE_TARGET) $(addprefix --bin ,$(RELEASE_BINS))
	@cd target/$(RELEASE_TARGET)/release && ls -l $(RELEASE_BINS) && sha256sum $(RELEASE_BINS)

# The vault as a sidecar image for other projects' dev containers (docs/vault.md, "In a dev container").
# On the Mac host, where docker is. Builds this checkout's working tree; the image is labelled with its
# commit, and "-dirty" when the vault's files have uncommitted changes.
.PHONY: vault-image
vault-image: ## On the Mac: build the aegis-vault:dev sidecar image (etc/docker/aegis-vault)
	@[ ! -f /.dockerenv ] || { echo "vault-image runs on the Mac host, not in a container"; exit 1; }
	@revision="$$(git rev-parse --short=12 HEAD)"; \
	[ -z "$$(git status --porcelain -- Cargo.toml Cargo.lock crates etc/docker/aegis-vault)" ] || revision="$$revision-dirty"; \
	docker build -f etc/docker/aegis-vault/Dockerfile --label org.opencontainers.image.revision=$$revision \
		-t aegis-vault:dev . && echo "built aegis-vault:dev at $$revision"

# A vault for trying the CLI and the Python client, inside the dev container (dev-* targets are the
# container controls, run on the Mac). Everything is in dev/ (gitignored): master key, store, sockets, and
# a policy that makes you admin and reader of dev/example.
# In another shell: make vault-admin ARGS="set dev/example GREETING", then make vault-fetch.
.PHONY: vault-dev vault-admin vault-fetch
DEV_DIR := dev

vault-dev: ## Run a dev vault on dev/ (key, store, sockets, a policy naming you)
	@mkdir -p $(DEV_DIR) && chmod 700 $(DEV_DIR)
	@[ -f $(DEV_DIR)/master.key ] || cargo run -q --bin aegis-vault -- keygen --out $(DEV_DIR)/master.key
	@[ -f $(DEV_DIR)/policy.toml ] || { \
		printf '[admin]\nfull = ["%s"]\n\n[scope."dev/example"]\nallow_users = ["%s"]\n' \
			"$$(id -un)" "$$(id -un)" > $(DEV_DIR)/policy.toml; \
		chmod 644 $(DEV_DIR)/policy.toml; }
	cargo run -q --bin aegis-vault -- serve --policy $(DEV_DIR)/policy.toml --db $(DEV_DIR)/vault.db \
		--run-dir $(DEV_DIR)/run --master-key $(DEV_DIR)/master.key

vault-admin: ## aegis-vault-admin on the dev vault: make vault-admin ARGS="scopes"
	cargo run -q --bin aegis-vault-admin -- --socket $(DEV_DIR)/run/admin.sock $(ARGS)

vault-fetch: ## Fetch dev/example from the dev vault with the Python client (prints key names only)
	@python3 -I -c 'import sys; sys.path.insert(0, "clients/python"); import aegis_vault; \
		print(sorted(aegis_vault.fetch_scope("dev/example", socket_path="$(DEV_DIR)/run/read.sock")))'

# Dev container (on the Mac host; dev.sh refuses inside). See docs/dev-container.md.
# First time: dev-ssh-config, dev-up. After that: dev-up, dev-shell or ssh aegis-dev.
.PHONY: dev-build dev-up dev-push dev-shell dev-down dev-restart dev-ssh-config

dev-build: ## Build the dev container image only
	.devcontainer/dev.sh build

dev-up: ## Build if needed, start the dev container, seed its repo if empty, run setup
	.devcontainer/dev.sh up

dev-push: ## Push a branch into the dev container's repo (default: current). BRANCH=name for another
	.devcontainer/dev.sh push $(BRANCH)

dev-shell: ## Open a shell in the dev container
	.devcontainer/dev.sh shell

dev-down: ## Stop the dev container (data is kept)
	.devcontainer/dev.sh down

dev-restart: ## Restart the dev container: firewall and Claude policy re-read, no rebuild (ends its shells)
	.devcontainer/dev.sh restart

dev-ssh-config: ## Add "Host aegis-dev" to ~/.ssh/config so herdr can SSH into the container (once)
	.devcontainer/dev.sh ssh-config
