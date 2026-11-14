.PHONY: list build test check fmt clean

list: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

build: ## Debug build of the workspace
	cargo build --workspace

test: ## Run all tests
	cargo test --workspace

check: ## fmt check + clippy (warnings are errors) + tests
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace

fmt: ## Format the code
	cargo fmt --all

clean: ## Remove build output
	cargo clean

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
