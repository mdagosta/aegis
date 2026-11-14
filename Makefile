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
