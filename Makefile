.PHONY: all build test check fmt clippy clean wasi wasi-plugins bindgen-node bindgen-web

all: build test

# Build the workspace (for testing/linting only — production target is WASM)
build:
	cargo build --workspace

# Run all tests
test:
	cargo test --workspace

# Run formatting check + clippy (CI-friendly)
check: fmt clippy
	@echo "All checks passed."

# Check formatting
fmt:
	cargo fmt --all -- --check

# Run clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Build wawk-wasi for WASI target
wasi:
	cargo build -p wawk-wasi --target wasm32-wasip1 --release

# Build wawk-wasi with WIT plugin host function support
wasi-plugins:
	cargo build -p wawk-wasi --target wasm32-wasip1 --release --features plugins

# Build wawk-bindgen for Node.js
bindgen-node:
	wasm-pack build crates/wawk-bindgen --target nodejs --out-dir ../../pkg-node

# Build wawk-bindgen for browsers
bindgen-web:
	wasm-pack build crates/wawk-bindgen --target web --out-dir ../../pkg-web

# Clean all build artifacts
clean:
	cargo clean
	rm -rf pkg-node pkg-web
