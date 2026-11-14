.PHONY: all build test check fmt clippy clean wasi bindgen-node bindgen-web compose test-composed test-full clean-compose

all: build test

# Build the workspace (for testing/linting only — production target is WASM)
build: # workspace build for the default (wasip2) target
	cargo build --workspace

# Run all tests
test:
	cargo test --workspace --target x86_64-unknown-linux-gnu

# Run formatting check + clippy (CI-friendly)
check: fmt clippy
	@echo "All checks passed."

# Check formatting
fmt:
	cargo fmt --all -- --check

# Run clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Build wawk-wasi as WASM component (composable with WIT extensions via wac plug)
wasi:
	cargo component build -p wawk-wasi --release --target wasm32-wasip2

# Build wawk-bindgen for Node.js
bindgen-node:
	wasm-pack build crates/wawk-bindgen --target nodejs --out-dir ../../pkg-node

# Build wawk-bindgen for browsers
bindgen-web:
	wasm-pack build crates/wawk-bindgen --target web --out-dir ../../pkg-web

# Compose product with extensions via wac plug
compose:
	./scripts/wac-plug.sh extension-manifest.json ./wac-output

# Test composed output (basic suite)
test-composed:
	./scripts/test-composed.sh ./wac-output/*-composed.wasm basic

# Test composed output (full suite with benchmarks)
test-full:
	./scripts/test-composed.sh ./wac-output/*-composed.wasm full

# Clean composed output
clean-compose:
	rm -rf ./wac-output

# Clean all build artifacts
clean:
	cargo clean
	rm -rf pkg-node pkg-web ./wac-output
