# wac plug Automation Guide

This document describes the automated wac plug workflow for composing wawk-rs with WIT extensions.

## Overview

The wac plug process composes multiple WebAssembly components into a single executable:

```
wawk-wasi (host) + dispatcher (codegen) + extensions → composed.wasm
```

**Components:**
- **wawk-wasi**: Core AWK engine compiled to WASM component
- **dispatcher**: Auto-generated routing layer from extension-manifest.json
- **extensions**: Product-specific WIT components (e.g., my-ext-a, my-ext-b)

## Prerequisites

Install required tools:

```bash
# Rust toolchain with wasm32-wasip2 target
rustup target add wasm32-wasip2

# cargo-component (WASM component build tool)
cargo install cargo-component

# wac CLI (WebAssembly Component composition)
cargo install wac

# Optional: wasm-tools (validation)
cargo install wasm-tools

# Optional: wasmtime (testing)
cargo install wasmtime
```

Verify installation:

```bash
cargo component --version  # Should show cargo-component 0.X.X
wac --version              # Should show wac-cli 0.10.X
wasmtime --version         # Should show wasmtime 47.X.X
```

## Quick Start

### 1. Create Extension Manifest

Create `extension-manifest.json`:

```json
{
  "name": "my-product",
  "version": "1.0.0",
  "description": "My product with extensions",
  "extensions": [
    {
      "name": "formula",
      "interface": "formula-functions",
      "format": false,
      "description": "Excel-compatible formula functions",
      "path": "./extensions/my-ext-a.wasm"
    },
    {
      "name": "crypto",
      "interface": "crypto-functions",
      "format": false,
      "description": "Cryptographic operations",
      "path": "./extensions/my-ext-b.wasm"
    }
  ],
  "host_services": {
    "notify": "Notifications",
    "store_set": "Storage set",
    "store_get": "Storage get",
    "log": "Logging"
  }
}
```

### 2. Run Automated Composition

```bash
./scripts/wac-plug.sh extension-manifest.json ./output
```

This will:
1. Generate dispatcher project from manifest
2. Build dispatcher as WASM component
3. Build wawk-wasi host component
4. Compose all components via `wac plug`
5. Validate the composed output
6. Run smoke tests
7. Generate summary report

### 3. Test the Output

```bash
# Basic tests
./scripts/test-composed.sh ./output/my-product-composed.wasm basic

# Full test suite (includes performance benchmarks)
./scripts/test-composed.sh ./output/my-product-composed.wasm full

# Quick smoke test
./scripts/test-composed.sh ./output/my-product-composed.wasm smoke
```

### 4. Run the Composed WASM

```bash
# Interactive AWK session
echo '{"name":"Alice","age":30}' | wasmtime run ./output/my-product-composed.wasm '{ print $.name }'

# With extension functions
echo 'data' | wasmtime run ./output/my-product-composed.wawk 'BEGIN { print formula.SQRT(16) }'
```

## Manual Workflow (Reference)

If you need to run steps manually:

### Step 1: Generate Dispatcher

```bash
cd wawk-rs
cargo run -p wawk-core --bin wawk-codegen --target x86_64-unknown-linux-gnu -- \
  extension-manifest.json ./dispatcher
```

### Step 2: Build Dispatcher

```bash
cd ./dispatcher
cargo component build --release --target wasm32-wasip2
```

Output: `./dispatcher/target/wasm32-wasip2/release/my_product_dispatcher.wasm`

### Step 3: Build wawk-wasi

```bash
cd wawk-rs
make wasi
```

Output: `./target/wasm32-wasip2/release/wawk_wasi.wasm`

### Step 4: Compose with wac plug

```bash
wac plug ./target/wasm32-wasip2/release/wawk_wasi.wasm \
  --into ./dispatcher/target/wasm32-wasip2/release/my_product_dispatcher.wasm \
  --into ./extensions/my-ext-a.wasm \
  --into ./extensions/my-ext-b.wasm \
  -o ./output/my-product-composed.wasm
```

### Step 5: Validate

```bash
wasm-tools validate ./output/my-product-composed.wasm
wasmtime run ./output/my-product-composed.wasm -- --help
```

## Makefile Integration

Add these targets to your `Makefile`:

```makefile
# Compose product with extensions
compose:
	./scripts/wac-plug.sh extension-manifest.json ./wac-output

# Test composed output
test-composed:
	./scripts/test-composed.sh ./wac-output/*-composed.wasm basic

# Full test suite (includes benchmarks)
test-full:
	./scripts/test-composed.sh ./wac-output/*-composed.wasm full

# Clean composed output
clean-compose:
	rm -rf ./wac-output
```

Usage:

```bash
make compose          # Build composed WASM
make test-composed    # Run tests
make test-full        # Run full test suite
make clean-compose    # Clean output
```

## Extension Development

### Building Extensions

Extensions are standalone WASM components. Example for my-ext-a:

```bash
cd my-ext-a
cargo component build --release --target wasm32-wasip2
```

Output: `./target/wasm32-wasip2/release/wawk_formula.wasm`

### Extension Manifest Schema

```typescript
{
  "name": string,              // Product name (used in naming)
  "version": string,           // Semver version
  "description": string,       // Product description
  "extensions": [
    {
      "name": string,          // Extension namespace
      "interface": string,     // WIT interface name
      "format": boolean,       // Has format extension?
      "description": string,   // Extension description
      "path": string           // Path to .wasm file (optional)
    }
  ],
  "host_services": {           // Host callback functions
    [key: string]: string      // function_name: description
  }
}
```

### Namespace Routing

Extensions are called via namespace-qualified AWK syntax:

```awk
# Qualified call
result = formula.SQRT(16)
hash = crypto.sha256("data")

# Unqualified call (uses @extension directive)
@extension "formula"
BEGIN {
    x = SQRT(16)  # Resolves to formula.SQRT(16)
}
```

## Testing

### Test Suites

| Suite | Tests | Use Case |
|-------|-------|----------|
| `smoke` | Basic execution | Quick validation |
| `basic` | Smoke + integration | Standard testing |
| `full` | Basic + extensions + performance | Release validation |

### Test Coverage

**Structure validation:**
- File exists and non-empty
- WASM magic bytes
- wasm-tools validation
- File size sanity check

**Smoke tests:**
- `--help` flag
- `--version` flag
- Empty input handling
- Simple AWK execution

**Integration tests:**
- Field splitting
- BEGIN/END blocks
- Pattern matching
- Built-in functions
- Associative arrays

**Extension tests:**
- Namespace routing
- Extension function calls
- Cross-extension interaction

**Performance benchmarks:**
- Simple pass-through (10K lines)
- Field extraction
- Pattern matching

### Custom Tests

Add product-specific tests to `test-composed.sh`:

```bash
test_my_product() {
    log_info "=== My Product Tests ==="
    
    run_test "Custom extension function" \
        "echo '' | wasmtime run '$COMPOSED_WASM' 'BEGIN { print myext.function() }' 2>&1 | grep -q 'expected'"
    
    echo ""
}
```

## Troubleshooting

### Composition Fails

**Error:** `wac plug: failed to resolve imports`

**Cause:** Extension WIT interfaces don't match dispatcher

**Fix:**
1. Verify extension WIT matches manifest interface names
2. Rebuild dispatcher: `cargo run -p wawk-codegen -- extension-manifest.json ./dispatcher`
3. Rebuild extension: `cargo component build --release --target wasm32-wasip2`

### Build Fails

**Error:** `error: target not found: wasm32-wasip2`

**Fix:**
```bash
rustup target add wasm32-wasip2
```

### Smoke Test Fails

**Error:** `wasmtime: error while executing at wasm backtrace`

**Cause:** Missing host imports or invalid WASM

**Fix:**
1. Validate WASM: `wasm-tools validate ./output/composed.wasm`
2. Check dispatcher logs for missing namespace routes
3. Verify all extensions are composed: `wac plug` command includes all extension paths

### Performance Issues

**Symptom:** Slow execution (> 10s for 10K lines)

**Diagnosis:**
```bash
# Profile with wasmtime
wasmtime run --profile perf ./output/composed.wasm '{ print $0 }' < large.txt
```

**Common causes:**
- Unoptimized build (use `--release`)
- Missing JIT optimizations (upgrade wasmtime)
- Large extension overhead (profile individual extensions)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Test Composed WASM

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  compose:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-wasip2,x86_64-unknown-linux-gnu
      
      - name: Install tools
        run: |
          cargo install cargo-component wac wasm-tools wasmtime
      
      - name: Compose
        run: |
          ./scripts/wac-plug.sh extension-manifest.json ./output
      
      - name: Test
        run: |
          ./scripts/test-composed.sh ./output/*-composed.wasm full
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: composed-wasm
          path: ./output/*-composed.wasm
```

### Docker Build

```dockerfile
FROM rust:1.82 AS builder

RUN rustup target add wasm32-wasip2 x86_64-unknown-linux-gnu
RUN cargo install cargo-component wac

WORKDIR /app
COPY . .

RUN ./scripts/wac-plug.sh extension-manifest.json ./output

FROM scratch
COPY --from=builder /app/output/*-composed.wasm /app.wasm
ENTRYPOINT ["/app.wasm"]
```

## Advanced Topics

### Multi-Stage Composition

Compose incrementally for large products:

```bash
# Stage 1: Core + formula
wac plug wawk-wasi.wasm --into dispatcher.wasm --into formula.wasm -o stage1.wasm

# Stage 2: Add crypto
wac plug stage1.wasm --into crypto.wasm -o stage2.wasm

# Stage 3: Add custom extensions
wac plug stage2.wasm --into custom.wasm -o final.wasm
```

### Extension Versioning

Pin extension versions in manifest:

```json
{
  "extensions": [
    {
      "name": "formula",
      "version": "1.2.3",
      "path": "./extensions/my-ext-a-1.2.3.wasm"
    }
  ]
}
```

### Debug Builds

Use debug builds for development:

```bash
# Build dispatcher in debug mode
cd ./dispatcher
cargo component build --target wasm32-wasip2  # No --release

# Use debug WASM in composition
wac plug ./target/wasm32-wasip2/debug/wawk_wasi.wasm ...
```

## Resources

- [WASM Component Model](https://component-model.bytecodealliance.org/)
- [wac CLI documentation](https://github.com/bytecodealliance/wac)
- [wawk-rs architecture](./ARCHITECTURE.md)
- [Extension development guide](./EXTENSIONS.md)

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review test output in `./wac-output/SUMMARY.md`
3. Open issue at https://github.com/ailurlabs/wawk-rs/issues
