# wawk-rs

A modern, Wasm-portable AWK engine written in Rust.

## Crates

| Crate | Description |
|-------|-------------|
| `wawk-core` | Pure AWK interpreter with trait-based I/O |
| `wawk-wasi` | WASI CLI wrapper |
| `wawk-bindgen` | Browser/Node.js bindings via wasm-bindgen |

## Quick Start

### Native CLI
```bash
echo "hello\nworld" | wawk '{ print $0 }'
```

### Rust API
```rust
use wawk_core::WawkEngine;
use wawk_core::traits::{BufferedReader, BufferedWriter, SandboxEnvironment, BlockedCommandExecutor};

let engine = WawkEngine::new();
let mut reader = BufferedReader::new("hello\nworld\n");
let mut writer = BufferedWriter::new();
let env = SandboxEnvironment::default();
let mut cmd = BlockedCommandExecutor;

engine.execute("{ print $0 }", &mut reader, &mut writer, &env, &mut cmd).unwrap();
assert_eq!(writer.output, "hello\nworld\n");
```

### Browser (wasm-bindgen)
```javascript
import init, { exec_awk } from './wawk.js';
await init();
const result = exec_awk('{ print $1, $2 }', 'hello world\nfoo bar\n');
```

## Features

### POSIX AWK Compliance
Full POSIX AWK support: patterns, field splitting, built-in variables (NR, NF, FS, OFS, RS, ORS, FILENAME, FNR, ARGV, ARGC), built-in functions (50+), user-defined functions, associative arrays, control flow, and ERE regex.

See [AWK_COMPAT.md](AWK_COMPAT.md) for the complete compatibility matrix.

### PropertyTree-Native Data Model
Automatic structured data detection and parsing via the PropertyTree data model. All input formats are parsed into a universal PropertyTree representation, enabling uniform field access regardless of source format:
```awk
# Input: {"name":"Alice","address":{"city":"Berlin"}}
{ print $.name, $.address.city }
# Output: Alice Berlin
```

Dot-notation (`$.field`) and positional access (`$1`, `$2`) work across all structured formats.

### Multi-Format Input/Output
Built-in handlers for JSON, XML, YAML, and CSV — all supported as both input and output formats with automatic detection on input. Custom format extensions can extend support via the WIT extension-formats interface.

### Extension System (WIT Component Model)
Two extension interfaces:
- **External Functions**: Export callable functions from Wasm to AWK
- **Format Handler**: Custom input/output format detection, parsing, and serialization

Extensions are standard WebAssembly components built to the `wasm32-wasip2` target with `cargo component build` and the `wit-bindgen` v0.42 binding generator.


#### Namespace System
Each extension declares a namespace in its `__meta__` JSON. Functions are called using qualified notation:

```awk
# Qualified call: namespace.function(args)
result = my_extension.compute(1, 2, 3)
output = another_extension.transform("hello")
```

The `@extension` directive sets a default namespace for unqualified calls (in addition to compile-time prefix rewriting):

```awk
@extension "my_extension"
BEGIN {
    # Unqualified calls resolve via default namespace
    x = compute(1, 2, 3)    # equivalent to my_extension.compute(1, 2, 3)
}
```

Example extension namespaces:

| Namespace | Extension | Functions |
|-----------|--------|-----------|
| `hello` | wawk-hello | greet, echo |

Additional extensions can be developed following the extension specification in [SPEC.md](SPEC.md) §3.
See [SPEC.md](SPEC.md) §3 for the full extension specification.

## Optimizations

- Zero-allocation hot paths with reusable buffers
- Format auto-detection skip for plain text (first-byte check)
- Ultra-fast `print $N` with zero-copy direct write
- FxHashMap for O(1) variable/array lookups
- Deferred field materialization (byte ranges, no String alloc)
- Single-hot-rule dispatch for single-pattern programs
- Pre-compiled regex with NFA engine (ReDoS-immune)
- `itoa`/`ryu` for fast number formatting
- Single-pass whitespace splitting
- Leaf expression depth check bypass

## Security

Security-by-design with Wasm sandboxing. See [SECURITY.md](SECURITY.md) for details.

| Limit | Value |
|-------|-------|
| Output size | 64 MB (amortized checks) |
| Record size | 16 MB |
| Call depth | 256 |
| Expression depth | 1024 |
| Array entries | 1,000,000 |
| Open files | 256 |
| Regex pattern | 4096 chars |
| Object nesting | 64 levels |
| Object keys | 10,000 |
| Audit log | 1024 entries |
| Loop iterations | 100,000,000 |

**SecurityProfile presets** (engine-level deployment tuning; all presets enforce the limits above):

| Preset | Execution timeout | Memory limit | Audit log | Record audit | Intended use |
|--------|-------------------|--------------|-----------|--------------|--------------|
| `default` | 300 s | 256 MB | On | Off | General-purpose processing |
| `strict` | 30 s | 64 MB | On | On | Untrusted input, web-facing services |
| `relaxed` | 600 s | 512 MB | Off | Off | Trusted internal batch workloads |

**Stack depth:** worker threads run with a 64 MB stack, so deeply nested expressions and recursive user functions fail on the engine's call-depth ceiling (256) instead of a native stack overflow.

**Sandbox properties:**
- `system()` blocked via `BlockedCommandExecutor`
- No network/filesystem access in WASM sandbox
- Environment variable whitelisting
- Read-only ENVIRON/ARGV
- NFA regex engine (ReDoS-immune)
- Execution timeout with amortized checks

## Testing

```bash
# Run all tests
cargo test --lib

# Security tests
cargo test --test security_tests

# Wasmtime integration tests
python3 crates/wawk-bindgen/tests/wasmtime_tests.py
```

**228+ tests**, all passing.

## Dispatcher Codegen (`wawk-codegen`)

Build-time code generation tool for the dynamic extension dispatch system. Reads a `extension-manifest.json` and generates a complete WASM dispatcher component project.

```bash
# Generate dispatcher project from manifest
cargo run -p wawk-codegen -- <manifest.json> <output-dir>

# Dry run (print to stdout)
cargo run -p wawk-codegen -- <manifest.json> <output-dir> --dry-run
```

**Generated output:**
- `Cargo.toml` — WASM component project configuration
- `src/lib.rs` — crate root with `wit_bindgen::generate!` and all interface mappings
- `src/dispatcher.rs` — namespace-based routing (e.g. `product-a.lookup` → extension)
- `wit/dispatcher.wit` — dispatcher world importing all extension + host-services interfaces
- `wit/deps/extensions/world.wit` — extension interface definitions
- `wit/deps/services/host-services.wit` — host callback interface

**Architecture:** Each product (mcp-server-*) has a `extension-manifest.json` declaring its extension dependencies. The codegen produces a dispatcher that routes tool calls by namespace prefix to the correct extension via WIT imports. The dispatcher WASM is composed with extension WASMs via `wac plug` into the wawk-mcp host.

## Delivery Vehicles

1. **Native CLI** (`wawk-wasi`): Standalone binary via WASI
2. **NPM package** (`wawk-bindgen`): Browser and Node.js via wasm-bindgen

## License

MIT OR Apache-2.0
