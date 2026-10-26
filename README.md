# wawk-rs

Pure AWK engine + extension dispatcher targeting WebAssembly.

## Architecture

wawk-rs is a modular Rust workspace that compiles a POSIX-compliant AWK engine to WebAssembly. Extensions are loaded at build time through a dynamic dispatcher with namespace-based routing — there is no runtime plugin loading.

### Crate Structure

| Crate | Role |
|-------|------|
| `wawk-core` | AWK engine, extension dispatcher, and codegen binary (`wawk-codegen`) |
| `wawk-wasi` | WASI CLI build target — standalone command-line binary |
| `wawk-bindgen` | Browser / Node.js binding generator via `wasm-bindgen` |

### Extension Architecture

Extensions are compiled as WebAssembly components and wired into the dispatcher at build time by `wawk-codegen`. The codegen reads an `extension-manifest.json` and produces a dispatcher component that routes calls by namespace prefix to the correct extension via WIT imports.

```text
extension-manifest.json
        |
        v
  wawk-codegen  -->  dispatcher WASM component
        |                    |
        |                    |-- namespace "hello"   -> wawk-hello extension
        |                    |-- namespace "compute" -> wawk-compute extension
        |                    |-- host-services       -> wawk-core callbacks
        |
        v
  composed via wac plug into the wawk host
```

There is no runtime plugin mechanism. All extensions are resolved and composed before execution.

### Extension Interface (WIT)

Two unified WIT interfaces cover all extension capabilities:

- **`extension-functions`** — export callable functions from a Wasm component to AWK
- **`extension-formats`** — custom input/output format detection, parsing, and serialization

Extensions target `wasm32-wasip2` and use `wit-bindgen` v0.42 for binding generation.

#### Namespace-Based Routing

Each extension declares a namespace in its `__meta__` JSON. AWK code calls extension functions using qualified notation:

```awk
# Qualified call: namespace.function(args)
result = compute.evaluate(1, 2, 3)
output = hello.greet("world")
```

The `@extension` directive sets a default namespace for unqualified calls:

```awk
@extension "compute"
BEGIN {
    x = evaluate(1, 2, 3)    # resolves to compute.evaluate(1, 2, 3)
}
```

## PropertyTree

PropertyTree is the native JSON data model built into `wawk-core`. All input formats are parsed into a universal PropertyTree representation, enabling uniform field access regardless of source format:

```awk
# Input: {"name":"Alice","address":{"city":"Berlin"}}
{ print $.name, $.address.city }
# Output: Alice Berlin
```

Dot-notation (`$.field`) and positional access (`$1`, `$2`) work across all structured formats. Built-in handlers cover JSON, XML, YAML, and CSV with automatic detection on input.

## Security

Sandboxed execution with deterministic output. No PII processing. See [SECURITY.md](SECURITY.md) for full details.

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

**Sandbox properties:**

- `system()` blocked via `BlockedCommandExecutor`
- No network / filesystem access in Wasm sandbox
- Environment variable whitelisting
- Read-only ENVIRON / ARGV
- NFA regex engine (ReDoS-immune)
- Execution timeout with amortized checks
- Deterministic execution — same input always produces same output

## Build Targets

### 1. Library (Rust DSL)

Use `wawk-core` directly as a Rust library:

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

### 2. WASI CLI (`wawk-wasi`)

Standalone command-line binary compiled to `wasm32-wasip2`:

```bash
echo "hello\nworld" | wawk '{ print $0 }'
```

### 3. Bindgen — JS / Browser (`wawk-bindgen`)

Browser and Node.js bindings generated via `wasm-bindgen`:

```javascript
import init, { exec_awk } from './wawk.js';
await init();
const result = exec_awk('{ print $1, $2 }', 'hello world\nfoo bar\n');
```

### Dispatcher Codegen (`wawk-codegen`)

Build-time code generation for the dynamic extension dispatch system. Reads an `extension-manifest.json` and generates a complete WASM dispatcher component project.

```bash
# Generate dispatcher project from manifest
cargo run -p wawk-codegen -- <manifest.json> <output-dir>

# Dry run (print to stdout)
cargo run -p wawk-codegen -- <manifest.json> <output-dir> --dry-run
```

**Generated output:**

- `Cargo.toml` — WASM component project configuration
- `src/lib.rs` — crate root with `wit_bindgen::generate!` and all interface mappings
- `src/dispatcher.rs` — namespace-based routing (e.g. `compute.evaluate` -> extension)
- `wit/dispatcher.wit` — dispatcher world importing all extension + host-services interfaces
- `wit/deps/extensions/world.wit` — extension interface definitions
- `wit/deps/services/host-services.wit` — host callback interface

## POSIX AWK Compliance

Full POSIX AWK support: patterns, field splitting, built-in variables (NR, NF, FS, OFS, RS, ORS, FILENAME, FNR, ARGV, ARGC), built-in functions (50+), user-defined functions, associative arrays, control flow, and ERE regex.

See [AWK_COMPAT.md](AWK_COMPAT.md) for the complete compatibility matrix.

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

## License

MIT OR Apache-2.0
