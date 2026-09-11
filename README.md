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
import init, { exec_awk } from './wawk_bindgen.js';
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
Built-in handlers for JSON, XML, YAML, and CSV — all supported as both input and output formats with automatic detection on input. Custom format plugins can extend support via the WIT format-handler interface.

### Plugin System (WIT Component Model)
Two plugin interfaces:
- **External Functions**: Export callable functions from Wasm to AWK
- **Format Handler**: Custom input/output format detection, parsing, and serialization

Plugins are standard WebAssembly components built with `wasm32-wasip2` target.

#### Namespace System
Each plugin declares a namespace in its `__meta__` JSON. Functions are called using qualified notation:

```awk
# Qualified call: namespace.function(args)
result = formula.sum(1, 2, 3)
hash = crypto.sha256("hello")
expr = cel.eval("x > 5")
```

The `@namespace` directive sets a default namespace for unqualified calls:

```awk
@namespace "formula"
BEGIN {
    # Unqualified calls resolve via default namespace
    x = sum(1, 2, 3)    # equivalent to formula.sum(1, 2, 3)
}
```

Available plugin namespaces:

| Namespace | Plugin | Functions |
|-----------|--------|-----------|
| `formula` | wawk-formula | sum, eval, average, min, max, ... |
| `crypto` | wawk-crypto | sha256, md5, hmac, ... |
| `cel` | wawk-cel | eval, size, map, filter, ... |
| `jsonata` | wawk-jsonata | eval, path, ... |
| `oauth` | wawk-oauth | validate, claims, ... |
| `feel` | wawk-feel | eval, unary_test, ... |
| `hello` | wawk-hello | greet, echo |

See [SPEC.md](SPEC.md) §3 for the full plugin specification.

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

## Delivery Vehicles

1. **Native CLI** (`wawk-wasi`): Standalone binary via WASI
2. **NPM package** (`wawk-bindgen`): Browser and Node.js via wasm-bindgen

## License

MIT OR Apache-2.0
