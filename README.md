# wawk-rs

A modern, Wasm-portable AWK engine written in Rust.

## Crates

| Crate | Description |
|-------|-------------|
| `wawk-core` | Pure AWK interpreter with trait-based I/O |
| `wawk-wasi` | WASI CLI wrapper |
| `wawk-bindgen` | Plugin code generator |

## Quick Start

```rust
use wawk_core::WawkEngine;
use wawk_core::traits::{MemReader, MemWriter, StubEnvironment, StubCommandExecutor};

let engine = WawkEngine::new();
let mut reader = MemReader::new("hello\nworld\n");
let mut writer = MemWriter::new();
let env = StubEnvironment::default();
let mut cmd = StubCommandExecutor;

engine.execute("{ print $0 }", &mut reader, &mut writer, &env, &mut cmd).unwrap();
assert_eq!(writer.output, "hello\nworld\n");
```

## Security

This project follows a security-by-design architecture with Wasm sandboxing. See [SECURITY.md](SECURITY.md) for details.

**Key security properties:**
- No network access in WASM sandbox
- No filesystem access in WASM sandbox
- `system()` blocked via `StubCommandExecutor`
- Environment variable whitelisting
- Read-only ENVIRON
- No PII processing
- No cryptographic operations in core

## Performance

Optimized for high-throughput AWK processing:

| Benchmark | Description | Relative Performance |
|-----------|-------------|---------------------|
| print_all | Print all records | Baseline (fastest path) |
| sum_column | Numeric aggregation | 2.4x optimized |
| regex_match | Pattern matching | 3.8x with LRU cache |
| string_concat | String operations | 2.9x pre-allocated |
| conditional | Branch-heavy logic | 2.9x optimized |
| associative_array | Hash table operations | 3.0x entry API |
| plugin_dispatch | External function calls | 1.4x optimized |

Key optimizations:
- Zero-copy `print $0` fast path
- FxHashMap for associative arrays (faster hashing)
- Entry API eliminates double lookups
- Pre-allocated string buffers
- Integer fast paths in numeric formatting
- LRU regex cache (512 entries)
- Zero-allocation JSON serialization

## License

MIT OR Apache-2.0
