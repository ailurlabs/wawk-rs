# Wawk Specification

**Version**: 1.2.0
**Date**: 2026-08-30
**Status**: Production Ready

---

## Overview

Wawk is a POSIX-compliant AWK interpreter compiled to WebAssembly, with plugin extensibility via the WIT Component Model. It runs identically across browsers, servers, and edge runtimes.

---

## Core Features

### 1. POSIX AWK Compliance

Wawk implements the full POSIX AWK specification:

- **Pattern-action rules**: `/pattern/ { action }`
- **Field splitting**: Automatic whitespace splitting, custom FS support
- **Built-in variables**: NR, NF, FS, OFS, RS, ORS, FILENAME, FNR, ARGV, ARGC
- **Built-in functions**: length, substr, index, split, sub, gsub, sprintf, tolower, toupper, match, atan2, cos, sin, exp, log, sqrt, int, rand, srand
- **User-defined functions**: `function name(params) { body }`
- **Associative arrays**: `arr[key] = value`, `for (k in arr)`
- **Control flow**: if/else, while, for, do-while, break, continue
- **Regular expressions**: ERE syntax, `~` and `!~` operators
- **I/O**: print, printf, getline, redirection

### 2. PropertyTree-Native Data Model

Wawk extends AWK with a universal structured data model (PropertyTree) that serves as the core representation for all structured input/output formats:

- **Universal data model**: All formats (JSON, XML, YAML, CSV) are parsed into PropertyTree
- **Auto-detection**: Input format is automatically detected and parsed
- **Field access**: `$.field` notation for object fields (works with any format)
- **Positional access**: `$1, $2, $3` for array elements
- **Nested access**: `$.parent.child` for nested structures
- **Format-agnostic**: Same AWK code works regardless of input format
- **Round-trip**: PropertyTree can be serialized back to any supported output format

**Example**:
```awk
# Works identically for JSON, XML, YAML, or CSV input
# Input: {"name":"Alice","address":{"city":"Berlin"}}
{ print $.name, $.address.city }
# Output: Alice Berlin
```

### 3. Plugin System

Wawk supports plugins via the WIT Component Model with two interfaces:

- **External Functions**: `wawk:plugins/external-functions`
  - Plugins export named functions callable from AWK scripts
  - Functions accept string arguments and return string results
  - Host dispatches via `FunctionDispatcher` trait

- **Format Handler**: `wawk:plugins/format-handler`
  - Plugins implement custom input format detection, parsing, and serialization
  - Convention-based: `__detect__`, `__parse__`, `__serialize__` functions
  - Priority-based registration (lower = higher priority)
  - Built-in handlers (input and output): JSON (10), XML (30), YAML (40), CSV (50)

- **Plugin format**: WebAssembly components (.wasm) built with `wasm32-unknown-unknown`
- **Loading**: `--plugin` flag or `plugins/` directory
- **Languages**: Rust, C, Go, TypeScript (any WIT-compatible language)
- **Sandboxing**: Plugins run in isolated Wasm sandbox

### 4. Security Features

Wawk includes comprehensive security limits:

- **Output size limit**: 64MB max (configurable)
- **Record size limit**: Prevents memory exhaustion
- **Regex safety**: NFA-based engine (no ReDoS), pattern length limit
- **Execution timeout**: Configurable timeout with amortized checks
- **Array size limit**: Max 1,000,000 entries
- **Object key limit**: Max 10,000 keys per structured object (PropertyTree)
- **Nesting depth limit**: Max 64 levels for structured data parsing (PropertyTree)
- **Field limit**: Max 100,000 fields per record
- **Open file limit**: Max 256 simultaneous file targets
- **Audit log cap**: Max 1024 entries (prevents audit bomb attacks)
- **Loop iteration limit**: 100M iterations (prevents infinite loops)
- **Field index clamping**: Prevents overflow from very large f64 values
- **Safe UTF-8 conversion**: No unsafe blocks in hot paths (defense-in-depth)

### 5. Performance Optimizations

Wawk includes numerous performance optimizations:

- **Zero-allocation hot paths**: Reusable buffers for print output, array keys, split parts
- **Fast integer formatting**: `itoa` library (avoids format! overhead)
- **Fast float formatting**: `ryu` library (avoids format! overhead)
- **Literal pattern fast-path**: Substring search instead of regex engine
- **FxHashMap**: Fast hashing for arrays and variables
- **Deferred field materialization**: Byte ranges into line buffer (no String alloc per field)
- **Regex compilation cache**: LRU eviction, max 512 entries
- **Scope stack**: Zero-copy variable scoping for user-defined functions
- **Format auto-detection skip**: First-byte check eliminates per-record trait dispatch for plain text
- **Single-hot-rule dispatch**: Bypasses rule loop for single-pattern programs
- **Pre-compiled regex**: Static patterns compiled once before main loop
- **Ultra-fast print $N**: Zero-copy direct write for constant field index
- **Single-pass whitespace splitting**: Merged has_whitespace + split into one pass (avoids double-scanning)
- **Leaf expression depth skip**: Expression depth check bypassed for leaf nodes (Number, String, Var)
- **Table-driven whitespace check**: WS_TABLE lookup instead of matches! macro

---

## Testing

### Test Coverage

- **Unit tests**: 207 tests covering core functionality
- **Security tests**: 18 tests (output limits, recursion, ReDoS, sandbox enforcement, audit bomb prevention, open files limit, format string safety, integer overflow, ENVIRON read-only)
- **Advanced security tests**: 12 tests (null bytes, nested JSON, unicode, edge cases)
- **Concurrency tests**: 4 tests for thread safety
- **Sandbox tests**: 6 tests for sandbox enforcement
- **Wasmtime integration tests**: 20 tests (text + JSON + system blocked)
- **Doc tests**: 2 documentation tests

**Total**: 269+ tests, all passing

---

## License

Wawk is dual-licensed under MIT and Apache 2.0.
