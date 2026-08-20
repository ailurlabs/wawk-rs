# Security Policy - wawk-rs

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Supported          |

Only the latest release of wawk-rs receives security updates. All crates in the workspace (wawk-core, wawk-wasi, wawk-bindgen) are versioned together.

## Reporting a Vulnerability

To report a security vulnerability, email **security@ailurlabs.com** with:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected component(s) (wawk-core, wawk-wasi, wawk-bindgen)
- Potential impact assessment

We will acknowledge receipt within 48 hours and provide a fix timeline within 7 days. Please do not open public issues for security vulnerabilities.

## Security Architecture

### Wasm Sandboxing

wawk-core is a pure AWK engine designed to compile to WebAssembly (wasm32-wasip1). The architecture enforces security through trait-based I/O abstractions:

| Trait | Purpose | Sandbox Behavior |
|-------|---------|-----------------|
| AwkReader | Input reading | Host-provided; no filesystem access |
| AwkWriter | Output writing | Host-provided; no filesystem access |
| AwkEnvironment | Environment variables | Host-controlled whitelist |
| AwkCommandExecutor | External commands | StubCommandExecutor blocks all system() calls |
| IncludeResolver | @include directives | StubIncludeResolver rejects all includes |
| AwkExternalFunction | Host function extensions | Only host-registered functions are callable |

### Resource Limits

- **No network access**: The WASM sandbox has no socket or HTTP capabilities. All I/O is mediated by the host runtime through WIT interfaces.
- **No filesystem access**: AWK scripts cannot read or write host filesystem paths. File I/O traits (open_file, write_file_line, etc.) are no-ops by default and must be explicitly enabled by the host.
- **No command execution**: system() and pipe operations (getline | "cmd") return sandbox violation errors via StubCommandExecutor.
- **Memory safety**: Written in safe Rust with no unsafe blocks in the core engine. The wasm32 target enforces linear memory bounds.
- **Environment filtering**: The SandboxEnvironment pattern demonstrates that hosts can restrict ENVIRON to a whitelist, preventing leakage of secrets (e.g., AWS_SECRET_KEY, PATH, HOME).
- **Read-only ENVIRON**: Attempts to assign to ENVIRON are rejected with a read-only error.

### Input Validation

- AWK lexer/parser operates on bounded input with no unbounded recursion.
- Regex compilation uses a cache with LRU eviction to prevent resource exhaustion.
- Field splitting is byte-oriented with deferred materialization to minimize allocation.

## Known Security Properties

1. **AWK scripts cannot escape the sandbox** - all I/O paths go through host-provided trait implementations.
2. **No PII processing** - wawk-core performs text transformation only. It does not collect, store, or transmit personally identifiable information.
3. **No cryptographic operations in core** - wawk-core contains no crypto primitives.
4. **Deterministic execution** - given the same input and environment, wawk-core produces identical output. No side channels from non-deterministic behavior.
5. **No external dependencies with network access** - wawk-core dependencies (nom, regex, thiserror, rustc-hash) are pure computation libraries.

## Dependency Security

- All dependencies are pinned to specific minor versions in Cargo.toml.
- Release builds use LTO, size optimization, single codegen unit, panic=abort, and symbol stripping to minimize binary size and attack surface.
- The regex crate uses default-features = false to exclude unnecessary features.

## Compliance Notes

- **Data processing**: wawk-core is a stateless text processor. It does not persist data between invocations.
- **No PHI/PII handling**: The engine has no awareness of protected health information or personally identifiable information.
- **Audit trail**: Execution logging is the responsibility of the host runtime (e.g., the host runtime's audit module).
