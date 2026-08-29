# Security Policy - wawk-rs

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Supported          |

Only the latest release of wawk-rs receives security updates. All crates in the workspace (wawk-core, wawk-wasi, wawk-bindgen) are versioned together.

## Reporting a Vulnerability

To report a security vulnerability, please open a [GitHub Security Advisory](https://github.com/ailurlabs/wawk-rs/security/advisories/new) with:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Affected component(s) (wawk-core, wawk-wasi, wawk-bindgen)
- Potential impact assessment

We will acknowledge receipt within 48 hours and provide a fix timeline within 7 days. Please do not open public issues for security vulnerabilities.

---

## Security Architecture

### Principle of Defense in Depth

wawk-rs employs multiple layers of security controls, from the language runtime (safe Rust) through the WASM sandbox, to application-level resource limits and audit logging.

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Safe Rust (no unsafe blocks in core)   │
│   - Memory safety, no buffer overflows          │
│   - Type safety, no type confusion              │
│   - Ownership model prevents data races         │
├─────────────────────────────────────────────────┤
│ Layer 2: WASM Sandbox (wasm32-wasip1)           │
│   - Linear memory bounds enforcement            │
│   - No direct host filesystem access            │
│   - No direct network access                    │
│   - No direct process spawning                  │
├─────────────────────────────────────────────────┤
│ Layer 3: Trait-Based I/O Abstraction            │
│   - AwkReader: host-mediated input only         │
│   - AwkWriter: host-mediated output only        │
│   - AwkEnvironment: host-controlled env vars    │
│   - AwkCommandExecutor: blocked by default      │
│   - IncludeResolver: blocked by default         │
├─────────────────────────────────────────────────┤
│ Layer 4: Resource Limits (Hardcoded + Profile)  │
│   - 12 configurable resource ceilings           │
│   - SecurityProfile for deployment contexts     │
│   - Execution timeout enforcement               │
│   - Memory usage tracking                       │
├─────────────────────────────────────────────────┤
│ Layer 5: Audit Logging                          │
│   - Security event recording                    │
│   - Limit violation tracking                    │
│   - Execution completion reports                │
│   - Compliance summary generation               │
└─────────────────────────────────────────────────┘
```

### Wasm Sandboxing

wawk-core is a pure AWK engine designed to compile to WebAssembly (wasm32-wasip1). The architecture enforces security through trait-based I/O abstractions:

| Trait | Purpose | Sandbox Behavior |
|-------|---------|-----------------|
| AwkReader | Input reading | Host-provided; no filesystem access |
| AwkWriter | Output writing | Host-provided; no filesystem access |
| AwkEnvironment | Environment variables | Host-controlled whitelist |
| AwkCommandExecutor | External commands | BlockedCommandExecutor blocks all system() calls |
| IncludeResolver | @include directives | StubIncludeResolver rejects all includes |
| AwkExternalFunction | Host function extensions | Only host-registered functions are callable |

### Resource Limits

All limits are enforced at runtime with clear error messages:

| Limit | Default Value | Purpose |
|-------|--------------|---------|
| MAX_PT_OBJECT_KEYS | 10,000 | Prevent memory exhaustion via large structured objects |
| MAX_PT_NESTING_DEPTH | 64 | Prevent stack overflow from deeply nested PropertyTree |
| MAX_PT_KEY_LENGTH | 1,000 | Prevent memory exhaustion via long keys |
| MAX_PT_ARRAY_LENGTH | 100,000 | Prevent memory exhaustion via large arrays |
| MAX_TOTAL_ARRAY_ENTRIES | 1,000,000 | Prevent cumulative memory exhaustion across all arrays |
| MAX_LOOP_ITERATIONS | 100,000,000 | Prevent infinite loops (DoS mitigation) |
| MAX_OUTPUT_BYTES | 64 MB | Prevent disk/memory exhaustion via output |
| MAX_OPEN_FILES | 256 | Prevent file descriptor exhaustion |
| MAX_FIELDS | 100,000 | Prevent memory exhaustion via field splitting |
| MAX_CALL_DEPTH | 256 | Prevent stack overflow from recursive functions |
| MAX_EXPR_DEPTH | 1,024 | Prevent stack overflow from deeply nested expressions |
| MAX_REGEX_PATTERN_LEN | 4,096 | Prevent ReDoS (Regular Expression Denial of Service) |

### Security Profiles

Configurable security profiles for different deployment contexts:

| Profile | Max Execution | Max Memory | Audit | Use Case |
|---------|--------------|------------|-------|----------|
| `default` | 300s (5 min) | 256 MB | Enabled | General purpose |
| `strict` | 30s | 64 MB | Enabled + Record audit | Web-facing, untrusted input |
| `relaxed` | Unlimited | Unlimited | Disabled | Trusted internal pipelines |

### Audit Logging

The evaluator maintains an audit log of security-relevant events:

| Event Type | Description | Compliance Mapping |
|-----------|-------------|-------------------|
| LimitViolation | A resource limit was hit | ISO 27001 A.12.4, SOC 2 CC7.2 |
| SandboxViolation | Attempted sandbox escape | ISO 27001 A.13.1, HIPAA 164.312(b) |
| ExecutionTimeout | Wall-clock time exceeded | SOC 2 CC6.6, ISO 27001 A.12.2 |
| MemoryLimitExceeded | Memory ceiling approached | ISO 27001 A.12.2, SOC 2 CC6.6 |
| RecordProcessed | Input record metadata logged | GDPR Art. 30, HIPAA 164.312(b) |
| ExecutionComplete | Summary of execution | ISO 27001 A.12.4, SOC 2 CC7.2 |

---

## Compliance Framework

### ISO 27001:2022 — Information Security Management

| Control | Requirement | wawk Implementation |
|---------|------------|---------------------|
| A.5.1 | Inventory of information assets | wawk-core is a stateless processor; no persistent data stores |
| A.8.1 | Asset management | All resources bounded by configurable limits |
| A.8.2 | Information classification | Input treated as untrusted by default |
| A.9.1 | Access control | WASM sandbox enforces least privilege; trait-based I/O gates all access |
| A.12.1 | Operational procedures | Deterministic execution; same input → same output |
| A.12.2 | Protection from malware | Resource limits prevent DoS; no code execution beyond AWK |
| A.12.4 | Logging and monitoring | AuditEvent system records all security events |
| A.13.1 | Network security | No network access in WASM sandbox; all I/O host-mediated |
| A.14.1 | Secure development | Safe Rust; no unsafe blocks in core; dependency pinning |
| A.14.2 | Security in development | LTO, panic=abort, symbol stripping in release builds |

### SOC 2 Type II — Trust Service Criteria

| Criterion | Requirement | wawk Implementation |
|-----------|------------|---------------------|
| CC6.1 | Logical and physical access controls | WASM linear memory isolation; trait-gated I/O |
| CC6.2 | Registration and authorization | Host-controlled environment variable whitelist |
| CC6.6 | Security for externally facing systems | Execution timeout; memory limits; strict security profile |
| CC7.1 | Detection of unauthorized activity | Audit log tracks all limit violations and sandbox escapes |
| CC7.2 | Monitoring for anomalies | Security event recording with timestamps |
| CC8.1 | Change management | Version-locked crates; pinned dependencies |
| CC9.1 | Risk mitigation | Defense in depth (5 layers); configurable security profiles |

### HIPAA — Health Insurance Portability and Accountability Act

| Requirement | wawk Implementation |
|------------|---------------------|
| 164.312(a)(1) Access control | WASM sandbox prevents unauthorized data access; all I/O host-mediated |
| 164.312(a)(2)(i) Unique user identification | Host runtime assigns execution context; wawk-core is stateless |
| 164.312(b) Audit controls | AuditEvent system logs all security-relevant events; compliance_summary() generates reports |
| 164.312(c)(1) Integrity | Safe Rust prevents memory corruption; deterministic execution ensures reproducibility |
| 164.312(d) Person or entity authentication | Host runtime handles authentication; wawk-core receives pre-authenticated input |
| 164.312(e)(1) Transmission security | WASM sandbox has no network access; data in transit managed by host |

**PHI Handling**: wawk-core is a stateless text processor. It does not collect, store, or transmit Protected Health Information (PHI). All data exists only in ephemeral WASM linear memory and is destroyed when the module instance is dropped. Host applications processing PHI must ensure:
- Input is de-identified before processing where possible
- WASM module instances are not persisted between requests
- Audit logs are stored in HIPAA-compliant infrastructure

### GDPR — General Data Protection Regulation

| Article | Requirement | wawk Implementation |
|---------|------------|---------------------|
| Art. 5 | Data minimization | Stateless processing; no data retention between invocations |
| Art. 13-14 | Right to information | wawk processes data on behalf of controller; controller manages notices |
| Art. 17 | Right to erasure | No persistent storage; data destroyed on module drop |
| Art. 25 | Data protection by design | WASM isolation; trait-based I/O; configurable security profiles |
| Art. 30 | Records of processing | AuditEvent::RecordProcessed tracks processing metadata |
| Art. 32 | Security of processing | 5-layer defense in depth; resource limits; sandbox isolation |
| Art. 33 | Breach notification | Audit log provides detection capability; host manages notification |
| Art. 35 | Data protection impact | No profiling, no automated decision-making; pure text transformation |

**Data Processing Role**: wawk-core operates as a **data processor** under GDPR. It processes personal data only on behalf of and under instructions from the data controller (the host application). wawk-core:
- Does not determine the purpose of processing
- Does not retain data between invocations
- Provides technical measures (Art. 32) through sandboxing and resource limits
- Supports the controller's obligations through audit logging

### EU AI Act — Artificial Intelligence Act

| Requirement | wawk Implementation |
|------------|---------------------|
| Transparency | wawk-core is a deterministic text processor, NOT an AI system. It does not use machine learning, neural networks, or probabilistic inference. |
| Non-determinism | Given identical input and environment, wawk-core produces byte-identical output. No randomness (except srand()/rand() which are seeded deterministically). |
| Human oversight | wawk-core is a tool, not an autonomous agent. All execution is initiated and controlled by human operators. |
| Record-keeping | Audit logging provides execution records for compliance documentation. |

**AI Act Classification**: wawk-core is explicitly **not an AI system** as defined by the EU AI Act (Article 3). It is a deterministic text/data transformation tool. However, when used as a component in AI pipelines (e.g., preprocessing training data, postprocessing model outputs), wawk-core's deterministic nature and audit capabilities support the broader system's compliance.

### ISO/IEC 42001 — AI Management System

| Requirement | wawk Implementation |
|------------|---------------------|
| Scope | wawk-core is a text processing engine, not an AI system. This section addresses its use within AI management systems. |
| Risk assessment | Resource limits prevent runaway execution; sandbox prevents data leakage |
| Controls | 5-layer defense in depth; configurable security profiles |
| Monitoring | AuditEvent system provides execution visibility |
| Documentation | Deterministic execution; reproducible results; version-locked releases |

### ISO 27701 — Privacy Information Management

| Requirement | wawk Implementation |
|------------|---------------------|
| PII processing | wawk-core has no awareness of PII; it processes all input as opaque text/JSON |
| Consent | Host application manages consent; wawk-core is a processor |
| Purpose limitation | Stateless; cannot repurpose data |
| Storage limitation | No persistence; all data ephemeral in WASM memory |
| Accuracy | Deterministic processing; no data mutation beyond explicit AWK transformations |
| Confidentiality | WASM isolation; no data leakage paths; ENVIRON filtering |
| Privacy by design | Trait-based I/O; sandbox-first architecture; configurable security profiles |

---

## Known Security Properties

1. **AWK scripts cannot escape the sandbox** — all I/O paths go through host-provided trait implementations.
2. **No PII processing** — wawk-core performs text transformation only. It does not collect, store, or transmit personally identifiable information.
3. **No cryptographic operations in core** — wawk-core contains no crypto primitives.
4. **Deterministic execution** — given the same input and environment, wawk-core produces identical output. No side channels from non-deterministic behavior.
5. **No external dependencies with network access** — wawk-core dependencies (nom, regex, thiserror, rustc-hash, serde_json) are pure computation libraries.
6. **No unsafe code in core** — wawk-core is written in 100% safe Rust. No `unsafe` blocks.
7. **Resource exhaustion prevention** — 12 hardcoded limits prevent DoS via memory, CPU, or I/O exhaustion.
8. **Audit trail** — all security events are recorded and queryable via the compliance API.

## Dependency Security

- All dependencies are pinned to specific minor versions in Cargo.toml.
- Release builds use LTO, size optimization, single codegen unit, panic=abort, and symbol stripping to minimize binary size and attack surface.
- The regex crate uses default-features = false to exclude unnecessary features.
- serde_json is used only for JSON parsing; no serialization of sensitive data.

### Dependency Audit

| Dependency | Version | Purpose | Network Access | Unsafe Code |
|-----------|---------|---------|---------------|-------------|
| nom | 8.x | Parser combinators | No | No |
| regex | 1.x (no default features) | Pattern matching | No | No |
| thiserror | 2.x | Error derivation | No | No |
| rustc-hash | 2.x | Fast hashing | No | No |
| serde_json | 1.x | JSON parsing | No | No |
| serde | 1.x | Serialization framework | No | No |
| itoa | 1.x | Fast integer formatting | No | No |
| ryu | 1.x | Fast float formatting | No | No |
| getrandom | 0.2.x | Random number seeding | No (uses WASI) | No |

## Build Security

Release builds are hardened with:

```toml
[profile.release]
lto = true          # Link-time optimization (eliminates dead code)
opt-level = "s"     # Size optimization (minimizes attack surface)
codegen-units = 1   # Single codegen unit (better optimization)
panic = "abort"     # Abort on panic (no unwinding, no information leakage)
strip = true        # Strip symbols (reduces information for attackers)
```

## Deployment Recommendations

### For Web-Facing Services (Strict)
```rust
let mut evaluator = Evaluator::new(reader, writer, env, cmd);
evaluator.set_security_profile(SecurityProfile::strict());
```

### For Internal Data Pipelines (Default)
```rust
let mut evaluator = Evaluator::new(reader, writer, env, cmd);
// Default profile: 5 min timeout, 256 MB memory, audit enabled
```

### For Trusted Batch Processing (Relaxed)
```rust
let mut evaluator = Evaluator::new(reader, writer, env, cmd);
evaluator.set_security_profile(SecurityProfile::relaxed());
```

### Compliance Checklist for Deployers

- [ ] Select appropriate SecurityProfile for your deployment context
- [ ] Configure host runtime to provide sandboxed AwkReader/AwkWriter
- [ ] Enable audit logging and route events to your SIEM
- [ ] Set execution timeouts appropriate for your SLA
- [ ] Configure ENVIRON whitelist (never expose secrets)
- [ ] If processing PHI: ensure infrastructure meets HIPAA requirements
- [ ] If processing EU personal data: ensure GDPR data processing agreements are in place
- [ ] Retain audit logs per your regulatory requirements (HIPAA: 6 years, GDPR: as needed)
- [ ] Pin wawk-rs to a specific version in your dependency manifest
- [ ] Watch the repository for security advisories
