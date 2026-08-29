# Contributing to wawk

Thank you for your interest in contributing to wawk! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs))
- WebAssembly targets:
  ```bash
  rustup target add wasm32-wasip1
  rustup target add wasm32-unknown-unknown
  ```
- `wasm-pack` (for wawk-bindgen):
  ```bash
  cargo install wasm-pack
  ```

### Building

```bash
# Build the entire workspace
make build

# Run all tests
make test

# Check formatting and lints
make check
```

## Contribution Workflow

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
4. **Make your changes** with clear, focused commits
5. **Run checks** before submitting:
   ```bash
   make check
   make test
   ```
6. **Push** your branch and open a Pull Request

## Code Standards

### Formatting

All Rust code must be formatted with `rustfmt`:

```bash
cargo fmt --all
```

### Linting

All code must pass `clippy` with no warnings:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Testing

- All new functionality must include tests
- Tests must pass on the wasm32 target
- Run the full test suite before submitting:
  ```bash
  cargo test --workspace
  ```

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(wawk-core): add support for POSIX character classes
fix(wawk-bindgen): handle empty input without panic
docs: update architecture documentation
test(wawk-core): add regression test for nested arrays
chore: update dependencies
```

**Scopes:** `wawk-core`, `wawk-wasi`, `wawk-bindgen`

## What to Contribute

### Good First Issues

- AWK compatibility improvements (POSIX compliance)
- Additional test cases for edge cases
- Documentation improvements
- Performance optimizations with benchmarks

### Architecture Guidelines

- **wawk-core** must have zero OS dependencies — it compiles to any Wasm target
- **wawk-wasi** is a thin wrapper — keep it minimal
- **wawk-bindgen** bridges to JS — no business logic

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be dual-licensed under MIT and Apache 2.0, consistent with the project's existing license.
