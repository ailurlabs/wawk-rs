# Changelog — wawk-rs

Pure AWK engine workspace: `wawk-core` (runtime + dispatcher codegen), `wawk-wasi` (wasip2 component CLI), `wawk-bindgen` (JS/browser bindings).

## 2026-11-05

### Website wasm upgrade

- **Context**: Upgrade the website integration to the latest wawk-bindgen / wawk-core, regenerate the website wasm, and verify the build is green.
- **Build**: `make bindgen-web` executed in wawk-rs workspace. Generated fresh wasm + JS bindings in `pkg-web/` (wasm-pack 0.15.0, wawk-bindgen 0.1.0, wawk-core 0.1.0).
- **Deployment**: Copied `wawk_bindgen.{js,d.ts}` and `wawk_bindgen_bg.wasm{,.d.ts}` into the website's `wawk/` asset directory, renamed to the `wawk.*` convention, and updated `package.json`.
- **Verification**: HTML files (extension.html, playground.html, specification.html) import from `./wawk/wawk.js` — no path changes needed, imports remain valid.
- **Evidence**: New wasm size 1.1MB (was 1.2MB), JS bindings 13K, TypeScript definitions 3.2K. Build completed in 40.79s with no warnings (except wasm-pack version notice).
- **Impact**: Website now runs on latest wawk-bindgen/wawk-core. No breaking changes to public API (exec_awk function signature unchanged).

## 2026-11-03

### Fixed: dispatcher codegen interface duplication

- **Discovery path**: While regenerating a downstream product dispatcher with the current `wawk-codegen`, the generator produced a `dispatcher/wit/deps/extensions/world.wit` containing the same `interface extension-functions` four times (WIT parse error: `duplicate item`), so the product pipeline `build.sh` Step 1 → Step 2 was broken end-to-end for every product whose manifest shares one interface name across extensions (all three current products).
- **Semantic (documented in code)**: every interface body the generator emits is a hardcoded template keyed only by the interface NAME; manifest inputs (name + format flag) cannot express divergent function sets for one name. Dedup by name is therefore byte-exact, not lossy.
- **Fix**: name-keyed deduplication (HashSet) applied consistently in `generate_extensions_deps_wit`, `generate_dispatcher_wit` imports, and the `with:` map of `generate_lib_rs`. Three regression tests added (`dispatcher::tests::test_dedup_*`), including a byte-identity proof that deduped output equals single-extension output.
- **Impact surface**: build-time generator only. No engine evaluation semantics, no dispatch runtime behavior, no WIT contract of the engine itself changed.
- **2026-11-04**: `.cargo/config.toml` header comment terminology aligned to "extension repos" rather than "plugin repos". Comment-only; no effect on engine behaviour.

### Build surfaces

- Added `.cargo/config.toml` with default target `wasm32-wasip2`: the `wawk-wasi` host cdylib could never link on x86_64 (wit-bindgen 0.42 export names such as `wasi:cli/run@0.2.6#run` break the ELF version script). `make build` green; `make test` pins `--target x86_64-unknown-linux-gnu` (336 passed); `make wasi` unchanged. README documents supported surfaces and host-pinned codegen invocation.
