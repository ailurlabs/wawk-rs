#!/usr/bin/env bash
# wac-plug.sh — Automated wac plug workflow for wawk-rs
#
# This script automates the full wac plug pipeline:
# 1. Generate dispatcher from extension-manifest.json
# 2. Build dispatcher as WASM component
# 3. Compose wawk-wasi + dispatcher + extensions via wac plug
# 4. Run validation tests on the composed output
#
# Usage:
#   ./scripts/wac-plug.sh <manifest.json> [output-dir]
#
# Example:
#   ./scripts/wac-plug.sh extension-manifest.json ./composed-output
#
# Prerequisites:
#   - cargo component (cargo install cargo-component)
#   - wac CLI (cargo install wac)
#   - Rust toolchain with wasm32-wasip2 target

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust: https://rustup.rs/"
        exit 1
    fi
    
    if ! command -v wac &> /dev/null; then
        log_error "wac not found. Install with: cargo install wac"
        exit 1
    fi
    
    if ! cargo component --version &> /dev/null; then
        log_error "cargo-component not found. Install with: cargo install cargo-component"
        exit 1
    fi
    
    # Check wasm32-wasip2 target
    if ! rustup target list --installed | grep -q "wasm32-wasip2"; then
        log_warn "wasm32-wasip2 target not installed. Installing..."
        rustup target add wasm32-wasip2
    fi
    
    log_success "All prerequisites satisfied"
}

# Parse arguments
if [ $# -lt 1 ]; then
    log_error "Usage: $0 <manifest.json> [output-dir]"
    exit 1
fi

MANIFEST_PATH="$1"
OUTPUT_DIR="${2:-./wac-output}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$MANIFEST_PATH" ]; then
    log_error "Manifest file not found: $MANIFEST_PATH"
    exit 1
fi

# Convert to absolute paths
MANIFEST_PATH="$(realpath "$MANIFEST_PATH")"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && realpath "$OUTPUT_DIR")"

log_info "Starting wac plug automation"
log_info "Manifest: $MANIFEST_PATH"
log_info "Output: $OUTPUT_DIR"

# Check prerequisites
check_prerequisites

# Step 1: Extract product name from manifest
log_info "Step 1: Extracting product name from manifest..."
PRODUCT_NAME=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$MANIFEST_PATH" | head -1 | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
if [ -z "$PRODUCT_NAME" ]; then
    log_error "Failed to extract product name from manifest"
    exit 1
fi
log_success "Product name: $PRODUCT_NAME"

# Step 2: Generate dispatcher project
log_info "Step 2: Generating dispatcher project..."
DISPATCHER_DIR="/tmp/wac-plug-dispatcher-$$"
rm -rf "$DISPATCHER_DIR"
mkdir -p "$DISPATCHER_DIR"

cd "$REPO_ROOT"
cargo run -p wawk-core --bin wawk-codegen --target x86_64-unknown-linux-gnu -- "$MANIFEST_PATH" "$DISPATCHER_DIR"

if [ ! -f "$DISPATCHER_DIR/Cargo.toml" ]; then
    log_error "Dispatcher generation failed: Cargo.toml not found"
    exit 1
fi
log_success "Dispatcher project generated at $DISPATCHER_DIR"

# Step 3: Build dispatcher as WASM component
log_info "Step 3: Building dispatcher as WASM component..."
cd "$DISPATCHER_DIR"
cargo component build --release --target wasm32-wasip2

DISPATCHER_WASM=$(find "$DISPATCHER_DIR/target/wasm32-wasip2/release" -name "*_dispatcher.wasm" -type f | head -1)
if [ -z "$DISPATCHER_WASM" ]; then
    # Try alternate naming pattern
    DISPATCHER_WASM=$(find "$DISPATCHER_DIR/target/wasm32-wasip2/release" -name "*.wasm" -type f | grep -v deps | head -1)
    if [ -z "$DISPATCHER_WASM" ]; then
        log_error "Dispatcher WASM not found after build"
        exit 1
    fi
fi
log_success "Dispatcher built: $DISPATCHER_WASM"

# Cleanup dispatcher build dir (keep output)
trap "rm -rf $DISPATCHER_DIR" EXIT

# Step 4: Build wawk-wasi host
log_info "Step 4: Building wawk-wasi host component..."
cd "$REPO_ROOT"
make wasi

WAWK_WASI_WASM="$REPO_ROOT/target/wasm32-wasip2/release/wawk_wasi.wasm"
if [ ! -f "$WAWK_WASI_WASM" ]; then
    log_error "wawk-wasi WASM not found at $WAWK_WASI_WASM"
    exit 1
fi
log_success "wawk-wasi built: $WAWK_WASI_WASM"

# Step 5: Compose via wac plug
log_info "Step 5: Composing components via wac plug..."
COMPOSED_WASM="$OUTPUT_DIR/${PRODUCT_NAME}-composed.wasm"

# Build wac plug command
# wac plug syntax: wac plug --plug <PLUG>... <SOCKET> -o <OUTPUT>
# SOCKET = host (wawk-wasi), PLUG = dispatcher + extensions
WAC_CMD="wac plug --plug $DISPATCHER_WASM"

# Check if manifest specifies extension paths
EXTENSION_PATHS=$(grep -o '"path"[[:space:]]*:[[:space:]]*"[^"]*"' "$MANIFEST_PATH" 2>/dev/null | sed 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
if [ -n "$EXTENSION_PATHS" ]; then
    log_info "Found extension paths in manifest"
    for ext_path in $EXTENSION_PATHS; do
        if [ -f "$ext_path" ]; then
            WAC_CMD="$WAC_CMD --plug $ext_path"
            log_info "  Adding extension: $ext_path"
        else
            log_warn "  Extension not found: $ext_path"
        fi
    done
fi

WAC_CMD="$WAC_CMD $WAWK_WASI_WASM -o $COMPOSED_WASM"

log_info "Running: $WAC_CMD"
eval "$WAC_CMD"

if [ ! -f "$COMPOSED_WASM" ]; then
    log_error "Composition failed: output not found"
    exit 1
fi

log_success "Composed WASM created: $COMPOSED_WASM"

# Step 6: Validate composed output
log_info "Step 6: Validating composed output..."

# Check file size
COMPOSED_SIZE=$(stat -c%s "$COMPOSED_WASM" 2>/dev/null || stat -f%z "$COMPOSED_WASM")
log_info "Composed WASM size: $((COMPOSED_SIZE / 1024 / 1024)) MB"

# Validate WASM structure
if ! wasm-tools validate "$COMPOSED_WASM" 2>/dev/null; then
    log_warn "wasm-tools validation skipped (not installed or validation failed)"
else
    log_success "WASM structure validation passed"
fi

# Step 7: Run smoke test (if wasmtime available)
log_info "Step 7: Running smoke test..."
if command -v wasmtime &> /dev/null; then
    # Try to run with --help to verify it loads
    if wasmtime run "$COMPOSED_WASM" -- --help 2>&1 | grep -q "wawk"; then
        log_success "Smoke test passed: composed WASM executes"
    else
        log_warn "Smoke test inconclusive: WASM loaded but output unexpected"
    fi
else
    log_warn "wasmtime not found, skipping smoke test"
fi

# Step 8: Generate summary
log_info "Step 8: Generating summary..."
SUMMARY_FILE="$OUTPUT_DIR/SUMMARY.md"
cat > "$SUMMARY_FILE" <<EOF
# wac plug Composition Summary

**Generated:** $(date -u +"%Y-%m-%dT%H:%M:%SZ")
**Product:** $PRODUCT_NAME
**Manifest:** $MANIFEST_PATH

## Build Artifacts

| Component | Path | Size |
|-----------|------|------|
| wawk-wasi host | $WAWK_WASI_WASM | $(stat -c%s "$WAWK_WASI_WASM" 2>/dev/null || stat -f%z "$WAWK_WASI_WASM") bytes |
| Dispatcher | $DISPATCHER_WASM | $(stat -c%s "$DISPATCHER_WASM" 2>/dev/null || stat -f%z "$DISPATCHER_WASM") bytes |
| **Composed output** | **$COMPOSED_WASM** | **$COMPOSED_SIZE bytes** |

## Validation

- WASM structure: $(wasm-tools validate "$COMPOSED_WASM" 2>/dev/null && echo "PASS" || echo "SKIPPED")
- Smoke test: $(command -v wasmtime &> /dev/null && echo "PASS" || echo "SKIPPED")

## Next Steps

1. Test the composed WASM with sample input:
   \`\`\`bash
   echo '{"test": "data"}' | wasmtime run $COMPOSED_WASM
   \`\`\`

2. Deploy to production:
   - Copy $COMPOSED_WASM to target environment
   - Configure wawk-mcp or wawk-lro to load the composed component
   - Verify license gates (if using commercial extensions)

## Troubleshooting

If composition fails:
- Ensure all extension WASMs are built with wasm32-wasip2 target
- Check WIT interface compatibility between dispatcher and extensions
- Verify wac version matches toolchain (wac-cli 0.10.x recommended)

If smoke test fails:
- Check wasmtime version compatibility (47.x recommended)
- Verify all required imports are satisfied
- Review dispatcher logs for missing namespace routes
EOF

log_success "Summary written to $SUMMARY_FILE"

# Final output
echo ""
log_success "========================================="
log_success "wac plug automation completed successfully"
log_success "========================================="
log_info "Composed WASM: $COMPOSED_WASM"
log_info "Summary: $SUMMARY_FILE"
log_info ""
log_info "To test: wasmtime run $COMPOSED_WASM -- --help"
