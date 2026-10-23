#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building wawk for Node.js..."

# Build with wasm-pack, output name = "wawk"
cd "$REPO_ROOT"
wasm-pack build crates/wawk-bindgen \
  --target nodejs \
  --out-dir "$SCRIPT_DIR/pkg-temp" \
  --out-name wawk \
  --release

# Copy JS glue and patch wasm reference: wawk_bg.wasm → wawk.wasm
sed 's/wawk_bg\.wasm/wawk.wasm/g' "$SCRIPT_DIR/pkg-temp/wawk.js" > "$SCRIPT_DIR/wawk.js"

# Rename wasm binary: wawk_bg.wasm → wawk.wasm
cp "$SCRIPT_DIR/pkg-temp/wawk_bg.wasm" "$SCRIPT_DIR/wawk.wasm"

# Copy TypeScript definitions
cp "$SCRIPT_DIR/pkg-temp/wawk.d.ts" "$SCRIPT_DIR/wawk.d.ts" 2>/dev/null || true

# Cleanup temp
rm -rf "$SCRIPT_DIR/pkg-temp"

echo "Done. Files in npm/:"
ls -lh "$SCRIPT_DIR"/wawk.{js,wasm,d.ts} 2>/dev/null
echo ""
echo "Test with: node npm/cli.js 'BEGIN { print \"hello from wawk\" }'"
