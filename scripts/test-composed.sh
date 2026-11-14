#!/usr/bin/env bash
# test-composed.sh — Post-wac-plug validation and testing
#
# Runs comprehensive tests on composed WASM output:
# 1. Structure validation (wasm-tools)
# 2. Smoke tests (basic execution)
# 3. Integration tests (sample workloads)
# 4. Performance benchmarks (optional)
#
# Usage:
#   ./scripts/test-composed.sh <composed.wasm> [test-suite]
#
# Example:
#   ./scripts/test-composed.sh ./wac-output/product-composed.wasm full

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[TEST]${NC} $*"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; }

# Parse arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <composed.wasm> [test-suite]"
    echo "  test-suite: smoke | basic | full (default: basic)"
    exit 1
fi

COMPOSED_WASM="$1"
TEST_SUITE="${2:-basic}"

if [ ! -f "$COMPOSED_WASM" ]; then
    log_fail "Composed WASM not found: $COMPOSED_WASM"
    exit 1
fi

log_info "Testing composed WASM: $COMPOSED_WASM"
log_info "Test suite: $TEST_SUITE"
echo ""

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    log_info "Running: $test_name"
    
    if eval "$test_cmd"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_pass "$test_name"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_fail "$test_name"
        return 1
    fi
}

skip_test() {
    local test_name="$1"
    local reason="$2"
    
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    log_skip "$test_name: $reason"
}

# ============================================================================
# Test Suite: Structure Validation
# ============================================================================

test_structure() {
    log_info "=== Structure Validation ==="
    
    # Test 1: File exists and is non-empty
    run_test "File exists and non-empty" "[ -s '$COMPOSED_WASM' ]"
    
    # Test 2: Valid WASM magic bytes
    run_test "WASM magic bytes" "head -c 4 '$COMPOSED_WASM' | od -An -tx1 | grep -q '00 61 73 6d'"
    
    # Test 3: wasm-tools validation (if available)
    if command -v wasm-tools &> /dev/null; then
        run_test "wasm-tools validate" "wasm-tools validate '$COMPOSED_WASM'"
    else
        skip_test "wasm-tools validate" "wasm-tools not installed"
    fi
    
    # Test 4: Check file size (sanity)
    local size=$(stat -c%s "$COMPOSED_WASM" 2>/dev/null || stat -f%z "$COMPOSED_WASM")
    local size_mb=$((size / 1024 / 1024))
    run_test "File size reasonable (< 100 MB)" "[ $size_mb -lt 100 ]"
    
    echo ""
}

# ============================================================================
# Test Suite: Smoke Tests
# ============================================================================

test_smoke() {
    log_info "=== Smoke Tests ==="
    
    if ! command -v wasmtime &> /dev/null; then
        skip_test "All smoke tests" "wasmtime not installed"
        echo ""
        return
    fi
    
    # Test 1: --help flag
    run_test "wasmtime --help" "wasmtime run '$COMPOSED_WASM' -- --help 2>&1 | grep -qi 'wawk\|usage\|help'"
    
    # Test 2: --version flag
    run_test "wasmtime --version" "wasmtime run '$COMPOSED_WASM' -- --version 2>&1 | grep -q '[0-9]\\.'"
    
    # Test 3: Empty input (should not crash)
    run_test "Empty input" "echo '' | timeout 5 wasmtime run '$COMPOSED_WASM' 2>&1"
    
    # Test 4: Simple AWK program
    run_test "Simple AWK execution" "echo 'hello' | timeout 5 wasmtime run '$COMPOSED_WASM' '{ print \$0 }' 2>&1 | grep -q 'hello'"
    
    echo ""
}

# ============================================================================
# Test Suite: Basic Integration Tests
# ============================================================================

test_basic_integration() {
    log_info "=== Basic Integration Tests ==="
    
    if ! command -v wasmtime &> /dev/null; then
        skip_test "All integration tests" "wasmtime not installed"
        echo ""
        return
    fi
    
    # Create temp directory for test files
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # Test 1: Field splitting
    echo "alice 25 berlin" > "$temp_dir/input1.txt"
    run_test "Field splitting" \
        "wasmtime run '$COMPOSED_WASM' '{ print \$1, \$3 }' < '$temp_dir/input1.txt' 2>&1 | grep -q 'alice berlin'"
    
    # Test 2: BEGIN/END blocks
    run_test "BEGIN/END blocks" \
        "echo '' | wasmtime run '$COMPOSED_WASM' 'BEGIN { print \"start\" } END { print \"end\" }' 2>&1 | grep -q 'start.*end'"
    
    # Test 3: Pattern matching
    echo -e "apple\nbanana\napricot" > "$temp_dir/input2.txt"
    run_test "Pattern matching" \
        "wasmtime run '$COMPOSED_WASM' '/^a/ { print \$0 }' < '$temp_dir/input2.txt' 2>&1 | grep -q 'apple'"
    
    # Test 4: Built-in functions
    run_test "Built-in functions (length)" \
        "echo 'hello' | wasmtime run '$COMPOSED_WASM' '{ print length(\$0) }' 2>&1 | grep -q '5'"
    
    # Test 5: Associative arrays
    run_test "Associative arrays" \
        "echo -e 'a\\nb\\na' | wasmtime run '$COMPOSED_WASM' '{ count[\$0]++ } END { for (k in count) print k, count[k] }' 2>&1 | grep -q 'a 2'"
    
    echo ""
}

# ============================================================================
# Test Suite: Extension Integration (if extensions available)
# ============================================================================

test_extensions() {
    log_info "=== Extension Integration Tests ==="
    
    if ! command -v wasmtime &> /dev/null; then
        skip_test "Extension tests" "wasmtime not installed"
        echo ""
        return
    fi
    
    # These tests assume extensions are composed into the WASM
    # They will fail gracefully if extensions are not present
    
    # Test 1: Check if extension namespace is callable
    # This is product-specific and would need customization
    log_info "Extension tests are product-specific"
    log_info "Customize this section for your extension namespace"
    
    # Example (uncomment and modify for your product):
    # run_test "Extension namespace callable" \
    #     "echo '' | wasmtime run '$COMPOSED_WASM' 'BEGIN { print extension.function() }' 2>&1"
    
    echo ""
}

# ============================================================================
# Test Suite: Performance Benchmarks (optional)
# ============================================================================

test_performance() {
    log_info "=== Performance Benchmarks ==="
    
    if ! command -v wasmtime &> /dev/null; then
        skip_test "Performance tests" "wasmtime not installed"
        echo ""
        return
    fi
    
    # Create large test file (10,000 lines)
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    log_info "Generating test data (10,000 lines)..."
    for i in {1..10000}; do
        echo "line $i field1 field2 field3"
    done > "$temp_dir/large.txt"
    
    # Benchmark 1: Simple pass-through
    log_info "Benchmark: Simple pass-through"
    local start_time=$(date +%s.%N)
    wasmtime run "$COMPOSED_WASM" '{ print $0 }' < "$temp_dir/large.txt" > /dev/null 2>&1
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)
    log_info "  Duration: ${duration}s"
    
    # Benchmark 2: Field extraction
    log_info "Benchmark: Field extraction"
    start_time=$(date +%s.%N)
    wasmtime run "$COMPOSED_WASM" '{ print $1, $3 }' < "$temp_dir/large.txt" > /dev/null 2>&1
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    log_info "  Duration: ${duration}s"
    
    # Benchmark 3: Pattern matching
    log_info "Benchmark: Pattern matching"
    start_time=$(date +%s.%N)
    wasmtime run "$COMPOSED_WASM" '/line 5/ { print $0 }' < "$temp_dir/large.txt" > /dev/null 2>&1
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    log_info "  Duration: ${duration}s"
    
    echo ""
}

# ============================================================================
# Main Test Runner
# ============================================================================

# Always run structure validation
test_structure

# Run tests based on suite
case "$TEST_SUITE" in
    smoke)
        test_smoke
        ;;
    basic)
        test_smoke
        test_basic_integration
        ;;
    full)
        test_smoke
        test_basic_integration
        test_extensions
        test_performance
        ;;
    *)
        log_fail "Unknown test suite: $TEST_SUITE"
        echo "Valid suites: smoke | basic | full"
        exit 1
        ;;
esac

# ============================================================================
# Test Summary
# ============================================================================

echo ""
log_info "========================================="
log_info "Test Summary"
log_info "========================================="
log_info "Total tests:  $TESTS_RUN"
log_pass "Passed:       $TESTS_PASSED"
[ $TESTS_FAILED -gt 0 ] && log_fail "Failed:       $TESTS_FAILED"
[ $TESTS_SKIPPED -gt 0 ] && log_skip "Skipped:      $TESTS_SKIPPED"
log_info ""

if [ $TESTS_FAILED -gt 0 ]; then
    log_fail "Some tests failed"
    exit 1
else
    log_pass "All tests passed"
    exit 0
fi
