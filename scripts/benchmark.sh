#!/bin/bash
# Benchmark: wawk-rs vs gawk vs mawk vs nawk
# Tests the most common AWK workloads on 1M lines of input

set -e

WAWK_BIN="wasmtime run target/wasm32-wasip1/release/wawk_wasi.wasm"
DATA="/tmp/bench_data.txt"

BOLD='\033[1m'
NC='\033[0m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'

echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWK Implementation Benchmark: wawk vs gawk vs mawk vs nawk${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo " Input: $(wc -l < $DATA) lines, $(ls -lh $DATA | awk '{print $5}')"
echo " System: $(uname -m), $(nproc) cores"
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Helper: run wawk (script + data via stdin protocol)
run_wawk() {
    local script="$1"
    local data_file="$2"
    { echo "$script"; cat "$data_file"; } | $WAWK_BIN > /dev/null
}

# Helper: run gawk/mawk/nawk (script -f or inline, data from file)
run_awk() {
    local cmd="$1"
    local script="$2"
    local data_file="$3"
    $cmd "$script" "$data_file" > /dev/null
}

# Helper: time a command, output milliseconds
time_ms() {
    local start end elapsed
    start=$(date +%s%N)
    "$@" > /dev/null 2>&1
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
}

RESULTS_FILE="/tmp/bench_results.txt"
> "$RESULTS_FILE"

run_test() {
    local name="$1"
    local script="$2"
    
    printf "  %-35s" "$name"
    
    local wawk_ms gawk_ms mawk_ms nawk_ms
    
    # wawk (3 runs, take best)
    local best=999999
    for i in 1 2 3; do
        local t=$(time_ms run_wawk "$script" "$DATA")
        [ "$t" -lt "$best" ] && best=$t
    done
    wawk_ms=$best
    
    # gawk
    best=999999
    for i in 1 2 3; do
        local t=$(time_ms run_awk "gawk" "$script" "$DATA")
        [ "$t" -lt "$best" ] && best=$t
    done
    gawk_ms=$best
    
    # mawk
    best=999999
    for i in 1 2 3; do
        local t=$(time_ms run_awk "mawk" "$script" "$DATA")
        [ "$t" -lt "$best" ] && best=$t
    done
    mawk_ms=$best
    
    # nawk
    best=999999
    for i in 1 2 3; do
        local t=$(time_ms run_awk "nawk" "$script" "$DATA")
        [ "$t" -lt "$best" ] && best=$t
    done
    nawk_ms=$best
    
    # Find fastest
    local fastest=$wawk_ms
    [ "$gawk_ms" -lt "$fastest" ] && fastest=$gawk_ms
    [ "$mawk_ms" -lt "$fastest" ] && fastest=$mawk_ms
    [ "$nawk_ms" -lt "$fastest" ] && fastest=$nawk_ms
    
    # Color: green if within 1.5x of fastest, yellow if within 3x, red otherwise
    local wawk_ratio=$(echo "scale=1; $wawk_ms / $fastest" | bc 2>/dev/null || echo "N/A")
    
    printf "${CYAN}wawk: %6d ms${NC}  gawk: %6d ms  mawk: %6d ms  nawk: %6d ms  (ratio: %sx)\n" \
        "$wawk_ms" "$gawk_ms" "$mawk_ms" "$nawk_ms" "$wawk_ratio"
    
    echo "$name | wawk=$wawk_ms | gawk=$gawk_ms | mawk=$mawk_ms | nawk=$nawk_ms" >> "$RESULTS_FILE"
}

echo "Test 1: I/O throughput (print all lines)"
run_test "print" '{ print }'

echo ""
echo "Test 2: Field splitting + arithmetic (whitespace FS)"
run_test "sum column" '{ s += $2 } END { print s }'

echo ""
echo "Test 3: Regex pattern match"
run_test "regex match" '/[0-9]+00 / { print $1 }' > /dev/null

echo ""
echo "Test 4: String concatenation"
run_test "string concat" '{ s = $1 ":" $2 ":" $3 } END { print s }'

echo ""
echo "Test 5: Conditional + arithmetic"
run_test "conditional" '{ if ($2 > 500) print $1, $2 * 2 }'

echo ""
echo "Test 6: Associative array"
run_test "assoc array" '{ a[$4]++ } END { for (k in a) print k, a[k] }' > /dev/null

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Summary (ratio = wawk_ms / fastest_awk_ms, lower is better)${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════════════${NC}"
while IFS='|' read -r name wawk gawk mawk nawk; do
    # Extract ms values
    w_ms=$(echo "$wawk" | grep -oP '\d+')
    g_ms=$(echo "$gawk" | grep -oP '\d+')
    m_ms=$(echo "$mawk" | grep -oP '\d+')
    n_ms=$(echo "$nawk" | grep -oP '\d+')
    
    # Find minimum
    fastest=$w_ms
    [ "$g_ms" -lt "$fastest" ] 2>/dev/null && fastest=$g_ms
    [ "$m_ms" -lt "$fastest" ] 2>/dev/null && fastest=$m_ms
    [ "$n_ms" -lt "$fastest" ] 2>/dev/null && fastest=$n_ms
    
    ratio=$(echo "scale=2; $w_ms / $fastest" | bc 2>/dev/null || echo "N/A")
    printf "  %-25s  wawk=%6d  ratio=%sx\n" "$name" "$w_ms" "$ratio"
done < "$RESULTS_FILE"

echo ""
echo "Done. Full results in $RESULTS_FILE"
