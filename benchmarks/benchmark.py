#!/usr/bin/env python3
"""
Phase 6: Benchmark Suite v2 - Fixed for mawk compatibility
"""
import subprocess
import time
import os
import statistics

# Pin each measured subprocess to a single logical CPU to remove
# scheduler-migration noise on the shared host (both engines pinned identically).
def _pin_cpu():
    try:
        os.sched_setaffinity(0, {0})
    except (AttributeError, OSError):
        pass

WAWK_NATIVE = "/home/charo/wawk-rs/target/release/wawk"
WAWK_WASM = "/home/charo/wawk-rs/target/wasm32-wasip1/release/wawk.wasm"
WASMTIME = os.path.expanduser("~/.cargo/bin/wasmtime")

d = chr(36)

def gen_csv(rows):
    lines = []
    cities = ["Tokyo", "Berlin", "NYC", "London", "Sydney"]
    for i in range(rows):
        lines.append(f"user{i},{20 + (i % 50)},{cities[i % 5]},{i * 3 % 100}")
    return "\n".join(lines) + "\n"

def gen_numbers(rows):
    return "\n".join(str(i) for i in range(rows)) + "\n"

def gen_log(rows):
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    lines = []
    for i in range(rows):
        lines.append(f"2024-01-{(i%28)+1:02d} {levels[i%4]}: message number {i} from component_{i%10}")
    return "\n".join(lines) + "\n"

def run_one(cmd, input_data):
    start = time.perf_counter()
    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=30, preexec_fn=_pin_cpu)
    elapsed = (time.perf_counter() - start) * 1000
    return elapsed if result.returncode == 0 else None


def run_bench(cmd, input_data, warmup=5, runs=21):
    for _ in range(warmup):
        subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=30, preexec_fn=_pin_cpu)
    times = []
    for _ in range(runs):
        elapsed = run_one(cmd, input_data)
        if elapsed is not None:
            times.append(elapsed)
    if not times:
        return (None, None, None)
    return (statistics.median(times), min(times), max(times))


def run_bench_interleaved(cmds, input_data, warmup=5, runs=21):
    """Time multiple implementations round-robin so transient system load
    affects all of them equally; report the median of each."""
    for impl, cmd in cmds.items():
        for _ in range(warmup):
            subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=30, preexec_fn=_pin_cpu)
    samples = {impl: [] for impl in cmds}
    for _ in range(runs):
        for impl, cmd in cmds.items():
            elapsed = run_one(cmd, input_data)
            if elapsed is not None:
                samples[impl].append(elapsed)
    out = {}
    for impl, ts in samples.items():
        if ts:
            out[impl] = (statistics.median(ts), min(ts), max(ts))
        else:
            out[impl] = (None, None, None)
    return out

# Build command for each implementation
def make_cmd(impl, script):
    if impl == "wawk":
        return [WAWK_NATIVE, "-e", script]
    elif impl == "wawk-wasm":
        return [WASMTIME, WAWK_WASM, "-e", script]
    elif impl == "mawk":
        return ["mawk", script]  # mawk doesn't support -e
    elif impl == "gawk":
        return ["gawk", "-e", script]
    return None

# Test data
csv_small = gen_csv(1000)
csv_medium = gen_csv(10000)
csv_large = gen_csv(100000)
nums = gen_numbers(100000)
logs = gen_log(10000)

impls = ["wawk", "mawk", "gawk", "wawk-wasm"]

# Verify
for impl in impls:
    cmd = make_cmd(impl, "BEGIN{print 1}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, preexec_fn=_pin_cpu)
        status = "OK" if r.returncode == 0 else f"FAIL({r.stderr[:30]})"
    except Exception as e:
        status = f"ERROR({e})"
    print(f"  {impl}: {status}")

print()

benchmarks = [
    ("field_extract_small", "{ print " + d + "2 }", csv_small),
    ("field_extract_med", "{ print " + d + "2 }", csv_medium),
    ("field_extract_large", "{ print " + d + "2 }", csv_large),
    ("sum_numbers", "{ s += " + d + "1 } END { print s }", nums),
    ("pattern_filter", "/ERROR/ { print " + d + "0 }", logs),
    ("custom_fs", 'BEGIN{FS=","} { print ' + d + '1, ' + d + '3 }', csv_medium),
    ("string_funcs", '{ print length(' + d + '1), substr(' + d + '3, 1, 3) }', csv_medium),
    ("conditional", '{ if (' + d + '4 > 50) print "HIGH"; else print "LOW" }', csv_medium),
    ("array_count", 'BEGIN{FS=","} { a[' + d + '3]++ } END { for (k in a) print k, a[k] }', csv_medium),
    ("begin_end", 'BEGIN { x = 0 } { x++ } END { print x }', csv_small),
    ("gsub", '{ gsub(/o/, "0"); print }', logs),
    ("split_print", '{ n = split(' + d + '0, a, " "); print a[1], a[n] }', csv_medium),
]

results = {}

for bench_name, script, data in benchmarks:
    print(f"--- {bench_name} ({len(data):,} bytes) ---")
    cmds = {impl: make_cmd(impl, script) for impl in impls}
    med = run_bench_interleaved(cmds, data)
    for impl in impls:
        mean, mn, mx = med[impl]
        results[(bench_name, impl)] = (mean, mn, mx)
        if mean is not None:
            print(f"  {impl:12s}: {mean:8.2f}ms")
        else:
            print(f"  {impl:12s}: FAILED")
    print()

# Summary
print("=" * 75)
print("SUMMARY TABLE (median ms)")
print("=" * 75)
header = f"{'Benchmark':<22}" + "".join(f"{n:>12}" for n in impls)
print(header)
print("-" * len(header))

for bench_name, _, _ in benchmarks:
    row = f"{bench_name:<22}"
    for impl in impls:
        mean, _, _ = results.get((bench_name, impl), (None, None, None))
        if mean is not None:
            row += f"{mean:>12.2f}"
        else:
            row += f"{'FAILED':>12}"
    print(row)

# Ranking
print()
print("=" * 75)
print("RANKING (by average rank across all benchmarks)")
print("=" * 75)

rankings = {name: [] for name in impls}
for bench_name, _, _ in benchmarks:
    times = []
    for impl in impls:
        mean, _, _ = results.get((bench_name, impl), (None, None, None))
        if mean is not None:
            times.append((mean, impl))
    times.sort()
    for rank, (t, impl) in enumerate(times):
        rankings[impl].append(rank + 1)

avg_ranks = []
for impl in impls:
    if rankings[impl]:
        avg = statistics.mean(rankings[impl])
        wins = sum(1 for r in rankings[impl] if r == 1)
        avg_ranks.append((avg, impl, wins))

avg_ranks.sort()
for rank, (avg, impl, wins) in enumerate(avg_ranks):
    trophy = ["1st", "2nd", "3rd", "4th"][rank] if rank < 4 else f"{rank+1}th"
    print(f"  {trophy}: {impl:12s} (avg rank: {avg:.1f}, wins: {wins})")

# Speedup relative to gawk
print()
print("=" * 75)
print("WAWK vs GAWK (speedup factor, >1.0 means wawk is faster)")
print("=" * 75)
for bench_name, _, _ in benchmarks:
    wawk_mean = results.get((bench_name, "wawk"), (None,))[0]
    gawk_mean = results.get((bench_name, "gawk"), (None,))[0]
    mawk_mean = results.get((bench_name, "mawk"), (None,))[0]
    if wawk_mean and gawk_mean:
        ratio = gawk_mean / wawk_mean
        bar = "+" * int(ratio * 10) if ratio > 1 else "-" * int((1/ratio) * 10)
        print(f"  {bench_name:<22}: {ratio:.2f}x {bar}")
    if wawk_mean and mawk_mean:
        ratio_m = mawk_mean / wawk_mean
        print(f"  {'  vs mawk':<22}: {ratio_m:.2f}x")
