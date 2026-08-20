# wawk-core Benchmarks

Formal benchmark suite for the wawk-core AWK engine, powered by [Criterion.rs](https://github.com/bheisler/criterion.rs).

## Running benchmarks

Run all benchmarks:

```bash
cargo bench -p wawk-core
```

Run a specific benchmark by name:

```bash
cargo bench -p wawk-core -- print_all
cargo bench -p wawk-core -- sum_column
cargo bench -p wawk-core -- regex_match
cargo bench -p wawk-core -- string_concat
cargo bench -p wawk-core -- conditional
cargo bench -p wawk-core -- associative_array
cargo bench -p wawk-core -- lexer_bench
cargo bench -p wawk-core -- parser_bench
cargo bench -p wawk-core -- plugin_dispatch
```

Run a benchmark group:

```bash
cargo bench -p wawk-core -- awk/        # all AWK workload benchmarks
cargo bench -p wawk-core -- parser/     # lexer and parser benchmarks
cargo bench -p wawk-core -- plugin/     # plugin dispatch benchmarks
```

## Benchmark descriptions

### AWK workloads (100K lines of input each)

| Benchmark | Script | What it measures |
|---|---|---|
| `print_all` | `{ print $0 }` | I/O throughput baseline (field splitting + print) |
| `sum_column` | `{ sum += $1 } END { print sum }` | Numeric computation and field parsing |
| `regex_match` | `/foo/ { count++ } END { print count }` | Regex pattern matching throughput |
| `string_concat` | `{ s = $0 " " $0; print length(s) }` | String allocation and concatenation |
| `conditional` | `{ if ($1 > 50) print "high"; else print "low" }` | Branch-heavy control flow |
| `associative_array` | `{ count[$1]++ } END { for (k in count) print k, count[k] }` | Hash table insert and iteration |

### Parser benchmarks

| Benchmark | Description |
|---|---|
| `lexer_bench` | Tokenize a complex AWK script (50 repetitions) - measures lexer throughput in bytes/second |
| `parser_bench` | Parse a complex AWK script (50 repetitions) - measures full parse pipeline throughput |

### Plugin benchmarks

| Benchmark | Description |
|---|---|
| `plugin_dispatch` | Measures overhead of external function dispatch using a mock handler that returns immediately |

## Output

Criterion generates HTML reports with statistical analysis after each run.
Reports are located at:

```
target/criterion/report/index.html
```

Individual benchmark results are stored under `target/criterion/<group>/<bench>/`.

## Methodology

- **Test data**: 100,000 lines generated deterministically (no randomness). Each line contains 5 fields: index, hash, keyword, float, and label.
- **Throughput**: Reported as elements/second (lines processed) or bytes/second (for parser benchmarks).
- **Latency**: Criterion reports mean, median, min, max, and confidence intervals.
- **Warmup**: Criterion handles warmup iterations automatically.
- **Setup/teardown**: `iter_batched` separates data generation (setup) from the measured operation.
