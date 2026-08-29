//! Formal benchmark suite for wawk-core using Criterion.
//!
//! Measures throughput and latency across the core AWK workloads:
//!   - I/O-bound (print_all)
//!   - Numeric computation (sum_column)
//!   - Pattern matching (regex_match)
//!   - String operations (string_concat)
//!   - Branch-heavy control flow (conditional)
//!   - Hash table operations (associative_array)
//!   - Lexer throughput (lexer_bench)
//!   - Parser throughput (parser_bench)
//!   - External function dispatch overhead (plugin_dispatch)
//!
//! Run with:
//!   cargo bench -p wawk-core
//!   cargo bench -p wawk-core -- benchmark_name

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use wawk_core::error::AwkResult;
use wawk_core::lexer::Lexer;
use wawk_core::parser::parse;
use wawk_core::traits::{
    FunctionDispatcher, PluginCapability, MemReader, MemWriter, StubCommandExecutor, StubEnvironment,
};
use wawk_core::WawkEngine;

// ---------------------------------------------------------------------------
// Deterministic test-data generation
// ---------------------------------------------------------------------------

/// Number of input lines for each data-driven benchmark.
const NUM_LINES: usize = 100_000;

/// Generate deterministic test input: NUM_LINES lines, each with several fields.
/// Format per line: "<index> <hash> foo|bar|baz <float> <label>"
/// This exercises field splitting, numeric parsing, and regex matching.
fn generate_test_data() -> String {
    let mut data = String::with_capacity(NUM_LINES * 40);
    for i in 0..NUM_LINES {
        let label = match i % 4 {
            0 => "alpha",
            1 => "bravo",
            2 => "charlie",
            _ => "delta",
        };
        let keyword = match i % 3 {
            0 => "foo",
            1 => "bar",
            _ => "baz",
        };
        let hash = (i.wrapping_mul(2654435761)) % 10000;
        let float_val = (i as f64) * 0.123;
        data.push_str(&format!(
            "{} {} {} {:.3} {}\n",
            i, hash, keyword, float_val, label
        ));
    }
    data
}

/// Generate a complex AWK script for lexer/parser benchmarks.
fn complex_script() -> &'static str {
    r###"
function abs(x) { return x < 0 ? -x : x }
function max(a, b) { return a > b ? a : b }
function min(a, b) { return a < b ? a : b }

BEGIN {
    FS = ","
    total = 0
    count = 0
}

/^[0-9]/ {
    if ($1 > 50) {
        category = "high"
    } else if ($1 > 25) {
        category = "medium"
    } else {
        category = "low"
    }
    buckets[category]++
    total += $2
    count++
    running_avg = total * 1
}

$3 ~ /error|warning|critical/ {
    errors[$3]++
    print NR, $0, ">>", category, running_avg
}

END {
    for (k in buckets) {
        print "bucket", k, buckets[k]
    }
    for (k in errors) {
        print "error", k, errors[k]
    }
    print "total", total, "count", count, "avg", running_avg
}
"###
}

// ---------------------------------------------------------------------------
// Helper: run an AWK script against pre-generated input
// ---------------------------------------------------------------------------

fn run_awk_script(script: &str, input: &str) {
    let engine = WawkEngine::new();
    let mut reader = MemReader::new(input);
    let mut writer = MemWriter::new();
    let env = StubEnvironment::default();
    let mut cmd = StubCommandExecutor;
    engine
        .execute(black_box(script), &mut reader, &mut writer, &env, &mut cmd)
        .expect("benchmark script should not fail");
}

// ---------------------------------------------------------------------------
// AWK script workloads
// ---------------------------------------------------------------------------

const SCRIPT_PRINT_ALL: &str = "{ print $0 }";
const SCRIPT_SUM_COLUMN: &str = "{ sum += $1 } END { print sum }";
const SCRIPT_REGEX_MATCH: &str = "/foo/ { count++ } END { print count }";
const SCRIPT_STRING_CONCAT: &str = r##"{ s = $0 " " $0; print length(s) }"##;
const SCRIPT_CONDITIONAL: &str = r##"{ if ($1 > 50) print "high"; else print "low" }"##;
const SCRIPT_ASSOCIATIVE_ARRAY: &str = "{ count[$1]++ } END { for (k in count) print k, count[k] }";

// ---------------------------------------------------------------------------
// Data-driven benchmarks (throughput: lines/second)
// ---------------------------------------------------------------------------

fn bench_print_all(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("print_all", |b| {
        b.iter(|| run_awk_script(SCRIPT_PRINT_ALL, black_box(&data)))
    });
    group.finish();
}

fn bench_sum_column(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("sum_column", |b| {
        b.iter(|| run_awk_script(SCRIPT_SUM_COLUMN, black_box(&data)))
    });
    group.finish();
}

fn bench_regex_match(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("regex_match", |b| {
        b.iter(|| run_awk_script(SCRIPT_REGEX_MATCH, black_box(&data)))
    });
    group.finish();
}

fn bench_string_concat(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("string_concat", |b| {
        b.iter(|| run_awk_script(SCRIPT_STRING_CONCAT, black_box(&data)))
    });
    group.finish();
}

fn bench_conditional(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("conditional", |b| {
        b.iter(|| run_awk_script(SCRIPT_CONDITIONAL, black_box(&data)))
    });
    group.finish();
}

fn bench_associative_array(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("awk");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("associative_array", |b| {
        b.iter(|| run_awk_script(SCRIPT_ASSOCIATIVE_ARRAY, black_box(&data)))
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Lexer benchmark
// ---------------------------------------------------------------------------

fn bench_lexer(c: &mut Criterion) {
    let script = complex_script();
    // Repeat the script to amplify lexer cost
    let large_script = script.repeat(50);

    let mut group = c.benchmark_group("parser");
    group.throughput(Throughput::Bytes(large_script.len() as u64));

    group.bench_function("lexer_bench", |b| {
        b.iter(|| {
            let tokens = Lexer::tokenize(black_box(&large_script))
                .expect("lexer should not fail on valid script");
            black_box(tokens)
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Parser benchmark
// ---------------------------------------------------------------------------

fn bench_parser(c: &mut Criterion) {
    let script = complex_script();
    let large_script = script.repeat(50);

    let mut group = c.benchmark_group("parser");
    group.throughput(Throughput::Bytes(large_script.len() as u64));

    group.bench_function("parser_bench", |b| {
        b.iter(|| {
            let program =
                parse(black_box(&large_script)).expect("parser should not fail on valid script");
            black_box(program)
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Plugin dispatch benchmark
// ---------------------------------------------------------------------------

/// A mock external function handler that returns immediately.
/// Used to measure the overhead of dispatching through the external function interface.
struct MockExternalHandler;

impl PluginCapability for MockExternalHandler {
    fn capability_name(&self) -> &'static str { "function_dispatch" }
}

impl FunctionDispatcher for MockExternalHandler {
    fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
        let _ = (name, args);
        // Return immediately with a fixed value to measure dispatch overhead
        Ok(Some("42".to_string()))
    }
}

/// AWK script that calls an external function on every line.
/// The function is not defined in AWK, so it falls through to the external handler.
const SCRIPT_PLUGIN_DISPATCH: &str = "{ print plugin_fn($1, $2) }";

fn bench_plugin_dispatch(c: &mut Criterion) {
    let data = generate_test_data();
    let mut group = c.benchmark_group("plugin");
    group.throughput(Throughput::Elements(NUM_LINES as u64));

    group.bench_function("plugin_dispatch", |b| {
        b.iter_batched(
            || {
                // Setup: create fresh engine, reader, writer per iteration batch
                let engine = WawkEngine::new();
                let reader = MemReader::new(&data);
                let writer = MemWriter::new();
                let env = StubEnvironment::default();
                let cmd = StubCommandExecutor;
                (engine, reader, writer, env, cmd)
            },
            |(engine, mut reader, mut writer, env, mut cmd)| {
                let handler = Box::new(MockExternalHandler);
                engine
                    .execute_with_handler(
                        black_box(SCRIPT_PLUGIN_DISPATCH),
                        &mut reader,
                        &mut writer,
                        &env,
                        &mut cmd,
                        handler,
                    )
                    .expect("plugin dispatch benchmark should not fail");
                black_box(writer)
            },
            criterion::BatchSize::LargeInput,
        )
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion group registration
// ---------------------------------------------------------------------------

criterion_group! {
    name = awk_workloads;
    config = Criterion::default();
    targets =
        bench_print_all,
        bench_sum_column,
        bench_regex_match,
        bench_string_concat,
        bench_conditional,
        bench_associative_array,
}

criterion_group! {
    name = parser_workloads;
    config = Criterion::default();
    targets =
        bench_lexer,
        bench_parser,
}

criterion_group! {
    name = plugin_workloads;
    config = Criterion::default();
    targets =
        bench_plugin_dispatch,
}

criterion_main!(awk_workloads, parser_workloads, plugin_workloads);
