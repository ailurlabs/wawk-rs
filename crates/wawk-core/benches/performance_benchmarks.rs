//! Performance benchmarks for wawk-core.
//!
//! Compares wawk performance against standard benchmarks.

use std::time::Instant;
use wawk_core::WawkEngine;
use wawk_core::traits::{MemReader, MemWriter, StubEnvironment, StubCommandExecutor};

fn run_benchmark(name: &str, script: &str, input: &str, iterations: usize) -> f64 {
    let mut total_ms = 0.0;
    
    for _ in 0..iterations {
        let engine = WawkEngine::new();
        let mut reader = MemReader::new(input);
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        
        let start = Instant::now();
        let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
        let elapsed = start.elapsed();
        
        assert!(result.is_ok(), "Benchmark {} failed: {:?}", name, result.err());
        total_ms += elapsed.as_secs_f64() * 1000.0;
    }
    
    total_ms / iterations as f64
}

#[test]
fn benchmark_field_extraction() {
    let script = "{ print $1, $3 }";
    let input = "Alice 25 engineer\nBob 30 designer\nCharlie 28 manager\n".repeat(1000);
    
    let avg_ms = run_benchmark("field_extraction", script, &input, 100);
    println!("Field extraction (3k records): {:.2}ms avg", avg_ms);
    
    // Should complete in reasonable time (< 100ms for 3k records)
    assert!(avg_ms < 100.0, "Field extraction too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_numeric_aggregation() {
    let script = "{ sum += $1 } END { print sum }";
    let input = (1..=10000).map(|i| format!("{}\n", i)).collect::<String>();
    
    let avg_ms = run_benchmark("numeric_aggregation", script, &input, 50);
    println!("Numeric aggregation (10k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 200.0, "Numeric aggregation too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_pattern_filtering() {
    let script = "/error/ { print }";
    let input = "info: ok\nerror: disk full\ninfo: done\nerror: timeout\n".repeat(2500);
    
    let avg_ms = run_benchmark("pattern_filtering", script, &input, 100);
    println!("Pattern filtering (10k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 150.0, "Pattern filtering too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_propertytree_native_access() {
    let script = "{ print $.name, $.age }";
    let json_record = "{\"name\":\"Alice\",\"age\":30}\n";
    let input = json_record.repeat(1000);
    
    let avg_ms = run_benchmark("propertytree_native", script, &input, 100);
    println!("PropertyTree-native access (1k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 100.0, "PropertyTree-native access too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_property_tree_conversion() {
    let script = "{ print $0 }";
    let json_record = "{\"name\":\"Alice\",\"address\":{\"city\":\"Berlin\"}}\n";
    let input = json_record.repeat(1000);
    
    let avg_ms = run_benchmark("property_tree", script, &input, 100);
    println!("PropertyTree conversion (1k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 150.0, "PropertyTree conversion too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_regex_matching() {
    let script = "/^[A-Z][a-z]+ [0-9]+$/ { print }";
    let input = "Alice 25\nBob 30\nCharlie 28\n".repeat(3000);
    
    let avg_ms = run_benchmark("regex_matching", script, &input, 100);
    println!("Regex matching (9k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 200.0, "Regex matching too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_array_operations() {
    let script = "{ count[$1]++ } END { for (k in count) print k, count[k] }";
    let input = "apple\nbanana\napple\ncherry\nbanana\napple\n".repeat(1000);
    
    let avg_ms = run_benchmark("array_operations", script, &input, 100);
    println!("Array operations (6k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 150.0, "Array operations too slow: {:.2}ms", avg_ms);
}

#[test]
fn benchmark_string_functions() {
    let script = "{ print toupper($1), length($2) }";
    let input = "alice 25\nbob 30\ncharlie 28\n".repeat(3000);
    
    let avg_ms = run_benchmark("string_functions", script, &input, 100);
    println!("String functions (9k records): {:.2}ms avg", avg_ms);
    
    assert!(avg_ms < 200.0, "String functions too slow: {:.2}ms", avg_ms);
}
