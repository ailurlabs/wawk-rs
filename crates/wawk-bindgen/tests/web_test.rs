//! Browser-based tests for wawk using wasm-bindgen-test.
//!
//! These tests verify that the AWK interpreter works correctly
//! in a WebAssembly/browser environment.
//!
//! Run with: wasm-pack test --headless --chrome (or --firefox)

use wasm_bindgen_test::*;
use wawk_bindgen::{exec_awk, exec_awk_with_fs};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_basic_print() {
    let output = exec_awk("BEGIN { print \"hello\" }", "");
    assert_eq!(output.trim(), "hello");
}

#[wasm_bindgen_test]
fn test_field_splitting() {
    let output = exec_awk("{ print $2 }", "hello world\nfoo bar");
    assert_eq!(output, "world\nbar\n");
}

#[wasm_bindgen_test]
fn test_sum_column() {
    let output = exec_awk("{ sum += $1 } END { print sum }", "10\n20\n30\n");
    assert_eq!(output.trim(), "60");
}

#[wasm_bindgen_test]
fn test_regex_match() {
    let output = exec_awk(
        "$2 ~ /ERROR/ { print $1 }",
        "100 INFO\n200 ERROR\n300 WARN\n400 ERROR\n",
    );
    assert_eq!(output, "200\n400\n");
}

#[wasm_bindgen_test]
fn test_begin_end_blocks() {
    let output = exec_awk("BEGIN { print \"start\" } END { print \"end\" }", "");
    assert_eq!(output, "start\nend\n");
}

#[wasm_bindgen_test]
fn test_associative_array() {
    let output = exec_awk(
        "{ count[$1]++ } END { for (k in count) print k, count[k] }",
        "a\nb\na\nc\nb\na\n",
    );
    // Output order may vary, so check both lines exist
    assert!(output.contains("a 3"));
    assert!(output.contains("b 2"));
    assert!(output.contains("c 1"));
}

#[wasm_bindgen_test]
fn test_arithmetic() {
    let output = exec_awk("BEGIN { print 2 + 3 * 4 }", "");
    assert_eq!(output.trim(), "14");
}

#[wasm_bindgen_test]
fn test_string_functions() {
    let output = exec_awk(
        "BEGIN { print length(\"hello\"), substr(\"hello\", 2, 3) }",
        "",
    );
    assert_eq!(output.trim(), "5 ell");
}

#[wasm_bindgen_test]
fn test_for_loop() {
    let output = exec_awk("BEGIN { for (i = 1; i <= 5; i++) printf i \" \" }", "");
    assert_eq!(output.trim(), "1 2 3 4 5");
}

#[wasm_bindgen_test]
fn test_ternary_operator() {
    let output = exec_awk("BEGIN { x = 10; print (x > 5) ? \"yes\" : \"no\" }", "");
    assert_eq!(output.trim(), "yes");
}

#[wasm_bindgen_test]
fn test_error_handling() {
    // Invalid syntax should return an error string, not crash
    let output = exec_awk("{ print $1", "");
    assert!(output.starts_with("Error: "));
}

#[wasm_bindgen_test]
fn test_system_blocked_in_browser() {
    // system() should be blocked in browser environment
    let output = exec_awk("BEGIN { system(\"echo hello\") }", "");
    assert!(output.starts_with("Error: "));
    assert!(output.contains("not available in browser"));
}

#[wasm_bindgen_test]
fn test_custom_field_separator() {
    let output = exec_awk_with_fs("{ print $2 }", "a:b:c\nd:e:f", ":");
    assert_eq!(output, "b\ne\n");
}

#[wasm_bindgen_test]
fn test_nr_variable() {
    let output = exec_awk("{ print NR, $0 }", "first\nsecond\nthird");
    assert_eq!(output, "1 first\n2 second\n3 third\n");
}

#[wasm_bindgen_test]
fn test_nf_variable() {
    let output = exec_awk("{ print NF }", "a b c\nx y\n");
    assert_eq!(output, "3\n2\n");
}
