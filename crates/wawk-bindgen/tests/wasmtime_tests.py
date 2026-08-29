#!/usr/bin/env python3
"""Comprehensive wasmtime (WASI) test suite for wawk"""
import subprocess
import sys
import os

WAWK = "/home/charo/wawk-rs/target/wasm32-wasip1/release/wawk.wasm"
WASMTIME = os.path.expanduser("~/.cargo/bin/wasmtime")

d = chr(36)  # dollar sign
passed = 0
failed = 0

def run_wawk(script, input_data=""):
    """Run wawk via wasmtime and return stdout"""
    result = subprocess.run(
        [WASMTIME, WAWK, "-e", script],
        input=input_data,
        capture_output=True, text=True,
        timeout=30
    )
    if result.returncode != 0:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout

def test(name, script, input_data, expected):
    global passed, failed
    actual = run_wawk(script, input_data)
    if actual.strip() == expected.strip():
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name}")
        print(f"    Expected: {repr(expected.strip())}")
        print(f"    Actual:   {repr(actual.strip())}")
        failed += 1

print("wawk wasmtime (WASI) Tests")
print("=" * 40)

# Basic AWK tests
test("BEGIN block", 'BEGIN { print "hello" }', "", "hello")
test("field splitting", "{ print " + d + "1 }", "hello world\nfoo bar", "hello\nfoo")
test("summation", "{ s += " + d + "1 } END { print s }", "10\n20\n30", "60")
test("pattern matching", "/error/ { print " + d + "0 }", "ok\nerror: fail\nwarn", "error: fail")
test("NR variable", "{ print NR, " + d + "0 }", "a\nb\nc", "1 a\n2 b\n3 c")
test("NF variable", "{ print NF }", "a b c\nx y", "3\n2")
test("arithmetic", "BEGIN { print 2 + 3 * 4 }", "", "14")
test("string functions", 'BEGIN { print length("hello"), substr("hello", 2, 3) }', "", "5 ell")
test("custom FS", 'BEGIN{FS=":"} { print ' + d + '2 }', "a:b:c\nd:e:f", "b\ne")

# JSON-Native tests (Phase 2)
test("JSON $.field", "{ print " + d + ".name, " + d + ".age }",
     '{"name": "Alice", "age": 30}', "Alice 30")

test("JSON nested $.a.b", "{ print " + d + ".user.city }",
     '{"user": {"city": "Tokyo"}}', "Tokyo")

test("JSON positional $1 $2", "{ print " + d + "1, " + d + "2 }",
     '{"a": 10, "b": 20}', "10 20")

test("JSON array $1", "{ print " + d + "1, " + d + "2 }",
     '[100, 200, 300]', "100 200")

test("JSON print $0", "{ print " + d + "0 }",
     '{"x": 1}', '{"x":1}')

test("JSON NF", "{ print NF }",
     '{"a": 1, "b": 2, "c": 3}', "3")

test("JSON typeof object", "{ print typeof(" + d + "0) }",
     '{"x": 1}', "object")

test("JSON typeof array", "{ print typeof(" + d + "0) }",
     '[1, 2]', "array")

test("JSON bare print", "1", '{"x": 42}', '{"x":42}')

# Mixed mode
test("Mixed text+JSON", "{ print " + d + "1 }",
     "hello world\n{\"name\": \"Alice\"}\nfoo bar",
     "hello\nAlice\nfoo")

# Security tests
actual = run_wawk('BEGIN { x = system("echo hi") }', ''); passed += 1 if 'ERROR' in actual or 'not available' in actual else 0; failed += 0 if 'ERROR' in actual else 1; print(f'  {"PASS" if "ERROR" in actual else "FAIL"}: system() blocked')

print(f"\nResults: {passed} passed, {failed} failed, {passed + failed} total")
sys.exit(1 if failed > 0 else 0)
