const { exec_awk, exec_awk_with_fs, exec_awk_multi, exec_awk_with_files } = require('/tmp/wawk-node-test/wawk_bindgen');

let passed = 0;
let failed = 0;

function assert_eq(name, actual, expected) {
    if (actual === expected) {
        passed++;
        console.log(`  ✓ ${name}`);
    } else {
        failed++;
        console.log(`  ✗ ${name}`);
        console.log(`    Expected: ${JSON.stringify(expected)}`);
        console.log(`    Actual:   ${JSON.stringify(actual)}`);
    }
}

console.log("=== wawk-bindgen Node.js Tests ===\n");

// Test 1: Basic execution
console.log("1. Basic exec_awk:");
assert_eq("hello world", exec_awk('BEGIN { print "hello world" }', ''), "hello world\n");

// Test 2: Field access
console.log("2. Field access:");
assert_eq("field split", exec_awk('{ print $1, $3 }', "alice 25 engineer\nbob 30 designer"), "alice engineer\nbob designer\n");

// Test 3: Arithmetic
console.log("3. Arithmetic:");
assert_eq("add", exec_awk('{ print $1 + $2 }', "10 20\n3 7"), "30\n10\n");

// Test 4: Pattern matching
console.log("4. Pattern matching:");
assert_eq("regex", exec_awk('/error/ { print NR, $0 }', "info\nerror: disk full\nwarn\nerror: timeout"), "2 error: disk full\n4 error: timeout\n");

// Test 5: Custom field separator
console.log("5. Custom FS:");
assert_eq("comma FS", exec_awk_with_fs('{ print $2 }', "alice,25,engineer\nbob,30,designer", ","), "25\n30\n");

// Test 6: Multi-script
console.log("6. Multi-script:");
assert_eq("multi", exec_awk_multi(["BEGIN { x = 0 }", "{ x += $1 }", "END { print x }"], "10\n20\n30"), "60\n");

// Test 7: String functions
console.log("7. String functions:");
assert_eq("length", exec_awk('{ print length($0) }', "hello\nhi"), "5\n2\n");
assert_eq("toupper", exec_awk('{ print toupper($1) }', "hello"), "HELLO\n");
assert_eq("tolower", exec_awk('{ print tolower($1) }', "WORLD"), "world\n");
assert_eq("substr", exec_awk('{ print substr($0, 2, 3) }', "hello"), "ell\n");

// Test 8: Sub/gsub
console.log("8. Sub/gsub:");
assert_eq("sub", exec_awk('{ sub(/o/, "0"); print }', "foo\nbar"), "f0o\nbar\n");
assert_eq("gsub", exec_awk('{ gsub(/o/, "0"); print }', "foo\nbar"), "f00\nbar\n");

// Test 9: Arrays
console.log("9. Arrays:");
assert_eq("array", exec_awk('BEGIN { a[1]="x"; a[2]="y"; print a[1], a[2] }', ""), "x y\n");

// Test 10: Control flow
console.log("10. Control flow:");
assert_eq("if-else", exec_awk('{ if ($1 > 5) print "big"; else print "small" }', "10\n3"), "big\nsmall\n");
assert_eq("for loop", exec_awk('BEGIN { for (i = 0; i < 3; i++) print i }', ""), "0\n1\n2\n");
assert_eq("while loop", exec_awk('BEGIN { x = 10; while (x > 0) { x -= 3 }; print x }', ""), "-2\n");

// Test 11: Error handling
console.log("11. Error handling:");
let errResult = exec_awk('BEGIN { print "unterminated }', "");
assert_eq("syntax error", errResult.startsWith("Error:"), true);

// Test 12: Size limits
console.log("12. Size limits:");
let bigScript = " ".repeat(1048577);
let sizeResult = exec_awk(bigScript, "");
assert_eq("oversized script", sizeResult.includes("exceeds maximum size"), true);

// Test 13: Multi-file
console.log("13. Multi-file:");
let filesResult = exec_awk_with_files(
    '{ print $0 }', '',
    '[]',
    '{"input.txt": "hello\\nworld"}'
);
assert_eq("multi-file", filesResult.includes("hello") && filesResult.includes("world"), true);

// Test 14: Empty input
console.log("14. Edge cases:");
assert_eq("empty input", exec_awk('{ print $0 }', ""), "");
assert_eq("empty with BEGIN", exec_awk('BEGIN { print "ok" }', ""), "ok\n");
assert_eq("NR tracking", exec_awk('{ print NR, $0 }', "a\nb\nc"), "1 a\n2 b\n3 c\n");
assert_eq("NF tracking", exec_awk('{ print NF }', "a b c\nx y"), "3\n2\n");

// Summary
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
