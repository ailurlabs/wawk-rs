//! Node.js integration test for wawk-bindgen.
//!
//! Run with: node crates/wawk-bindgen/tests/node_test.js
//! Requires: wasm-pack build crates/wawk-bindgen --target nodejs --out-dir ../../pkg/nodejs --dev

const assert = require('assert');
const { exec_awk, exec_awk_with_fs } = require('../../../npm/wawk.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  ✓ ${name}`);
        passed++;
    } catch (e) {
        console.log(`  ✗ ${name}: ${e.message}`);
        failed++;
    }
}

console.log('wawk-bindgen Node.js tests:\n');

test('BEGIN block prints', () => {
    const output = exec_awk('BEGIN { print "hello" }', '');
    assert.strictEqual(output.trim(), 'hello');
});

test('field splitting', () => {
    const output = exec_awk('{ print $2 }', 'hello world\nfoo bar');
    assert.strictEqual(output, 'world\nbar\n');
});

test('sum column', () => {
    const output = exec_awk('{ sum += $1 } END { print sum }', '10\n20\n30\n');
    assert.strictEqual(output.trim(), '60');
});

test('regex match', () => {
    const output = exec_awk(
        '$2 ~ /ERROR/ { print $1 }',
        '100 INFO\n200 ERROR\n300 WARN\n400 ERROR\n'
    );
    assert.strictEqual(output, '200\n400\n');
});

test('BEGIN/END blocks', () => {
    const output = exec_awk('BEGIN { print "start" } END { print "end" }', '');
    assert.strictEqual(output, 'start\nend\n');
});

test('arithmetic', () => {
    const output = exec_awk('BEGIN { print 2 + 3 * 4 }', '');
    assert.strictEqual(output.trim(), '14');
});

test('string functions', () => {
    const output = exec_awk('BEGIN { print length("hello"), substr("hello", 2, 3) }', '');
    assert.strictEqual(output.trim(), '5 ell');
});

test('custom field separator', () => {
    const output = exec_awk_with_fs('{ print $2 }', 'a:b:c\nd:e:f', ':');
    assert.strictEqual(output, 'b\ne\n');
});

test('NR variable', () => {
    const output = exec_awk('{ print NR, $0 }', 'first\nsecond\nthird');
    assert.strictEqual(output, '1 first\n2 second\n3 third\n');
});

test('NF variable', () => {
    const output = exec_awk('{ print NF }', 'a b c\nx y\n');
    assert.strictEqual(output, '3\n2\n');
});

test('error handling returns error string', () => {
    const output = exec_awk('{ print $1', '');
    assert(output.startsWith('Error: '), 'Should start with "Error: "');
});

test('system() blocked in browser', () => {
    const output = exec_awk('BEGIN { system("echo hello") }', '');
    assert(output.startsWith('Error: '), 'Should start with "Error: "');
    assert(output.includes('not available'), 'Should mention unavailable');
});

console.log(`\n${passed} passing, ${failed} failing`);
process.exit(failed > 0 ? 1 : 0);
