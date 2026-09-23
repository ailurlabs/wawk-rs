// browser_wasm_test.js — Test the web-targeted WASM build in Node.js
// This tests the EXACT same WASM binary and JS glue that the browser uses,
// just initialized via initSync() instead of async fetch().
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const WEB_BUILD_DIR = join(__dirname, '..', '..', '..', 'wawk-website', 'wawk');

// Load the WASM binary (same file the browser fetches)
const wasmPath = join(WEB_BUILD_DIR, 'wawk_bindgen_bg.wasm');
const wasmBytes = readFileSync(wasmPath);

// Dynamically import the web build JS glue
// The web build uses ES module exports, same as browser
const webBuild = await import(join(WEB_BUILD_DIR, 'wawk_bindgen.js'));

// Initialize synchronously with the WASM bytes
webBuild.initSync({ module: wasmBytes });

const { exec_awk } = webBuild;

let passed = 0;
let failed = 0;

function assert(name, actual, expected) {
    const a = actual.trim();
    const e = expected.trim();
    if (a === e) {
        console.log(`  \x1b[32mPASS\x1b[0m: ${name}`);
        passed++;
    } else {
        console.log(`  \x1b[31mFAIL\x1b[0m: ${name}`);
        console.log(`    Expected: ${JSON.stringify(e)}`);
        console.log(`    Actual:   ${JSON.stringify(a)}`);
        failed++;
    }
}

console.log('wawk-bindgen Browser WASM E2E Tests (web build)');
console.log('================================================');

// --- Basic AWK tests ---
assert(
    'Simple print $1',
    exec_awk('{ print $1 }', 'hello world\nfoo bar\n'),
    'hello\nfoo'
);

assert(
    'Summation with END',
    exec_awk('{ sum += $1 } END { print sum }', '1\n2\n3\n'),
    '6'
);

assert(
    'Pattern matching /regex/',
    exec_awk('/error/ { print $0 }', 'info: ok\nerror: fail\nwarn: maybe\n'),
    'error: fail'
);

assert(
    'Field splitting with FS=","',
    exec_awk('BEGIN{FS=","} { print $2 }', 'a,hello,c\nd,world,f\n'),
    'hello\nworld'
);

// --- JSON-Native tests (Phase 2) ---
assert(
    'JSON auto-detect: $.field',
    exec_awk('{ print $.name, $.age }', '{"name": "Alice", "age": 30}'),
    'Alice 30'
);

assert(
    'JSON nested: $.user.city',
    exec_awk('{ print $.user.city }', '{"user": {"city": "Tokyo"}}'),
    'Tokyo'
);

assert(
    'JSON positional: $1 on array',
    exec_awk('{ print $1, $2 }', '[10, 20, 30]'),
    '10 20'
);

assert(
    'JSON: print $0 serializes',
    exec_awk('{ print $0 }', '{"x": 1}'),
    '{"x":1}'
);

assert(
    'JSON: NF reflects key count',
    exec_awk('{ print NF }', '{"a": 1, "b": 2, "c": 3}'),
    '3'
);

assert(
    'JSON: typeof object',
    exec_awk('{ print typeof($0) }', '{"x": 1}'),
    'object'
);

assert(
    'JSON: typeof array',
    exec_awk('{ print typeof($0) }', '[1, 2]'),
    'array'
);

assert(
    'JSON: bare print (default action)',
    exec_awk('1', '{"x": 42}'),
    '{"x":42}'
);

assert(
    'Mixed: text + JSON records',
    exec_awk('{ print $1 }', 'hello world\n{"name": "Alice"}\nfoo bar'),
    'hello\nAlice\nfoo'
);

// --- Additional edge-case tests ---
assert(
    'JSON: empty object',
    exec_awk('{ print NF, $0 }', '{}'),
    '0 {}'
);

assert(
    'JSON: empty array',
    exec_awk('{ print NF, $0 }', '[]'),
    '0 []'
);

assert(
    'JSON: nested array access',
    exec_awk('{ print $.items[0] }', '{"items": [100, 200]}'),
    '100'
);

assert(
    'JSON: boolean values',
    exec_awk('{ print $.active }', '{"active": true}'),
    '1'  // AWK converts true to 1 when printing
);

assert(
    'JSON: null value',
    exec_awk('{ print $.val }', '{"val": null}'),
    ''  // AWK converts null to empty string
);

assert(
    'Multi-line text processing',
    exec_awk('BEGIN{OFS=","} { print $1, $2 }', 'a b\nc d\ne f'),
    'a,b\nc,d\ne,f'
);

assert(
    'BEGIN/END blocks',
    exec_awk('BEGIN{ print "start" } END{ print "end" }', ''),
    'start\nend'
);

assert(
    'Conditional pattern',
    exec_awk('$1 > 2 { print $0 }', '1\n2\n3\n4\n'),
    '3\n4'
);
assert(
    'String concatenation',
    exec_awk('{ print $1 " " $2 }', 'hello world\n'),
    'hello world'
);

assert(
    'For loop',
    exec_awk('BEGIN { for (i=1; i<=5; i++) sum+=i; print sum }', ''),
    '15'
);

assert(
    'While loop',
    exec_awk('BEGIN { i=1; while(i<=3) { print i; i++ } }', ''),
    '1\n2\n3'
);

assert(
    'Array usage',
    exec_awk('BEGIN { a[1]="x"; a[2]="y"; for (i in a) print i, a[i] }', ''),
    '1 x\n2 y'
);

assert(
    'sub() function',
    exec_awk('{ sub(/world/, "earth"); print }', 'hello world\n'),
    'hello earth'
);

assert(
    'gsub() function',
    exec_awk('{ gsub(/o/, "0"); print }', 'foo boo\n'),
    'f00 b00'
);

console.log(`\nResults: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
    console.log('\x1b[31mBROWSER WASM E2E FAILED\x1b[0m');
    process.exitCode = 1;
} else {
    console.log('\x1b[32mALL BROWSER WASM E2E TESTS PASSED\x1b[0m');
}
