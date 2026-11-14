// browser_e2e.js — Browser E2E test for wawk-bindgen (Phase 2 JSON-Native)
import init, { exec_awk } from '../../../../wawk-website/wawk/wawk_bindgen.js';

const results = document.getElementById('results');
let passed = 0;
let failed = 0;

function log(msg, cls = '') {
    const span = document.createElement('span');
    span.className = cls;
    span.textContent = msg + '\n';
    results.appendChild(span);
}

function assert(name, actual, expected) {
    if (actual.trim() === expected.trim()) {
        log(`  PASS: ${name}`, 'pass');
        passed++;
    } else {
        log(`  FAIL: ${name}`, 'fail');
        log(`    Expected: ${JSON.stringify(expected)}`);
        log(`    Actual:   ${JSON.stringify(actual)}`);
        failed++;
    }
}

async function run() {
    results.textContent = '';
    log('wawk-bindgen Browser E2E Tests (Phase 2 JSON-Native)');
    log('====================================================');

    await init();

    // Basic AWK tests
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

    // JSON-Native tests (Phase 2)
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

    log('');
    log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);

    if (failed > 0) {
        log('BROWSER E2E FAILED', 'fail');
    } else {
        log('ALL BROWSER E2E TESTS PASSED', 'pass');
    }
}

run().catch(e => {
    log(`FATAL: ${e.message}`, 'fail');
});
