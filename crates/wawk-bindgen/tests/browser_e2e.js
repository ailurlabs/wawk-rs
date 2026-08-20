// browser_e2e.js — Browser E2E test for wawk-bindgen
import init, { exec_awk } from '../../../npm/wawk.js';

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
    log('wawk-bindgen Browser E2E Tests');
    log('==============================');

    await init();

    // Test 1: Simple print
    assert(
        'Simple print $1',
        exec_awk('{ print $1 }', 'hello world\nfoo bar\n'),
        'hello\nfoo'
    );

    // Test 2: Summation
    assert(
        'Summation with END',
        exec_awk('{ sum += $1 } END { print sum }', '1\n2\n3\n'),
        '6'
    );

    // Test 3: Pattern matching
    assert(
        'Pattern matching /regex/',
        exec_awk('/error/ { print $0 }', 'info: ok\nerror: fail\nwarn: maybe\n'),
        'error: fail'
    );

    // Test 4: Field splitting
    assert(
        'Field splitting with FS=","',
        exec_awk('BEGIN{FS=","} { print $2 }', 'a,hello,c\nd,world,f\n'),
        'hello\nworld'
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
