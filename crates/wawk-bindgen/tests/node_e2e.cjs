// tests/node_e2e.js — Node.js E2E test for wawk-bindgen
const { exec_awk } = require('../../../npm/wawk.js');

let passed = 0;
let failed = 0;

function assert(name, actual, expected) {
  if (actual.trim() === expected.trim()) {
    console.log(`  PASS: ${name}`);
    passed++;
  } else {
    console.log(`  FAIL: ${name}`);
    console.log(`    Expected: ${JSON.stringify(expected)}`);
    console.log(`    Actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

console.log('wawk-bindgen Node.js E2E Tests');
console.log('==============================');

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

// Test 3: Field splitting with FS
assert(
  'Field splitting with FS=":"',
  exec_awk('BEGIN{FS=":"} { print $1, $3 }', 'alice:x:1001\nbob:x:1002\n'),
  'alice 1001\nbob 1002'
);

// Test 4: Pattern matching
assert(
  'Pattern matching /regex/',
  exec_awk('/error/ { print $0 }', 'info: ok\nerror: fail\nwarn: maybe\nerror: again\n'),
  'error: fail\nerror: again'
);

// Test 5: String functions
assert(
  'String functions (length, substr)',
  exec_awk('{ print length($1), substr($1,1,3) }', 'hello\nworld\n'),
  '5 hel\n5 wor'
);

console.log('');
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);

if (failed > 0) {
  process.exit(1);
}
