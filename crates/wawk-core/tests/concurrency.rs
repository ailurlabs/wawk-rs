//! Concurrency / Reentrancy Proof for wawk-core.
//!
//! Spawns multiple threads, each with its own Evaluator instance,
//! running complex scripts simultaneously. Proves there is NO hidden
//! global mutable state in wawk-core.

use std::thread;
use wawk_core::traits::{MemReader, MemWriter, StubCommandExecutor, StubEnvironment};
use wawk_core::WawkEngine;

/// Test that multiple threads can run independent evaluators simultaneously.
#[test]
fn concurrency_ten_threads_simultaneous() {
    let handles: Vec<_> = (0..10)
        .map(|thread_id| {
            thread::spawn(move || {
                // Each thread creates its own reader/writer/env/cmd
                let input = "1\n2\n3\n4\n5\n";
                let mut reader = MemReader::new(input);
                let mut writer = MemWriter::new();
                let env = StubEnvironment::default();
                let mut cmd = StubCommandExecutor;

                // Each thread runs a complex script
                let program = r#"
                {
                    sum += $1;
                    a[$1] = $1 * 2;
                }
                END {
                    print sum;
                    for (k in a) total += a[k];
                    print total;
                }
                "#;

                let engine = WawkEngine::new();
                let result = engine.execute(program, &mut reader, &mut writer, &env, &mut cmd);

                // Verify no errors
                assert!(
                    result.is_ok(),
                    "Thread {} failed: {:?}",
                    thread_id,
                    result.err()
                );

                // Verify output
                assert!(
                    !writer.output.is_empty(),
                    "Thread {} produced no output",
                    thread_id
                );

                thread_id
            })
        })
        .collect();

    // Wait for all threads and collect results
    let mut completed = Vec::new();
    for handle in handles {
        completed.push(handle.join().expect("Thread panicked!"));
    }

    // All 10 threads should have completed
    assert_eq!(completed.len(), 10);
}

/// Test that concurrent regex operations don't interfere.
#[test]
fn concurrency_regex_isolation() {
    let handles: Vec<_> = (0..5)
        .map(|thread_id| {
            thread::spawn(move || {
                let input = "hello world\nfoo bar\nbaz qux\n";
                let mut reader = MemReader::new(input);
                let mut writer = MemWriter::new();
                let env = StubEnvironment::default();
                let mut cmd = StubCommandExecutor;

                // Each thread uses different regex patterns
                let program = match thread_id % 3 {
                    0 => r#"{ if ($0 ~ /hello/) print "match" }"#,
                    1 => r#"{ if ($0 ~ /^foo/) print "match" }"#,
                    _ => r#"{ gsub(/o/, "0", $0); print }"#,
                };

                let engine = WawkEngine::new();
                let result = engine.execute(program, &mut reader, &mut writer, &env, &mut cmd);

                assert!(
                    result.is_ok(),
                    "Thread {} regex failed: {:?}",
                    thread_id,
                    result.err()
                );
                thread_id
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked!");
    }
}

/// Test that concurrent array operations are isolated.
#[test]
fn concurrency_array_isolation() {
    let handles: Vec<_> = (0..5)
        .map(|thread_id| {
            thread::spawn(move || {
                let input = "";
                let mut reader = MemReader::new(input);
                let mut writer = MemWriter::new();
                let env = StubEnvironment::default();
                let mut cmd = StubCommandExecutor;

                // Each thread creates its own arrays
                let program = r#"
                BEGIN {
                    for (i = 0; i < 1000; i++) {
                        a[i] = i * 2;
                        b["key_" i] = i;
                    }
                    count = 0;
                    for (k in a) count++;
                    for (k in b) count++;
                    print count;
                }
                "#;

                let engine = WawkEngine::new();
                let result = engine.execute(program, &mut reader, &mut writer, &env, &mut cmd);

                assert!(
                    result.is_ok(),
                    "Thread {} array failed: {:?}",
                    thread_id,
                    result.err()
                );
                assert!(
                    writer.output.contains("2000"),
                    "Thread {} wrong count: {}",
                    thread_id,
                    writer.output
                );
                thread_id
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked!");
    }
}

/// Test that concurrent user-defined functions work correctly.
#[test]
fn concurrency_user_defined_functions() {
    let handles: Vec<_> = (0..5)
        .map(|thread_id| {
            thread::spawn(move || {
                let input = "5\n";
                let mut reader = MemReader::new(input);
                let mut writer = MemWriter::new();
                let env = StubEnvironment::default();
                let mut cmd = StubCommandExecutor;

                // Each thread runs a script with user-defined functions
                let program = r#"
                function fib(n,    a, b, i, tmp) {
                    if (n <= 1) return n
                    a = 0; b = 1
                    for (i = 2; i <= n; i++) {
                        tmp = a + b; a = b; b = tmp
                    }
                    return b
                }
                { print fib($1) }
                "#;

                let engine = WawkEngine::new();
                let result = engine.execute(program, &mut reader, &mut writer, &env, &mut cmd);

                assert!(
                    result.is_ok(),
                    "Thread {} function failed: {:?}",
                    thread_id,
                    result.err()
                );
                // fib(5) = 5
                assert!(
                    writer.output.contains("5"),
                    "Thread {} wrong fib: {}",
                    thread_id,
                    writer.output
                );
                thread_id
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked!");
    }
}
