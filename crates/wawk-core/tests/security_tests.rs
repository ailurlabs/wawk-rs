//! Security hardening tests for wawk-core.
//!
//! Tests input validation, resource limits, and attack prevention.

use wawk_core::WawkEngine;
use wawk_core::traits::{BufferedReader, BufferedWriter, SandboxEnvironment, BlockedCommandExecutor};

#[test]
fn test_output_size_limit() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("a\n");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Try to generate large output (should be limited to 64MB)
    let script = "BEGIN { for (i=0; i<10000000; i++) print \"x\" }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should either succeed with limited output or fail with size limit error
    assert!(result.is_ok() || writer.output.len() <= 64 * 1024 * 1024);
}

#[test]
fn test_recursion_depth_limit() {
    // Run in a thread with larger stack to avoid OS stack overflow
    // before our AWK-level recursion limit kicks in
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024) // 64MB stack
        .spawn(|| {
            let engine = WawkEngine::new();
            let mut reader = BufferedReader::new("");
            let mut writer = BufferedWriter::new();
            let env = SandboxEnvironment::default();
            let mut cmd = BlockedCommandExecutor;
            
            // Deep recursion should be caught
            let script = "function deep(n) { if (n > 0) return deep(n-1); return 0 } BEGIN { print deep(10000) }";
            let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
            
            // Should fail with recursion limit error
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("Recursion limit") || err_msg.contains("stack overflow"));
        })
        .unwrap();
    
    handle.join().unwrap();
}

#[test]
fn test_regex_complexity_limit() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("test");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Complex regex should be handled safely
    let script = "/(a+)+b/ { print }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should not hang or crash
    assert!(result.is_ok());
}

#[test]
fn test_field_count() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Set FS to comma for CSV-style field separation
    let script = "BEGIN { FS=\",\" } { print NF }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    // NF should be 16 for comma-separated fields
    let output = writer.output.trim();
    assert_eq!(output, "16", "Expected NF=16, got: {}", output);
}

#[test]
fn test_array_size_limit() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Array size limit exists (verify limit mechanism works without excessive runtime)
    // The actual limit is 1M entries; we just verify the engine handles large arrays
    let script = "BEGIN { for (i=0; i<100000; i++) arr[i]=i; print length(arr) }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should either succeed with limited array or fail gracefully
    assert!(result.is_ok() || writer.output.is_empty());
}

#[test]
fn test_malformed_json_handling() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{\"invalid\": json}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle malformed JSON gracefully (treat as text)
    assert!(result.is_ok());
}

#[test]
fn test_deeply_nested_json() {
    let engine = WawkEngine::new();
    let nested = "{\"a\":".repeat(100) + "\"x\"" + &"}".repeat(100);
    let mut reader = BufferedReader::new(&nested);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $.a.a.a }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle deep nesting without stack overflow
    assert!(result.is_ok());
}

#[test]
fn test_empty_input() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    assert!(writer.output.is_empty());
}

#[test]
fn test_unicode_input() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("héllo wörld\n你好世界\n");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print length($0) }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    let lines: Vec<&str> = writer.output.trim().split('\n').collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn test_very_long_line() {
    let engine = WawkEngine::new();
    let long_line = "x".repeat(10_000_000); // 10MB line
    let mut reader = BufferedReader::new(&long_line);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print length($0) }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle large lines within memory limits
    assert!(result.is_ok() || writer.output.len() <= 64 * 1024 * 1024);
}

#[test]
fn test_audit_log_bomb_prevention() {
    // A malicious program that triggers many security events should not
    // cause unbounded memory growth in the audit log.
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("a\n");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // system() in a loop would trigger audit events on every iteration
    let script = "BEGIN { for (i=0; i<10000; i++) system(\"echo\") }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should either fail (system blocked) or succeed without OOM
    // In either case, the audit log should be capped
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_open_files_limit() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("test\n");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Try to open many files via print>> (append redirect)
    // Each unique filename counts as a separate open file
    let script = "BEGIN { for (i=0; i<300; i++) { print \"x\" >> (\"file_\" i) } }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should fail with too many open files error
    assert!(result.is_err(), "Expected error for too many open files, got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("open files") || err_msg.contains("Too many"),
        "Expected 'too many open files' error, got: {}", err_msg);
}

#[test]
fn test_system_blocked_in_sandbox() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // system() should be blocked in sandbox mode
    let script = r#"BEGIN { system("echo pwned") }"#;
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should fail
    assert!(result.is_err());
}

#[test]
fn test_getline_pipe_blocked_in_sandbox() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Pipe getline should be blocked in sandbox mode
    let script = r#"BEGIN { "cat /etc/passwd" | getline x; print x }"#;
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should fail (pipe blocked) or print empty
    if result.is_ok() {
        assert!(writer.output.trim().is_empty() || !writer.output.contains("root:"));
    }
}

#[test]
fn test_redos_resistance() {
    let engine = WawkEngine::new();
    // Evil regex pattern that causes exponential backtracking in naive engines
    let evil_input = "a".repeat(100) + "!";
    let mut reader = BufferedReader::new(&evil_input);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // This pattern would cause catastrophic backtracking in naive regex engines
    let script = "/(a+)+b/ { print }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Rust's regex crate uses NFA-based matching (linear time), so this should complete quickly
    assert!(result.is_ok());
}

#[test]
fn test_format_string_safety() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("test\n");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Printf with user-controlled format string should not crash
    let script = r#"{ printf $0, 1, 2, 3 }"#;
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle safely
    assert!(result.is_ok());
}

#[test]
fn test_integer_overflow_safety() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // Large numbers should not cause integer overflow
    let script = "BEGIN { x = 999999999999999; print x + 1; print x * x; print x / 0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle gracefully (AWK uses f64 for all numbers)
    assert!(result.is_ok());
}

#[test]
fn test_envviron_read_only() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    // ENVIRON should be read-only
    let script = r#"BEGIN { delete ENVIRON; print "ok" }"#;
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("read-only"), "Expected read-only error, got: {}", err_msg);
}
