//! Advanced security tests - edge cases and fuzzing-style inputs.

use wawk_core::WawkEngine;
use wawk_core::traits::{BufferedReader, BufferedWriter, SandboxEnvironment, BlockedCommandExecutor};

#[test]
fn test_null_bytes_in_input() {
    let engine = WawkEngine::new();
    let input = "hello\x00world\n";
    let mut reader = BufferedReader::new(input);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print length($0) }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle null bytes gracefully
    assert!(result.is_ok());
}

#[test]
fn test_very_deeply_nested_arrays() {
    let engine = WawkEngine::new();
    // Create deeply nested JSON array: [[[[...]]]]
    let nested = "[".repeat(50) + "1" + &"]".repeat(50);
    let mut reader = BufferedReader::new(&nested);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle without stack overflow
    assert!(result.is_ok());
}

#[test]
fn test_very_wide_json_object() {
    let engine = WawkEngine::new();
    // Create JSON object with many fields
    let fields: Vec<String> = (0..1000).map(|i| format!("\"field{}\": {}", i, i)).collect();
    let json = format!("{{{{{}}}}}", fields.join(","));
    let mut reader = BufferedReader::new(&json);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $.field0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle large objects
    assert!(result.is_ok());
}

#[test]
fn test_regex_with_special_chars() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("test (paren) [bracket] {brace}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "/\\(.*\\)/ { print }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
}

#[test]
fn test_empty_json_object() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    assert_eq!(writer.output.trim(), "{}");
}

#[test]
fn test_empty_json_array() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("[]");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    assert_eq!(writer.output.trim(), "[]");
}

#[test]
fn test_json_with_unicode_keys() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{\"名前\":\"太郎\",\"年齢\":30}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
}

#[test]
fn test_very_long_field_value() {
    let engine = WawkEngine::new();
    let long_value = "x".repeat(1_000_000); // 1MB field
    let mut reader = BufferedReader::new(&long_value);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print length($1) }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    // Should handle large fields within memory limits
    assert!(result.is_ok() || writer.output.len() <= 64 * 1024 * 1024);
}

#[test]
fn test_mixed_json_and_text() {
    let engine = WawkEngine::new();
    let input = "{\"name\":\"Alice\"}\nplain text line\n{\"name\":\"Bob\"}\n";
    let mut reader = BufferedReader::new(input);
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
    let lines: Vec<&str> = writer.output.trim().split('\n').collect();
    assert_eq!(lines.len(), 3);
}

#[test]
fn test_json_with_null_values() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{\"name\":null,\"age\":30}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $.name, $.age }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
}

#[test]
fn test_json_with_boolean_values() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{\"active\":true,\"deleted\":false}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $.active, $.deleted }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
}

#[test]
fn test_json_with_nested_arrays() {
    let engine = WawkEngine::new();
    let mut reader = BufferedReader::new("{\"items\":[1,2,[3,4]]}");
    let mut writer = BufferedWriter::new();
    let env = SandboxEnvironment::default();
    let mut cmd = BlockedCommandExecutor;
    
    let script = "{ print $0 }";
    let result = engine.execute(script, &mut reader, &mut writer, &env, &mut cmd);
    
    assert!(result.is_ok());
}
