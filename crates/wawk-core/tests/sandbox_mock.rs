//! Sandbox Enforcement Mock Test.
//!
//! Proves the trait-based architecture allows a Host to securely restrict
//! the engine. A MockSandboxEnvironment blocks system(), filters ENVIRON,
//! and restricts file I/O — all without changing wawk-core.

use wawk_core::error::AwkError;
use wawk_core::traits::{AwkCommandExecutor, AwkEnvironment, AwkReader, AwkWriter};
use wawk_core::WawkEngine;

// ============================================================================
// Mock Sandbox Implementations
// ============================================================================

/// A reader that provides test input.
struct SandboxReader {
    lines: Vec<String>,
    pos: usize,
}

impl SandboxReader {
    fn new(input: &str) -> Self {
        Self {
            lines: input.lines().map(String::from).collect(),
            pos: 0,
        }
    }
}

impl AwkReader for SandboxReader {
    fn read_line(&mut self) -> wawk_core::error::AwkResult<Option<String>> {
        if self.pos < self.lines.len() {
            let line = self.lines[self.pos].clone();
            self.pos += 1;
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }
}

/// A writer that collects output.
struct SandboxWriter {
    output: String,
}

impl SandboxWriter {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }
}

impl AwkWriter for SandboxWriter {
    fn write_line(&mut self, output: &str) -> wawk_core::error::AwkResult<()> {
        self.output.push_str(output);
        self.output.push('\n');
        Ok(())
    }

    fn write_str(&mut self, output: &str) -> wawk_core::error::AwkResult<()> {
        self.output.push_str(output);
        Ok(())
    }
}

/// A sandboxed environment that ONLY allows whitelisted env vars.
struct SandboxEnvironment {
    whitelist: Vec<(String, String)>,
}

impl SandboxEnvironment {
    fn new() -> Self {
        Self {
            whitelist: vec![
                ("TZ".to_string(), "UTC".to_string()),
                ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ],
        }
    }
}

impl AwkEnvironment for SandboxEnvironment {
    fn get_env(&self, name: &str) -> Option<String> {
        // Only allow whitelisted vars
        self.whitelist
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    fn systime(&self) -> i64 {
        1700000000
    }

    fn all_env_vars(&self) -> Vec<(String, String)> {
        self.whitelist.clone()
    }
}

/// A sandboxed command executor that BLOCKS all command execution.
struct SandboxCommandExecutor;

impl AwkCommandExecutor for SandboxCommandExecutor {
    fn execute(&mut self, cmd: &str) -> wawk_core::error::AwkResult<String> {
        Err(AwkError::RuntimeError(format!(
            "Sandbox violation: system() is blocked. Attempted: {}",
            cmd
        )))
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn sandbox_system_blocked() {
    // Attempting system() should return a sandbox violation error
    let mut reader = SandboxReader::new("");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"BEGIN { system("rm -rf /") }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(result.is_err(), "system() should be blocked in sandbox");
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("Sandbox violation") || err_msg.contains("blocked"),
        "Error should mention sandbox violation, got: {}",
        err_msg
    );
}

#[test]
fn sandbox_environ_filters_secrets() {
    // ENVIRON should only show whitelisted vars, not secrets
    let mut reader = SandboxReader::new("");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"BEGIN { print ENVIRON["AWS_SECRET_KEY"] }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(result.is_ok(), "Should not error, just return empty");
    // AWS_SECRET_KEY is not whitelisted, so it should return empty string
    assert_eq!(
        writer.output.trim(),
        "",
        "Secret should be filtered, got: {:?}",
        writer.output
    );
}

#[test]
fn sandbox_environ_allows_whitelisted() {
    // ENVIRON should allow whitelisted vars
    let mut reader = SandboxReader::new("");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"BEGIN { print ENVIRON["TZ"] }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(result.is_ok(), "Should succeed for whitelisted var");
    assert_eq!(writer.output.trim(), "UTC", "TZ should be UTC");
}

#[test]
fn sandbox_environ_for_in_only_whitelisted() {
    // for (x in ENVIRON) should only iterate whitelisted vars
    let mut reader = SandboxReader::new("");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"BEGIN { for (k in ENVIRON) print k }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(result.is_ok(), "Should succeed");
    let output = &writer.output;
    // Should only contain TZ and LANG
    assert!(output.contains("TZ"), "Should contain TZ");
    assert!(output.contains("LANG"), "Should contain LANG");
    // Should NOT contain PATH or HOME or any OS vars
    assert!(!output.contains("PATH"), "Should not contain PATH");
    assert!(!output.contains("HOME"), "Should not contain HOME");
}

#[test]
fn sandbox_normal_script_works() {
    // Normal AWK scripts should work fine in sandbox
    let mut reader = SandboxReader::new("1\n2\n3\n");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"{ sum += $1 } END { print sum }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(
        result.is_ok(),
        "Normal script should work: {:?}",
        result.err()
    );
    assert_eq!(writer.output.trim(), "6", "Sum should be 6");
}

#[test]
fn sandbox_environ_read_only() {
    // Attempting to write to ENVIRON should error
    let mut reader = SandboxReader::new("");
    let mut writer = SandboxWriter::new();
    let env = SandboxEnvironment::new();
    let mut cmd = SandboxCommandExecutor;

    let engine = WawkEngine::new();
    let result = engine.execute(
        r#"BEGIN { ENVIRON["TZ"] = "hacked" }"#,
        &mut reader,
        &mut writer,
        &env,
        &mut cmd,
    );

    assert!(result.is_err(), "ENVIRON assignment should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("read-only"),
        "Error should mention read-only, got: {}",
        err_msg
    );
}
