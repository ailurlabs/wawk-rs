//! Security limits and audit logging for AWK execution.

use crate::error::{AwkResult, AwkError};
use super::AuditEvent;

pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024; // 64 MB
pub const MAX_CALL_DEPTH: usize = 256;
pub const MAX_EXPR_DEPTH: usize = 1024;
pub const MAX_FIELDS: usize = 100_000;
pub const MAX_REGEX_PATTERN_LEN: usize = 4096;
pub const MAX_ARRAY_SIZE: usize = 1_000_000;
pub const MAX_OPEN_FILES: usize = 256;
pub const MAX_AUDIT_LOG_ENTRIES: usize = 1024;


pub struct SecurityManager {
    pub output_bytes: usize,
    pub call_depth: usize,
    pub expr_depth: usize,
    pub audit_log: Vec<AuditEvent>,
    pub enforce_limits: bool,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            output_bytes: 0,
            call_depth: 0,
            expr_depth: 0,
            audit_log: Vec::new(),
            enforce_limits: true,
        }
    }

    pub fn record_audit(&mut self, event: AuditEvent) {
        // Cap audit log to prevent unbounded memory growth (audit bomb prevention)
        if self.audit_log.len() < MAX_AUDIT_LOG_ENTRIES {
            self.audit_log.push(event);
        }
    }

    pub fn check_output_limit(&mut self, additional_bytes: usize) -> AwkResult<()> {
        if !self.enforce_limits {
            return Ok(());
        }

        self.output_bytes = self.output_bytes.saturating_add(additional_bytes);
        
        if self.output_bytes > MAX_OUTPUT_BYTES {
            self.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_OUTPUT_BYTES".to_string(),
                limit_value: MAX_OUTPUT_BYTES,
                actual_value: self.output_bytes,
            });
            return Err(AwkError::RuntimeError(format!(
                "Output size limit exceeded ({} MB max)",
                MAX_OUTPUT_BYTES / (1024 * 1024)
            )));
        }

        Ok(())
    }

    pub fn increment_call_depth(&mut self) -> AwkResult<()> {
        if !self.enforce_limits {
            return Ok(());
        }

        self.call_depth += 1;
        
        if self.call_depth > MAX_CALL_DEPTH {
            self.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_CALL_DEPTH".to_string(),
                limit_value: MAX_CALL_DEPTH,
                actual_value: self.call_depth,
            });
            return Err(AwkError::RuntimeError(format!(
                "Recursion limit exceeded (max {})",
                MAX_CALL_DEPTH
            )));
        }

        Ok(())
    }

    pub fn decrement_call_depth(&mut self) {
        if self.call_depth > 0 {
            self.call_depth -= 1;
        }
    }

    pub fn increment_expr_depth(&mut self) -> AwkResult<()> {
        if !self.enforce_limits {
            return Ok(());
        }

        self.expr_depth += 1;
        
        if self.expr_depth > MAX_EXPR_DEPTH {
            self.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_EXPR_DEPTH".to_string(),
                limit_value: MAX_EXPR_DEPTH,
                actual_value: self.expr_depth,
            });
            return Err(AwkError::RuntimeError(format!(
                "Expression nesting too deep (max {})",
                MAX_EXPR_DEPTH
            )));
        }

        Ok(())
    }

    pub fn decrement_expr_depth(&mut self) {
        if self.expr_depth > 0 {
            self.expr_depth -= 1;
        }
    }

    pub fn check_regex_pattern(&self, pattern: &str) -> AwkResult<()> {
        if !self.enforce_limits {
            return Ok(());
        }

        if pattern.len() > MAX_REGEX_PATTERN_LEN {
            return Err(AwkError::RuntimeError(format!(
                "Regex pattern too long ({} > {})",
                pattern.len(),
                MAX_REGEX_PATTERN_LEN
            )));
        }

        Ok(())
    }

    pub fn check_array_size(&self, size: usize) -> AwkResult<()> {
        if !self.enforce_limits {
            return Ok(());
        }

        if size > MAX_ARRAY_SIZE {
            return Err(AwkError::RuntimeError(format!(
                "Array size exceeded ({} > {})",
                size,
                MAX_ARRAY_SIZE
            )));
        }

        Ok(())
    }

    pub fn audit_summary(&self) -> String {
        if self.audit_log.is_empty() {
            return "No security violations".to_string();
        }

        let mut summary = format!("Security audit: {} violations\n", self.audit_log.len());
        for event in &self.audit_log {
            summary.push_str(&format!("  - {:?}\n", event));
        }
        summary
    }

    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}
