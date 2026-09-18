//! Security limits and audit logging for AWK execution.

use super::AuditEvent;
use crate::error::{AwkError, AwkResult};

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
    /// E4: Count of audit events dropped when log reached capacity.
    /// Useful for monitoring — if this is non-zero, the log is lossy.
    pub audit_dropped: usize,
    pub enforce_limits: bool,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            output_bytes: 0,
            call_depth: 0,
            expr_depth: 0,
            audit_log: Vec::new(),
            audit_dropped: 0,
            enforce_limits: true,
        }
    }

    /// Record an audit event (security violation, limit breach, etc.).
    ///
    /// E4: Audit log behavior at capacity:
    /// - When `audit_log.len() < MAX_AUDIT_LOG_ENTRIES` (1024): event is appended.
    /// - When `audit_log.len() >= MAX_AUDIT_LOG_ENTRIES`: event is silently dropped
    ///   and `audit_dropped` is incremented. Oldest entries are preserved.
    ///
    /// This is a "stop logging when full" strategy — it prevents unbounded memory
    /// growth (audit bomb prevention) while preserving the first 1024 events for
    /// post-mortem analysis. Callers can check `audit_dropped` to detect lossiness.
    ///
    /// Design rationale: Ring buffer would lose early events (often the most important
    /// for root cause analysis). Error-on-full would block execution. Silent drop with
    /// counter provides observability without blocking.
    pub fn record_audit(&mut self, event: AuditEvent) {
        if self.audit_log.len() < MAX_AUDIT_LOG_ENTRIES {
            self.audit_log.push(event);
        } else {
            // E4: Log is full — drop event and track for monitoring
            self.audit_dropped += 1;
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
                size, MAX_ARRAY_SIZE
            )));
        }

        Ok(())
    }

    pub fn audit_summary(&self) -> String {
        if self.audit_log.is_empty() && self.audit_dropped == 0 {
            return "No security violations".to_string();
        }

        let mut summary = format!("Security audit: {} violations", self.audit_log.len());
        if self.audit_dropped > 0 {
            summary.push_str(&format!(" ({} events dropped due to log capacity)", self.audit_dropped));
        }
        summary.push_str("\n");
        for event in &self.audit_log {
            summary.push_str(&format!("  - {:?}\n", event));
        }
        summary
    }

    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
        self.audit_dropped = 0;
    }
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}
