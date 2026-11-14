//! Field access for AWK records.
//!
//! Provides zero-copy field access via byte-range indexing into `line_buf`.
//! Field splitting is performed by `Evaluator::split_fields_inplace()` which
//! directly populates `field_ranges` and `fields` on this struct.

use crate::error::AwkResult;

/// Manages field access for the current AWK record.
///
/// After field splitting, `field_ranges` contains `(start, end)` byte offsets
/// into `line_buf` for each field. When fields are modified (via `set_field`),
/// they are materialized into the `fields` Vec and `fields_modified` is set.
pub struct FieldAccessor {
    pub line_buf: String,
    pub field_ranges: Vec<(usize, usize)>,
    pub fields_modified: bool,
    pub fields: Vec<String>,
    pub nf: usize,
    pub fs: String,
    pub ofs: String,
    pub ors: String,
}

impl FieldAccessor {
    pub fn new() -> Self {
        Self {
            line_buf: String::new(),
            field_ranges: Vec::new(),
            fields_modified: false,
            fields: Vec::new(),
            nf: 0,
            fs: " ".to_string(),
            ofs: " ".to_string(),
            ors: "\n".to_string(),
        }
    }

    /// Get field `n` as an owned String.
    /// Field 0 returns the entire line_buf.
    pub fn get_field(&self, n: usize) -> String {
        if n == 0 {
            return self.line_buf.clone();
        }

        if self.fields_modified {
            return self.fields.get(n).cloned().unwrap_or_default();
        }

        if let Some(&(start, end)) = self.field_ranges.get(n - 1) {
            return self.line_buf[start..end].to_string();
        }

        String::new()
    }

    /// Get field `n` as a byte slice (zero-copy).
    /// Falls back to materialized fields if fields were modified.
    pub fn get_field_bytes(&self, n: usize) -> &[u8] {
        if !self.fields_modified {
            if n == 0 {
                return self.line_buf.as_bytes();
            }
            if let Some(&(start, end)) = self.field_ranges.get(n - 1) {
                return &self.line_buf.as_bytes()[start..end];
            }
        }
        self.fields.get(n).map(|s| s.as_bytes()).unwrap_or(&[])
    }

    /// Set field `n` to `value`. Materializes all fields from byte ranges
    /// on first modification (lazy materialization).
    pub fn set_field(&mut self, n: usize, value: &str) {
        if n == 0 {
            let _ = self.set_field_zero(value);
            return;
        }

        if !self.fields_modified {
            self.materialize_fields();
        }

        while self.fields.len() <= n {
            self.fields.push(String::new());
        }

        self.fields[n] = value.to_string();
        self.fields_modified = true;
    }

    /// Set $0 (the entire record) to `value`, resetting field state.
    pub fn set_field_zero(&mut self, value: &str) -> AwkResult<()> {
        self.line_buf = value.to_string();
        self.fields.clear();
        self.field_ranges.clear();
        self.fields_modified = false;
        Ok(())
    }

    /// Materialize fields from byte ranges into owned Strings.
    /// Called lazily on first field modification.
    fn materialize_fields(&mut self) {
        self.fields.clear();
        self.fields.push(String::new());

        for &(start, end) in &self.field_ranges {
            self.fields.push(self.line_buf[start..end].to_string());
        }

        self.fields_modified = true;
    }
}

impl Default for FieldAccessor {
    fn default() -> Self {
        Self::new()
    }
}
