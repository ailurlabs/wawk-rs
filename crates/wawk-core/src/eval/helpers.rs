//! Helper methods and utility functions for the AWK evaluator.

use super::*;

/// Security profile for different deployment contexts.
/// Compliance: ISO 27001 A.8.1 (Asset Management), SOC 2 CC6.1 (Logical Access)
#[derive(Debug, Clone)]
pub struct SecurityProfile {
    /// Maximum execution wall-clock time in seconds (0 = no limit)
    pub max_execution_secs: u64,
    /// Whether to track audit events for compliance reporting
    pub audit_enabled: bool,
    /// Maximum estimated memory in bytes (0 = no limit)
    pub max_memory_bytes: usize,
    /// Whether to log input record metadata for audit trail
    pub record_audit: bool,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self {
            max_execution_secs: 300, // 5 minutes default
            audit_enabled: true,
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB default
            record_audit: false,
        }
    }
}

impl SecurityProfile {
    /// Strictest profile for untrusted input (e.g., web-facing services)
    /// Compliance: HIPAA 164.312(a)(1), GDPR Art. 32
    pub fn strict() -> Self {
        Self {
            max_execution_secs: 30,
            audit_enabled: true,
            max_memory_bytes: 64 * 1024 * 1024,
            record_audit: true,
        }
    }

    /// Relaxed profile for trusted internal use.
    /// Still enforces basic safety limits to prevent runaway resource consumption.
    pub fn relaxed() -> Self {
        Self {
            max_execution_secs: 600, // 10 min hard cap
            audit_enabled: false,
            max_memory_bytes: 512 * 1024 * 1024, // 512 MB
            record_audit: false,
        }
    }
}

// === AST analysis methods ===

impl<'a> Evaluator<'a> {
    pub(super) fn program_uses_property_tree_features(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_uses = rule.pattern.as_ref().is_some_and(Self::pattern_uses_property_tree);
            let action_uses = rule
                .action
                .as_ref()
                .map(|a| Self::block_uses_property_tree(&a.statements))
                .unwrap_or(false);
            pattern_uses || action_uses
        })
    }

    pub(super) fn pattern_uses_property_tree(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_uses_property_tree(expr),
            Pattern::Range(start, end) => {
                Self::pattern_uses_property_tree(start) || Self::pattern_uses_property_tree(end)
            }
        }
    }

    pub(super) fn block_uses_property_tree(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_uses_property_tree)
    }

    pub(super) fn stmt_uses_property_tree(stmt: &Statement) -> bool {
        match stmt {
            Statement::Expr(expr) => Self::expr_uses_property_tree(expr),
            Statement::Print(exprs) => exprs.iter().any(Self::expr_uses_property_tree),
            Statement::Printf(fmt, args) => {
                Self::expr_uses_property_tree(fmt) || args.iter().any(Self::expr_uses_property_tree)
            }
            Statement::PrintRedirect(exprs, _, target) => {
                exprs.iter().any(Self::expr_uses_property_tree) || Self::expr_uses_property_tree(target)
            }
            Statement::PrintfRedirect(fmt, args, _, target) => {
                Self::expr_uses_property_tree(fmt)
                    || args.iter().any(Self::expr_uses_property_tree)
                    || Self::expr_uses_property_tree(target)
            }
            Statement::Assign(_, value) => Self::expr_uses_property_tree(value),
            Statement::CompoundAssign(_, _, value) => Self::expr_uses_property_tree(value),
            Statement::ArrayAssign(_, idx, value) => {
                Self::expr_uses_property_tree(idx) || Self::expr_uses_property_tree(value)
            }
            Statement::FieldAssign(_, _) => false,
            Statement::If(cond, then_s, else_s) => {
                Self::expr_uses_property_tree(cond)
                    || Self::stmt_uses_property_tree(then_s)
                    || else_s.as_ref().is_some_and(|s| Self::stmt_uses_property_tree(s))
            }
            Statement::While(cond, body) => {
                Self::expr_uses_property_tree(cond) || Self::stmt_uses_property_tree(body)
            }
            Statement::For(init, cond, incr, body) => {
                init.as_ref().is_some_and(|s| Self::stmt_uses_property_tree(s))
                    || cond.as_ref().is_some_and(|e| Self::expr_uses_property_tree(e))
                    || incr.as_ref().is_some_and(|e| Self::expr_uses_property_tree(e))
                    || Self::stmt_uses_property_tree(body)
            }
            Statement::ForIn(_, _, body) => Self::stmt_uses_property_tree(body),
            Statement::Block(stmts) => stmts.iter().any(Self::stmt_uses_property_tree),
            Statement::Return(expr) => expr.as_ref().is_some_and(Self::expr_uses_property_tree),
            _ => false,
        }
    }

    pub(super) fn expr_uses_property_tree(expr: &Expr) -> bool {
        match expr {
            Expr::DotAccess(_, _) | Expr::IndexExpr(_, _) => true,
            Expr::Field(_) | Expr::Record => false,
            Expr::Number(_) | Expr::String(_) | Expr::Var(_) | Expr::BoolLit(_) | Expr::NullLit => {
                false
            }
            Expr::BinOp(l, _, r) => Self::expr_uses_property_tree(l) || Self::expr_uses_property_tree(r),
            Expr::UnaryOp(_, e) => Self::expr_uses_property_tree(e),
            Expr::FuncCall(_, args) | Expr::QualifiedFuncCall { args, .. } => {
                args.iter().any(Self::expr_uses_property_tree)
            }
            Expr::ArrayAccess(_, idx) => Self::expr_uses_property_tree(idx),
            Expr::Match(e, _) | Expr::NotMatch(e, _) => Self::expr_uses_property_tree(e),
            Expr::Ternary(c, t, f) => {
                Self::expr_uses_property_tree(c) || Self::expr_uses_property_tree(t) || Self::expr_uses_property_tree(f)
            }
            Expr::Concat(exprs) => exprs.iter().any(Self::expr_uses_property_tree),
            Expr::PostIncrement(e, _) | Expr::PreIncrement(e, _) => Self::expr_uses_property_tree(e),
            Expr::AssignExpr(_, e) => Self::expr_uses_property_tree(e),
            Expr::ObjectLit(pairs) => pairs.iter().any(|(_, e)| Self::expr_uses_property_tree(e)),
            Expr::ArrayLit(exprs) => exprs.iter().any(Self::expr_uses_property_tree),
            Expr::GetlineExpr(_, _) => false,
        }
    }

    /// True if any expression in the program can produce a container value
    /// (ObjectLit / ArrayLit). When false, scope variables can never shadow
    /// array names, so container-shadow scope scans can be skipped.
    pub(super) fn program_has_container_literals(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_has = rule
                .pattern
                .as_ref()
                .is_some_and(Self::pattern_has_container);
            let action_has = rule
                .action
                .as_ref()
                .map(|a| Self::block_has_container(&a.statements))
                .unwrap_or(false);
            pattern_has || action_has
        }) || program
            .functions
            .iter()
            .any(|f| Self::block_has_container(&f.body.statements))
    }

    pub(super) fn pattern_has_container(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_has_container(expr),
            Pattern::Range(start, end) => {
                Self::pattern_has_container(start) || Self::pattern_has_container(end)
            }
        }
    }

    pub(super) fn block_has_container(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_has_container)
    }

    pub(super) fn stmt_has_container(stmt: &Statement) -> bool {
        match stmt {
            Statement::Expr(e) => Self::expr_has_container(e),
            Statement::Print(es) => es.iter().any(Self::expr_has_container),
            Statement::Printf(f, args) => {
                Self::expr_has_container(f) || args.iter().any(Self::expr_has_container)
            }
            Statement::PrintRedirect(es, _, t) => {
                es.iter().any(Self::expr_has_container) || Self::expr_has_container(t)
            }
            Statement::PrintfRedirect(f, args, _, t) => {
                Self::expr_has_container(f)
                    || args.iter().any(Self::expr_has_container)
                    || Self::expr_has_container(t)
            }
            Statement::Assign(_, v) => Self::expr_has_container(v),
            Statement::CompoundAssign(_, _, v) => Self::expr_has_container(v),
            Statement::ArrayAssign(_, i, v) => {
                Self::expr_has_container(i) || Self::expr_has_container(v)
            }
            Statement::FieldAssign(_, v) => Self::expr_has_container(v),
            Statement::If(c, t, e) => {
                Self::expr_has_container(c)
                    || Self::stmt_has_container(t)
                    || e.as_ref().is_some_and(|s| Self::stmt_has_container(s))
            }
            Statement::While(c, b) => Self::expr_has_container(c) || Self::stmt_has_container(b),
            Statement::For(i, c, u, b) => {
                i.as_ref().is_some_and(|s| Self::stmt_has_container(s))
                    || c.as_ref().is_some_and(|e| Self::expr_has_container(e))
                    || u.as_ref().is_some_and(|e| Self::expr_has_container(e))
                    || Self::stmt_has_container(b)
            }
            Statement::ForIn(_, _, b) => Self::stmt_has_container(b),
            Statement::Block(ss) => ss.iter().any(Self::stmt_has_container),
            #[allow(clippy::redundant_closure)]
            Statement::Return(e) => e.as_ref().is_some_and(|e| Self::expr_has_container(e)),
            _ => false,
        }
    }

    pub(super) fn expr_has_container(expr: &Expr) -> bool {
        match expr {
            Expr::ObjectLit(_) | Expr::ArrayLit(_) => true,
            Expr::BinOp(l, _, r) => Self::expr_has_container(l) || Self::expr_has_container(r),
            Expr::UnaryOp(_, e) => Self::expr_has_container(e),
            Expr::FuncCall(_, args) => args.iter().any(Self::expr_has_container),
            Expr::ArrayAccess(_, i) => Self::expr_has_container(i),
            Expr::Match(e, _) | Expr::NotMatch(e, _) => Self::expr_has_container(e),
            Expr::Ternary(c, t, f) => {
                Self::expr_has_container(c)
                    || Self::expr_has_container(t)
                    || Self::expr_has_container(f)
            }
            Expr::Concat(es) => es.iter().any(Self::expr_has_container),
            Expr::PostIncrement(e, _) | Expr::PreIncrement(e, _) => Self::expr_has_container(e),
            Expr::AssignExpr(_, e) => Self::expr_has_container(e),
            _ => false,
        }
    }

    pub(super) fn program_needs_fields(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_needs = rule
                .pattern
                .as_ref()
                .is_some_and(Self::pattern_needs_fields);
            let action_needs = rule
                .action
                .as_ref()
                .map(|a| Self::block_needs_fields(&a.statements))
                .unwrap_or(false);
            pattern_needs || action_needs
        })
    }

    pub(super) fn pattern_needs_fields(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_needs_fields(expr),
            Pattern::Range(start, end) => {
                Self::pattern_needs_fields(start) || Self::pattern_needs_fields(end)
            }
        }
    }

    pub(super) fn block_needs_fields(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_needs_fields)
    }

    pub(super) fn stmt_needs_fields(stmt: &Statement) -> bool {
        match stmt {
            Statement::Expr(expr) => Self::expr_needs_fields(expr),
            Statement::Print(exprs) => exprs.iter().any(Self::expr_needs_fields),
            Statement::Printf(fmt, args) => {
                Self::expr_needs_fields(fmt) || args.iter().any(Self::expr_needs_fields)
            }
            Statement::PrintRedirect(exprs, _, target) => {
                exprs.iter().any(Self::expr_needs_fields) || Self::expr_needs_fields(target)
            }
            Statement::PrintfRedirect(fmt, args, _, target) => {
                Self::expr_needs_fields(fmt)
                    || args.iter().any(Self::expr_needs_fields)
                    || Self::expr_needs_fields(target)
            }
            Statement::Assign(_, value) => Self::expr_needs_fields(value),
            Statement::CompoundAssign(_, _, value) => Self::expr_needs_fields(value),
            Statement::ArrayAssign(_, idx, value) => {
                Self::expr_needs_fields(idx) || Self::expr_needs_fields(value)
            }
            Statement::FieldAssign(_, _) => true,
            Statement::If(cond, then_s, else_s) => {
                Self::expr_needs_fields(cond)
                    || Self::stmt_needs_fields(then_s)
                    || else_s.as_ref().is_some_and(|s| Self::stmt_needs_fields(s))
            }
            Statement::While(cond, body) => {
                Self::expr_needs_fields(cond) || Self::stmt_needs_fields(body)
            }
            Statement::For(init, cond, incr, body) => {
                init.as_ref().is_some_and(|s| Self::stmt_needs_fields(s))
                    || cond.as_ref().is_some_and(|e| Self::expr_needs_fields(e))
                    || incr.as_ref().is_some_and(|e| Self::expr_needs_fields(e))
                    || Self::stmt_needs_fields(body)
            }
            Statement::ForIn(_, _, body) => Self::stmt_needs_fields(body),
            Statement::Block(stmts) => stmts.iter().any(Self::stmt_needs_fields),
            Statement::Return(expr) => expr.as_ref().is_some_and(Self::expr_needs_fields),
            Statement::Getline(var, _) => var.is_some(),
            Statement::Increment(_, _)
            | Statement::Next
            | Statement::NextFile
            | Statement::Break
            | Statement::Continue
            | Statement::Delete(_, _)
            | Statement::DeleteAll(_)
            | Statement::Close(_) => false,
        }
    }

    pub(super) fn expr_needs_fields(expr: &Expr) -> bool {
        match expr {
            Expr::Field(_) => true,
            Expr::Record => false, // $0 doesn't need field splitting
            Expr::Var(name) => name == "NF" || name == "FILENAME",
            Expr::Number(_) | Expr::String(_) | Expr::BoolLit(_) | Expr::NullLit => false,
            Expr::BinOp(l, _, r) => Self::expr_needs_fields(l) || Self::expr_needs_fields(r),
            Expr::UnaryOp(_, e) => Self::expr_needs_fields(e),
            Expr::FuncCall(_, args) | Expr::QualifiedFuncCall { args, .. } => {
                args.iter().any(Self::expr_needs_fields)
            }
            Expr::ArrayAccess(_, idx) => Self::expr_needs_fields(idx),
            Expr::Match(e, _) | Expr::NotMatch(e, _) => Self::expr_needs_fields(e),
            Expr::Ternary(c, t, f) => {
                Self::expr_needs_fields(c)
                    || Self::expr_needs_fields(t)
                    || Self::expr_needs_fields(f)
            }
            Expr::Concat(exprs) => exprs.iter().any(Self::expr_needs_fields),
            Expr::PostIncrement(e, _) | Expr::PreIncrement(e, _) => Self::expr_needs_fields(e),
            Expr::AssignExpr(_, e) => Self::expr_needs_fields(e),
            Expr::GetlineExpr(_, _) => true,
            Expr::ObjectLit(pairs) => pairs.iter().any(|(_, e)| Self::expr_needs_fields(e)),
            Expr::ArrayLit(exprs) => exprs.iter().any(Self::expr_needs_fields),
            Expr::DotAccess(e, _) => Self::expr_needs_fields(e),
            Expr::IndexExpr(e, idx) => Self::expr_needs_fields(e) || Self::expr_needs_fields(idx),
        }
    }

}

// === Field splitting and pattern matching ===

impl<'a> Evaluator<'a> {
    pub(super) fn split_fields_inplace(&mut self) -> AwkResult<()> {
        self.field.fields.clear();
        self.field.field_ranges.clear();
        self.field.fields_modified = false;

        // If FPAT is set, use field pattern splitting (gawk extension)
        if !self.fpat.is_empty() {
            self.field.fields.push(String::new()); // $0 placeholder
            let rust_fpat = regex_escape_to_rust(&self.fpat);
            let line = std::mem::take(&mut self.field.line_buf); // avoid clone: take ownership temporarily
            match self.regex.get_or_compile(&rust_fpat) {
                Ok(re) => {
                    for m in re.find_iter(&line) {
                        self.field.fields.push(m.as_str().to_string());
                    }
                }
                Err(_) => {
                    self.field.fields.push(line.clone());
                }
            }
            self.field.line_buf = line;
            self.nf = self.field.fields.len() - 1;
            self.field.fields_modified = true;
            return Ok(());
        }

        if self.fs == " " {
            // HOT PATH: Single-pass byte-oriented whitespace splitting.
            // No String allocations — just record byte ranges into line_buf.
            // Merged has_whitespace + split into one pass to avoid double-scanning.
            let bytes = self.field.line_buf.as_bytes();
            let len = bytes.len();
            let mut i = 0;
            // Skip leading whitespace
            while i < len && WS_TABLE[bytes[i] as usize] {
                i += 1;
            }
            if i >= len {
                // No fields (empty or all-whitespace line)
            } else {
                let start = i;
                // Scan for next whitespace or end
                while i < len && !WS_TABLE[bytes[i] as usize] {
                    i += 1;
                }
                if i >= len {
                    // Ultra-fast path: no whitespace found — entire line is one field
                    self.field.field_ranges.push((start, len));
                } else {
                    // Multi-field path: record first field, continue scanning
                    self.field.field_ranges.push((start, i));
                    while i < len {
                        // Skip whitespace
                        while i < len && WS_TABLE[bytes[i] as usize] {
                            i += 1;
                        }
                        if i >= len {
                            break;
                        }
                        let s = i;
                        // Scan field
                        while i < len && !WS_TABLE[bytes[i] as usize] {
                            i += 1;
                        }
                        self.field.field_ranges.push((s, i));
                    }
                }
            }
        } else if self.fs.is_empty() {
            // FS="": split each character into its own field (materialize immediately)
            self.field.fields.push(String::new()); // $0 placeholder
            for ch in self.field.line_buf.chars() {
                self.field.fields.push(ch.to_string());
            }
        } else if self.fs.len() == 1 && !Self::is_regex_metachar(self.fs.as_bytes()[0]) {
            // HOT PATH: Single-byte literal FS (e.g. "," or ":" or "\t").
            // Use byte-range mode like whitespace splitting — no String allocations.
            let sep = self.fs.as_bytes()[0];
            let bytes = self.field.line_buf.as_bytes();
            let len = bytes.len();
            let mut start = 0;
            // Pre-allocate field_ranges for common case
            if self.field.field_ranges.capacity() < 16 {
                self.field.field_ranges.reserve(16);
            }
            // field_ranges already cleared at top of split_fields_inplace()
            let mut i = 0;
            while i < len {
                if bytes[i] == sep {
                    self.field.field_ranges.push((start, i));
                    start = i + 1;
                }
                i += 1;
            }
            self.field.field_ranges.push((start, len));
        } else {
            // Regex/literal FS split (materialize immediately)
            self.field.fields.push(String::new()); // $0 placeholder
            let rust_fs = regex_escape_to_rust(&self.fs);
            let line = self.field.line_buf.clone(); // need owned for regex borrow
            match self.regex.get_or_compile(&rust_fs) {
                Ok(re) => {
                    let mut last_end = 0;
                    for m in re.find_iter(&line) {
                        self.field
                            .fields
                            .push(line[last_end..m.start()].to_string());
                        last_end = m.end();
                    }
                    self.field.fields.push(line[last_end..].to_string());
                    if line.starts_with(&self.fs) && self.field.fields.len() > 1 {
                        self.field.fields.remove(1);
                    }
                }
                Err(_) => {
                    for field in line.split(&self.fs) {
                        self.field.fields.push(field.to_string());
                    }
                }
            }
        }

        self.nf = if !self.field.field_ranges.is_empty() {
            self.field.field_ranges.len()
        } else {
            self.field.fields.len() - 1
        };

        if self.field.fields.len() > MAX_FIELDS {
            self.security.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_FIELDS".to_string(),
                limit_value: MAX_FIELDS,
                actual_value: self.field.fields.len(),
            });
            return Err(AwkError::RuntimeError(format!(
                "Field count {} exceeds maximum allowed ({})",
                self.field.fields.len(),
                MAX_FIELDS
            )));
        }
        Ok(())
    }

    /// Split an arbitrary string into fields, storing result in line_buf.
    /// Used by getline, sub/gsub when target is $0.
    #[inline]
    pub(super) fn split_fields_from(&mut self, line: &str) -> AwkResult<()> {
        // Security: enforce same 16MB limit as input records
        if line.len() > 16_777_216 {
            return Err(AwkError::RuntimeError(
                "Record exceeds maximum size (16 MB)".to_string(),
            ));
        }
        self.field.line_buf.clear();
        self.field.line_buf.push_str(line);
        self.split_fields_inplace()
    }

    /// Check if a pattern string contains no regex metacharacters (static literal).
    #[inline]
    pub(super) fn is_literal_pattern_str(pattern: &str) -> bool {
        !pattern.bytes().any(Self::is_regex_metachar)
    }

    /// Check if a byte is a regex metacharacter.
    #[inline]
    pub(super) fn is_regex_metachar(b: u8) -> bool {
        matches!(
            b,
            b'.' | b'*'
                | b'+'
                | b'?'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'\\'
                | b'^'
                | b'$'
                | b'|'
        )
    }

    pub(super) fn matches_regex(&mut self, text: &str, pattern: &str) -> AwkResult<bool> {
        // Fast path 1: literal substring match (no regex metacharacters)
        if Self::is_literal_pattern(pattern) {
            return Ok(text.contains(pattern));
        }
        // Fast path 2: simple digit pattern [0-9]+ — use byte scanning
        if pattern == "[0-9]+" || pattern == "[[:digit:]]+" {
            return Ok(text.bytes().any(|b| b.is_ascii_digit()));
        }
        // Fast path 3: simple alpha pattern [a-zA-Z]+ — use byte scanning
        if pattern == "[a-zA-Z]+" || pattern == "[[:alpha:]]+" {
            return Ok(text.bytes().any(|b| b.is_ascii_alphabetic()));
        }
        // Fast path 4: simple whitespace pattern
        if pattern == "[ \t]+" || pattern == "[[:space:]]+" {
            return Ok(text.bytes().any(|b| b == b' ' || b == b'\t'));
        }
        // AWK patterns are already valid Rust regex syntax (no escaping needed)
        let re = self.regex.get_or_compile(pattern)?;
        Ok(re.is_match(text))
    }

    /// Check if an AWK regex pattern is a literal string (no regex metacharacters).
    /// This enables a fast path using simple substring search instead of the regex engine.
    pub(super) fn is_literal_pattern(pattern: &str) -> bool {
        if pattern.is_empty() {
            return true;
        }
        !pattern.bytes().any(|b| {
            matches!(
                b,
                b'.' | b'*'
                    | b'+'
                    | b'?'
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'\\'
                    | b'^'
                    | b'$'
                    | b'|'
            )
        })
    }

    pub(super) fn pattern_matches(&mut self, pattern: &Pattern, line: &str) -> AwkResult<bool> {
        match pattern {
            Pattern::Regex(re) => self.matches_regex(line, re),
            Pattern::Expression(expr) => {
                let val = self.eval_expr(expr)?;
                Ok(val.is_truthy())
            }
            _ => Ok(false),
        }
    }

    pub(super) fn regex_match_pos(&mut self, text: &str, pattern: &str) -> AwkResult<Option<(usize, usize)>> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.regex.get_or_compile(&rust_pattern)?;
        Ok(re.find(text).map(|m| (m.start() + 1, m.end() - m.start())))
    }

}

// === Formatting and string utility methods ===

impl<'a> Evaluator<'a> {
    pub(super) fn awk_split(&mut self, s: &str, sep: &str) -> AwkResult<Vec<String>> {
        if s.is_empty() {
            return Ok(Vec::new());
        }
        if sep == " " {
            Ok(s.split_whitespace().map(String::from).collect())
        } else if sep.is_empty() {
            Ok(s.chars().map(|c| c.to_string()).collect())
        } else {
            let rust_sep = regex_escape_to_rust(sep);
            let re = self.regex.get_or_compile(&rust_sep)?;
            let mut result: Vec<String> = re.split(s).map(String::from).collect();
            while result.last().is_some_and(|s| s.is_empty()) {
                result.pop();
            }
            Ok(result)
        }
    }

    pub(super) fn awk_sub(
        &mut self,
        target: &str,
        pattern: &str,
        replacement: &str,
        global: bool,
    ) -> AwkResult<String> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.regex.get_or_compile(&rust_pattern)?.clone();
        if global {
            let mut result = String::with_capacity(target.len());
            let mut last_end = 0;
            for m in re.find_iter(target) {
                result.push_str(&target[last_end..m.start()]);
                result.push_str(&self.expand_replacement(replacement, m.as_str()));
                last_end = m.end();
                if m.start() == m.end() && last_end < target.len() {
                    result.push_str(&target[last_end..=last_end]);
                    last_end += 1;
                }
            }
            result.push_str(&target[last_end..]);
            Ok(result)
        } else if let Some(m) = re.find(target) {
            let mut result = String::with_capacity(target.len());
            result.push_str(&target[..m.start()]);
            result.push_str(&self.expand_replacement(replacement, m.as_str()));
            result.push_str(&target[m.end()..]);
            Ok(result)
        } else {
            Ok(target.to_string())
        }
    }

    pub(super) fn expand_replacement(&self, replacement: &str, matched: &str) -> String {
        // Fast path: if replacement has no & or \, return it directly
        if !replacement.contains('&') && !replacement.contains('\\') {
            return replacement.to_string();
        }
        let mut result = String::with_capacity(replacement.len() + matched.len());
        let mut chars = replacement.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == '&' {
                        result.push('&');
                        chars.next();
                        continue;
                    }
                    result.push('\\');
                } else {
                    result.push('\\');
                }
            } else if c == '&' {
                result.push_str(matched);
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Build an array key from an expression into the reusable `array_key_buf`.
    /// For Field access ($N), this avoids allocating a new String.
    /// For complex expressions, falls back to eval_expr.
    pub(super) fn build_array_key(&mut self, expr: &Expr) -> AwkResult<()> {
        self.array_key_buf.clear();
        match expr {
            Expr::Field(idx_expr) => {
                let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                if !self.field.fields_modified && !self.field.field_ranges.is_empty() {
                    if idx == 0 {
                        self.array_key_buf.push_str(&self.field.line_buf);
                    } else if let Some(&(start, end)) = self.field.field_ranges.get(idx - 1) {
                        // line_buf is always valid UTF-8, field boundaries align on char boundaries
                        self.array_key_buf
                            .push_str(&self.field.line_buf[start..end]);
                    }
                } else {
                    self.array_key_buf.push_str(&self.field.get_field(idx));
                }
            }
            Expr::Var(name) => {
                let val = self.get_variable(name);
                match val {
                    Value::Str(s) => self.array_key_buf.push_str(&s),
                    Value::Number(n) => {
                        use std::fmt::Write;
                        let _ = write!(self.array_key_buf, "{}", n);
                    }
                    Value::Uninit => {}
                    Value::Bool(true) => self.array_key_buf.push('1'),
                    Value::Bool(false) => self.array_key_buf.push('0'),
                    Value::Null => {}
                    Value::Object(_) | Value::Array(_) => {
                        self.array_key_buf.push_str(&val.as_string());
                    }
                }
            }
            Expr::String(s) => {
                self.array_key_buf.push_str(s);
            }
            _ => {
                let val = self.eval_expr(expr)?;
                self.array_key_buf.push_str(&val.as_string());
            }
        }
        Ok(())
    }

    /// Like awk_sub(global=true) but also returns the substitution count.
    pub(super) fn awk_sub_counted(
        &mut self,
        target: &str,
        pattern: &str,
        replacement: &str,
    ) -> AwkResult<(String, f64)> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.regex.get_or_compile(&rust_pattern)?.clone();
        // Pre-allocate: assume result is similar in size to target
        let mut result = String::with_capacity(target.len() + replacement.len());
        let mut last_end = 0;
        let mut count = 0f64;
        for m in re.find_iter(target) {
            result.push_str(&target[last_end..m.start()]);
            result.push_str(&self.expand_replacement(replacement, m.as_str()));
            last_end = m.end();
            count += 1.0;
            if m.start() == m.end() && last_end < target.len() {
                result.push_str(&target[last_end..=last_end]);
                last_end += 1;
            }
        }
        result.push_str(&target[last_end..]);
        Ok((result, count))
    }
    pub(super) fn format_ofmt(&self, n: &f64) -> String {
        // Use cached OFMT precision (avoids parsing on every call)
        let precision = self.ofmt_precision;
        if *n == 0.0 {
            return "0".to_string();
        }
        // Fast path: integer values use itoa (no format! overhead)
        if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
            let mut buf = itoa::Buffer::new();
            return buf.format(*n as i64).to_string();
        }
        // Note: ryu fast path removed — it outputs shortest round-trip representation
        // (e.g. 0.3333333333333333) instead of OFMT significant digits (0.333333).
        // The manual %g implementation below is correct for AWK semantics.
        if !n.is_finite() {
            return if n.is_nan() {
                "nan".to_string()
            } else if n.is_sign_positive() {
                "inf".to_string()
            } else {
                "-inf".to_string()
            };
        }
        let abs_n = n.abs();
        let exp = abs_n.log10().floor() as i32;
        if exp >= -4 && exp < precision as i32 {
            let decimals = (precision as i32 - 1 - exp) as usize;
            let s = format!("{:.prec$}", n, prec = decimals);
            if s.contains('.') {
                let s = s.trim_end_matches('0');
                let s = s.trim_end_matches('.');
                s.to_string()
            } else {
                s
            }
        } else {
            let scaled = n / 10f64.powi(exp);
            let s = format!("{:.prec$}", scaled, prec = precision - 1);
            let s = s.trim_end_matches('0');
            let s = s.trim_end_matches('.');
            let sign = if exp < 0 { "e-" } else { "e+" };
            format!("{}{}{:02}", s, sign, exp.abs())
        }
    }

    pub(super) fn format_strftime(&self, fmt: &str, timestamp: i64) -> String {
        // Minimal strftime — zero-dependency UTC timestamp formatting.
        // Supports: %Y %m %d %H %M %S %a %b %d %e %j %u %w %% %n %t %p %P
        let (y, mo, d, h, mi, s, wday) = Self::ts_to_components(timestamp);
        const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let yday = Self::day_of_year(y, mo, d);
        let mut out = String::with_capacity(fmt.len() + 16);
        let mut chars = fmt.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('Y') => {
                        let _ = write!(out, "{:04}", y);
                    }
                    Some('y') => {
                        let _ = write!(out, "{:02}", y % 100);
                    }
                    Some('m') => {
                        let _ = write!(out, "{:02}", mo);
                    }
                    Some('d') => {
                        let _ = write!(out, "{:02}", d);
                    }
                    Some('e') => {
                        let _ = write!(out, "{:>2}", d);
                    }
                    Some('H') => {
                        let _ = write!(out, "{:02}", h);
                    }
                    Some('M') => {
                        let _ = write!(out, "{:02}", mi);
                    }
                    Some('S') => {
                        let _ = write!(out, "{:02}", s);
                    }
                    Some('a') => {
                        out.push_str(DAYS[wday]);
                    }
                    Some('A') => {
                        out.push_str(match wday {
                            0 => "Sunday",
                            1 => "Monday",
                            2 => "Tuesday",
                            3 => "Wednesday",
                            4 => "Thursday",
                            5 => "Friday",
                            _ => "Saturday",
                        });
                    }
                    Some('b') | Some('h') => {
                        out.push_str(MONTHS[(mo - 1) as usize]);
                    }
                    Some('B') => {
                        out.push_str(match mo {
                            1 => "January",
                            2 => "February",
                            3 => "March",
                            4 => "April",
                            5 => "May",
                            6 => "June",
                            7 => "July",
                            8 => "August",
                            9 => "September",
                            10 => "October",
                            11 => "November",
                            _ => "December",
                        });
                    }
                    Some('j') => {
                        let _ = write!(out, "{:03}", yday);
                    }
                    Some('u') => {
                        let _ = write!(out, "{}", if wday == 0 { 7 } else { wday });
                    }
                    Some('w') => {
                        let _ = write!(out, "{}", wday);
                    }
                    Some('p') => {
                        out.push_str(if h < 12 { "AM" } else { "PM" });
                    }
                    Some('P') => {
                        out.push_str(if h < 12 { "am" } else { "pm" });
                    }
                    Some('n') => {
                        out.push('\n');
                    }
                    Some('t') => {
                        out.push('\t');
                    }
                    Some('%') => {
                        out.push('%');
                    }
                    Some(c) => {
                        out.push('%');
                        out.push(c);
                    }
                    None => {
                        out.push('%');
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    pub(super) fn parse_mktime(&self, datespec: &str) -> i64 {
        // Minimal mktime — zero-dependency date parsing to Unix timestamp.
        let parts: Vec<i32> = datespec
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        let parts = if parts.len() >= 6 {
            parts
        } else {
            let p: Vec<i32> = datespec
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if p.len() < 6 {
                return -1;
            }
            p
        };
        let (yr, mo, dy, hr, mi, sc) = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
        if !(1..=12).contains(&mo) || !(1..=31).contains(&dy) || hr > 23 || mi > 59 || sc > 59 {
            return -1;
        }
        if !(0..=9999).contains(&yr) {
            return -1;
        }
        Self::ymd_hms_to_timestamp(yr, mo as u32, dy as u32, hr as u32, mi as u32, sc as u32)
    }

    // ── Minimal date/time helpers (replaces chrono) ──────────────────────

    pub(super) fn is_leap_year(y: i32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    pub(super) fn days_in_month(y: i32, m: u32) -> u32 {
        match m {
            1 => 31,
            2 => {
                if Self::is_leap_year(y) {
                    29
                } else {
                    28
                }
            }
            3 => 31,
            4 => 30,
            5 => 31,
            6 => 30,
            7 => 31,
            8 => 31,
            9 => 30,
            10 => 31,
            11 => 30,
            12 => 31,
            _ => 0,
        }
    }

    pub(super) fn day_of_year(y: i32, m: u32, d: u32) -> u32 {
        let mut yday = 0u32;
        for i in 1..m {
            yday += Self::days_in_month(y, i);
        }
        yday + d
    }

    /// Convert Unix timestamp to (year, month, day, hour, minute, second, weekday).
    /// weekday: 0=Sun, 1=Mon, ..., 6=Sat
    pub(super) fn ts_to_components(ts: i64) -> (i32, u32, u32, u32, u32, u32, usize) {
        let secs = ts.rem_euclid(86400) as u32;
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        let mut days = ts.div_euclid(86400);
        // 1970-01-01 was Thursday (wday=4)
        let wday = ((days % 7) + 4).rem_euclid(7) as usize;
        let mut y = 1970;
        loop {
            if y > 9999 {
                return (9999, 12, 31, 23, 59, 59, 5);
            }
            let yd = if Self::is_leap_year(y) { 366 } else { 365 };
            if days < yd {
                break;
            }
            days -= yd;
            y += 1;
        }
        let mut mo = 1u32;
        loop {
            let md = Self::days_in_month(y, mo);
            if days < md as i64 {
                break;
            }
            days -= md as i64;
            mo += 1;
        }
        let d = (days + 1) as u32;
        (y, mo, d, h, m, s, wday)
    }

    /// Convert ymdhms to Unix timestamp (UTC).
    pub(super) fn ymd_hms_to_timestamp(yr: i32, mo: u32, dy: u32, hr: u32, mi: u32, sc: u32) -> i64 {
        // Days from 1970-01-01 to yr-mo-dy
        let mut days: i64 = 0;
        let yr = yr.clamp(0, 9999);
        if yr >= 1970 {
            for y in 1970..yr {
                days += if Self::is_leap_year(y) { 366 } else { 365 };
            }
        } else {
            for y in yr..1970 {
                days -= if Self::is_leap_year(y) { 366 } else { 365 };
            }
        }
        for m in 1..mo {
            days += Self::days_in_month(yr, m) as i64;
        }
        days += (dy - 1) as i64;
        days * 86400 + hr as i64 * 3600 + mi as i64 * 60 + sc as i64
    }

    pub(super) fn format_printf(&self, fmt: &str, args: &[Value]) -> String {
        // Pre-allocate buffer: format string length + estimated expansion per argument
        let mut result = String::with_capacity(fmt.len() + args.len() * 16);
        let mut chars = fmt.chars().peekable();
        let mut arg_idx = 0;

        while let Some(c) = chars.next() {
            if c == '%' {
                if chars.peek() == Some(&'%') {
                    chars.next();
                    result.push('%');
                    continue;
                }
                let mut flags = String::new();
                while let Some(&fc) = chars.peek() {
                    if matches!(fc, '-' | '+' | ' ' | '#' | '0') {
                        flags.push(fc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let mut width = String::new();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_digit() || d == '*' {
                        width.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let width: i32 = if width == "*" {
                    if arg_idx < args.len() {
                        let w = args[arg_idx].as_number() as i32;
                        arg_idx += 1;
                        w
                    } else {
                        0
                    }
                } else {
                    width.parse().unwrap_or(0)
                };
                let mut precision = None;
                if chars.peek() == Some(&'.') {
                    chars.next();
                    let mut prec_str = String::new();
                    while let Some(&d) = chars.peek() {
                        if d.is_ascii_digit() || d == '*' {
                            prec_str.push(d);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    precision = Some(if prec_str == "*" {
                        if arg_idx < args.len() {
                            let p = args[arg_idx].as_number() as i32;
                            arg_idx += 1;
                            p
                        } else {
                            0
                        }
                    } else if prec_str.is_empty() {
                        0
                    } else {
                        prec_str.parse::<i32>().unwrap_or(0).clamp(0, 1_000_000)
                    });
                }
                if let Some(&spec) = chars.peek() {
                    chars.next();
                    if arg_idx >= args.len() && !matches!(spec, '%') {
                        continue;
                    }
                    let arg = if arg_idx < args.len() {
                        &args[arg_idx]
                    } else {
                        &Value::Uninit
                    };
                    let formatted = match spec {
                        'd' | 'i' => {
                            let n = arg.as_number() as i64;
                            format_int(n, &flags, width)
                        }
                        'o' => {
                            let n = arg.as_number() as i64;
                            let s = format!("{:o}", n);
                            pad_string(&s, &flags, width, precision)
                        }
                        'x' => {
                            let n = arg.as_number() as i64;
                            let s = format!("{:x}", n);
                            pad_string(&s, &flags, width, precision)
                        }
                        'X' => {
                            let n = arg.as_number() as i64;
                            let s = format!("{:X}", n);
                            pad_string(&s, &flags, width, precision)
                        }
                        'u' => {
                            let n = arg.as_number() as u64;
                            format!("{}", n)
                        }
                        'f' => {
                            let n = arg.as_number();
                            let prec = precision.unwrap_or(6);
                            let s = format!("{:.prec$}", n, prec = (prec as usize).min(10000));
                            pad_float(&s, &flags, width)
                        }
                        'e' => {
                            let n = arg.as_number();
                            let prec = precision.unwrap_or(6);
                            let s = format!("{:.prec$e}", n, prec = (prec as usize).min(10000));
                            format_exponent(&s)
                        }
                        'E' => {
                            let n = arg.as_number();
                            let prec = precision.unwrap_or(6);
                            let s = format!("{:.prec$E}", n, prec = (prec as usize).min(10000));
                            format_exponent(&s)
                        }
                        'g' | 'G' => {
                            let n = arg.as_number();
                            let prec = if let Some(p) = precision {
                                if p == 0 {
                                    1
                                } else {
                                    (p as usize).min(10000)
                                }
                            } else {
                                6
                            };
                            let s = format!("{:.prec$}", n, prec = prec);
                            let s = if s.contains('.') {
                                let s = s.trim_end_matches('0');
                                let s = s.trim_end_matches('.');
                                s.to_string()
                            } else {
                                s
                            };
                            if spec == 'G' {
                                s.to_uppercase()
                            } else {
                                s
                            }
                        }
                        's' => {
                            let s = arg.as_string();
                            let s = if let Some(prec) = precision {
                                if prec >= 0 {
                                    s.chars().take(prec as usize).collect()
                                } else {
                                    s
                                }
                            } else {
                                s
                            };
                            if flags.contains('-') {
                                format!("{:<width$}", s, width = (width as usize).min(10000))
                            } else if width > 0 {
                                format!("{:>width$}", s, width = (width as usize).min(10000))
                            } else {
                                s
                            }
                        }
                        'c' => {
                            let n = arg.as_number() as u32;
                            if let Some(ch) = char::from_u32(n) {
                                ch.to_string()
                            } else {
                                String::new()
                            }
                        }
                        _ => {
                            result.push('%');
                            result.push(spec);
                            arg_idx += 1;
                            continue;
                        }
                    };
                    result.push_str(&formatted);
                    arg_idx += 1;
                }
            } else if c == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('t') => result.push('\t'),
                    Some('r') => result.push('\r'),
                    Some('\\') => result.push('\\'),
                    Some('a') => result.push('\x07'),
                    Some('b') => result.push('\x08'),
                    Some('f') => result.push('\x0C'),
                    Some('v') => result.push('\x0B'),
                    Some(c) => {
                        result.push('\\');
                        result.push(c);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }
        result
    }
}


// Helper functions

fn format_int(n: i64, flags: &str, width: i32) -> String {
    let width = width.min(10000);
    let sign = if flags.contains('+') {
        if n >= 0 {
            "+"
        } else {
            ""
        }
    } else if flags.contains(' ') {
        if n >= 0 {
            " "
        } else {
            ""
        }
    } else {
        ""
    };
    let abs_val = n.unsigned_abs();
    let abs_str = itoa::Buffer::new().format(abs_val).to_string();
    let full = if n < 0 {
        format!("-{}", abs_str)
    } else {
        format!("{}{}", sign, abs_str)
    };
    if width > 0 {
        if flags.contains('-') {
            format!("{:<width$}", full, width = width as usize)
        } else if flags.contains('0') && !flags.contains('-') {
            if n < 0 {
                let padding = (width as usize).saturating_sub(full.len());
                format!("-{:0>pad$}", abs_str, pad = padding)
            } else {
                format!("{:0>width$}", full, width = width as usize)
            }
        } else {
            format!("{:>width$}", full, width = width as usize)
        }
    } else {
        full
    }
}

fn pad_string(s: &str, flags: &str, width: i32, _precision: Option<i32>) -> String {
    if width > 0 {
        let width = width.min(10000);
        if flags.contains('-') {
            format!("{:<width$}", s, width = width as usize)
        } else {
            format!("{:>width$}", s, width = width as usize)
        }
    } else {
        s.to_string()
    }
}

fn pad_float(s: &str, flags: &str, width: i32) -> String {
    if width > 0 {
        let width = width.min(10000);
        if flags.contains('-') {
            format!("{:<width$}", s, width = width as usize)
        } else if flags.contains('0') {
            format!("{:0>width$}", s, width = width as usize)
        } else {
            format!("{:>width$}", s, width = width as usize)
        }
    } else {
        s.to_string()
    }
}

/// AWK uses ERE (Extended Regular Expressions).
/// The `regex` crate supports ERE syntax natively.
/// Pre-filter for regex patterns: allows skipping the regex engine entirely
/// when a simple byte check can determine non-match.
#[derive(Clone)]
pub(super) struct RegexPreFilter {
    /// If true, the pattern is exact (no regex metacharacters) and we can
    /// use simple substring search.
    exact: bool,
    /// For exact mode, the literal string to search for.
    literal: String,
}

impl RegexPreFilter {
    pub(super) fn new(pattern: &str) -> Self {
        let rust_pat = regex_escape_to_rust(pattern);
        // Check if the pattern is purely literal (no regex metacharacters)
        let is_literal = !rust_pat.bytes().any(|b| {
            matches!(
                b,
                b'.' | b'*'
                    | b'+'
                    | b'?'
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'\\'
                    | b'^'
                    | b'$'
                    | b'|'
            )
        });
        RegexPreFilter {
            exact: is_literal,
            literal: if is_literal { rust_pat } else { String::new() },
        }
    }

    /// Returns Some(true) if the pre-filter confirms a match without regex,
    /// Some(false) if it confirms no match, None if regex is needed.
    pub(super) fn check<'a>(&'a self, line: &'a str) -> Option<bool> {
        if self.exact {
            Some(line.contains(&self.literal))
        } else {
            None
        }
    }
}

pub(super) fn regex_escape_to_rust(pattern: &str) -> String {
    pattern.to_string()
}

/// Parse the leading numeric prefix of a string, per AWK semantics.
/// "10abc" -> 10.0, "3.14xyz" -> 3.14, "abc" -> 0.0
/// Handles leading whitespace, optional sign, digits, optional decimal point, and exponent.
static WS_TABLE: [bool; 256] = {
    let mut t = [false; 256];
    t[b' ' as usize] = true;
    t[b'\t' as usize] = true;
    t[b'\n' as usize] = true;
    t[b'\r' as usize] = true;
    t[0x0b] = true;
    t[0x0c] = true;
    t
};

#[inline]
pub(super) fn has_whitespace(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| WS_TABLE[b as usize])
}

pub(super) fn awk_str_to_number(s: &str) -> f64 {
    // Fast path: empty string
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Fast path: single character
    if len == 1 {
        return match bytes[0] {
            b'0' => 0.0,
            b'1' => 1.0,
            b'2' => 2.0,
            b'3' => 3.0,
            b'4' => 4.0,
            b'5' => 5.0,
            b'6' => 6.0,
            b'7' => 7.0,
            b'8' => 8.0,
            b'9' => 9.0,
            _ => 0.0,
        };
    }

    // Fast path: skip leading whitespace manually (common case: no whitespace)
    let trimmed = if bytes[0] == b' ' || bytes[0] == b'\t' {
        s.trim_start()
    } else {
        s
    };
    if trimmed.is_empty() {
        return 0.0;
    }
    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Fast path: 2-digit integer (very common: "10"-"99")
    if len == 2 && bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit() {
        return ((bytes[0] - b'0') * 10 + (bytes[1] - b'0')) as f64;
    }

    // Fast path: short integer (3-5 digits, no sign, no decimal)
    if (3..=5).contains(&len) && bytes[0].is_ascii_digit() {
        let mut all_digits = true;
        let mut val: u32 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() {
                all_digits = false;
                break;
            }
            val = val * 10 + (b - b'0') as u32;
        }
        if all_digits {
            return val as f64;
        }
    }

    // Fast path: all-ascii-digit string up to 18 digits (exact in f64)
    if (5..=18).contains(&len) && bytes[0].is_ascii_digit() {
        let mut all_digits = true;
        let mut val: u64 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() {
                all_digits = false;
                break;
            }
            val = val * 10 + (b - b'0') as u64;
        }
        if all_digits {
            return val as f64;
        }
    }

    // Find the longest numeric prefix
    let mut end = 0;
    let bytes = trimmed.as_bytes();
    let len = bytes.len();

    // Optional sign
    if end < len && (bytes[end] == b'+' || bytes[end] == b'-') {
        end += 1;
    }

    // Check for hex: 0x or 0X
    if end + 1 < len && bytes[end] == b'0' && (bytes[end + 1] == b'x' || bytes[end + 1] == b'X') {
        end += 2;
        let start = end;
        while end < len && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end == start {
            return 0.0;
        }
        let hex_str = &trimmed[..end];
        return i64::from_str_radix(&hex_str[2..], 16)
            .map(|v| v as f64)
            .unwrap_or(0.0);
    }

    // Digits before decimal
    let has_digits = end < len && bytes[end].is_ascii_digit();
    while end < len && bytes[end].is_ascii_digit() {
        end += 1;
    }

    // Optional decimal point and digits after
    if end < len && bytes[end] == b'.' {
        end += 1;
        while end < len && bytes[end].is_ascii_digit() {
            end += 1;
        }
    }

    // If no digits at all before or after decimal, return 0
    if !has_digits
        && end > 0
        && (bytes.first() == Some(&b'.')
            || (end > 1 && (bytes[0] == b'+' || bytes[0] == b'-') && bytes.get(1) == Some(&b'.')))
    {
        // Check if there were any digits after the dot
        let digit_start = if bytes[0] == b'+' || bytes[0] == b'-' {
            1
        } else {
            0
        };
        let has_any_digit =
            (digit_start..end).any(|i| bytes.get(i).is_some_and(|b| b.is_ascii_digit()));
        if !has_any_digit {
            return 0.0;
        }
    } else if !(has_digits || (end > 0 && bytes.first().is_some_and(|b| *b == b'+' || *b == b'-')))
    {
        return 0.0;
    }

    // Optional exponent
    if end < len && (bytes[end] == b'e' || bytes[end] == b'E') {
        let exp_start = end;
        end += 1;
        if end < len && (bytes[end] == b'+' || bytes[end] == b'-') {
            end += 1;
        }
        if end < len && bytes[end].is_ascii_digit() {
            while end < len && bytes[end].is_ascii_digit() {
                end += 1;
            }
        } else {
            // No digits after exponent marker, don't consume it
            end = exp_start;
        }
    }

    if end == 0 {
        return 0.0;
    }

    trimmed[..end].parse::<f64>().unwrap_or(0.0)
}

/// Format exponent in scientific notation to match gawk's output.
fn format_exponent(s: &str) -> String {
    for marker in &['e', 'E'] {
        if let Some(pos) = s.find(*marker) {
            let (mantissa, exp_part) = s.split_at(pos);
            let exp_str = &exp_part[1..];
            let (sign, digits) = if let Some(stripped) = exp_str.strip_prefix('-') {
                ("-", stripped)
            } else if let Some(stripped) = exp_str.strip_prefix('+') {
                ("+", stripped)
            } else {
                ("+", exp_str)
            };
            let exp_val: usize = digits.parse().unwrap_or(0);
            return format!("{}{}{}{:02}", mantissa, marker, sign, exp_val);
        }
    }
    s.to_string()
}

/// Parse JSON string into Value via PropertyTree (single source of truth).
/// Defined in input module; re-exported here for use by builtin functions.

impl<'a> Evaluator<'a> {
    /// Collect all user-defined variables in the current scope into an Object.
    /// Used by expression language extensions for variable injection (Phase 2).
    pub fn collect_scope_variables(&self) -> Value {
        let mut pairs = Vec::new();
        // Use the global scope (index 0) for variable collection
        if let Some(scope) = self.scope.scope_stack.first() {
            for (name, val) in scope {
                if is_user_variable(name) {
                    pairs.push((name.clone(), val.clone()));
                }
            }
        }
        Value::Object(pairs)
    }
}

fn is_user_variable(name: &str) -> bool {
    !matches!(
        name,
        "NR" | "NF"
            | "FS"
            | "RS"
            | "OFS"
            | "ORS"
            | "OFMT"
            | "FILENAME"
            | "FNR"
            | "SUBSEP"
            | "RSTART"
            | "RLENGTH"
            | "ARGC"
            | "ARGV"
            | "ENVIRON"
            | "ERRNO"
            | "CONVFMT"
            | "FPAT"
    )
}

