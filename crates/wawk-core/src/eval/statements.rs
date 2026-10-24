//! Statement execution for the AWK evaluator.

use super::*;
use crate::eval::output::serialize_for_output;
use super::helpers::awk_str_to_number;

impl<'a> Evaluator<'a> {
    pub(super) fn exec_statements(&mut self, stmts: &[Statement]) -> AwkResult<EvalSignal> {
        for stmt in stmts {
            let signal = self.exec_statement(stmt)?;
            if !matches!(signal, EvalSignal::None) {
                return Ok(signal);
            }
        }
        Ok(EvalSignal::None)
    }

    pub(super) fn exec_statement(&mut self, stmt: &Statement) -> AwkResult<EvalSignal> {
        match stmt {
            Statement::Print(exprs) => {
                if exprs.is_empty() {
                    // Fast path for bare `print`
                    if let Some(ref pt) = self.property_tree {
                        let val = Value::from_property_tree(pt);
                        let json_str = crate::eval::output::serialize_output(
                            &val,
                            &self.format_registry,
                            self.output_format.as_deref(),
                        )
                        .unwrap_or_else(|| serialize_for_output(&val));
                        self.security.output_bytes = self
                            .security
                            .output_bytes
                            .saturating_add(json_str.len() + self.ors.len());
                        if self.security.output_bytes > MAX_OUTPUT_BYTES {
                            return Err(AwkError::RuntimeError(format!(
                                "Output size limit exceeded ({} MB max)",
                                MAX_OUTPUT_BYTES / (1024 * 1024)
                            )));
                        }
                        self.writer.write_str(&json_str)?;
                        self.writer.write_str(&self.ors)?;
                        return Ok(EvalSignal::None);
                    }
                    // Text mode: zero-copy
                    self.security.output_bytes = self
                        .security
                        .output_bytes
                        .saturating_add(self.field.line_buf.len() + self.ors.len());
                    // Security: amortized output limit check (every 1024 records)
                    if (self.nr & 1023) == 0 && self.security.output_bytes > MAX_OUTPUT_BYTES {
                        self.security.record_audit(AuditEvent::LimitViolation {
                            limit_name: "MAX_OUTPUT_BYTES".to_string(),
                            limit_value: MAX_OUTPUT_BYTES,
                            actual_value: self.security.output_bytes,
                        });
                        return Err(AwkError::RuntimeError(format!(
                            "Output size limit exceeded ({} MB max)",
                            MAX_OUTPUT_BYTES / (1024 * 1024)
                        )));
                    }
                    self.writer.write_str(&self.field.line_buf)?;
                    self.writer.write_str(&self.ors)?;
                    return Ok(EvalSignal::None);
                }
                // Fast path for `print $0`
                if exprs.len() == 1 {
                    if let Expr::Record = &exprs[0] {
                        if let Some(ref pt) = self.property_tree {
                            let val = Value::from_property_tree(pt);
                            let json_str = crate::eval::output::serialize_output(
                                &val,
                                &self.format_registry,
                                self.output_format.as_deref(),
                            )
                            .unwrap_or_else(|| serialize_for_output(&val));
                            self.security.output_bytes = self
                                .security
                                .output_bytes
                                .saturating_add(json_str.len() + self.ors.len());
                            if self.security.output_bytes > MAX_OUTPUT_BYTES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Output size limit exceeded ({} MB max)",
                                    MAX_OUTPUT_BYTES / (1024 * 1024)
                                )));
                            }
                            self.writer.write_str(&json_str)?;
                            self.writer.write_str(&self.ors)?;
                            return Ok(EvalSignal::None);
                        }
                        self.security.output_bytes = self
                            .security
                            .output_bytes
                            .saturating_add(self.field.line_buf.len() + self.ors.len());
                        self.writer.write_str(&self.field.line_buf)?;
                        self.writer.write_str(&self.ors)?;
                        return Ok(EvalSignal::None);
                    }
                    // Ultra-fast path: `print $N` single constant field — zero-copy direct write
                    if let Expr::Field(idx_expr) = &exprs[0] {
                        if let Expr::Number(n) = idx_expr.as_ref() {
                            if !self.field.fields_modified
                                && !self.field.field_ranges.is_empty()
                                && self.property_tree.is_none()
                            {
                                let idx = *n as usize;
                                if idx > 0 {
                                    if let Some(&(start, end)) =
                                        self.field.field_ranges.get(idx - 1)
                                    {
                                        self.security.output_bytes = self
                                            .security
                                            .output_bytes
                                            .saturating_add((end - start) + self.ors.len());
                                        self.writer.write_str(&self.field.line_buf[start..end])?;
                                        self.writer.write_str(&self.ors)?;
                                        return Ok(EvalSignal::None);
                                    }
                                    // Out-of-range field: print empty + ORS
                                    self.security.output_bytes =
                                        self.security.output_bytes.saturating_add(self.ors.len());
                                    if (self.nr & 1023) == 0
                                        && self.security.output_bytes > MAX_OUTPUT_BYTES
                                    {
                                        return Err(AwkError::RuntimeError(format!(
                                            "Output size limit exceeded ({} MB max)",
                                            MAX_OUTPUT_BYTES / (1024 * 1024)
                                        )));
                                    }
                                    self.writer.write_str(&self.ors)?;
                                    return Ok(EvalSignal::None);
                                }
                            }
                        }
                    }
                }
                // Performance: fast path for `print $N` (single field, text mode)
                // Writes directly from byte ranges without eval_expr allocation
                if !self.field.fields_modified
                    && !self.field.field_ranges.is_empty()
                    && self.property_tree.is_none()
                {
                    let all_fields = exprs.iter().all(|e| matches!(e, Expr::Field(_)));
                    if all_fields {
                        self.print_buf.clear();
                        for (i, e) in exprs.iter().enumerate() {
                            if i > 0 {
                                self.print_buf.push_str(&self.ofs);
                            }
                            if let Expr::Field(ref idx_expr) = e {
                                // Try constant index first
                                if let Expr::Number(n) = idx_expr.as_ref() {
                                    let idx = *n as usize;
                                    if idx > 0 {
                                        if let Some(&(start, end)) =
                                            self.field.field_ranges.get(idx - 1)
                                        {
                                            self.print_buf
                                                .push_str(&self.field.line_buf[start..end]);
                                            continue;
                                        }
                                    }
                                }
                                // Fallback: evaluate index expression with overflow protection
                                let idx_f64 = self.eval_expr(idx_expr)?.as_number().max(0.0);
                                let idx = if idx_f64 > MAX_FIELDS as f64 {
                                    MAX_FIELDS
                                } else {
                                    idx_f64 as usize
                                };
                                if idx > 0 {
                                    if let Some(&(start, end)) =
                                        self.field.field_ranges.get(idx - 1)
                                    {
                                        self.print_buf.push_str(&self.field.line_buf[start..end]);
                                    }
                                }
                            }
                        }
                        self.security.output_bytes = self
                            .security
                            .output_bytes
                            .saturating_add(self.print_buf.len() + self.ors.len());
                        self.writer.write_str(&self.print_buf)?;
                        self.writer.write_str(&self.ors)?;
                        return Ok(EvalSignal::None);
                    }
                }

                // Performance: same-array print fast path (`print a[1], a[n]` style):
                // one array lookup for all elements instead of per-element HashMap probes.
                if exprs.len() >= 2 && !self.containers_possible && self.property_tree.is_none() {
                    let mut aname: Option<&str> = None;
                    let mut supported = true;
                    for e in exprs.iter() {
                        match e {
                            Expr::ArrayAccess(name, idx) if name != "ENVIRON" && name != "ARGV" => {
                                let ok_idx = match idx.as_ref() {
                                    Expr::Number(n) => *n >= 0.0 && (*n as usize) as f64 == *n,
                                    Expr::Var(_) | Expr::String(_) => true,
                                    _ => false,
                                };
                                if !ok_idx {
                                    supported = false;
                                    break;
                                }
                                match aname {
                                    None => aname = Some(name.as_str()),
                                    Some(p) if p == name.as_str() => {}
                                    _ => {
                                        supported = false;
                                        break;
                                    }
                                }
                            }
                            _ => {
                                supported = false;
                                break;
                            }
                        }
                    }
                    if let (true, Some(aname)) = (supported, aname) {
                        if let Some(arr) = self.scope.arrays.get(aname) {
                            self.print_buf.clear();
                            let mut handled = true;
                            for (i, e) in exprs.iter().enumerate() {
                                if i > 0 {
                                    self.print_buf.push_str(&self.ofs);
                                }
                                if let Expr::ArrayAccess(_, idx) = e {
                                    let key_ready = match idx.as_ref() {
                                        Expr::Number(n) => {
                                            self.array_key_buf.clear();
                                            self.array_key_buf
                                                .push_str(self.num_buf.format(*n as usize));
                                            true
                                        }
                                        Expr::Var(vn) => {
                                            let iv = self.get_variable(vn);
                                            match &iv {
                                                Value::Number(n)
                                                    if *n >= 0.0 && (*n as usize) as f64 == *n =>
                                                {
                                                    self.array_key_buf.clear();
                                                    self.array_key_buf
                                                        .push_str(self.num_buf.format(*n as usize));
                                                    true
                                                }
                                                Value::Str(ks) => {
                                                    self.array_key_buf.clear();
                                                    self.array_key_buf.push_str(ks);
                                                    true
                                                }
                                                Value::Uninit | Value::Null => {
                                                    self.array_key_buf.clear();
                                                    true
                                                }
                                                Value::Bool(true) => {
                                                    self.array_key_buf.clear();
                                                    self.array_key_buf.push('1');
                                                    true
                                                }
                                                Value::Bool(false) => {
                                                    self.array_key_buf.clear();
                                                    self.array_key_buf.push('0');
                                                    true
                                                }
                                                _ => false,
                                            }
                                        }
                                        Expr::String(s) => {
                                            self.array_key_buf.clear();
                                            self.array_key_buf.push_str(s);
                                            true
                                        }
                                        _ => false,
                                    };
                                    if !key_ready {
                                        handled = false;
                                        break;
                                    }
                                    match arr.get(self.array_key_buf.as_str()) {
                                        Some(Value::Str(s)) => {
                                            self.print_buf.push_str(s);
                                        }
                                        Some(Value::Number(n)) => {
                                            if n.is_finite()
                                                && *n == (*n as i64) as f64
                                                && n.abs() < 1e15
                                            {
                                                let s = self.num_buf.format(*n as i64);
                                                self.print_buf.push_str(s);
                                            } else {
                                                self.print_buf.push_str(&self.format_ofmt(n));
                                            }
                                        }
                                        Some(Value::Bool(true)) => {
                                            self.print_buf.push('1');
                                        }
                                        Some(Value::Bool(false)) => {
                                            self.print_buf.push('0');
                                        }
                                        Some(v @ Value::Object(_)) | Some(v @ Value::Array(_)) => {
                                            let s = crate::eval::output::serialize_output(
                                                v,
                                                &self.format_registry,
                                                self.output_format.as_deref(),
                                            )
                                            .unwrap_or_else(|| serialize_for_output(v));
                                            self.print_buf.push_str(&s);
                                        }
                                        Some(Value::Uninit) | Some(Value::Null) | None => {}
                                    }
                                }
                            }
                            if handled {
                                self.security.output_bytes = self
                                    .security
                                    .output_bytes
                                    .saturating_add(self.print_buf.len() + self.ors.len());
                                if self.security.output_bytes > MAX_OUTPUT_BYTES {
                                    self.security.record_audit(AuditEvent::LimitViolation {
                                        limit_name: "MAX_OUTPUT_BYTES".to_string(),
                                        limit_value: MAX_OUTPUT_BYTES,
                                        actual_value: self.security.output_bytes,
                                    });
                                    return Err(AwkError::RuntimeError(format!(
                                        "Output size limit exceeded ({} MB max)",
                                        MAX_OUTPUT_BYTES / (1024 * 1024)
                                    )));
                                }
                                self.writer.write_str(&self.print_buf)?;
                                self.writer.write_str(&self.ors)?;
                                return Ok(EvalSignal::None);
                            }
                        }
                    }
                }

                self.print_buf.clear();
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        self.print_buf.push_str(&self.ofs);
                    }
                    // Fast path: string literal - avoid eval_expr + clone
                    if let Expr::String(s) = e {
                        self.print_buf.push_str(s);
                        continue;
                    }
                    // Fast path: numeric literal - avoid eval_expr overhead
                    if let Expr::Number(n) = e {
                        if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                            let s = self.num_buf.format(*n as i64);
                            self.print_buf.push_str(s);
                        } else {
                            self.print_buf.push_str(&self.format_ofmt(n));
                        }
                        continue;
                    }
                    // Fast path: array element with numeric/field key — direct lookup,
                    // skips recursive eval_expr depth tracking and value boxing.
                    if let Expr::ArrayAccess(name, idx) = e {
                        if name != "ENVIRON" && name != "ARGV" {
                            let mut container_shadow = false;
                            if self.containers_possible {
                                for scope in self.scope.scope_stack.iter().rev() {
                                    if let Some(v) = scope.get(name.as_str()) {
                                        container_shadow =
                                            matches!(v, Value::Array(_) | Value::Object(_));
                                        break;
                                    }
                                }
                            }
                            if !container_shadow {
                                // Outer None = unsupported index, fall through to eval_expr.
                                // Some(inner) = handled; inner None means absent key (prints empty).
                                // Build a borrowed key in array_key_buf (zero alloc).
                                let key_ready = match idx.as_ref() {
                                    Expr::Number(n) if *n >= 0.0 && (*n as usize) as f64 == *n => {
                                        self.array_key_buf.clear();
                                        self.array_key_buf
                                            .push_str(self.num_buf.format(*n as usize));
                                        true
                                    }
                                    Expr::Var(vn) => {
                                        let iv = self.get_variable(vn);
                                        match &iv {
                                            Value::Number(n)
                                                if *n >= 0.0 && (*n as usize) as f64 == *n =>
                                            {
                                                self.array_key_buf.clear();
                                                self.array_key_buf
                                                    .push_str(self.num_buf.format(*n as usize));
                                                true
                                            }
                                            Value::Str(ks) => {
                                                self.array_key_buf.clear();
                                                self.array_key_buf.push_str(ks);
                                                true
                                            }
                                            Value::Uninit | Value::Null => {
                                                self.array_key_buf.clear();
                                                true
                                            }
                                            Value::Bool(true) => {
                                                self.array_key_buf.clear();
                                                self.array_key_buf.push('1');
                                                true
                                            }
                                            Value::Bool(false) => {
                                                self.array_key_buf.clear();
                                                self.array_key_buf.push('0');
                                                true
                                            }
                                            _ => false, // non-integral number / container: fall through
                                        }
                                    }
                                    Expr::Field(_) => {
                                        self.build_array_key(idx)?;
                                        true
                                    }
                                    Expr::String(s) => {
                                        self.array_key_buf.clear();
                                        self.array_key_buf.push_str(s);
                                        true
                                    }
                                    _ => false,
                                };
                                if key_ready {
                                    let fetched = self
                                        .scope
                                        .arrays
                                        .get(name.as_str())
                                        .and_then(|arr| arr.get(self.array_key_buf.as_str()));
                                    match fetched {
                                        Some(Value::Str(s)) => {
                                            self.print_buf.push_str(s);
                                        }
                                        Some(Value::Number(n)) => {
                                            if n.is_finite()
                                                && *n == (*n as i64) as f64
                                                && n.abs() < 1e15
                                            {
                                                let s = self.num_buf.format(*n as i64);
                                                self.print_buf.push_str(s);
                                            } else {
                                                self.print_buf.push_str(&self.format_ofmt(n));
                                            }
                                        }
                                        Some(Value::Bool(true)) => {
                                            self.print_buf.push('1');
                                        }
                                        Some(Value::Bool(false)) => {
                                            self.print_buf.push('0');
                                        }
                                        Some(v @ Value::Object(_)) | Some(v @ Value::Array(_)) => {
                                            let s = crate::eval::output::serialize_output(
                                                v,
                                                &self.format_registry,
                                                self.output_format.as_deref(),
                                            )
                                            .unwrap_or_else(|| serialize_for_output(v));
                                            self.print_buf.push_str(&s);
                                        }
                                        Some(Value::Uninit) | Some(Value::Null) | None => {
                                            // Absent element prints as empty
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    let val = self.eval_expr(e)?;
                    match &val {
                        Value::Number(n) => {
                            if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                                // Fast path: itoa for integers (no format! overhead)
                                let s = self.num_buf.format(*n as i64);
                                self.print_buf.push_str(s);
                            } else {
                                self.print_buf.push_str(&self.format_ofmt(n));
                            }
                        }
                        Value::Str(s) => self.print_buf.push_str(s.as_str()),
                        Value::Uninit => {}
                        Value::Bool(true) => self.print_buf.push('1'),
                        Value::Bool(false) => self.print_buf.push('0'),
                        Value::Null => {}
                        Value::Object(_) | Value::Array(_) => {
                            let s = crate::eval::output::serialize_output(
                                &val,
                                &self.format_registry,
                                self.output_format.as_deref(),
                            )
                            .unwrap_or_else(|| serialize_for_output(&val));
                            self.print_buf.push_str(&s)
                        }
                    }
                }
                // Track output size for security limit
                self.security.output_bytes = self
                    .security
                    .output_bytes
                    .saturating_add(self.print_buf.len() + self.ors.len());
                if self.security.output_bytes > MAX_OUTPUT_BYTES {
                    self.security.record_audit(AuditEvent::LimitViolation {
                        limit_name: "MAX_OUTPUT_BYTES".to_string(),
                        limit_value: MAX_OUTPUT_BYTES,
                        actual_value: self.security.output_bytes,
                    });
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                // Write directly from reusable buffer (no clone needed)
                self.writer.write_str(&self.print_buf)?;
                self.writer.write_str(&self.ors)?;
                Ok(EvalSignal::None)
            }
            Statement::Printf(format_expr, args) => {
                let fmt = self.eval_expr(format_expr)?.as_string();
                let arg_vals: Vec<Value> = args
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let output = self.format_printf(&fmt, &arg_vals);
                self.security.output_bytes =
                    self.security.output_bytes.saturating_add(output.len());
                if self.security.output_bytes > MAX_OUTPUT_BYTES {
                    self.security.record_audit(AuditEvent::LimitViolation {
                        limit_name: "MAX_OUTPUT_BYTES".to_string(),
                        limit_value: MAX_OUTPUT_BYTES,
                        actual_value: self.security.output_bytes,
                    });
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                self.writer.write_str(&output)?;
                Ok(EvalSignal::None)
            }
            Statement::If(cond, then_stmt, else_stmt) => {
                let cond_val = self.eval_expr(cond)?;
                if cond_val.is_truthy() {
                    self.exec_statement(then_stmt)
                } else if let Some(else_s) = else_stmt {
                    self.exec_statement(else_s)
                } else {
                    Ok(EvalSignal::None)
                }
            }
            Statement::While(cond, body) => {
                let mut iterations = 0usize;
                while self.eval_expr(cond)?.is_truthy() {
                    iterations += 1;
                    if iterations > MAX_LOOP_ITERATIONS {
                        self.security.record_audit(AuditEvent::LimitViolation {
                            limit_name: "MAX_LOOP_ITERATIONS".to_string(),
                            limit_value: MAX_LOOP_ITERATIONS,
                            actual_value: iterations,
                        });
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    let signal = self.exec_statement(body)?;
                    match signal {
                        EvalSignal::Break => break,
                        EvalSignal::Continue => continue,
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => {
                            return Ok(signal)
                        }
                        EvalSignal::None => {}
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::For(init, cond, incr, body) => {
                if let Some(init_stmt) = init {
                    self.exec_statement(init_stmt)?;
                }
                let mut iterations = 0usize;
                loop {
                    if let Some(cond_expr) = cond {
                        if !self.eval_expr(cond_expr)?.is_truthy() {
                            break;
                        }
                    }
                    iterations += 1;
                    if iterations > MAX_LOOP_ITERATIONS {
                        self.security.record_audit(AuditEvent::LimitViolation {
                            limit_name: "MAX_LOOP_ITERATIONS".to_string(),
                            limit_value: MAX_LOOP_ITERATIONS,
                            actual_value: iterations,
                        });
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    let signal = self.exec_statement(body)?;
                    match signal {
                        EvalSignal::Break => break,
                        EvalSignal::Continue => {}
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => {
                            return Ok(signal)
                        }
                        EvalSignal::None => {}
                    }
                    if let Some(incr_expr) = incr {
                        self.eval_expr(incr_expr)?;
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::ForIn(var, array_name, body) => {
                let keys: Vec<String> = if array_name == "ENVIRON" {
                    // Iterate over environment variable keys
                    self.env
                        .all_env_vars()
                        .into_iter()
                        .map(|(k, _)| k)
                        .collect()
                } else {
                    self.scope
                        .arrays
                        .get(array_name)
                        .map(|a| a.keys().cloned().collect())
                        .unwrap_or_default()
                };
                let mut iterations = 0usize;
                for key in keys {
                    iterations += 1;
                    if iterations > MAX_LOOP_ITERATIONS {
                        self.security.record_audit(AuditEvent::LimitViolation {
                            limit_name: "MAX_LOOP_ITERATIONS".to_string(),
                            limit_value: MAX_LOOP_ITERATIONS,
                            actual_value: iterations,
                        });
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    self.scope.set_var(var.clone(), Value::Str(key.clone()));
                    let signal = self.exec_statement(body)?;
                    match signal {
                        EvalSignal::Break => break,
                        EvalSignal::Continue => continue,
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => {
                            return Ok(signal)
                        }
                        EvalSignal::None => {}
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::Block(stmts) => self.exec_statements(stmts),
            Statement::Assign(name, value) => {
                let val = self.eval_expr(value)?;
                match name.as_str() {
                    "FS" => {
                        self.fs = val.as_string();
                        self.format_auto = false;
                    }
                    "RS" => {
                        self.rs = val.as_string();
                        self.format_auto = false;
                    }
                    "OFS" => self.ofs = val.as_string(),
                    "ORS" => self.ors = val.as_string(),
                    "OUTPUT_FORMAT" => {
                        let s = val.as_string();
                        self.output_format = if s.is_empty() { None } else { Some(s) };
                    }
                    "SUBSEP" => self.subsep = val.as_string(),
                    "FPAT" => self.fpat = val.as_string(),
                    "OFMT" => {
                        let new_ofmt = val.as_string();
                        // Parse precision from %.[digits][gfe] — accept any format char
                        self.ofmt_precision = new_ofmt
                            .strip_prefix("%.")
                            .and_then(|s| {
                                let digits: String =
                                    s.chars().take_while(|c| c.is_ascii_digit()).collect();
                                digits.parse::<usize>().ok()
                            })
                            .unwrap_or(6);
                        self.ofmt = new_ofmt;
                    }
                    "CONVFMT" => self.convfmt = val.as_string(),
                    _ => {}
                }
                // Use &str setter: avoids cloning the name String when the
                // variable already exists (the common per-record case).
                self.scope.set_var_str(name.as_str(), val);
                Ok(EvalSignal::None)
            }
            Statement::ArrayAssign(arr_name, idx_expr, value) => {
                // ENVIRON is read-only
                if arr_name == "ENVIRON" {
                    return Err(AwkError::RuntimeError("ENVIRON is read-only".to_string()));
                }
                let val = self.eval_expr(value)?;
                // Optimized array assignment: for field-access keys ($N), use reusable buffer.
                if matches!(idx_expr, Expr::Field(_)) {
                    self.build_array_key(idx_expr)?;
                    // Try to update existing entry in-place (avoids entry API overhead)
                    if let Some(arr) = self.scope.arrays.get_mut(arr_name) {
                        if arr.contains_key(self.array_key_buf.as_str()) {
                            let key = std::mem::take(&mut self.array_key_buf);
                            arr.insert(key, val);
                            return Ok(EvalSignal::None);
                        }
                    }
                    // Key doesn't exist — insert new entry (with limit check)
                    let key = std::mem::take(&mut self.array_key_buf);
                    self.scope.array_insert(arr_name, key, val)?;
                } else {
                    let key = self.eval_expr(idx_expr)?.as_string();
                    self.scope.array_insert(arr_name, key, val)?;
                }
                Ok(EvalSignal::None)
            }
            Statement::FieldAssign(field_expr, value) => {
                // Clamp field index to prevent overflow from very large f64 values
                let idx_f64 = self.eval_expr(field_expr)?.as_number().max(0.0);
                let idx = if idx_f64 > MAX_FIELDS as f64 {
                    MAX_FIELDS
                } else {
                    idx_f64 as usize
                };
                let val = self.eval_expr(value)?.as_string();
                if idx == 0 {
                    self.field.set_field_zero(&val)?;
                } else {
                    self.field.set_field(idx, &val);
                }
                Ok(EvalSignal::None)
            }
            Statement::CompoundAssign(name, op, value) => {
                // Fast path: var += $N — zero-alloc numeric accumulation
                if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) {
                    if let Expr::Field(idx_expr) = value {
                        if let Expr::Number(n) = idx_expr.as_ref() {
                            // Clamp field index to prevent overflow
                            let idx = if *n > MAX_FIELDS as f64 {
                                MAX_FIELDS
                            } else {
                                n.max(0.0) as usize
                            };
                            let field_bytes = self.field.get_field_bytes(idx);
                            // Safe UTF-8 conversion (field_bytes is from line_buf which is always valid UTF-8)
                            let field_str = std::str::from_utf8(field_bytes).unwrap_or("");
                            let field_num = awk_str_to_number(field_str);
                            // Single-lookup in-place update when only global scope exists
                            // and the name is not a special variable.
                            let name_str = name.as_str();
                            if self.scope.scope_stack.len() == 1
                                && !matches!(
                                    name_str,
                                    "NR" | "NF"
                                        | "FNR"
                                        | "FS"
                                        | "RS"
                                        | "OFS"
                                        | "ORS"
                                        | "FILENAME"
                                        | "SUBSEP"
                                        | "FPAT"
                                        | "OFMT"
                                        | "CONVFMT"
                                        | "ARGC"
                                        | "ERRNO"
                                )
                            {
                                match self.scope.scope_stack[0].get_mut(name_str) {
                                    Some(slot) => {
                                        let current = slot.as_number();
                                        let result = match op {
                                            BinOp::Add => current + field_num,
                                            BinOp::Sub => current - field_num,
                                            BinOp::Mul => current * field_num,
                                            _ => unreachable!(),
                                        };
                                        *slot = Value::Number(result);
                                    }
                                    None => {
                                        let result = match op {
                                            BinOp::Add => field_num,
                                            BinOp::Sub => -field_num,
                                            BinOp::Mul => 0.0,
                                            _ => unreachable!(),
                                        };
                                        self.scope.scope_stack[0]
                                            .insert(name.clone(), Value::Number(result));
                                    }
                                }
                                return Ok(EvalSignal::None);
                            }
                            let current = self.get_variable_f64(name);
                            let result = match op {
                                BinOp::Add => current + field_num,
                                BinOp::Sub => current - field_num,
                                BinOp::Mul => current * field_num,
                                _ => unreachable!(),
                            };
                            self.scope.set_var_str(name, Value::Number(result));
                            return Ok(EvalSignal::None);
                        }
                    }
                }
                let current = self.get_variable(name);
                let rhs = self.eval_expr(value)?;
                let result = self.apply_binop(current, op.clone(), rhs)?;
                self.scope.set_var(name.clone(), result);
                Ok(EvalSignal::None)
            }
            Statement::Increment(name, is_inc) => {
                let name_str = name.as_str();
                // Fast path: global scope only (no function calls active).
                // Single hashmap lookup; skip double scope walk.
                // Builtins are excluded: they resolve before scope lookup.
                if self.scope.scope_stack.len() == 1
                    && !matches!(
                        name_str,
                        "NR" | "NF"
                            | "FNR"
                            | "FS"
                            | "RS"
                            | "OFS"
                            | "ORS"
                            | "FILENAME"
                            | "SUBSEP"
                            | "FPAT"
                            | "OFMT"
                            | "CONVFMT"
                            | "ARGC"
                            | "ERRNO"
                    )
                {
                    let delta = if *is_inc { 1.0 } else { -1.0 };
                    match self.scope.scope_stack[0].get_mut(name_str) {
                        Some(slot) => *slot = Value::Number(slot.as_number() + delta),
                        None => {
                            self.scope.scope_stack[0].insert(name.clone(), Value::Number(delta));
                        }
                    }
                    return Ok(EvalSignal::None);
                }
                let current = {
                    let mut found = None;
                    for scope in self.scope.scope_stack.iter().rev() {
                        if let Some(val) = scope.get(name_str) {
                            found = Some(val.as_number());
                            break;
                        }
                    }
                    found.unwrap_or(0.0)
                };
                let new_val = if *is_inc {
                    current + 1.0
                } else {
                    current - 1.0
                };
                let mut set_in = None;
                for i in (1..self.scope.scope_stack.len()).rev() {
                    if self.scope.scope_stack[i].contains_key(name_str) {
                        set_in = Some(i);
                        break;
                    }
                }
                let idx = set_in.unwrap_or(0);
                self.scope.scope_stack[idx].insert(name.clone(), Value::Number(new_val));
                Ok(EvalSignal::None)
            }
            Statement::Expr(expr) => {
                self.eval_expr(expr)?;
                Ok(EvalSignal::None)
            }
            Statement::Next => Ok(EvalSignal::Next),
            Statement::NextFile => Ok(EvalSignal::NextFile),
            Statement::Break => Ok(EvalSignal::Break),
            Statement::Continue => Ok(EvalSignal::Continue),
            Statement::Return(expr) => {
                let val = if let Some(e) = expr {
                    self.eval_expr(e)?
                } else {
                    Value::Str(String::new())
                };
                Ok(EvalSignal::Return(val))
            }
            Statement::Delete(array_name, idx) => {
                // Security: ENVIRON and ARGV are read-only
                if array_name == "ENVIRON" || array_name == "ARGV" {
                    return Err(AwkError::RuntimeError(format!(
                        "attempt to modify read-only array {}",
                        array_name
                    )));
                }
                let key = self.eval_expr(idx)?.as_string();
                if let Some(arr) = self.scope.arrays.get_mut(array_name) {
                    if arr.remove(&key).is_some() {
                        self.total_array_entries = self.total_array_entries.saturating_sub(1);
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::DeleteAll(array_name) => {
                // Security: ENVIRON and ARGV are read-only
                if array_name == "ENVIRON" || array_name == "ARGV" {
                    return Err(AwkError::RuntimeError(format!(
                        "attempt to modify read-only array {}",
                        array_name
                    )));
                }
                if let Some(arr) = self.scope.arrays.remove(array_name) {
                    self.total_array_entries = self.total_array_entries.saturating_sub(arr.len());
                }
                Ok(EvalSignal::None)
            }
            Statement::Getline(var, source) => {
                let line = match source {
                    GetlineSource::Default => self.reader.read_line()?,
                    GetlineSource::File(file_expr) => {
                        let fname = self.eval_expr(file_expr)?.as_string();
                        self.reader.read_file_line(&fname)?
                    }
                    GetlineSource::Pipe(cmd_expr) => {
                        let cmd_str = self.eval_expr(cmd_expr)?.as_string();
                        self.security.record_audit(AuditEvent::SandboxViolation {
                            action: format!("getline from pipe: {}", &cmd_str),
                        });
                        self.cmd.read_pipe_line(&cmd_str)?
                    }
                };
                let result = if let Some(l) = line {
                    // Security: enforce 16MB record limit on getline input
                    if l.len() > 16_777_216 {
                        return Err(AwkError::RuntimeError(
                            "record exceeds maximum size (16 MB)".into(),
                        ));
                    }
                    if let Some(var_name) = var {
                        self.scope.set_var(var_name.clone(), Value::Str(l));
                    } else {
                        self.nr += 1;
                        self.fnr += 1;
                        self.split_fields_from(&l)?;
                    }
                    1.0
                } else {
                    0.0
                };
                self.scope.set_var("!".to_string(), Value::Number(result));
                Ok(EvalSignal::None)
            }
            Statement::PrintRedirect(exprs, redirect_type, target_expr) => {
                self.print_buf.clear();
                if exprs.is_empty() {
                    // Zero-copy fast path for redirect
                    self.print_buf.push_str(&self.field.line_buf);
                } else {
                    for (i, e) in exprs.iter().enumerate() {
                        if i > 0 {
                            self.print_buf.push_str(&self.ofs);
                        }
                        let val = self.eval_expr(e)?;
                        match &val {
                            Value::Number(n) => {
                                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                                    // Fast path: itoa for integers (no format! overhead)
                                    let s = self.num_buf.format(*n as i64);
                                    self.print_buf.push_str(s);
                                } else {
                                    self.print_buf.push_str(&self.format_ofmt(n));
                                }
                            }
                            Value::Str(s) => self.print_buf.push_str(s.as_str()),
                            Value::Uninit => {}
                            Value::Bool(true) => self.print_buf.push('1'),
                            Value::Bool(false) => self.print_buf.push('0'),
                            Value::Null => {}
                            Value::Object(_) | Value::Array(_) => {
                                let s = crate::eval::output::serialize_output(
                                    &val,
                                    &self.format_registry,
                                    self.output_format.as_deref(),
                                )
                                .unwrap_or_else(|| serialize_for_output(&val));
                                self.print_buf.push_str(&s)
                            }
                        }
                    }
                }
                self.print_buf.push_str(&self.ors);
                let target = self.eval_expr(target_expr)?.as_string();
                match redirect_type {
                    RedirectionType::ToFile | RedirectionType::AppendToFile
                        if !self.open_files.contains(&target) =>
                    {
                        if self.open_files.len() >= MAX_OPEN_FILES {
                            return Err(AwkError::RuntimeError(format!(
                                "Too many open files ({} max)",
                                MAX_OPEN_FILES
                            )));
                        }
                        self.open_files.insert(target.clone());
                    }
                    _ => {}
                }
                match redirect_type {
                    RedirectionType::ToFile => {
                        self.writer.write_file_str(&target, &self.print_buf)?;
                    }
                    RedirectionType::AppendToFile => {
                        self.writer.append_file_str(&target, &self.print_buf)?;
                    }
                    RedirectionType::Pipe => {
                        self.security.record_audit(AuditEvent::SandboxViolation {
                            action: format!("print | {}", &target),
                        });
                        self.cmd.write_pipe(&target, &self.print_buf)?;
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::PrintfRedirect(format_expr, args, redirect_type, target_expr) => {
                let fmt = self.eval_expr(format_expr)?.as_string();
                let arg_vals: Vec<Value> = args
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let output = self.format_printf(&fmt, &arg_vals);
                self.security.output_bytes =
                    self.security.output_bytes.saturating_add(output.len());
                if self.security.output_bytes > MAX_OUTPUT_BYTES {
                    self.security.record_audit(AuditEvent::LimitViolation {
                        limit_name: "MAX_OUTPUT_BYTES".to_string(),
                        limit_value: MAX_OUTPUT_BYTES,
                        actual_value: self.security.output_bytes,
                    });
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                let target = self.eval_expr(target_expr)?.as_string();
                match redirect_type {
                    RedirectionType::ToFile | RedirectionType::AppendToFile
                        if !self.open_files.contains(&target) =>
                    {
                        if self.open_files.len() >= MAX_OPEN_FILES {
                            return Err(AwkError::RuntimeError(format!(
                                "Too many open files ({} max)",
                                MAX_OPEN_FILES
                            )));
                        }
                        self.open_files.insert(target.clone());
                    }
                    _ => {}
                }
                match redirect_type {
                    RedirectionType::ToFile => {
                        self.writer.write_file_str(&target, &output)?;
                    }
                    RedirectionType::AppendToFile => {
                        self.writer.append_file_str(&target, &output)?;
                    }
                    RedirectionType::Pipe => {
                        self.security.record_audit(AuditEvent::SandboxViolation {
                            action: format!("printf | {}", &target),
                        });
                        self.cmd.write_pipe(&target, &output)?;
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::Close(expr) => {
                let target = self.eval_expr(expr)?.as_string();
                self.open_files.remove(&target);
                let _ = self.reader.close_file(&target);
                let _ = self.writer.close_file(&target);
                let _ = self.cmd.close_pipe(&target);
                Ok(EvalSignal::None)
            }
        }
    }

}
