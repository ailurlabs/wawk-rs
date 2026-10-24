//! Expression evaluation for the AWK evaluator.

use super::*;

impl<'a> Evaluator<'a> {
    pub(super) fn eval_expr(&mut self, expr: &Expr) -> AwkResult<Value> {
        // Skip depth check for leaf nodes — they can't cause stack overflow
        // since they don't recursively call eval_expr.
        if expr.is_leaf() {
            return self.eval_expr_inner(expr);
        }
        self.security.expr_depth += 1;
        if self.security.expr_depth > MAX_EXPR_DEPTH {
            self.security.expr_depth -= 1;
            return Err(AwkError::RuntimeError(
                "expression nesting too deep".to_string(),
            ));
        }
        let result = self.eval_expr_inner(expr);
        self.security.expr_depth -= 1;
        result
    }

    pub(super) fn eval_expr_inner(&mut self, expr: &Expr) -> AwkResult<Value> {
        match expr {
            Expr::Number(n) => Ok(Value::Number(*n)),
            Expr::String(s) => Ok(Value::Str(s.clone())),
            Expr::Var(name) => Ok(self.get_variable(name)),
            Expr::Record => {
                if let Some(ref pt) = self.property_tree {
                    Ok(Value::from_property_tree(pt))
                } else {
                    Ok(Value::Str(self.field.get_field(0)))
                }
            }
            Expr::Field(idx_expr) => {
                // Clamp field index to prevent overflow from very large f64 values
                let idx_f64 = self.eval_expr(idx_expr)?.as_number().max(0.0);
                let idx = if idx_f64 > MAX_FIELDS as f64 {
                    MAX_FIELDS
                } else {
                    idx_f64 as usize
                };
                if let Some(ref pt) = self.property_tree {
                    match pt {
                        crate::types::PropertyTree::Object(pairs) => {
                            if idx == 0 {
                                Ok(Value::from_property_tree(pt))
                            } else if idx <= pairs.len() {
                                Ok(Value::from_property_tree(&pairs[idx - 1].1))
                            } else {
                                Ok(Value::Str(String::new()))
                            }
                        }
                        crate::types::PropertyTree::Array(arr) => {
                            if idx == 0 {
                                Ok(Value::from_property_tree(pt))
                            } else if idx <= arr.len() {
                                Ok(Value::from_property_tree(&arr[idx - 1]))
                            } else {
                                Ok(Value::Str(String::new()))
                            }
                        }
                        _ => Ok(Value::Str(self.field.get_field(idx))),
                    }
                } else {
                    Ok(Value::Str(self.field.get_field(idx)))
                }
            }
            Expr::BinOp(left, op, right) => {
                let lval = self.eval_expr(left)?;
                let rval = self.eval_expr(right)?;
                self.apply_binop(lval, op.clone(), rval)
            }
            Expr::UnaryOp(op, operand) => {
                let val = self.eval_expr(operand)?;
                match op {
                    UnaryOp::Neg => Ok(Value::Number(-val.as_number())),
                    UnaryOp::Pos => Ok(Value::Number(val.as_number())),
                    UnaryOp::Not => Ok(Value::Number(if val.is_truthy() { 0.0 } else { 1.0 })),
                }
            }
            Expr::FuncCall(name, args) => self.eval_func_call(name, args),
            Expr::QualifiedFuncCall {
                namespace,
                function,
                args,
            } => self.eval_qualified_func_call(namespace, function, args),
            Expr::ArrayAccess(name, idx) => {
                // Fast path: name is a real array or unbound — skip variable lookup.
                // Only when a VARIABLE of this name holds an Object/Array value do we
                // need the value-based path below.
                let mut var_is_container = false;
                if self.containers_possible {
                    for scope in self.scope.scope_stack.iter().rev() {
                        if let Some(v) = scope.get(name.as_str()) {
                            var_is_container = matches!(v, Value::Array(_) | Value::Object(_));
                            break;
                        }
                    }
                }
                if !var_is_container {
                    // Special handling for ENVIRON array (read-only)
                    if name == "ENVIRON" {
                        let key = self.eval_expr(idx)?.as_string();
                        let val = self.env.get_env(&key).unwrap_or_default();
                        return Ok(Value::Str(val));
                    }
                    // Special handling for ARGV array (read-only)
                    if name == "ARGV" {
                        let key = self.eval_expr(idx)?.as_string();
                        if let Ok(index) = key.parse::<usize>() {
                            let val = self.argv.get(index).cloned().unwrap_or_default();
                            return Ok(Value::Str(val));
                        }
                        return Ok(Value::Uninit);
                    }
                    // Optimized: for field-access keys ($N), use reusable buffer to avoid String alloc
                    // For numeric literals, use int_key cache to avoid eval_expr + as_string
                    let found = if matches!(idx.as_ref(), Expr::Field(_)) {
                        self.build_array_key(idx)?;
                        self.scope
                            .arrays
                            .get(name)
                            .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                            .cloned()
                    } else if let Expr::Number(n) = idx.as_ref() {
                        // Fast path: numeric literal - borrowed key, zero alloc
                        self.array_key_buf.clear();
                        {
                            use std::fmt::Write as _;
                            let _ = write!(self.array_key_buf, "{}", *n as usize);
                        }
                        self.scope
                            .arrays
                            .get(name)
                            .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                            .cloned()
                    } else {
                        let val = self.eval_expr(idx)?;
                        // Fast path: numeric index -> borrowed key, zero alloc
                        if let Value::Number(n) = &val {
                            let i = *n as usize;
                            if *n >= 0.0 && i as f64 == *n {
                                self.array_key_buf.clear();
                                {
                                    use std::fmt::Write as _;
                                    let _ = write!(self.array_key_buf, "{}", i);
                                }
                                return Ok(self
                                    .scope
                                    .arrays
                                    .get(name)
                                    .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                                    .cloned()
                                    .unwrap_or(Value::Uninit));
                            }
                        }
                        let key = val.as_string();
                        self.scope
                            .arrays
                            .get(name)
                            .and_then(|arr| arr.get(&key))
                            .cloned()
                    };
                    return Ok(found.unwrap_or(Value::Uninit));
                }
                // Slow path: a variable of this name holds an Object/Array value
                let var_val = self.get_variable(name);
                match &var_val {
                    Value::Array(arr) => {
                        let idx_val = self.eval_expr(idx)?;
                        let i = idx_val.as_number() as i64;
                        if i < 0 {
                            return Ok(Value::Null);
                        }
                        Ok(arr.get(i as usize).cloned().unwrap_or(Value::Null))
                    }
                    Value::Object(_) => {
                        let key = self.eval_expr(idx)?.as_string();
                        Ok(var_val.object_get(&key).cloned().unwrap_or(Value::Null))
                    }
                    _ => {
                        // Drop the temporary — these are handled by the symbol table below
                        drop(var_val);
                        // Special handling for ENVIRON array (read-only)
                        if name == "ENVIRON" {
                            let key = self.eval_expr(idx)?.as_string();
                            let val = self.env.get_env(&key).unwrap_or_default();
                            return Ok(Value::Str(val));
                        }
                        // Special handling for ARGV array (read-only)
                        if name == "ARGV" {
                            let key = self.eval_expr(idx)?.as_string();
                            if let Ok(index) = key.parse::<usize>() {
                                let val = self.argv.get(index).cloned().unwrap_or_default();
                                return Ok(Value::Str(val));
                            }
                            return Ok(Value::Uninit);
                        }
                        // Optimized: for field-access keys ($N), use reusable buffer to avoid String alloc
                        // For numeric literals, use int_key cache to avoid eval_expr + as_string
                        let found = if matches!(idx.as_ref(), Expr::Field(_)) {
                            self.build_array_key(idx)?;
                            self.scope
                                .arrays
                                .get(name)
                                .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                                .cloned()
                        } else if let Expr::Number(n) = idx.as_ref() {
                            // Fast path: numeric literal - zero-alloc lookup via itoa buffer
                            let mut buf = itoa::Buffer::new();
                            let key = buf.format(*n as usize);
                            self.scope
                                .arrays
                                .get(name)
                                .and_then(|arr| arr.get(key))
                                .cloned()
                        } else {
                            let val = self.eval_expr(idx)?;
                            // Fast path: numeric index -> use int_key cache (avoid String alloc)
                            if let Value::Number(n) = &val {
                                let i = *n as usize;
                                if *n >= 0.0 && i as f64 == *n {
                                    let mut buf = itoa::Buffer::new();
                                    let key = buf.format(i);
                                    return Ok(self
                                        .scope
                                        .arrays
                                        .get(name)
                                        .and_then(|arr| arr.get(key))
                                        .cloned()
                                        .unwrap_or(Value::Uninit));
                                }
                            }
                            let key = val.as_string();
                            self.scope
                                .arrays
                                .get(name)
                                .and_then(|arr| arr.get(&key))
                                .cloned()
                        };
                        Ok(found.unwrap_or(Value::Uninit))
                    } // end _ fallback arm
                } // end match on var_val
            } // end ArrayAccess
            Expr::Match(expr, pattern) => {
                let matched = match expr.as_ref() {
                    // Fast path for field access: check literal pattern without alloc
                    Expr::Field(idx_expr) => {
                        let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                        if Self::is_literal_pattern(pattern) {
                            // Zero-alloc literal substring search on raw bytes
                            let field_bytes = self.field.get_field_bytes(idx);
                            let pat_bytes = pattern.as_bytes();
                            if pat_bytes.is_empty() {
                                true
                            } else {
                                field_bytes.windows(pat_bytes.len()).any(|w| w == pat_bytes)
                            }
                        } else {
                            // Regex path needs mutable borrow for cache
                            let text = self.field.get_field(idx);
                            self.matches_regex(&text, pattern)?
                        }
                    }
                    _ => {
                        let text = self.eval_expr(expr)?.as_string();
                        self.matches_regex(&text, pattern)?
                    }
                };
                Ok(Value::Number(if matched { 1.0 } else { 0.0 }))
            }
            Expr::NotMatch(expr, pattern) => {
                let matched = match expr.as_ref() {
                    Expr::Field(idx_expr) => {
                        let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                        if Self::is_literal_pattern(pattern) {
                            let field_bytes = self.field.get_field_bytes(idx);
                            let pat_bytes = pattern.as_bytes();
                            if pat_bytes.is_empty() {
                                true
                            } else {
                                field_bytes.windows(pat_bytes.len()).any(|w| w == pat_bytes)
                            }
                        } else {
                            let text = self.field.get_field(idx);
                            self.matches_regex(&text, pattern)?
                        }
                    }
                    _ => {
                        let text = self.eval_expr(expr)?.as_string();
                        self.matches_regex(&text, pattern)?
                    }
                };
                Ok(Value::Number(if matched { 0.0 } else { 1.0 }))
            }
            Expr::Ternary(cond, then_expr, else_expr) => {
                let cond_val = self.eval_expr(cond)?;
                if cond_val.is_truthy() {
                    self.eval_expr(then_expr)
                } else {
                    self.eval_expr(else_expr)
                }
            }
            Expr::Concat(parts) => {
                let mut result = String::with_capacity(parts.len() * 16);
                for part in parts {
                    let val = self.eval_expr(part)?;
                    // Zero-alloc: write directly to result buffer
                    val.write_to_buf(&mut result);
                }
                Ok(Value::Str(result))
            }
            Expr::PostIncrement(var_expr, is_inc) => match var_expr.as_ref() {
                Expr::Var(name) => {
                    // Fast path: global scope only, non-builtin, existing slot:
                    // single in-place update, zero allocations.
                    if self.scope.scope_stack.len() == 1
                        && !matches!(
                            name.as_str(),
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
                        if let Some(slot) = self.scope.scope_stack[0].get_mut(name.as_str()) {
                            let old = slot.as_number();
                            *slot = Value::Number(if *is_inc { old + 1.0 } else { old - 1.0 });
                            return Ok(Value::Number(old));
                        }
                    }
                    let old_val = self.get_variable(name).as_number();
                    let new_val = if *is_inc {
                        old_val + 1.0
                    } else {
                        old_val - 1.0
                    };
                    self.scope.set_var(name.clone(), Value::Number(new_val));
                    Ok(Value::Number(old_val))
                }
                Expr::ArrayAccess(arr_name, idx_expr) => {
                    // Ultra fast path: constant field index key — borrow the key bytes
                    // directly from the record buffer (no key-buffer copy at all).
                    if let Expr::Field(fidx) = idx_expr.as_ref() {
                        if let Expr::Number(fn_) = fidx.as_ref() {
                            // Clamp field index to prevent overflow
                            let n = if *fn_ > MAX_FIELDS as f64 {
                                MAX_FIELDS
                            } else {
                                *fn_ as usize
                            };
                            let fbytes: Option<&[u8]> = if !self.field.fields_modified {
                                if n == 0 {
                                    Some(self.field.line_buf.as_bytes())
                                } else if !self.field.field_ranges.is_empty() {
                                    self.field.field_ranges.get(n - 1).map(|&(start, end)| {
                                        &self.field.line_buf.as_bytes()[start..end]
                                    })
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(fbytes) = fbytes {
                                // Safe UTF-8 conversion (fbytes is from line_buf which is always valid UTF-8)
                                if let Ok(key) = std::str::from_utf8(fbytes) {
                                    if let Some(arr) = self.scope.arrays.get_mut(arr_name.as_str())
                                    {
                                        if let Some(slot) = arr.get_mut(key) {
                                            let old = slot.as_number();
                                            *slot = Value::Number(if *is_inc {
                                                old + 1.0
                                            } else {
                                                old - 1.0
                                            });
                                            return Ok(Value::Number(old));
                                        }
                                        if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                                            return Err(AwkError::RuntimeError(format!(
                                                "Array size limit exceeded ({} entries max)",
                                                MAX_TOTAL_ARRAY_ENTRIES
                                            )));
                                        }
                                        self.total_array_entries += 1;
                                        arr.insert(
                                            key.to_string(),
                                            Value::Number(if *is_inc { 1.0 } else { -1.0 }),
                                        );
                                        return Ok(Value::Number(0.0));
                                    }
                                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                                        return Err(AwkError::RuntimeError(format!(
                                            "Array size limit exceeded ({} entries max)",
                                            MAX_TOTAL_ARRAY_ENTRIES
                                        )));
                                    }
                                    self.total_array_entries += 1;
                                    let mut arr = FxHashMap::default();
                                    arr.insert(
                                        key.to_string(),
                                        Value::Number(if *is_inc { 1.0 } else { -1.0 }),
                                    );
                                    self.scope.arrays.insert(arr_name.to_string(), arr);
                                    return Ok(Value::Number(0.0));
                                }
                            }
                        }
                    }
                    // Build key in reusable buffer (no String alloc for field keys)
                    self.build_array_key(idx_expr)?;
                    // Hot path: array exists and key exists — single lookup, no allocations
                    if let Some(arr) = self.scope.arrays.get_mut(arr_name.as_str()) {
                        if let Some(slot) = arr.get_mut(self.array_key_buf.as_str()) {
                            let old = slot.as_number();
                            *slot = Value::Number(if *is_inc { old + 1.0 } else { old - 1.0 });
                            return Ok(Value::Number(old));
                        }
                        // Key vacant: allocate owned key from buffer
                        if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                            return Err(AwkError::RuntimeError(format!(
                                "Array size limit exceeded ({} entries max)",
                                MAX_TOTAL_ARRAY_ENTRIES
                            )));
                        }
                        self.total_array_entries += 1;
                        let key = std::mem::take(&mut self.array_key_buf);
                        arr.insert(key, Value::Number(if *is_inc { 1.0 } else { -1.0 }));
                        return Ok(Value::Number(0.0));
                    }
                    // Array vacant
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    self.total_array_entries += 1;
                    let key = std::mem::take(&mut self.array_key_buf);
                    let mut arr = FxHashMap::default();
                    arr.insert(key, Value::Number(if *is_inc { 1.0 } else { -1.0 }));
                    self.scope.arrays.insert(arr_name.to_string(), arr);
                    Ok(Value::Number(0.0))
                }
                _ => {
                    let old_val = self.eval_expr(var_expr)?.as_number();
                    Ok(Value::Number(old_val))
                }
            },
            Expr::PreIncrement(var_expr, is_inc) => match var_expr.as_ref() {
                Expr::Var(name) => {
                    let old_val = self.get_variable(name).as_number();
                    let new_val = if *is_inc {
                        old_val + 1.0
                    } else {
                        old_val - 1.0
                    };
                    self.scope.set_var(name.clone(), Value::Number(new_val));
                    Ok(Value::Number(new_val))
                }
                Expr::ArrayAccess(arr_name, idx_expr) => {
                    // Build key in reusable buffer (no String alloc for field keys)
                    self.build_array_key(idx_expr)?;
                    // Hot path: array exists and key exists — single lookup, no allocations
                    if let Some(arr) = self.scope.arrays.get_mut(arr_name.as_str()) {
                        if let Some(slot) = arr.get_mut(self.array_key_buf.as_str()) {
                            let old = slot.as_number();
                            let new_val = if *is_inc { old + 1.0 } else { old - 1.0 };
                            *slot = Value::Number(new_val);
                            return Ok(Value::Number(new_val));
                        }
                        // Key vacant: allocate owned key from buffer
                        if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                            return Err(AwkError::RuntimeError(format!(
                                "Array size limit exceeded ({} entries max)",
                                MAX_TOTAL_ARRAY_ENTRIES
                            )));
                        }
                        self.total_array_entries += 1;
                        let key = std::mem::take(&mut self.array_key_buf);
                        arr.insert(key, Value::Number(if *is_inc { 1.0 } else { -1.0 }));
                        return Ok(Value::Number(if *is_inc { 1.0 } else { -1.0 }));
                    }
                    // Array vacant
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    self.total_array_entries += 1;
                    let key = std::mem::take(&mut self.array_key_buf);
                    let mut arr = FxHashMap::default();
                    arr.insert(key, Value::Number(if *is_inc { 1.0 } else { -1.0 }));
                    self.scope.arrays.insert(arr_name.to_string(), arr);
                    Ok(Value::Number(if *is_inc { 1.0 } else { -1.0 }))
                }
                _ => {
                    let old_val = self.eval_expr(var_expr)?.as_number();
                    let new_val = if *is_inc {
                        old_val + 1.0
                    } else {
                        old_val - 1.0
                    };
                    Ok(Value::Number(new_val))
                }
            },
            Expr::AssignExpr(name, value) => {
                let val = self.eval_expr(value)?;
                self.scope.set_var(name.clone(), val.clone());
                Ok(val)
            }
            Expr::BoolLit(b) => Ok(Value::Bool(*b)),
            Expr::NullLit => Ok(Value::Null),
            Expr::ObjectLit(pairs) => {
                let mut fields = Vec::with_capacity(pairs.len());
                for (key, val_expr) in pairs {
                    let val = self.eval_expr(val_expr)?;
                    fields.push((key.clone(), val));
                }
                Ok(Value::Object(fields))
            }
            Expr::ArrayLit(elements) => {
                let mut arr = Vec::with_capacity(elements.len());
                for elem_expr in elements {
                    arr.push(self.eval_expr(elem_expr)?);
                }
                Ok(Value::Array(arr))
            }
            Expr::DotAccess(obj_expr, field) => {
                // Performance: fast path for $.field on JSON record (avoids deep clone of $0)
                if matches!(obj_expr.as_ref(), Expr::Record) {
                    if let Some(ref pt) = self.property_tree {
                        return Ok(pt
                            .get_field(field)
                            .map(Value::from_property_tree)
                            .unwrap_or(Value::Null));
                    }
                }
                // Chained access: $1.field (evaluate idx BEFORE borrowing property_tree)
                if let Expr::Field(ref idx_expr) = obj_expr.as_ref() {
                    // Clamp field index to prevent overflow from very large f64 values
                    let idx_f64 = self.eval_expr(idx_expr)?.as_number().max(0.0);
                    let idx = if idx_f64 > MAX_FIELDS as f64 {
                        MAX_FIELDS
                    } else {
                        idx_f64 as usize
                    };
                    if let Some(ref pt) = self.property_tree {
                        let result = match pt {
                            crate::types::PropertyTree::Object(pairs) => {
                                if idx == 0 {
                                    pt.get_field(field).cloned()
                                } else if idx <= pairs.len() {
                                    pairs[idx - 1].1.get_field(field).cloned()
                                } else {
                                    None
                                }
                            }
                            crate::types::PropertyTree::Array(arr) => {
                                if idx == 0 {
                                    pt.get_field(field).cloned()
                                } else if idx <= arr.len() {
                                    arr[idx - 1].get_field(field).cloned()
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };
                        return Ok(result
                            .map(|v| Value::from_property_tree(&v))
                            .unwrap_or(Value::Null));
                    }
                }
                let obj = self.eval_expr(obj_expr)?;
                match obj {
                    Value::Object(_) => Ok(obj.object_get(field).cloned().unwrap_or(Value::Null)),
                    _ => Ok(Value::Null),
                }
            }
            Expr::IndexExpr(base_expr, idx_expr) => {
                // Performance: fast path for $0[idx] on JSON record
                if matches!(base_expr.as_ref(), Expr::Record) {
                    let idx_val = self.eval_expr(idx_expr)?;
                    if let Some(ref pt) = self.property_tree {
                        match pt {
                            crate::types::PropertyTree::Array(arr) => {
                                let i = idx_val.as_number() as i64;
                                if i < 0 {
                                    return Ok(Value::Null);
                                }
                                return Ok(arr
                                    .get(i as usize)
                                    .map(Value::from_property_tree)
                                    .unwrap_or(Value::Null));
                            }
                            crate::types::PropertyTree::Object(_) => {
                                let key = idx_val.as_string();
                                return Ok(pt
                                    .get_field(&key)
                                    .map(Value::from_property_tree)
                                    .unwrap_or(Value::Null));
                            }
                            _ => {}
                        }
                    }
                }
                let base = self.eval_expr(base_expr)?;
                match base {
                    Value::Array(arr) => {
                        let idx_val = self.eval_expr(idx_expr)?;
                        let i = idx_val.as_number() as i64;
                        if i < 0 {
                            Ok(Value::Null)
                        } else {
                            Ok(arr.get(i as usize).cloned().unwrap_or(Value::Null))
                        }
                    }
                    Value::Object(_) => {
                        let key = self.eval_expr(idx_expr)?.as_string();
                        Ok(base.object_get(&key).cloned().unwrap_or(Value::Null))
                    }
                    _ => Ok(Value::Null),
                }
            }
            Expr::GetlineExpr(var, source) => {
                let line = match source {
                    GetlineSource::Default => self.reader.read_line()?,
                    GetlineSource::File(file_expr) => {
                        let fname = self.eval_expr(file_expr)?.as_string();
                        self.reader.read_file_line(&fname)?
                    }
                    GetlineSource::Pipe(cmd_expr) => {
                        let cmd_str = self.eval_expr(cmd_expr)?.as_string();
                        self.security.record_audit(AuditEvent::SandboxViolation {
                            action: format!("getline expr from pipe: {}", &cmd_str),
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
                Ok(Value::Number(result))
            }
        }
    }

    pub(super) fn apply_binop(&self, left: Value, op: BinOp, right: Value) -> AwkResult<Value> {
        if let BinOp::In(array_name) = &op {
            let key = left.as_string();
            let exists = self
                .scope
                .arrays
                .get(array_name)
                .map(|arr| arr.contains_key(&key))
                .unwrap_or(false);
            return Ok(Value::Number(if exists { 1.0 } else { 0.0 }));
        }

        match op {
            BinOp::Add => Ok(Value::Number(left.as_number() + right.as_number())),
            BinOp::Sub => Ok(Value::Number(left.as_number() - right.as_number())),
            BinOp::Mul => Ok(Value::Number(left.as_number() * right.as_number())),
            BinOp::Div => {
                let l = left.as_number();
                let r = right.as_number();
                // AWK/gawk: division by zero produces inf/-inf/nan, not a fatal error
                Ok(Value::Number(l / r))
            }
            BinOp::Mod => {
                let l = left.as_number();
                let r = right.as_number();
                if r == 0.0 {
                    // gawk: modulo by zero produces nan
                    Ok(Value::Number(f64::NAN))
                } else {
                    Ok(Value::Number(l % r))
                }
            }
            BinOp::Pow => Ok(Value::Number(left.as_number().powf(right.as_number()))),
            BinOp::Eq => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => a == b,
                    (Value::Number(a), Value::Number(b)) => a == b,
                    (Value::Bool(a), Value::Bool(b)) => a == b,
                    (Value::Null, Value::Null) => true,
                    _ => left == right,
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Ne => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => a != b,
                    (Value::Number(a), Value::Number(b)) => a != b,
                    (Value::Bool(a), Value::Bool(b)) => a != b,
                    (Value::Null, Value::Null) => false,
                    _ => left != right,
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Lt => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na < nb
                        } else {
                            a < b
                        }
                    }
                    (Value::Number(a), Value::Number(b)) => a < b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(Value::Number(if left.as_number() < right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Le => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na <= nb
                        } else {
                            a <= b
                        }
                    }
                    (Value::Number(a), Value::Number(b)) => a <= b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(Value::Number(if left.as_number() <= right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Gt => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na > nb
                        } else {
                            a > b
                        }
                    }
                    (Value::Number(a), Value::Number(b)) => a > b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(Value::Number(if left.as_number() > right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Ge => {
                let result = match (&left, &right) {
                    (Value::Str(a), Value::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na >= nb
                        } else {
                            a >= b
                        }
                    }
                    (Value::Number(a), Value::Number(b)) => a >= b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(Value::Number(if left.as_number() >= right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(Value::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::And => Ok(Value::Number(if left.is_truthy() && right.is_truthy() {
                1.0
            } else {
                0.0
            })),
            BinOp::Or => Ok(Value::Number(if left.is_truthy() || right.is_truthy() {
                1.0
            } else {
                0.0
            })),
            BinOp::In(_) => unreachable!("In operator handled in first match"),
        }
    }

}
