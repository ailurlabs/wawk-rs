//! Function call handling for the AWK evaluator.

use super::*;
use super::helpers::{has_whitespace, regex_escape_to_rust};
use crate::eval::output::serialize_for_output;

impl<'a> Evaluator<'a> {
    pub(super) fn eval_func_call(&mut self, name: &str, args: &[Expr]) -> AwkResult<Value> {
        if let Some(func) = self.functions.get(name) {
            let func = Rc::clone(func);
            return self.call_user_function(&func, args);
        }

        match name {
            "length" => {
                if args.is_empty() {
                    // Fast path: length of $0 using byte ranges (zero-alloc)
                    let bytes = self.field.get_field_bytes(0);
                    if bytes.is_ascii() {
                        Ok(Value::Number(bytes.len() as f64))
                    } else {
                        Ok(Value::Number(
                            std::str::from_utf8(bytes)
                                .map(|s| s.chars().count())
                                .unwrap_or(bytes.len()) as f64,
                        ))
                    }
                } else {
                    // Check if argument is an array name (length(array) returns element count)
                    if let Expr::Var(name) = &args[0] {
                        if self.scope.arrays.contains_key(name) {
                            let count = self.scope.arrays[name].len();
                            return Ok(Value::Number(count as f64));
                        }
                    }
                    // Fast path: length($N) using byte ranges (zero-alloc)
                    if let Expr::Field(idx_expr) = &args[0] {
                        if let Expr::Number(n) = idx_expr.as_ref() {
                            let idx = *n as usize;
                            let bytes = self.field.get_field_bytes(idx);
                            if bytes.is_ascii() {
                                return Ok(Value::Number(bytes.len() as f64));
                            } else {
                                return Ok(Value::Number(
                                    std::str::from_utf8(bytes)
                                        .map(|s| s.chars().count())
                                        .unwrap_or(bytes.len())
                                        as f64,
                                ));
                            }
                        }
                    }
                    let s = self.eval_expr(&args[0])?.as_string();
                    if s.is_ascii() {
                        Ok(Value::Number(s.len() as f64))
                    } else {
                        Ok(Value::Number(s.chars().count() as f64))
                    }
                }
            }
            "substr" => {
                // Extract literal args without eval_expr dispatch overhead
                let start_raw = match &args[1] {
                    Expr::Number(n) => *n as i64,
                    _ => self.eval_expr(&args[1])?.as_number() as i64,
                };
                let start = if start_raw < 1 {
                    0
                } else {
                    (start_raw - 1) as usize
                };
                let length = if args.len() > 2 {
                    Some(match &args[2] {
                        Expr::Number(n) => *n as usize,
                        _ => self.eval_expr(&args[2])?.as_number() as usize,
                    })
                } else {
                    None
                };
                // Fast path: substr($N, ...) using byte ranges (zero-copy from field)
                if let Expr::Field(idx_expr) = &args[0] {
                    if let Expr::Number(n) = idx_expr.as_ref() {
                        let idx = *n as usize;
                        let field_bytes = self.field.get_field_bytes(idx);
                        if field_bytes.is_ascii() {
                            let blen = field_bytes.len();
                            let end = match length {
                                Some(l) => start.saturating_add(l).min(blen),
                                None => blen,
                            };
                            let s = start.min(blen);
                            if end <= s {
                                // Empty result: String::new() performs no heap allocation
                                return Ok(Value::Str(String::new()));
                            }
                            // Safe UTF-8 conversion (ASCII-checked slice of line_buf)
                            return Ok(Value::Str(
                                std::str::from_utf8(&field_bytes[s..end])
                                    .unwrap_or("")
                                    .to_string(),
                            ));
                        }
                    }
                }
                let s = self.eval_expr(&args[0])?.as_string();
                if s.is_ascii() {
                    let end = match length {
                        Some(l) => start.saturating_add(l).min(s.len()),
                        None => s.len(),
                    };
                    let st = start.min(s.len());
                    if end <= st {
                        return Ok(Value::Str(String::new()));
                    }
                    Ok(Value::Str(s[st..end].to_string()))
                } else {
                    let len = length.unwrap_or(s.len());
                    let substr: String = s.chars().skip(start).take(len).collect();
                    Ok(Value::Str(substr))
                }
            }
            "index" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let target = self.eval_expr(&args[1])?.as_string();
                if target.is_empty() {
                    return Ok(Value::Number(0.0));
                }
                let pos = s.find(&target).map(|p| p + 1).unwrap_or(0);
                Ok(Value::Number(pos as f64))
            }
            "split" => {
                // For split($0, ...): check ultra-fast path first before taking line_buf
                let is_record_arg = matches!(&args[0], Expr::Record);
                let array_name: &str = match &args[1] {
                    Expr::Var(n) => n.as_str(),
                    _ => {
                        return Err(AwkError::RuntimeError(
                            "split: second argument must be an array name".to_string(),
                        ))
                    }
                };
                let sep: std::borrow::Cow<str> = if args.len() > 2 {
                    match &args[2] {
                        Expr::String(s) => std::borrow::Cow::Borrowed(s.as_str()),
                        _ => std::borrow::Cow::Owned(self.eval_expr(&args[2])?.as_string()),
                    }
                } else {
                    std::borrow::Cow::Owned(self.fs.clone())
                };
                // Security: prevent writing to ENVIRON (read-only)
                if array_name == "ENVIRON" {
                    return Err(AwkError::RuntimeError(
                        "attempt to write to read-only array ENVIRON".to_string(),
                    ));
                }
                // Ultra-fast path for split($0, a, " ") when $0 has no whitespace:
                // Avoid take+restore by cloning line_buf directly into array
                if is_record_arg
                    && sep.as_ref() == " "
                    && !self.field.line_buf.is_empty()
                    && !has_whitespace(self.field.line_buf.as_bytes())
                {
                    let plen = self.field.line_buf.len();
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    if let Some(arr) = self.scope.arrays.get_mut(array_name) {
                        let old_len = arr.len();
                        match arr.get_mut("1") {
                            Some(Value::Str(slot)) => {
                                // Reuse existing buffer: zero allocation after first record
                                slot.clear();
                                slot.push_str(&self.field.line_buf);
                            }
                            Some(slot) => {
                                *slot = Value::Str(self.field.line_buf.clone());
                            }
                            None => {
                                arr.insert(
                                    "1".to_string(),
                                    Value::Str(self.field.line_buf.clone()),
                                );
                            }
                        }
                        if old_len > 1 {
                            arr.retain(|k, _| k == "1");
                        }
                        self.total_array_entries = self.total_array_entries.saturating_sub(old_len);
                    } else {
                        let mut arr = FxHashMap::with_capacity_and_hasher(1, Default::default());
                        arr.insert("1".to_string(), Value::Str(self.field.line_buf.clone()));
                        self.scope.arrays.insert(array_name.to_string(), arr);
                    }
                    self.total_array_entries = self.total_array_entries.saturating_add(1);
                    self.estimated_memory = self.estimated_memory.saturating_add(plen + 32);
                    return Ok(Value::Number(1.0));
                }
                // General path: take line_buf for zero-copy when possible
                let s = if is_record_arg {
                    std::mem::take(&mut self.field.line_buf)
                } else {
                    self.eval_expr(&args[0])?.as_string()
                };
                // Ultra fast path: sep == " " and the string contains no whitespace
                // -> exactly one part equal to the whole string. Move the owned
                // string into the array with zero allocations, recycling the
                // previous element's buffer to restore $0.
                if sep.as_ref() == " " && !s.is_empty() && !has_whitespace(s.as_bytes()) {
                    let plen = s.len();
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    let mut part = s;
                    let mut recycled: Option<String> = None;
                    if let Some(arr) = self.scope.arrays.get_mut(array_name) {
                        let old_len = arr.len();
                        match arr.get_mut("1") {
                            Some(slot) => {
                                if let Value::Str(old) = std::mem::replace(slot, Value::Uninit) {
                                    recycled = Some(old);
                                }
                                *slot = Value::Str(std::mem::take(&mut part));
                            }
                            None => {
                                arr.insert("1".to_string(), Value::Str(std::mem::take(&mut part)));
                            }
                        }
                        if old_len > 1 {
                            // split() clears the array: drop every key other than "1"
                            arr.retain(|k, _| k == "1");
                        }
                        self.total_array_entries = self.total_array_entries.saturating_sub(old_len);
                    } else {
                        let mut arr = FxHashMap::with_capacity_and_hasher(1, Default::default());
                        arr.insert("1".to_string(), Value::Str(std::mem::take(&mut part)));
                        self.scope.arrays.insert(array_name.to_string(), arr);
                    }
                    self.total_array_entries = self.total_array_entries.saturating_add(1);
                    self.estimated_memory = self.estimated_memory.saturating_add(plen + 32);
                    if is_record_arg {
                        // Restore $0 (split does not modify the record). Reuse the
                        // recycled element buffer so this is allocation-free.
                        let mut buf = recycled.unwrap_or_default();
                        buf.clear();
                        if let Some(arr) = self.scope.arrays.get(array_name) {
                            if let Some(Value::Str(p)) = arr.get("1") {
                                buf.push_str(p);
                            }
                        }
                        self.field.line_buf = buf;
                    }
                    return Ok(Value::Number(1.0));
                }
                // Optimized: split and insert with cached integer keys
                // Fast path: for " " or single-byte literal sep, skip regex overhead.
                // Parts go into self.split_parts (reusable buffer, no Vec alloc per call).
                self.split_parts.clear();
                if sep.as_ref() == " " {
                    self.split_parts
                        .extend(s.split_whitespace().map(String::from));
                } else if sep.len() == 1 && !Evaluator::is_regex_metachar(sep.as_bytes()[0]) {
                    // Inline single-byte split (avoid function call overhead).
                    // POSIX: empty fields are preserved (split("a,,b",a,",") -> 3).
                    let sep_byte = sep.as_bytes()[0];
                    if !s.is_empty() {
                        let bytes = s.as_bytes();
                        let mut start = 0;
                        for (i, &b) in bytes.iter().enumerate() {
                            if b == sep_byte {
                                self.split_parts.push(s[start..i].to_string());
                                start = i + 1;
                            }
                        }
                        self.split_parts.push(s[start..].to_string());
                    }
                } else {
                    self.split_parts = self.awk_split(&s, &sep)?;
                };
                // Security: check array limit before inserting
                if self.split_parts.len() > MAX_TOTAL_ARRAY_ENTRIES {
                    return Err(AwkError::RuntimeError(format!(
                        "Array size limit exceeded ({} entries max)",
                        MAX_TOTAL_ARRAY_ENTRIES
                    )));
                }
                let count = self.split_parts.len();
                let mem = self.split_parts.iter().map(|p| p.len() + 32).sum::<usize>();
                if let Some(arr) = self.scope.arrays.get_mut(array_name) {
                    use std::fmt::Write as _;
                    let old_len = arr.len();
                    // Reuse array slots in place: split keys are the consecutive
                    // integers "1"..="count", so overwrite existing entries via
                    // borrowed lookups (no key realloc, no rehash steady-state).
                    if count > old_len
                        && self.total_array_entries + (count - old_len) > MAX_TOTAL_ARRAY_ENTRIES
                    {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    for i in 1..=count {
                        self.array_key_buf.clear();
                        let _ = write!(self.array_key_buf, "{}", i);
                        let part = std::mem::take(&mut self.split_parts[i - 1]);
                        if let Some(slot) = arr.get_mut(self.array_key_buf.as_str()) {
                            *slot = Value::Str(part);
                        } else {
                            let key = std::mem::take(&mut self.array_key_buf);
                            arr.insert(key, Value::Str(part));
                        }
                    }
                    // Drop any leftover keys outside 1..=count (split clears the array).
                    if arr.len() > count {
                        arr.retain(|k, _| {
                            !k.is_empty()
                                && k.bytes().all(|b| b.is_ascii_digit())
                                && k.parse::<usize>().is_ok_and(|v| (1..=count).contains(&v))
                        });
                    }
                    self.total_array_entries = self.total_array_entries.saturating_sub(old_len);
                } else {
                    let mut arr = FxHashMap::with_capacity_and_hasher(count, Default::default());
                    for (i, part) in self.split_parts.drain(..).enumerate() {
                        arr.insert(int_key(i + 1), Value::Str(part));
                    }
                    self.scope.arrays.insert(array_name.to_string(), arr);
                }
                self.total_array_entries = self.total_array_entries.saturating_add(count);
                self.estimated_memory = self.estimated_memory.saturating_add(mem);
                if is_record_arg {
                    // Restore $0 after split($0, ...) — split doesn't modify the record
                    self.field.line_buf = s;
                }
                Ok(Value::Number(count as f64))
            }
            "sub" => {
                // Fast path: extract literal string args without eval_expr dispatch
                let pattern = match &args[0] {
                    Expr::String(s) => s.clone(),
                    _ => self.eval_expr(&args[0])?.as_string(),
                };
                let replacement = match &args[1] {
                    Expr::String(s) => s.clone(),
                    _ => self.eval_expr(&args[1])?.as_string(),
                };
                if args.len() > 2 {
                    let target = self.eval_expr(&args[2])?.as_string();
                    let result = self.awk_sub(&target, &pattern, &replacement, false)?;
                    let count = if result != target { 1.0 } else { 0.0 };
                    match &args[2] {
                        Expr::Var(name) => {
                            self.scope.set_var(name.clone(), Value::Str(result));
                        }
                        Expr::Record => {
                            self.split_fields_from(&result)?;
                        }
                        Expr::Field(idx_expr) => {
                            let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                            if idx > 0 {
                                self.field.set_field(idx, &result);
                            } else {
                                self.field.set_field_zero(&result)?;
                            }
                        }
                        _ => {}
                    }
                    Ok(Value::Number(count))
                } else {
                    // Fast path: literal pattern - use line_buf directly (avoid clone)
                    if Self::is_literal_pattern_str(&pattern) && !replacement.contains('&') {
                        if let Some(pos) = self.field.line_buf.find(&pattern) {
                            let mut result = String::with_capacity(self.field.line_buf.len());
                            result.push_str(&self.field.line_buf[..pos]);
                            result.push_str(&replacement);
                            result.push_str(&self.field.line_buf[pos + pattern.len()..]);
                            if self.fields_needed {
                                self.split_fields_from(&result)?;
                            } else {
                                self.field.line_buf = result;
                                self.field.fields_modified = false;
                                self.property_tree = None;
                            }
                            return Ok(Value::Number(1.0));
                        }
                        return Ok(Value::Number(0.0));
                    }
                    // Regex path: need to clone (awk_sub requires &mut self)
                    let target = self.field.get_field(0);
                    let result = self.awk_sub(&target, &pattern, &replacement, false)?;
                    let count = if result != target { 1.0 } else { 0.0 };
                    if self.fields_needed {
                        self.split_fields_from(&result)?;
                    } else {
                        self.field.line_buf = result;
                        self.field.fields_modified = false;
                        self.property_tree = None;
                    }
                    Ok(Value::Number(count))
                }
            }
            "gsub" => {
                // Fast path: borrow literal string args (zero per-record alloc)
                let pattern: std::borrow::Cow<str> = match &args[0] {
                    Expr::String(s) => std::borrow::Cow::Borrowed(s.as_str()),
                    _ => std::borrow::Cow::Owned(self.eval_expr(&args[0])?.as_string()),
                };
                let replacement: std::borrow::Cow<str> = match &args[1] {
                    Expr::String(s) => std::borrow::Cow::Borrowed(s.as_str()),
                    _ => std::borrow::Cow::Owned(self.eval_expr(&args[1])?.as_string()),
                };
                let is_literal = Self::is_literal_pattern_str(&pattern);
                if args.len() > 2 {
                    let target = self.eval_expr(&args[2])?.as_string();
                    if is_literal && !replacement.contains('&') {
                        // Single-pass count+replace
                        let mut result = String::with_capacity(target.len());
                        let mut count = 0f64;
                        let mut last_end = 0;
                        for (start, _) in target.match_indices(pattern.as_ref()) {
                            result.push_str(&target[last_end..start]);
                            result.push_str(&replacement);
                            last_end = start + pattern.len();
                            count += 1.0;
                        }
                        result.push_str(&target[last_end..]);
                        match &args[2] {
                            Expr::Var(name) => {
                                self.scope.set_var(name.clone(), Value::Str(result));
                            }
                            Expr::Record => {
                                self.split_fields_from(&result)?;
                            }
                            Expr::Field(idx_expr) => {
                                let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                                if idx > 0 {
                                    self.field.set_field(idx, &result);
                                } else {
                                    self.field.set_field_zero(&result)?;
                                }
                            }
                            _ => {}
                        }
                        return Ok(Value::Number(count));
                    }
                    let (result, count) = self.awk_sub_counted(&target, &pattern, &replacement)?;
                    match &args[2] {
                        Expr::Var(name) => {
                            self.scope.set_var(name.clone(), Value::Str(result));
                        }
                        Expr::Record => {
                            self.split_fields_from(&result)?;
                        }
                        Expr::Field(idx_expr) => {
                            let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                            if idx > 0 {
                                self.field.set_field(idx, &result);
                            } else {
                                self.field.set_field_zero(&result)?;
                            }
                        }
                        _ => {}
                    }
                    Ok(Value::Number(count))
                } else {
                    // Fast path: literal pattern - single-pass count+replace (avoid clone + double scan)
                    if is_literal && !replacement.contains('&') {
                        // Ultra fast path: equal-length replacement on $0 can be done
                        // in place with zero allocation (byte lengths match, so UTF-8
                        // boundaries remain valid).
                        if !pattern.is_empty()
                            && pattern.len() == replacement.len()
                            && pattern.len() <= 4
                        {
                            let mut count = 0f64;
                            let pb = pattern.as_bytes();
                            let rb = replacement.as_bytes();
                            let n_len = pb.len();
                            // SAFETY: replacing a matched byte span with a valid UTF-8
                            // string of identical byte length preserves UTF-8 validity.
                            let bytes = unsafe { self.field.line_buf.as_mut_vec() };
                            // Ultra-specialized path for 1-byte patterns (most common case)
                            if n_len == 1 {
                                let target_byte = pb[0];
                                let replace_byte = rb[0];
                                for b in bytes.iter_mut() {
                                    if *b == target_byte {
                                        *b = replace_byte;
                                        count += 1.0;
                                    }
                                }
                            } else {
                                let mut i = 0usize;
                                while i + n_len <= bytes.len() {
                                    if &bytes[i..i + n_len] == pb {
                                        bytes[i..i + n_len].copy_from_slice(rb);
                                        count += 1.0;
                                        i += n_len;
                                    } else {
                                        i += 1;
                                    }
                                }
                            }
                            if self.fields_needed {
                                self.split_fields_inplace()?;
                            } else {
                                self.field.fields_modified = false;
                                self.property_tree = None;
                            }
                            return Ok(Value::Number(count));
                        }
                        let mut result = String::with_capacity(self.field.line_buf.len());
                        let mut count = 0f64;
                        let mut last_end = 0;
                        for (start, _) in self.field.line_buf.match_indices(pattern.as_ref()) {
                            result.push_str(&self.field.line_buf[last_end..start]);
                            result.push_str(&replacement);
                            last_end = start + pattern.len();
                            count += 1.0;
                        }
                        result.push_str(&self.field.line_buf[last_end..]);
                        if self.fields_needed {
                            self.split_fields_from(&result)?;
                        } else {
                            self.field.line_buf = result;
                            self.field.fields_modified = false;
                            self.property_tree = None;
                        }
                        return Ok(Value::Number(count));
                    }
                    // Regex path: need to clone (awk_sub_counted requires &mut self)
                    let target = self.field.get_field(0);
                    let (result, count) = self.awk_sub_counted(&target, &pattern, &replacement)?;
                    if self.fields_needed {
                        self.split_fields_from(&result)?;
                    } else {
                        self.field.line_buf = result;
                        self.field.fields_modified = false;
                        self.property_tree = None;
                    }
                    Ok(Value::Number(count))
                }
            }
            "match" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let pattern = self.eval_expr(&args[1])?.as_string();
                if let Some((pos, len)) = self.regex_match_pos(&s, &pattern)? {
                    if args.len() > 2 {
                        if let Expr::Var(arr_name) = &args[2] {
                            let rust_pat = regex_escape_to_rust(&pattern);
                            if let Ok(re) = self.regex.get_or_compile(&rust_pat) {
                                if let Some(caps) = re.captures(&s) {
                                    let arr =
                                        self.scope.arrays.entry(arr_name.clone()).or_default();
                                    let old_match_len = arr.len();
                                    arr.clear();
                                    self.total_array_entries =
                                        self.total_array_entries.saturating_sub(old_match_len);
                                    arr.insert("RSTART".to_string(), Value::Number(pos as f64));
                                    arr.insert("RLENGTH".to_string(), Value::Number(len as f64));
                                    let mut new_entries = 2;
                                    for i in 0..caps.len() {
                                        if let Some(m) = caps.get(i) {
                                            arr.insert(
                                                i.to_string(),
                                                Value::Str(m.as_str().to_string()),
                                            );
                                            new_entries += 1;
                                        }
                                    }
                                    if self.total_array_entries + new_entries
                                        > MAX_TOTAL_ARRAY_ENTRIES
                                    {
                                        return Err(AwkError::RuntimeError(format!(
                                            "Array size limit exceeded ({} entries max)",
                                            MAX_TOTAL_ARRAY_ENTRIES
                                        )));
                                    }
                                    self.total_array_entries += new_entries;
                                }
                            }
                        }
                    }
                    self.scope
                        .set_var("RSTART".to_string(), Value::Number(pos as f64));
                    self.scope
                        .set_var("RLENGTH".to_string(), Value::Number(len as f64));
                    Ok(Value::Number(pos as f64))
                } else {
                    self.scope.set_var("RSTART".to_string(), Value::Number(0.0));
                    self.scope
                        .set_var("RLENGTH".to_string(), Value::Number(-1.0));
                    Ok(Value::Number(0.0))
                }
            }
            "sprintf" => {
                let fmt = self.eval_expr(&args[0])?.as_string();
                let arg_vals: Vec<Value> = args[1..]
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let result = self.format_printf(&fmt, &arg_vals);
                Ok(Value::Str(result))
            }
            "tolower" => {
                // Fast path: tolower($N) using byte ranges
                if let Expr::Field(idx_expr) = &args[0] {
                    if let Expr::Number(n) = idx_expr.as_ref() {
                        let idx = *n as usize;
                        let bytes = self.field.get_field_bytes(idx);
                        let mut result = Vec::with_capacity(bytes.len());
                        for &b in bytes {
                            result.push(if b.is_ascii_uppercase() { b + 32 } else { b });
                        }
                        return Ok(Value::Str(String::from_utf8(result).unwrap_or_default()));
                    }
                }
                let mut s = self.eval_expr(&args[0])?.as_string();
                s.make_ascii_lowercase();
                Ok(Value::Str(s))
            }
            "toupper" => {
                // Fast path: toupper($N) using byte ranges
                if let Expr::Field(idx_expr) = &args[0] {
                    if let Expr::Number(n) = idx_expr.as_ref() {
                        let idx = *n as usize;
                        let bytes = self.field.get_field_bytes(idx);
                        let mut result = Vec::with_capacity(bytes.len());
                        for &b in bytes {
                            result.push(if b.is_ascii_lowercase() { b - 32 } else { b });
                        }
                        return Ok(Value::Str(String::from_utf8(result).unwrap_or_default()));
                    }
                }
                let mut s = self.eval_expr(&args[0])?.as_string();
                s.make_ascii_uppercase();
                Ok(Value::Str(s))
            }
            "int" => Ok(Value::Number(BuiltinFunctions::int(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "sqrt" => Ok(Value::Number(BuiltinFunctions::sqrt(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "abs" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(Value::Number(n.abs()))
            }
            "log" => Ok(Value::Number(BuiltinFunctions::log(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "exp" => Ok(Value::Number(BuiltinFunctions::exp(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "sin" => Ok(Value::Number(BuiltinFunctions::sin(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "cos" => Ok(Value::Number(BuiltinFunctions::cos(
                self.eval_expr(&args[0])?.as_number(),
            ))),
            "atan2" => Ok(Value::Number(BuiltinFunctions::atan2(
                self.eval_expr(&args[0])?.as_number(),
                self.eval_expr(&args[1])?.as_number(),
            ))),
            "rand" => {
                self.rng_state = self
                    .rng_state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let val = (self.rng_state >> 33) as f64 / (1u64 << 31) as f64;
                Ok(Value::Number(val))
            }
            "srand" => {
                let old = self.rng_state;
                if args.is_empty() {
                    self.rng_state = self.env.systime() as u64;
                } else {
                    self.rng_state = self.eval_expr(&args[0])?.as_number() as u64;
                }
                if self.rng_state == 0 {
                    self.rng_state = 1;
                }
                Ok(Value::Number(old as f64))
            }
            "and" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(Value::Number((a & b) as f64))
            }
            "or" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(Value::Number((a | b) as f64))
            }
            "xor" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(Value::Number((a ^ b) as f64))
            }
            "lshift" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let count = self.eval_expr(&args[1])?.as_number() as u32;
                Ok(Value::Number(a.wrapping_shl(count & 63) as f64))
            }
            "rshift" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let count = self.eval_expr(&args[1])?.as_number() as u32;
                Ok(Value::Number(a.wrapping_shr(count & 63) as f64))
            }
            "compl" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                Ok(Value::Number((!a) as f64))
            }
            "systime" => Ok(Value::Number(self.env.systime() as f64)),
            "strftime" => {
                let fmt = if args.is_empty() {
                    "%c".to_string()
                } else {
                    self.eval_expr(&args[0])?.as_string()
                };
                let timestamp = if args.len() > 1 {
                    self.eval_expr(&args[1])?.as_number() as i64
                } else {
                    self.env.systime()
                };
                let result = self.format_strftime(&fmt, timestamp);
                Ok(Value::Str(result))
            }
            "mktime" => {
                let datespec = self.eval_expr(&args[0])?.as_string();
                let result = self.parse_mktime(&datespec);
                Ok(Value::Number(result as f64))
            }
            "system" => {
                let cmd_str = self.eval_expr(&args[0])?.as_string();
                self.security.record_audit(AuditEvent::SandboxViolation {
                    action: format!("system({})", &cmd_str),
                });
                let output = self.cmd.execute(&cmd_str)?;
                Ok(Value::Number(output.trim().parse::<f64>().unwrap_or(0.0)))
            }
            "close" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "close: requires a filename argument".to_string(),
                    ));
                }
                let target = self.eval_expr(&args[0])?.as_string();
                let r_ok = self.reader.close_file(&target).is_ok();
                let w_ok = self.writer.close_file(&target).is_ok();
                let p_ok = self.cmd.close_pipe(&target).is_ok();
                if !r_ok || !w_ok || !p_ok {
                    self.errno = format!("close failed for {}", target);
                    Ok(Value::Number(-1.0))
                } else {
                    Ok(Value::Number(0.0))
                }
            }
            "fflush" => {
                if args.is_empty() {
                    self.writer.flush()?;
                    Ok(Value::Number(0.0))
                } else {
                    let target = self.eval_expr(&args[0])?.as_string();
                    if target.is_empty() {
                        self.writer.flush()?;
                        Ok(Value::Number(0.0))
                    } else {
                        self.errno = format!("fflush: cannot flush {}", target);
                        Ok(Value::Number(-1.0))
                    }
                }
            }
            "patsplit" => {
                // patsplit(string, array, fieldpat [, seps])
                // Split string into array elements matching fieldpat
                if args.len() < 3 {
                    return Err(AwkError::RuntimeError(
                        "patsplit: requires at least 3 arguments (string, array, pattern)"
                            .to_string(),
                    ));
                }
                let s = self.eval_expr(&args[0])?.as_string();
                let array_name = match &args[1] {
                    Expr::Var(n) => n.clone(),
                    _ => {
                        return Err(AwkError::RuntimeError(
                            "patsplit: second argument must be an array name".to_string(),
                        ))
                    }
                };
                let pattern = self.eval_expr(&args[2])?.as_string();
                let seps_name = if args.len() > 3 {
                    match &args[3] {
                        Expr::Var(n) => Some(n.clone()),
                        _ => None,
                    }
                } else {
                    None
                };

                // Security: prevent writing to ENVIRON (read-only)
                if array_name == "ENVIRON" {
                    return Err(AwkError::RuntimeError(
                        "attempt to write to read-only array ENVIRON".to_string(),
                    ));
                }
                let rust_pat = regex_escape_to_rust(&pattern);
                let re = self.regex.get_or_compile(&rust_pat)?;

                let arr = self.scope.arrays.entry(array_name).or_default();
                let old_len = arr.len();
                arr.clear();
                self.total_array_entries = self.total_array_entries.saturating_sub(old_len);

                let mut count = 0;
                let mut seps = Vec::new();
                let mut last_end = 0;

                for m in re.find_iter(&s) {
                    count += 1;
                    seps.push(s[last_end..m.start()].to_string());
                    arr.insert(count.to_string(), Value::Str(m.as_str().to_string()));
                    last_end = m.end();
                }
                if self.total_array_entries + count > MAX_TOTAL_ARRAY_ENTRIES {
                    return Err(AwkError::RuntimeError(format!(
                        "Array size limit exceeded ({} entries max)",
                        MAX_TOTAL_ARRAY_ENTRIES
                    )));
                }
                self.total_array_entries += count;
                // Trailing separator
                if last_end < s.len() {
                    seps.push(s[last_end..].to_string());
                }

                // Fill seps array if provided
                if let Some(seps_arr_name) = seps_name {
                    let seps_arr = self.scope.arrays.entry(seps_arr_name).or_default();
                    let old_seps_len = seps_arr.len();
                    seps_arr.clear();
                    self.total_array_entries =
                        self.total_array_entries.saturating_sub(old_seps_len);
                    for (i, sep) in seps.iter().enumerate() {
                        seps_arr.insert(i.to_string(), Value::Str(sep.clone()));
                    }
                    if self.total_array_entries + seps.len() > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)",
                            MAX_TOTAL_ARRAY_ENTRIES
                        )));
                    }
                    self.total_array_entries += seps.len();
                }

                Ok(Value::Number(count as f64))
            }
            "typeof" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "typeof: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                let type_name = match &val {
                    Value::Number(_) => "number",
                    Value::Str(s) => {
                        if let Some(extension_type) = self.type_registry.resolve_tag(s.as_str()) {
                            return Ok(Value::Str(extension_type.to_string()));
                        }
                        "string"
                    }
                    Value::Bool(_) => "boolean",
                    Value::Null => "null",
                    Value::Object(_) => "object",
                    Value::Array(_) => "array",
                    Value::Uninit => "undefined",
                };
                Ok(Value::Str(type_name.to_string()))
            }
            "is_null" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "is_null: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                Ok(Value::Number(if matches!(val, Value::Null) {
                    1.0
                } else {
                    0.0
                }))
            }
            "is_object" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "is_object: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                Ok(Value::Number(if matches!(val, Value::Object(_)) {
                    1.0
                } else {
                    0.0
                }))
            }
            _ => {
                // Check external function handler (Wasm extensions)
                // Try String ABI first, then fall back to legacy Numeric ABI.
                if self.external_fn.is_some() {
                    // Evaluate args as strings BEFORE borrowing handler
                    let mut str_args: Vec<String> = args
                        .iter()
                        .map(|a| self.eval_expr(a).map(|v| v.as_string()))
                        .collect::<AwkResult<Vec<_>>>()?;

                    // Phase 2: Auto variable injection for single-arg external calls.
                    // Convention: any external function called with exactly 1 argument
                    // (the expression) automatically receives scope variables as a 2nd
                    // argument (JSON context), without hardcoding extension names.
                    if str_args.len() == 1 {
                        let scope_vars = self.collect_scope_variables();
                        let context_json = serialize_for_output(&scope_vars);
                        str_args.push(context_json);
                    }

                    // Now borrow handler (avoids conflicting borrow with self)
                    let Some(handler) = self.external_fn.as_deref_mut() else {
                        return Err(AwkError::RuntimeError(format!(
                            "no external function handler for '{}'",
                            name
                        )));
                    };
                    // Try String ABI first
                    let str_result = handler.dispatch(name, &str_args);
                    match str_result {
                        Ok(Some(result_str)) => {
                            if result_str.starts_with("ERROR:") {
                                self.errno = result_str.clone();
                            }
                            return Ok(Value::Str(result_str));
                        }
                        Err(e) => return Err(e),
                        Ok(None) => {} // Unknown function — try next extension or report error
                    }
                }
                Err(AwkError::RuntimeError(format!(
                    "Unknown function: {}",
                    name
                )))
            }
        }
    }

    /// Evaluate a qualified function call: ns.func(args).
    /// The qualified name is passed to the host-supplied dispatcher as-is.
    pub(super) fn eval_qualified_func_call(
        &mut self,
        namespace: &str,
        function: &str,
        args: &[Expr],
    ) -> AwkResult<Value> {
        let qualified_name = format!("{}.{}", namespace, function);

        // Evaluate arguments to strings first (before borrowing handler)
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args {
            let val = self.eval_expr(arg)?;
            str_args.push(val.as_string());
        }

        let handler = match self.external_fn {
            Some(ref mut h) => h,
            None => {
                return Err(AwkError::RuntimeError(format!(
                    "Unknown function: {} (no dispatcher configured)",
                    qualified_name
                )));
            }
        };

        // Route via the host-supplied dispatcher as a qualified name
        match handler.dispatch(&qualified_name, &str_args)? {
            Some(result) => {
                if result.starts_with("ERROR:") {
                    Err(AwkError::RuntimeError(result[6..].trim().to_string()))
                } else {
                    Ok(Value::Str(result))
                }
            }
            None => Err(AwkError::RuntimeError(format!(
                "Unknown function: {}",
                qualified_name
            ))),
        }
    }

    /// Check if a string looks like a var=val assignment.
    pub(super) fn is_var_assign(s: &str) -> bool {
        if let Some(eq) = s.find('=') {
            let name = &s[..eq];
            !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
        } else {
            false
        }
    }

    /// Call a user-defined function using the scope stack.
    /// This is zero-copy: we push a new scope, set params/locals,
    /// execute the body, then pop the scope. No HashMap cloning needed.
    pub(super) fn call_user_function(&mut self, func: &FunctionDef, args: &[Expr]) -> AwkResult<Value> {
        self.security.call_depth += 1;
        if self.security.call_depth > MAX_CALL_DEPTH {
            self.security.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_CALL_DEPTH".to_string(),
                limit_value: MAX_CALL_DEPTH,
                actual_value: self.security.call_depth,
            });
            return Err(AwkError::RuntimeError(
                "Recursion limit exceeded".to_string(),
            ));
        }

        // Evaluate arguments in the CALLER's scope
        let mut arg_vals = Vec::with_capacity(args.len());
        for arg in args {
            arg_vals.push(self.eval_expr(arg)?);
        }

        // Push a new scope for this function call
        self.scope.push_scope();

        // Set parameters from pre-evaluated values
        for (i, param) in func.params.iter().enumerate() {
            let val = if i < arg_vals.len() {
                arg_vals[i].clone()
            } else {
                Value::Uninit
            };
            self.scope
                .scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope
                .scope_stack
                .last_mut()
                .unwrap()
                .insert(local.clone(), Value::Uninit);
        }

        // Execute body
        let result = self.exec_statements(&func.body.statements);

        // Pop the scope - all locals and params are automatically discarded
        self.scope.pop_scope();
        self.security.call_depth -= 1;

        match result {
            Ok(EvalSignal::Return(val)) => Ok(val),
            Ok(_) => Ok(Value::Uninit),
            Err(e) => Err(e),
        }
    }

    /// Call a user-defined function by name with pre-evaluated string arguments.
    ///
    /// This is the **Host-driven function call** API. It allows the Rust host
    /// to invoke AWK functions directly (e.g., for Nginx-style event routing)
    /// without going through the BEGIN/records/END execution loop.
    ///
    /// The function must have been registered via `register_functions()` or `execute()`.
    /// Returns the function's return value as a String.
    pub fn call_function(&mut self, name: &str, args: &[String]) -> AwkResult<String> {
        let func = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| AwkError::RuntimeError(format!("Undefined function: '{}'", name)))?;

        self.security.call_depth += 1;
        if self.security.call_depth > MAX_CALL_DEPTH {
            self.security.record_audit(AuditEvent::LimitViolation {
                limit_name: "MAX_CALL_DEPTH".to_string(),
                limit_value: MAX_CALL_DEPTH,
                actual_value: self.security.call_depth,
            });
            return Err(AwkError::RuntimeError(
                "Recursion limit exceeded".to_string(),
            ));
        }

        // Push a new scope for this function call
        self.scope.push_scope();

        // Set parameters from string args
        for (i, param) in func.params.iter().enumerate() {
            let val = if i < args.len() {
                Value::Str(args[i].clone())
            } else {
                Value::Uninit
            };
            self.scope
                .scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope
                .scope_stack
                .last_mut()
                .unwrap()
                .insert(local.clone(), Value::Uninit);
        }

        // Execute body
        let result = self.exec_statements(&func.body.statements);

        // Pop the scope
        self.scope.pop_scope();
        self.security.call_depth -= 1;

        match result {
            Ok(EvalSignal::Return(val)) => Ok(val.as_string()),
            Ok(_) => Ok(String::new()),
            Err(e) => Err(e),
        }
    }

    /// Register function definitions from a parsed program without executing it.
    /// This is used by the Host-driven function call model.
    pub fn register_functions(&mut self, program: &Program) {
        for func in &program.functions {
            self.functions
                .insert(func.name.clone(), Rc::new(func.clone()));
        }
    }

    /// Execute all BEGIN blocks from a parsed program.
    /// This is used by the Host-driven function call model to ensure
    /// BEGIN-initialized state is available before calling functions.
    pub fn execute_begin_blocks(&mut self, program: &Program) -> AwkResult<()> {
        self.uses_property_tree_features = Self::program_uses_property_tree_features(program);
        self.containers_possible =
            self.uses_property_tree_features || Self::program_has_container_literals(program);
        for rule in &program.rules {
            if rule.pattern.as_ref() == Some(&Pattern::Begin) {
                if let Some(action) = &rule.action {
                    let signal = self.exec_statements(&action.statements)?;
                    if matches!(signal, EvalSignal::Return(_)) {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

}
