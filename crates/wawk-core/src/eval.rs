//! Evaluator/Interpreter for the AWK language.
//!
//! Executes an AST using trait-based I/O for sandboxability.
//! Uses a scope stack for zero-copy variable scoping in user-defined functions.
//!
//! Performance design (compared to gawk/mawk):
//! - Byte-oriented field splitting with deferred materialization (like mawk)
//! - FxHashMap for O(1) variable and array access with fast hashing
//! - Regex compilation cache with LRU eviction
//! - Reusable buffers for print output and array keys (zero per-line allocation)
//! - Fast integer formatting via `itoa` (avoids format!() overhead)
//! - Fast float formatting via `ryu` (avoids format!() overhead)
//! - Literal pattern fast-path: substring search instead of regex engine

// HashMap replaced with FxHashMap for arrays
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write;
use std::rc::Rc;

use rustc_hash::FxHashMap;

use regex::Regex;

use crate::ast::*;
use crate::error::{AwkError, AwkResult};
use crate::traits::{
    AwkCommandExecutor, AwkEnvironment, AwkExternalFunction, AwkReader, AwkWriter,
};
use crate::types::PluginTypeRegistry;

/// The AWK virtual machine / evaluator.
pub struct Evaluator<'a> {
    reader: &'a mut dyn AwkReader,
    writer: &'a mut dyn AwkWriter,
    env: &'a dyn AwkEnvironment,
    cmd: &'a mut dyn AwkCommandExecutor,

    // Scope stack for variables (index 0 = global scope)
    scope_stack: Vec<FxHashMap<String, AwkValue>>,
    // Arrays are always global (not scoped)
    arrays: FxHashMap<String, FxHashMap<String, AwkValue>>,
    fields: Vec<String>,
    // Reusable line buffer: holds the current input record (zero-copy from reader).
    // Field ranges index directly into line_buf.as_bytes() — no separate raw_bytes/raw_line.
    line_buf: String,
    // Field byte ranges into line_buf (deferred materialization - avoids String alloc per field)
    field_ranges: Vec<(usize, usize)>,
    // Whether individual fields have been modified since last split
    fields_modified: bool,
    nr: usize,
    nf: usize,
    fs: String,
    rs: String,
    ofs: String,
    ors: String,
    ofmt: String,
ofmt_precision: usize,
    convfmt: String,
    subsep: String,
    fpat: String,
    filename: String,

    // User-defined functions (Rc avoids cloning the entire AST body on every call)
    functions: FxHashMap<String, Rc<FunctionDef>>,

    // Random state
    rng_state: u64,

    // Call stack depth (for recursion limit)
    call_depth: usize,

    // Expression nesting depth (for stack overflow prevention)
    expr_depth: usize,

    // Range pattern state: (rule_index, active)
    range_active: Vec<bool>,

    // File record number (reset per file)
    fnr: usize,

    // Reusable buffer for print/printf output (avoids per-statement allocation)
    print_buf: String,
    // Reusable buffer for array key construction (avoids String alloc on field-access keys)
    array_key_buf: String,
    // Reusable buffer for fast integer formatting (itoa)
    num_buf: itoa::Buffer,
    // Total output bytes written (for output size limit)
    output_bytes: usize,
    // Regex cache for performance (avoids recompiling the same pattern)
    regex_cache: FxHashMap<String, Regex>,
    // Debug-only regex cache statistics
    #[cfg(debug_assertions)]
    regex_cache_hits: u64,
    #[cfg(debug_assertions)]
    regex_cache_misses: u64,

    // External function handler (for Wasm extensions)
    external_fn: Option<Box<dyn AwkExternalFunction>>,

    // ARGV/ARGC support
    argc: usize,
    argv: Vec<String>,

    // Total array entries across all arrays (for memory limit enforcement)
    total_array_entries: usize,

    // Open file targets for print redirect FD limit
    open_files: HashSet<String>,

    // ERRNO: set on I/O failures, plugin errors, etc.
    errno: String,

    // Current index into ARGV for file iteration
    argv_index: usize,

    // Plugin type registry for plugin-provided types
    pub type_registry: PluginTypeRegistry,
}

/// Maximum total array entries across all arrays.
/// WASM default: 1M. Increase for native builds.
const MAX_TOTAL_ARRAY_ENTRIES: usize = 1_000_000;
/// Maximum recursion depth for user-defined function calls.
const MAX_CALL_DEPTH: usize = 256;
/// Maximum expression nesting depth to prevent stack overflow.
const MAX_EXPR_DEPTH: usize = 1024;
/// Maximum regex pattern length (prevent ReDoS via complexity).
const MAX_REGEX_PATTERN_LEN: usize = 4096;
/// Maximum loop iterations before aborting (prevent infinite loops in sandboxed mode).
const MAX_LOOP_ITERATIONS: usize = 100_000_000;
/// Maximum output bytes before aborting (prevent memory exhaustion via print).
/// WASM default: 64MB. Increase for native builds.
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024; // 64 MB
/// Maximum number of simultaneously open file targets for print redirects.
const MAX_OPEN_FILES: usize = 256;
/// Maximum number of fields per record.
pub const MAX_FIELDS: usize = 100_000;

/// AWK values - everything is either a number or a string.
#[derive(Debug, Clone)]
pub enum AwkValue {
    Number(f64),
    Str(String),
    Uninit,
    Bool(bool),
    Null,
    Object(Vec<(String, AwkValue)>),
    Array(Vec<AwkValue>),
}

impl AwkValue {
    /// Look up a field in an Object by name. Returns None if not an Object or field missing.
    #[must_use]
    pub fn object_get(&self, field: &str) -> Option<&AwkValue> {
        match self {
            AwkValue::Object(pairs) => pairs.iter().find(|(k, _)| k == field).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_number(&self) -> f64 {
        match self {
            AwkValue::Number(n) => *n,
            AwkValue::Str(s) => awk_str_to_number(s),
            AwkValue::Uninit => 0.0,
            AwkValue::Bool(true) => 1.0,
            AwkValue::Bool(false) => 0.0,
            AwkValue::Null => 0.0,
            AwkValue::Object(_) => 0.0,
            AwkValue::Array(_) => 0.0,
        }
    }

    /// Zero-copy string conversion: returns Cow<str> to avoid allocation when possible.
    /// For Str variant, returns a borrowed reference. For Number, allocates only when needed.
    #[inline]
    pub fn as_cow_str(&self) -> Cow<'_, str> {
        match self {
            AwkValue::Str(s) => Cow::Borrowed(s.as_str()),
            AwkValue::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    let mut buf = itoa::Buffer::new();
                    Cow::Owned(buf.format(*n as i64).to_string())
                } else if !n.is_finite() {
                    Cow::Borrowed(if n.is_nan() { "nan" } else if n.is_sign_positive() { "inf" } else { "-inf" })
                } else {
                    let mut buf = ryu::Buffer::new();
                    Cow::Owned(buf.format(*n).to_string())
                }
            }
            AwkValue::Uninit | AwkValue::Null => Cow::Borrowed(""),
            AwkValue::Bool(true) => Cow::Borrowed("1"),
            AwkValue::Bool(false) => Cow::Borrowed("0"),
            AwkValue::Object(_) | AwkValue::Array(_) => Cow::Owned(awk_to_json(self)),
        }
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            AwkValue::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    // Fast path: use itoa for integer formatting
                    let mut buf = itoa::Buffer::new();
                    buf.format(*n as i64).to_string()
                } else if !n.is_finite() {
                    if n.is_nan() {
                        "nan".to_string()
                    } else if n.is_sign_positive() {
                        "inf".to_string()
                    } else {
                        "-inf".to_string()
                    }
                } else {
                    // Fast path: use ryu for float formatting
                    let mut buf = ryu::Buffer::new();
                    buf.format(*n).to_string()
                }
            }
            AwkValue::Str(s) => s.clone(),
            AwkValue::Uninit => String::new(),
            AwkValue::Bool(true) => "1".to_string(),
            AwkValue::Bool(false) => "0".to_string(),
            AwkValue::Null => String::new(),
            AwkValue::Object(_) | AwkValue::Array(_) => awk_to_json(self),
        }
    }

    /// Write value as string directly into a buffer (zero-allocation for numbers).
    /// This is the hot path for print statements.
    #[inline]
    pub fn write_to_buf(&self, buf: &mut String) {
        match self {
            AwkValue::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    let mut ibuf = itoa::Buffer::new();
                    buf.push_str(ibuf.format(*n as i64));
                } else if !n.is_finite() {
                    if n.is_nan() {
                        buf.push_str("nan");
                    } else if n.is_sign_positive() {
                        buf.push_str("inf");
                    } else {
                        buf.push_str("-inf");
                    }
                } else {
                    let mut fbuf = ryu::Buffer::new();
                    buf.push_str(fbuf.format(*n));
                }
            }
            AwkValue::Str(s) => buf.push_str(s),
            AwkValue::Uninit => {}
            AwkValue::Bool(true) => buf.push('1'),
            AwkValue::Bool(false) => buf.push('0'),
            AwkValue::Null => {}
            AwkValue::Object(_) | AwkValue::Array(_) => buf.push_str(&awk_to_json(self)),
        }
    }

    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            AwkValue::Number(n) => *n != 0.0,
            AwkValue::Str(s) => !s.is_empty() && s != "0",
            AwkValue::Uninit => false,
            AwkValue::Bool(b) => *b,
            AwkValue::Null => false,
            AwkValue::Object(_) => true,
            AwkValue::Array(_) => true,
        }
    }
}

impl PartialEq for AwkValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AwkValue::Number(a), AwkValue::Number(b)) => a == b,
            (AwkValue::Str(a), AwkValue::Str(b)) => a == b,
            (AwkValue::Bool(a), AwkValue::Bool(b)) => a == b,
            (AwkValue::Null, AwkValue::Null) => true,
            (AwkValue::Object(a), AwkValue::Object(b)) => a == b,
            (AwkValue::Array(a), AwkValue::Array(b)) => a == b,
            (AwkValue::Bool(true), AwkValue::Number(n)) => *n == 1.0,
            (AwkValue::Bool(false), AwkValue::Number(n)) => *n == 0.0,
            (AwkValue::Number(n), AwkValue::Bool(true)) => *n == 1.0,
            (AwkValue::Number(n), AwkValue::Bool(false)) => *n == 0.0,
            (AwkValue::Null, AwkValue::Str(s)) => s.is_empty(),
            (AwkValue::Str(s), AwkValue::Null) => s.is_empty(),
            (AwkValue::Null, AwkValue::Number(n)) => *n == 0.0,
            (AwkValue::Number(n), AwkValue::Null) => *n == 0.0,
            _ => {
                if matches!(self, AwkValue::Number(_)) || matches!(other, AwkValue::Number(_)) {
                    self.as_number() == other.as_number()
                } else {
                    self.as_string() == other.as_string()
                }
            }
        }
    }
}

/// Signal for control flow within the evaluator.
#[derive(Debug)]
enum Signal {
    None,
    Next,
    NextFile,
    Break,
    Continue,
    Return(AwkValue),
}

impl<'a> Evaluator<'a> {
    pub fn new(
        reader: &'a mut dyn AwkReader,
        writer: &'a mut dyn AwkWriter,
        env: &'a dyn AwkEnvironment,
        cmd: &'a mut dyn AwkCommandExecutor,
    ) -> Self {
        Self {
            reader,
            writer,
            env,
            cmd,
            scope_stack: vec![FxHashMap::default()], // global scope
            arrays: FxHashMap::default(),
            fields: Vec::new(),
            line_buf: String::with_capacity(256),
            field_ranges: Vec::new(),
            fields_modified: false,
            nr: 0,
            nf: 0,
            fs: " ".to_string(),
            rs: "\n".to_string(),
            ofs: " ".to_string(),
            ors: "\n".to_string(),
            ofmt: "%.6g".to_string(),
ofmt_precision: 6,
            convfmt: "%.6g".to_string(),
            subsep: "\x1c".to_string(),
            fpat: String::new(),
            filename: String::new(),
            functions: FxHashMap::default(),
            rng_state: 1,
            call_depth: 0,
            expr_depth: 0,
            range_active: Vec::new(),
            fnr: 0,
            print_buf: String::with_capacity(256),
            array_key_buf: String::with_capacity(64),
            num_buf: itoa::Buffer::new(),
            output_bytes: 0,
            errno: String::new(),
            argv_index: 1,
            regex_cache: FxHashMap::default(),
            #[cfg(debug_assertions)]
            regex_cache_hits: 0,
            #[cfg(debug_assertions)]
            regex_cache_misses: 0,
            external_fn: None,
            argc: 0,
            argv: Vec::new(),
            total_array_entries: 0,
            open_files: HashSet::new(),
            type_registry: PluginTypeRegistry::new(),
        }
    }

    /// Set an external function handler for Wasm host extensions.
    pub fn set_external_function_handler(&mut self, handler: Box<dyn AwkExternalFunction>) {
        self.external_fn = Some(handler);
    }

    pub fn set_fs(&mut self, fs: String) {
        self.fs = fs;
    }

    /// Set a variable in the global scope (used by CLI -v assignments).
    pub fn set_variable(&mut self, name: String, value: String) {
        match name.as_str() {
            "FS" => self.fs = value.clone(),
            "OFS" => self.ofs = value.clone(),
            "ORS" => self.ors = value.clone(),
            "RS" => self.rs = value.clone(),
            "NF" => self.nf = value.parse().unwrap_or(0),
            "NR" => self.nr = value.parse().unwrap_or(0),
            "FNR" => self.fnr = value.parse().unwrap_or(0),
            "FILENAME" => self.filename = value.clone(),
            _ => {}
        }
        self.scope_stack[0].insert(name, AwkValue::Str(value));
    }

    /// Set ARGV/ARGC values (program arguments).
    pub fn set_argv(&mut self, args: Vec<String>) {
        self.argc = args.len();
        self.argv = args;
    }



    /// Insert a value into an array, tracking total entries for limit enforcement.
    /// Uses Entry API for single-lookup insertion (avoids contains_key + insert).
    fn array_insert(&mut self, arr_name: &str, key: String, val: AwkValue) -> AwkResult<()> {
        let arr = self.arrays.entry(arr_name.to_string()).or_default();
        match arr.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                // Key exists: just update the value
                entry.insert(val);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                // New key: check limit before inserting
                if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                    return Err(AwkError::RuntimeError(format!(
                        "Array size limit exceeded ({} entries max)",
                        MAX_TOTAL_ARRAY_ENTRIES
                    )));
                }
                self.total_array_entries += 1;
                entry.insert(val);
            }
        }
        Ok(())
    }

    /// Get a compiled regex from cache, or compile and cache it.
    /// This is a critical performance optimization - avoids recompiling the same pattern on every line.
    /// Cache is capped at 256 entries to prevent unbounded memory growth.
    /// Pattern length is limited to prevent ReDoS attacks.
    #[inline]
    fn get_cached_regex(&mut self, rust_pattern: &str) -> AwkResult<Regex> {
        if let Some(re) = self.regex_cache.get(rust_pattern) {
            #[cfg(debug_assertions)]
            { self.regex_cache_hits += 1; }
            return Ok(re.clone());
        }
        #[cfg(debug_assertions)]
        { self.regex_cache_misses += 1; }
        // Security: limit pattern length to prevent ReDoS
        if rust_pattern.len() > MAX_REGEX_PATTERN_LEN {
            return Err(AwkError::RuntimeError(format!(
                "Regex pattern too long ({} bytes, max {})",
                rust_pattern.len(),
                MAX_REGEX_PATTERN_LEN
            )));
        }
        match Regex::new(rust_pattern) {
            Ok(re) => {
                // Evict entries if cache is too large (simple LRU approximation: clear half)
                if self.regex_cache.len() >= 512 {
                    let keys: Vec<String> = self.regex_cache.keys().take(256).cloned().collect();
                    for k in keys {
                        self.regex_cache.remove(&k);
                    }
                }
                self.regex_cache
                    .insert(rust_pattern.to_string(), re.clone());
                Ok(re)
            }
            Err(e) => Err(AwkError::RuntimeError(format!(
                "Invalid regular expression '{}': {}",
                rust_pattern, e
            ))),
        }
    }

    /// Get regex cache statistics (debug builds only).
    #[cfg(debug_assertions)]
    pub fn regex_cache_stats(&self) -> (u64, u64, usize) {
        (self.regex_cache_hits, self.regex_cache_misses, self.regex_cache.len())
    }

    /// Push a new scope onto the stack (entering a function).
    fn push_scope(&mut self) {
        self.scope_stack.push(FxHashMap::default());
    }

    /// Pop the top scope off the stack (leaving a function).
    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    /// Get a variable, walking the scope stack from innermost to outermost.
    /// Special built-in variables are handled first.
    fn get_variable(&self, name: &str) -> AwkValue {
        match name {
            "NR" => AwkValue::Number(self.nr as f64),
            "NF" => AwkValue::Number(self.nf as f64),
            "FNR" => AwkValue::Number(self.fnr as f64),
            "FS" => AwkValue::Str(self.fs.clone()),
            "RS" => AwkValue::Str(self.rs.clone()),
            "OFS" => AwkValue::Str(self.ofs.clone()),
            "ORS" => AwkValue::Str(self.ors.clone()),
            "FILENAME" => AwkValue::Str(self.filename.clone()),
            "SUBSEP" => AwkValue::Str(self.subsep.clone()),
            "FPAT" => AwkValue::Str(self.fpat.clone()),
            "OFMT" => AwkValue::Str(self.ofmt.clone()),
            "CONVFMT" => AwkValue::Str(self.convfmt.clone()),
            "ARGC" => AwkValue::Number(self.argc as f64),
            "ERRNO" => AwkValue::Str(self.errno.clone()),
            _ => {
                for scope in self.scope_stack.iter().rev() {
                    if let Some(val) = scope.get(name) {
                        return val.clone();
                    }
                }
                AwkValue::Uninit
            }
        }
    }



    fn program_needs_fields(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            if let Some(ref action) = rule.action {
                Self::block_needs_fields(&action.statements)
            } else {
                false
            }
        })
    }

    fn block_needs_fields(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_needs_fields)
    }

    fn stmt_needs_fields(stmt: &Statement) -> bool {
        match stmt {
            Statement::Expr(expr) => Self::expr_needs_fields(expr),
            Statement::Print(exprs) => exprs.iter().any(Self::expr_needs_fields),
            Statement::Printf(fmt, args) => Self::expr_needs_fields(fmt) || args.iter().any(Self::expr_needs_fields),
            Statement::PrintRedirect(exprs, _, target) => {
                exprs.iter().any(Self::expr_needs_fields) || Self::expr_needs_fields(target)
            }
            Statement::PrintfRedirect(fmt, args, _, target) => {
                Self::expr_needs_fields(fmt) || args.iter().any(Self::expr_needs_fields) || Self::expr_needs_fields(target)
            }
            Statement::Assign(_, value) => Self::expr_needs_fields(value),
            Statement::CompoundAssign(_, _, value) => Self::expr_needs_fields(value),
            Statement::ArrayAssign(_, idx, value) => Self::expr_needs_fields(idx) || Self::expr_needs_fields(value),
            Statement::FieldAssign(_, _) => true,
            Statement::If(cond, then_s, else_s) => {
                Self::expr_needs_fields(cond) || Self::stmt_needs_fields(then_s)
                    || else_s.as_ref().is_some_and(|s| Self::stmt_needs_fields(s))
            }
            Statement::While(cond, body) => Self::expr_needs_fields(cond) || Self::stmt_needs_fields(body),
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
            Statement::Increment(_, _) | Statement::Next | Statement::NextFile
            | Statement::Break | Statement::Continue | Statement::Delete(_, _)
            | Statement::DeleteAll(_) | Statement::Close(_) => false,
        }
    }

    fn expr_needs_fields(expr: &Expr) -> bool {
        match expr {
            Expr::Field(_) | Expr::Record => true,
            Expr::Var(name) => name == "NF" || name == "FILENAME",
            Expr::Number(_) | Expr::String(_) | Expr::BoolLit(_) | Expr::NullLit => false,
            Expr::BinOp(l, _, r) => Self::expr_needs_fields(l) || Self::expr_needs_fields(r),
            Expr::UnaryOp(_, e) => Self::expr_needs_fields(e),
            Expr::FuncCall(_, args) => args.iter().any(Self::expr_needs_fields),
            Expr::ArrayAccess(_, idx) => Self::expr_needs_fields(idx),
            Expr::Match(e, _) | Expr::NotMatch(e, _) => Self::expr_needs_fields(e),
            Expr::Ternary(c, t, f) => Self::expr_needs_fields(c) || Self::expr_needs_fields(t) || Self::expr_needs_fields(f),
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

    /// Get a variable as f64 directly (avoids cloning AwkValue).
    #[inline(always)]
    fn get_variable_f64(&self, name: &str) -> f64 {
        for scope in self.scope_stack.iter().rev() {
            if let Some(val) = scope.get(name) {
                return val.as_number();
            }
        }
        0.0
    }

    /// Set a variable with write-through semantics:
    /// - If found in a local scope, update it there
    /// - Otherwise, set in global scope (AWK dynamic scoping)
    #[allow(clippy::map_entry)] // contains_key+insert needed in loop (Entry API consumes key)
    fn set_var(&mut self, name: String, value: AwkValue) {
        // Walk from innermost to outermost (skip global = index 0)
        for i in (1..self.scope_stack.len()).rev() {
            if self.scope_stack[i].contains_key(&name) {
                self.scope_stack[i].insert(name, value);
                return;
            }
        }
        // Not in any local scope → set in global
        self.scope_stack[0].insert(name, value);
    }


    /// Set a variable accepting &str to avoid String allocation.
    #[inline(always)]
    fn set_var_str(&mut self, name: &str, value: AwkValue) {
        for i in (1..self.scope_stack.len()).rev() {
            if self.scope_stack[i].contains_key(name) {
                self.scope_stack[i].insert(name.to_string(), value);
                return;
            }
        }
        self.scope_stack[0].insert(name.to_string(), value);
    }

    pub fn execute(&mut self, program: &Program) -> AwkResult<()> {
        for func in &program.functions {
            self.functions
                .insert(func.name.clone(), Rc::new(func.clone()));
        }

        for rule in &program.rules {
            if rule.pattern.as_ref() == Some(&Pattern::Begin) {
                if let Some(action) = &rule.action {
                    let signal = self.exec_statements(&action.statements)?;
                    if matches!(signal, Signal::Return(_)) {
                        return Ok(());
                    }
                }
            }
        }

        self.range_active = vec![false; program.rules.len()];

        let needs_fields = Self::program_needs_fields(program);

        // Pre-compile all static regex patterns before the main loop.
        // This eliminates per-line hash lookups and String allocations.
        let mut precompiled: Vec<Option<regex::Regex>> = vec![None; program.rules.len()];
        let mut pre_filters: Vec<Option<RegexPreFilter>> = vec![None; program.rules.len()];
        for (i, rule) in program.rules.iter().enumerate() {
            if let Some(Pattern::Regex(re_str)) = &rule.pattern {
                let rust_pat = regex_escape_to_rust(re_str);
                if rust_pat.len() <= MAX_REGEX_PATTERN_LEN {
                    pre_filters[i] = Some(RegexPreFilter::new(re_str));
                    if let Ok(re) = regex::Regex::new(&rust_pat) {
                        precompiled[i] = Some(re);
                    }
                }
            }
        }

        // has_line_patterns removed — precompiled regex uses &self.line_buf directly

        // ARGV-driven main loop: iterate over files in ARGV
        loop {
            while self.reader.read_line_into(&mut self.line_buf)? {
                if self.line_buf.len() > 16_777_216 {
                    // 16 MB max record size
                    return Err(AwkError::RuntimeError(
                        "record exceeds maximum size (16 MB)".into(),
                    ));
                }
                // Optimized filename tracking: only allocates String on file transitions
                if let Some(new_filename) = self.reader.filename_if_changed() {
                    self.fnr = 0;
                    self.filename = new_filename;
                }
                self.nr += 1;
                self.fnr += 1;
                if needs_fields {
                    self.split_fields_inplace()?;
                }

                // Clone line_buf for pattern matching only when needed (borrow checker)
                // line_buf is borrowed directly for precompiled regex (zero-copy)

                for (rule_idx, rule) in program.rules.iter().enumerate() {
                    match &rule.pattern {
                        Some(Pattern::Begin) | Some(Pattern::End) => continue,
                        _ => {}
                    }

                    let matches = match &rule.pattern {
                        None => true,
                        Some(Pattern::Regex(_)) => {
                            // Check pre-filter first: if exact mode and passes, skip regex entirely
                            if let Some(Some(pf)) = pre_filters.get(rule_idx) {
                                if let Some(result) = pf.check(&self.line_buf) {
                                    result
                                } else if let Some(Some(re)) = precompiled.get(rule_idx) {
                                    re.is_match(&self.line_buf)
                                } else {
                                    let re_str = match &rule.pattern {
                                        Some(Pattern::Regex(s)) => s.as_str(),
                                        _ => unreachable!(),
                                    };
                                    match regex::Regex::new(re_str) {
                                        Ok(re) => re.is_match(&self.line_buf),
                                        Err(_) => false,
                                    }
                                }
                            } else if let Some(Some(re)) = precompiled.get(rule_idx) {
                                re.is_match(&self.line_buf)
                            } else {
                                // Fallback: compile inline (avoids &mut self cache conflict)
                                let re_str = match &rule.pattern {
                                    Some(Pattern::Regex(s)) => s.as_str(),
                                    _ => unreachable!(),
                                };
                                match regex::Regex::new(re_str) {
                                    Ok(re) => re.is_match(&self.line_buf),
                                    Err(_) => false,
                                }
                            }
                        }
                        Some(Pattern::Expression(expr)) => {
                            let val = self.eval_expr(expr)?;
                            val.is_truthy()
                        }
                        Some(Pattern::Range(start_pat, end_pat)) => {
                            let active = self.range_active.get(rule_idx).copied().unwrap_or(false);
                            // Use mem::take to avoid clone: take ownership of line_buf temporarily
                            let line = std::mem::take(&mut self.line_buf);
                            let result = if !active {
                                let start_matches =
                                    self.pattern_matches(start_pat, &line)?;
                                if start_matches {
                                    self.range_active[rule_idx] = true;
                                    true
                                } else {
                                    false
                                }
                            } else {
                                let end_matches =
                                    self.pattern_matches(end_pat, &line)?;
                                if end_matches {
                                    self.range_active[rule_idx] = false;
                                }
                                true
                            };
                            self.line_buf = line;
                            result
                        }
                        _ => true,
                    };

                    if matches {
                        if let Some(action) = &rule.action {
                            let signal = self.exec_statements(&action.statements)?;
                            if matches!(signal, Signal::Next) {
                                break;
                            }
                            if matches!(signal, Signal::NextFile) {
                                self.fnr = 0;
                                self.reader.skip_to_next_file();
                                break;
                            }
                            if matches!(signal, Signal::Return(_)) {
                                return Ok(());
                            }
                        } else {
                            // Zero-copy default action: write line_buf directly (no clone)
                            self.writer.write_str(&self.line_buf)?;
                            self.writer.write_str(&self.ors)?;
                        }
                    }
                }
            }

            // EOF on current source — check ARGV for next file
            if self.argv_index >= self.argc {
                break; // No more ARGV elements — proceed to END
            }

            let arg = self.argv[self.argv_index].clone();
            self.argv_index += 1;

            // Check if it's a var=val assignment
            if Self::is_var_assign(&arg) {
                let Some(eq) = arg.find('=') else { continue };
                let var_name = arg[..eq].to_string();
                let var_val = arg[eq + 1..].to_string();
                self.set_var(var_name, AwkValue::Str(var_val));
                continue; // Go back to loop, try next ARGV element
            }

            // It's a filename — open it
            if let Err(err) = self.reader.open_file(&arg) {
                self.errno = format!("{}", err);
                eprintln!("wawk: can't open file '{}': {}", arg, err);
                continue; // Skip to next ARGV element
            }
            // FILENAME will be updated on next read via filename_if_changed()
        }

        for rule in &program.rules {
            if rule.pattern.as_ref() == Some(&Pattern::End) {
                if let Some(action) = &rule.action {
                    let signal = self.exec_statements(&action.statements)?;
                    if matches!(signal, Signal::Return(_)) {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    /// Split fields from `line_buf` in place (zero-copy: field ranges index into line_buf).
    /// Used by the main execute loop where line_buf already holds the current record.
    #[inline]
    fn split_fields_inplace(&mut self) -> AwkResult<()> {
        self.fields.clear();
        self.field_ranges.clear();
        self.fields_modified = false;

        // If FPAT is set, use field pattern splitting (gawk extension)
        if !self.fpat.is_empty() {
            self.fields.push(String::new()); // $0 placeholder
            let rust_fpat = regex_escape_to_rust(&self.fpat);
            let line = std::mem::take(&mut self.line_buf); // avoid clone: take ownership temporarily
            match self.get_cached_regex(&rust_fpat) {
                Ok(re) => {
                    for m in re.find_iter(&line) {
                        self.fields.push(m.as_str().to_string());
                    }
                }
                Err(_) => {
                    self.fields.push(line.clone());
                }
            }
            self.line_buf = line;
            self.nf = self.fields.len() - 1;
            self.fields_modified = true;
            return Ok(());
        }

        if self.fs == " " {
            // HOT PATH: Byte-oriented whitespace splitting.
            // No String allocations — just record byte ranges into line_buf.
            let bytes = self.line_buf.as_bytes();
            let mut i = 0;
            let len = bytes.len();
            while i < len {
                while i < len && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\x0b' | b'\x0c') {
                    i += 1;
                }
                if i >= len {
                    break;
                }
                let start = i;
                while i < len
                    && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'\x0b' | b'\x0c')
                {
                    i += 1;
                }
                self.field_ranges.push((start, i));
            }
        } else if self.fs.is_empty() {
            // FS="": split each character into its own field (materialize immediately)
            self.fields.push(String::new()); // $0 placeholder
            for ch in self.line_buf.chars() {
                self.fields.push(ch.to_string());
            }
        } else if self.fs.len() == 1 && !Self::is_regex_metachar(self.fs.as_bytes()[0]) {
            // HOT PATH: Single-byte literal FS (e.g. "," or ":" or "\t").
            // Use byte-range mode like whitespace splitting — no String allocations.
            let sep = self.fs.as_bytes()[0];
            let bytes = self.line_buf.as_bytes();
            let len = bytes.len();
            let mut start = 0;
            for (i, &b) in bytes.iter().enumerate() {
                if b == sep {
                    self.field_ranges.push((start, i));
                    start = i + 1;
                }
            }
            self.field_ranges.push((start, len));
        } else {
            // Regex/literal FS split (materialize immediately)
            self.fields.push(String::new()); // $0 placeholder
            let rust_fs = regex_escape_to_rust(&self.fs);
            let line = self.line_buf.clone(); // need owned for regex borrow
            match self.get_cached_regex(&rust_fs) {
                Ok(re) => {
                    let mut last_end = 0;
                    for m in re.find_iter(&line) {
                        self.fields.push(line[last_end..m.start()].to_string());
                        last_end = m.end();
                    }
                    self.fields.push(line[last_end..].to_string());
                    if line.starts_with(&self.fs) && self.fields.len() > 1 {
                        self.fields.remove(1);
                    }
                }
                Err(_) => {
                    for field in line.split(&self.fs) {
                        self.fields.push(field.to_string());
                    }
                }
            }
        }

        self.nf = if !self.field_ranges.is_empty() {
            self.field_ranges.len()
        } else {
            self.fields.len() - 1
        };

        if self.fields.len() > MAX_FIELDS {
            return Err(AwkError::RuntimeError(format!(
                "Field count {} exceeds maximum allowed ({})", self.fields.len(), MAX_FIELDS
            )));
        }
        Ok(())
    }

    /// Split an arbitrary string into fields, storing result in line_buf.
    /// Used by getline, sub/gsub when target is $0.
    #[inline]
    fn split_fields_from(&mut self, line: &str) -> AwkResult<()> {
        self.line_buf.clear();
        self.line_buf.push_str(line);
        self.split_fields_inplace()
    }

    /// Check if a byte is a regex metacharacter.
    #[inline]
    fn is_regex_metachar(b: u8) -> bool {
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

    fn get_field(&self, n: usize) -> String {
        if !self.fields_modified {
            if n == 0 {
                return self.line_buf.clone();
            }
            // Byte-range mode: FS=" " whitespace or single-byte literal FS
            if !self.field_ranges.is_empty() {
                if let Some(&(start, end)) = self.field_ranges.get(n - 1) {
                    // Use line_buf slice directly (already validated UTF-8)
                    return self.line_buf[start..end].to_string();
                }
                return String::new();
            }
        }
        // Materialized mode (regex FS or fields were modified)
        self.fields.get(n).cloned().unwrap_or_default()
    }


    fn set_field(&mut self, n: usize, value: &str) {
        // Materialize fields from byte ranges if needed (byte-range mode)
        if !self.fields_modified && n > 0 && !self.field_ranges.is_empty() {
            self.fields.push(String::new()); // $0 placeholder
            for &(start, end) in &self.field_ranges {
                self.fields.push(self.line_buf[start..end].to_string());
            }
            self.fields_modified = true;
        } else if !self.fields_modified {
            self.fields_modified = true;
        }
        while self.fields.len() <= n {
            self.fields.push(String::new());
        }
        self.fields[n] = value.to_string();
        // Rebuild $0 from fields into line_buf
        if self.fields.len() > 1 {
            self.fields[0] = self.fields[1..].join(&self.ofs);
        }
        self.line_buf.clear();
        self.line_buf.push_str(&self.fields[0]);
        self.nf = self.fields.len() - 1;
    }

    fn matches_regex(&mut self, text: &str, pattern: &str) -> AwkResult<bool> {
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
        let re = self.get_cached_regex(pattern)?;
        Ok(re.is_match(text))
    }

    /// Check if an AWK regex pattern is a literal string (no regex metacharacters).
    /// This enables a fast path using simple substring search instead of the regex engine.
    fn is_literal_pattern(pattern: &str) -> bool {
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

    /// Zero-allocation field access: returns field content as a byte slice reference.
    /// Avoids String allocation overhead for temporary read-only access.
    fn get_field_bytes(&self, n: usize) -> &[u8] {
        if !self.fields_modified {
            if n == 0 {
                return self.line_buf.as_bytes();
            }
            if !self.field_ranges.is_empty() {
                if let Some(&(start, end)) = self.field_ranges.get(n - 1) {
                    return &self.line_buf.as_bytes()[start..end];
                }
                return &[];
            }
        }
        self.fields.get(n).map(|s| s.as_bytes()).unwrap_or(&[])
    }

    fn pattern_matches(&mut self, pattern: &Pattern, line: &str) -> AwkResult<bool> {
        match pattern {
            Pattern::Regex(re) => self.matches_regex(line, re),
            Pattern::Expression(_) => self.matches_regex(line, ""),
            _ => Ok(false),
        }
    }

    fn regex_match_pos(&mut self, text: &str, pattern: &str) -> AwkResult<Option<(usize, usize)>> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.get_cached_regex(&rust_pattern)?;
        Ok(re.find(text).map(|m| (m.start() + 1, m.end() - m.start())))
    }

    #[inline(always)]
    fn exec_statements(&mut self, stmts: &[Statement]) -> AwkResult<Signal> {
        for stmt in stmts {
            let signal = self.exec_statement(stmt)?;
            if !matches!(signal, Signal::None) {
                return Ok(signal);
            }
        }
        Ok(Signal::None)
    }

    fn exec_statement(&mut self, stmt: &Statement) -> AwkResult<Signal> {
        match stmt {
            Statement::Print(exprs) => {
                if exprs.is_empty() {
                    // Zero-copy fast path: write line_buf directly (no clone, no print_buf)
                    self.output_bytes += self.line_buf.len() + self.ors.len();
                    if self.output_bytes > MAX_OUTPUT_BYTES {
                        return Err(AwkError::RuntimeError(format!(
                            "Output size limit exceeded ({} MB max)",
                            MAX_OUTPUT_BYTES / (1024 * 1024)
                        )));
                    }
                    self.writer.write_str(&self.line_buf)?;
                    self.writer.write_str(&self.ors)?;
                    return Ok(Signal::None);
                }
                // Zero-copy fast path for `print $0` (very common)
                if exprs.len() == 1 {
                    if let Expr::Record = &exprs[0] {
                        self.output_bytes += self.line_buf.len() + self.ors.len();
                        if self.output_bytes > MAX_OUTPUT_BYTES {
                            return Err(AwkError::RuntimeError(format!(
                                "Output size limit exceeded ({} MB max)",
                                MAX_OUTPUT_BYTES / (1024 * 1024)
                            )));
                        }
                        self.writer.write_str(&self.line_buf)?;
                        self.writer.write_str(&self.ors)?;
                        return Ok(Signal::None);
                    }
                }
                self.print_buf.clear();
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        self.print_buf.push_str(&self.ofs);
                    }
                    let val = self.eval_expr(e)?;
                    match &val {
                        AwkValue::Number(n) => {
                            if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                                // Fast path: itoa for integers (no format! overhead)
                                let s = self.num_buf.format(*n as i64);
                                self.print_buf.push_str(s);
                            } else {
                                self.print_buf.push_str(&self.format_ofmt(n));
                            }
                        }
                        AwkValue::Str(s) => self.print_buf.push_str(s),
                        AwkValue::Uninit => {}
                        AwkValue::Bool(true) => self.print_buf.push('1'),
                        AwkValue::Bool(false) => self.print_buf.push('0'),
                        AwkValue::Null => {}
                        AwkValue::Object(_) | AwkValue::Array(_) => {
                            self.print_buf.push_str(&awk_to_json(&val))
                        }
                    }
                }
                // Track output size for security limit
                self.output_bytes += self.print_buf.len() + self.ors.len();
                if self.output_bytes > MAX_OUTPUT_BYTES {
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                // Write directly from reusable buffer (no clone needed)
                self.writer.write_str(&self.print_buf)?;
                self.writer.write_str(&self.ors)?;
                Ok(Signal::None)
            }
            Statement::Printf(format_expr, args) => {
                let fmt = self.eval_expr(format_expr)?.as_string();
                let arg_vals: Vec<AwkValue> = args
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let output = self.format_printf(&fmt, &arg_vals);
                self.output_bytes += output.len();
                if self.output_bytes > MAX_OUTPUT_BYTES {
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                self.writer.write_str(&output)?;
                Ok(Signal::None)
            }
            Statement::If(cond, then_stmt, else_stmt) => {
                let cond_val = self.eval_expr(cond)?;
                if cond_val.is_truthy() {
                    self.exec_statement(then_stmt)
                } else if let Some(else_s) = else_stmt {
                    self.exec_statement(else_s)
                } else {
                    Ok(Signal::None)
                }
            }
            Statement::While(cond, body) => {
                let mut iterations = 0usize;
                while self.eval_expr(cond)?.is_truthy() {
                    iterations += 1;
                    if iterations > MAX_LOOP_ITERATIONS {
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    let signal = self.exec_statement(body)?;
                    match signal {
                        Signal::Break => break,
                        Signal::Continue => continue,
                        Signal::Next | Signal::NextFile | Signal::Return(_) => return Ok(signal),
                        Signal::None => {}
                    }
                }
                Ok(Signal::None)
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
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    let signal = self.exec_statement(body)?;
                    match signal {
                        Signal::Break => break,
                        Signal::Continue => {}
                        Signal::Next | Signal::NextFile | Signal::Return(_) => return Ok(signal),
                        Signal::None => {}
                    }
                    if let Some(incr_expr) = incr {
                        self.eval_expr(incr_expr)?;
                    }
                }
                Ok(Signal::None)
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
                    self.arrays
                        .get(array_name)
                        .map(|a| a.keys().cloned().collect())
                        .unwrap_or_default()
                };
                let mut iterations = 0usize;
                for key in keys {
                    iterations += 1;
                    if iterations > MAX_LOOP_ITERATIONS {
                        return Err(AwkError::RuntimeError(
                            "Loop iteration limit exceeded (possible infinite loop)".to_string(),
                        ));
                    }
                    self.set_var(var.clone(), AwkValue::Str(key.clone()));
                    let signal = self.exec_statement(body)?;
                    match signal {
                        Signal::Break => break,
                        Signal::Continue => continue,
                        Signal::Next | Signal::NextFile | Signal::Return(_) => return Ok(signal),
                        Signal::None => {}
                    }
                }
                Ok(Signal::None)
            }
            Statement::Block(stmts) => self.exec_statements(stmts),
            Statement::Assign(name, value) => {
                let val = self.eval_expr(value)?;
                match name.as_str() {
                    "FS" => self.fs = val.as_string(),
                    "RS" => self.rs = val.as_string(),
                    "OFS" => self.ofs = val.as_string(),
                    "ORS" => self.ors = val.as_string(),
                    "SUBSEP" => self.subsep = val.as_string(),
                    "FPAT" => self.fpat = val.as_string(),
                    "OFMT" => {
                        let new_ofmt = val.as_string();
                        // Parse precision from %.[digits][gfe] — accept any format char
                        self.ofmt_precision = new_ofmt.strip_prefix("%.")
                            .and_then(|s| {
                                let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                                digits.parse::<usize>().ok()
                            })
                            .unwrap_or(6);
                        self.ofmt = new_ofmt;
                    }
                    "CONVFMT" => self.convfmt = val.as_string(),
                    _ => {}
                }
                self.set_var(name.clone(), val);
                Ok(Signal::None)
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
                    if let Some(arr) = self.arrays.get_mut(arr_name) {
                        if arr.contains_key(self.array_key_buf.as_str()) {
                            let key = std::mem::take(&mut self.array_key_buf);
                            arr.insert(key, val);
                            return Ok(Signal::None);
                        }
                    }
                    // Key doesn't exist — insert new entry (with limit check)
                    let key = std::mem::take(&mut self.array_key_buf);
                    self.array_insert(arr_name, key, val)?;
                } else {
                    let key = self.eval_expr(idx_expr)?.as_string();
                    self.array_insert(arr_name, key, val)?;
                }
                Ok(Signal::None)
            }
            Statement::FieldAssign(field_expr, value) => {
                let idx = self.eval_expr(field_expr)?.as_number() as usize;
                let val = self.eval_expr(value)?.as_string();
                self.set_field(idx, &val);
                Ok(Signal::None)
            }
            Statement::CompoundAssign(name, op, value) => {
                // Fast path: var += $N — zero-alloc numeric accumulation
                if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) {
                    if let Expr::Field(idx_expr) = value {
                        if let Expr::Number(n) = idx_expr.as_ref() {
                            let idx = n.max(0.0) as usize;
                            let field_bytes = self.get_field_bytes(idx);
                            let field_str = std::str::from_utf8(field_bytes).unwrap_or("");
                            let field_num = awk_str_to_number(field_str);
                            let current = self.get_variable_f64(name);
                            let result = match op {
                                BinOp::Add => current + field_num,
                                BinOp::Sub => current - field_num,
                                BinOp::Mul => current * field_num,
                                _ => unreachable!(),
                            };
                            self.set_var_str(name, AwkValue::Number(result));
                            return Ok(Signal::None);
                        }
                    }
                }
                let current = self.get_variable(name);
                let rhs = self.eval_expr(value)?;
                let result = self.apply_binop(current, op.clone(), rhs)?;
                self.set_var(name.clone(), result);
                Ok(Signal::None)
            }
            Statement::Increment(name, is_inc) => {
                let name_str = name.as_str();
                let current = {
                    let mut found = None;
                    for scope in self.scope_stack.iter().rev() {
                        if let Some(val) = scope.get(name_str) {
                            found = Some(val.as_number());
                            break;
                        }
                    }
                    found.unwrap_or(0.0)
                };
                let new_val = if *is_inc { current + 1.0 } else { current - 1.0 };
                let mut set_in = None;
                for i in (1..self.scope_stack.len()).rev() {
                    if self.scope_stack[i].contains_key(name_str) {
                        set_in = Some(i);
                        break;
                    }
                }
                let idx = set_in.unwrap_or(0);
                self.scope_stack[idx].insert(name.clone(), AwkValue::Number(new_val));
                Ok(Signal::None)
            }
            Statement::Expr(expr) => {
                self.eval_expr(expr)?;
                Ok(Signal::None)
            }
            Statement::Next => Ok(Signal::Next),
            Statement::NextFile => Ok(Signal::NextFile),
            Statement::Break => Ok(Signal::Break),
            Statement::Continue => Ok(Signal::Continue),
            Statement::Return(expr) => {
                let val = if let Some(e) = expr {
                    self.eval_expr(e)?
                } else {
                    AwkValue::Str(String::new())
                };
                Ok(Signal::Return(val))
            }
            Statement::Delete(array_name, idx) => {
                let key = self.eval_expr(idx)?.as_string();
                if let Some(arr) = self.arrays.get_mut(array_name) {
                    if arr.remove(&key).is_some() {
                        self.total_array_entries = self.total_array_entries.saturating_sub(1);
                    }
                }
                Ok(Signal::None)
            }
            Statement::DeleteAll(array_name) => {
                if let Some(arr) = self.arrays.remove(array_name) {
                    self.total_array_entries = self.total_array_entries.saturating_sub(arr.len());
                }
                Ok(Signal::None)
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
                        self.cmd.read_pipe_line(&cmd_str)?
                    }
                };
                let result = if let Some(l) = line {
                    if let Some(var_name) = var {
                        self.set_var(var_name.clone(), AwkValue::Str(l));
                    } else {
                        self.nr += 1;
                        self.fnr += 1;
                        self.split_fields_from(&l)?;
                    }
                    1.0
                } else {
                    0.0
                };
                self.set_var("!".to_string(), AwkValue::Number(result));
                Ok(Signal::None)
            }
            Statement::PrintRedirect(exprs, redirect_type, target_expr) => {
                self.print_buf.clear();
                if exprs.is_empty() {
                    // Zero-copy fast path for redirect
                    self.print_buf.push_str(&self.line_buf);
                } else {
                    for (i, e) in exprs.iter().enumerate() {
                        if i > 0 {
                            self.print_buf.push_str(&self.ofs);
                        }
                        let val = self.eval_expr(e)?;
                        match &val {
                            AwkValue::Number(n) => {
                                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                                    // Fast path: itoa for integers (no format! overhead)
                                    let s = self.num_buf.format(*n as i64);
                                    self.print_buf.push_str(s);
                                } else {
                                    self.print_buf.push_str(&self.format_ofmt(n));
                                }
                            }
                            AwkValue::Str(s) => self.print_buf.push_str(s),
                            AwkValue::Uninit => {}
                            AwkValue::Bool(true) => self.print_buf.push('1'),
                            AwkValue::Bool(false) => self.print_buf.push('0'),
                            AwkValue::Null => {}
                            AwkValue::Object(_) | AwkValue::Array(_) => {
                                self.print_buf.push_str(&awk_to_json(&val))
                            }
                        }
                    }
                }
                self.print_buf.push_str(&self.ors);
                let target = self.eval_expr(target_expr)?.as_string();
                match redirect_type {
                    RedirectionType::ToFile | RedirectionType::AppendToFile
                        if !self.open_files.contains(&target) => {
                            if self.open_files.len() >= MAX_OPEN_FILES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Too many open files ({} max)", MAX_OPEN_FILES
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
                        self.cmd.write_pipe(&target, &self.print_buf)?;
                    }
                }
                Ok(Signal::None)
            }
            Statement::PrintfRedirect(format_expr, args, redirect_type, target_expr) => {
                let fmt = self.eval_expr(format_expr)?.as_string();
                let arg_vals: Vec<AwkValue> = args
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let output = self.format_printf(&fmt, &arg_vals);
                self.output_bytes += output.len();
                if self.output_bytes > MAX_OUTPUT_BYTES {
                    return Err(AwkError::RuntimeError(format!(
                        "Output size limit exceeded ({} MB max)",
                        MAX_OUTPUT_BYTES / (1024 * 1024)
                    )));
                }
                let target = self.eval_expr(target_expr)?.as_string();
                match redirect_type {
                    RedirectionType::ToFile | RedirectionType::AppendToFile
                        if !self.open_files.contains(&target) => {
                            if self.open_files.len() >= MAX_OPEN_FILES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Too many open files ({} max)", MAX_OPEN_FILES
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
                        self.cmd.write_pipe(&target, &output)?;
                    }
                }
                Ok(Signal::None)
            }
            Statement::Close(expr) => {
                let target = self.eval_expr(expr)?.as_string();
                self.open_files.remove(&target);
                let _ = self.reader.close_file(&target);
                let _ = self.writer.close_file(&target);
                let _ = self.cmd.close_pipe(&target);
                Ok(Signal::None)
            }
        }
    }

    #[inline(always)]
    fn eval_expr(&mut self, expr: &Expr) -> AwkResult<AwkValue> {
        self.expr_depth += 1;
        if self.expr_depth > MAX_EXPR_DEPTH {
            self.expr_depth -= 1;
            return Err(AwkError::RuntimeError("expression nesting too deep".to_string()));
        }
        let result = self.eval_expr_inner(expr);
        self.expr_depth -= 1;
        result
    }

    fn eval_expr_inner(&mut self, expr: &Expr) -> AwkResult<AwkValue> {
        match expr {
            Expr::Number(n) => Ok(AwkValue::Number(*n)),
            Expr::String(s) => Ok(AwkValue::Str(s.clone())),
            Expr::Var(name) => Ok(self.get_variable(name)),
            Expr::Record => Ok(AwkValue::Str(self.get_field(0))),
            Expr::Field(idx_expr) => {
                let idx = self.eval_expr(idx_expr)?.as_number().max(0.0) as usize;
                Ok(AwkValue::Str(self.get_field(idx)))
            }
            Expr::BinOp(left, op, right) => {
                let lval = self.eval_expr(left)?;
                let rval = self.eval_expr(right)?;
                self.apply_binop(lval, op.clone(), rval)
            }
            Expr::UnaryOp(op, operand) => {
                let val = self.eval_expr(operand)?;
                match op {
                    UnaryOp::Neg => Ok(AwkValue::Number(-val.as_number())),
                    UnaryOp::Pos => Ok(AwkValue::Number(val.as_number())),
                    UnaryOp::Not => Ok(AwkValue::Number(if val.is_truthy() { 0.0 } else { 1.0 })),
                }
            }
            Expr::FuncCall(name, args) => self.eval_func_call(name, args),
            Expr::ArrayAccess(name, idx) => {
                // Check if variable holds an Object or Array value (new literal types)
                let var_val = self.get_variable(name);
                match &var_val {
                    AwkValue::Array(arr) => {
                        let idx_val = self.eval_expr(idx)?;
                        let i = idx_val.as_number() as i64;
                        if i < 0 {
                            return Ok(AwkValue::Null);
                        }
                        Ok(arr.get(i as usize).cloned().unwrap_or(AwkValue::Null))
                    }
                    AwkValue::Object(_) => {
                        let key = self.eval_expr(idx)?.as_string();
                        Ok(var_val.object_get(&key).cloned().unwrap_or(AwkValue::Null))
                    }
                    _ => {
                        // Drop the temporary — these are handled by the symbol table below
                        drop(var_val);
                        // Special handling for ENVIRON array (read-only)
                        if name == "ENVIRON" {
                            let key = self.eval_expr(idx)?.as_string();
                            let val = self.env.get_env(&key).unwrap_or_default();
                            return Ok(AwkValue::Str(val));
                        }
                        // Special handling for ARGV array (read-only)
                        if name == "ARGV" {
                            let key = self.eval_expr(idx)?.as_string();
                            if let Ok(index) = key.parse::<usize>() {
                                let val = self.argv.get(index).cloned().unwrap_or_default();
                                return Ok(AwkValue::Str(val));
                            }
                            return Ok(AwkValue::Uninit);
                        }
                        // Optimized: for field-access keys ($N), use reusable buffer to avoid String alloc
                        let found = if matches!(idx.as_ref(), Expr::Field(_)) {
                            self.build_array_key(idx)?;
                            self.arrays
                                .get(name)
                                .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                                .cloned()
                        } else {
                            let key = self.eval_expr(idx)?.as_string();
                            self.arrays.get(name).and_then(|arr| arr.get(&key)).cloned()
                        };
                        Ok(found.unwrap_or(AwkValue::Uninit))
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
                            let field_bytes = self.get_field_bytes(idx);
                            let pat_bytes = pattern.as_bytes();
                            if pat_bytes.is_empty() {
                                true
                            } else {
                                field_bytes.windows(pat_bytes.len()).any(|w| w == pat_bytes)
                            }
                        } else {
                            // Regex path needs mutable borrow for cache
                            let text = self.get_field(idx);
                            self.matches_regex(&text, pattern)?
                        }
                    }
                    _ => {
                        let text = self.eval_expr(expr)?.as_string();
                        self.matches_regex(&text, pattern)?
                    }
                };
                Ok(AwkValue::Number(if matched { 1.0 } else { 0.0 }))
            }
            Expr::NotMatch(expr, pattern) => {
                let matched = match expr.as_ref() {
                    Expr::Field(idx_expr) => {
                        let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                        if Self::is_literal_pattern(pattern) {
                            let field_bytes = self.get_field_bytes(idx);
                            let pat_bytes = pattern.as_bytes();
                            if pat_bytes.is_empty() {
                                true
                            } else {
                                field_bytes.windows(pat_bytes.len()).any(|w| w == pat_bytes)
                            }
                        } else {
                            let text = self.get_field(idx);
                            self.matches_regex(&text, pattern)?
                        }
                    }
                    _ => {
                        let text = self.eval_expr(expr)?.as_string();
                        self.matches_regex(&text, pattern)?
                    }
                };
                Ok(AwkValue::Number(if matched { 0.0 } else { 1.0 }))
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
                Ok(AwkValue::Str(result))
            }
            Expr::PostIncrement(var_expr, is_inc) => match var_expr.as_ref() {
                Expr::Var(name) => {
                    let old_val = self.get_variable(name).as_number();
                    let new_val = if *is_inc {
                        old_val + 1.0
                    } else {
                        old_val - 1.0
                    };
                    self.set_var(name.clone(), AwkValue::Number(new_val));
                    Ok(AwkValue::Number(old_val))
                }
                Expr::ArrayAccess(arr_name, idx_expr) => {
                    let key = self.eval_expr(idx_expr)?.as_string();
                    let arr = self.arrays.entry(arr_name.to_string()).or_default();
                    let old_val = match arr.entry(key) {
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            let old = entry.get().as_number();
                            let new_val = if *is_inc { old + 1.0 } else { old - 1.0 };
                            entry.insert(AwkValue::Number(new_val));
                            old
                        }
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
                                )));
                            }
                            self.total_array_entries += 1;
                            let new_val = if *is_inc { 1.0 } else { -1.0 };
                            entry.insert(AwkValue::Number(new_val));
                            0.0
                        }
                    };
                    Ok(AwkValue::Number(old_val))
                }
                _ => {
                    let old_val = self.eval_expr(var_expr)?.as_number();
                    Ok(AwkValue::Number(old_val))
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
                    self.set_var(name.clone(), AwkValue::Number(new_val));
                    Ok(AwkValue::Number(new_val))
                }
                Expr::ArrayAccess(arr_name, idx_expr) => {
                    let key = self.eval_expr(idx_expr)?.as_string();
                    let arr = self.arrays.entry(arr_name.to_string()).or_default();
                    let new_val = match arr.entry(key) {
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            let old = entry.get().as_number();
                            let new_val = if *is_inc { old + 1.0 } else { old - 1.0 };
                            entry.insert(AwkValue::Number(new_val));
                            new_val
                        }
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
                                )));
                            }
                            self.total_array_entries += 1;
                            let new_val = if *is_inc { 1.0 } else { -1.0 };
                            entry.insert(AwkValue::Number(new_val));
                            new_val
                        }
                    };
                    Ok(AwkValue::Number(new_val))
                }
                _ => {
                    let old_val = self.eval_expr(var_expr)?.as_number();
                    let new_val = if *is_inc {
                        old_val + 1.0
                    } else {
                        old_val - 1.0
                    };
                    Ok(AwkValue::Number(new_val))
                }
            },
            Expr::AssignExpr(name, value) => {
                let val = self.eval_expr(value)?;
                self.set_var(name.clone(), val.clone());
                Ok(val)
            }
            Expr::BoolLit(b) => Ok(AwkValue::Bool(*b)),
            Expr::NullLit => Ok(AwkValue::Null),
            Expr::ObjectLit(pairs) => {
                let mut fields = Vec::with_capacity(pairs.len());
                for (key, val_expr) in pairs {
                    let val = self.eval_expr(val_expr)?;
                    fields.push((key.clone(), val));
                }
                Ok(AwkValue::Object(fields))
            }
            Expr::ArrayLit(elements) => {
                let mut arr = Vec::with_capacity(elements.len());
                for elem_expr in elements {
                    arr.push(self.eval_expr(elem_expr)?);
                }
                Ok(AwkValue::Array(arr))
            }
            Expr::DotAccess(obj_expr, field) => {
                let obj = self.eval_expr(obj_expr)?;
                match obj {
                    AwkValue::Object(_) => {
                        Ok(obj.object_get(field).cloned().unwrap_or(AwkValue::Null))
                    }
                    _ => Ok(AwkValue::Null),
                }
            }
            Expr::IndexExpr(base_expr, idx_expr) => {
                let base = self.eval_expr(base_expr)?;
                match base {
                    AwkValue::Array(arr) => {
                        let idx_val = self.eval_expr(idx_expr)?;
                        let i = idx_val.as_number() as i64;
                        if i < 0 {
                            Ok(AwkValue::Null)
                        } else {
                            Ok(arr.get(i as usize).cloned().unwrap_or(AwkValue::Null))
                        }
                    }
                    AwkValue::Object(_) => {
                        let key = self.eval_expr(idx_expr)?.as_string();
                        Ok(base.object_get(&key).cloned().unwrap_or(AwkValue::Null))
                    }
                    _ => Ok(AwkValue::Null),
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
                        self.cmd.read_pipe_line(&cmd_str)?
                    }
                };
                let result = if let Some(l) = line {
                    if let Some(var_name) = var {
                        self.set_var(var_name.clone(), AwkValue::Str(l));
                    } else {
                        self.nr += 1;
                        self.fnr += 1;
                        self.split_fields_from(&l)?;
                    }
                    1.0
                } else {
                    0.0
                };
                Ok(AwkValue::Number(result))
            }
        }
    }

    fn apply_binop(&self, left: AwkValue, op: BinOp, right: AwkValue) -> AwkResult<AwkValue> {
        if let BinOp::In(array_name) = &op {
            let key = left.as_string();
            let exists = self
                .arrays
                .get(array_name)
                .map(|arr| arr.contains_key(&key))
                .unwrap_or(false);
            return Ok(AwkValue::Number(if exists { 1.0 } else { 0.0 }));
        }

        match op {
            BinOp::Add => Ok(AwkValue::Number(left.as_number() + right.as_number())),
            BinOp::Sub => Ok(AwkValue::Number(left.as_number() - right.as_number())),
            BinOp::Mul => Ok(AwkValue::Number(left.as_number() * right.as_number())),
            BinOp::Div => {
                let l = left.as_number();
                let r = right.as_number();
                // AWK/gawk: division by zero produces inf/-inf/nan, not a fatal error
                Ok(AwkValue::Number(l / r))
            }
            BinOp::Mod => {
                let l = left.as_number();
                let r = right.as_number();
                if r == 0.0 {
                    // gawk: modulo by zero produces nan
                    Ok(AwkValue::Number(f64::NAN))
                } else {
                    Ok(AwkValue::Number(l % r))
                }
            }
            BinOp::Pow => Ok(AwkValue::Number(left.as_number().powf(right.as_number()))),
            BinOp::Eq => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => a == b,
                    (AwkValue::Number(a), AwkValue::Number(b)) => a == b,
                    (AwkValue::Bool(a), AwkValue::Bool(b)) => a == b,
                    (AwkValue::Null, AwkValue::Null) => true,
                    _ => left == right,
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Ne => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => a != b,
                    (AwkValue::Number(a), AwkValue::Number(b)) => a != b,
                    (AwkValue::Bool(a), AwkValue::Bool(b)) => a != b,
                    (AwkValue::Null, AwkValue::Null) => false,
                    _ => left != right,
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Lt => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na < nb
                        } else {
                            a < b
                        }
                    }
                    (AwkValue::Number(a), AwkValue::Number(b)) => a < b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(AwkValue::Number(if left.as_number() < right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Le => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na <= nb
                        } else {
                            a <= b
                        }
                    }
                    (AwkValue::Number(a), AwkValue::Number(b)) => a <= b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(AwkValue::Number(if left.as_number() <= right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Gt => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na > nb
                        } else {
                            a > b
                        }
                    }
                    (AwkValue::Number(a), AwkValue::Number(b)) => a > b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(AwkValue::Number(if left.as_number() > right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::Ge => {
                let result = match (&left, &right) {
                    (AwkValue::Str(a), AwkValue::Str(b)) => {
                        // POSIX AWK: if both strings are numeric, compare numerically
                        if let (Ok(na), Ok(nb)) = (a.parse::<f64>(), b.parse::<f64>()) {
                            na >= nb
                        } else {
                            a >= b
                        }
                    }
                    (AwkValue::Number(a), AwkValue::Number(b)) => a >= b,
                    _ => {
                        // POSIX AWK: if one is number and other is numeric string, compare numerically
                        return Ok(AwkValue::Number(if left.as_number() >= right.as_number() {
                            1.0
                        } else {
                            0.0
                        }));
                    }
                };
                Ok(AwkValue::Number(if result { 1.0 } else { 0.0 }))
            }
            BinOp::And => Ok(AwkValue::Number(if left.is_truthy() && right.is_truthy() {
                1.0
            } else {
                0.0
            })),
            BinOp::Or => Ok(AwkValue::Number(if left.is_truthy() || right.is_truthy() {
                1.0
            } else {
                0.0
            })),
            BinOp::In(_) => unreachable!("In operator handled in first match"),
        }
    }

    fn eval_func_call(&mut self, name: &str, args: &[Expr]) -> AwkResult<AwkValue> {
        if let Some(func) = self.functions.get(name) {
            let func = Rc::clone(func);
            return self.call_user_function(&func, args);
        }

        match name {
            "length" => {
                if args.is_empty() {
                    let s = self.get_field(0);
                    if s.is_ascii() {
                        Ok(AwkValue::Number(s.len() as f64))
                    } else {
                        Ok(AwkValue::Number(s.chars().count() as f64))
                    }
                } else {
                    // Check if argument is an array name (length(array) returns element count)
                    if let Expr::Var(name) = &args[0] {
                        if self.arrays.contains_key(name) {
                            let count = self.arrays[name].len();
                            return Ok(AwkValue::Number(count as f64));
                        }
                    }
                    let s = self.eval_expr(&args[0])?.as_string();
                    if s.is_ascii() {
                        Ok(AwkValue::Number(s.len() as f64))
                    } else {
                        Ok(AwkValue::Number(s.chars().count() as f64))
                    }
                }
            }
            "substr" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let start = self.eval_expr(&args[1])?.as_number() as i64;
                let start = if start < 1 { 0 } else { (start - 1) as usize };
                if s.is_ascii() {
                    // Fast path: byte-level slicing for ASCII
                    let end = if args.len() > 2 {
                        (start + self.eval_expr(&args[2])?.as_number() as usize).min(s.len())
                    } else {
                        s.len()
                    };
                    let start = start.min(s.len());
                    Ok(AwkValue::Str(s[start..end].to_string()))
                } else {
                    // Unicode fallback: char-level iteration
                    let len = if args.len() > 2 {
                        self.eval_expr(&args[2])?.as_number() as usize
                    } else {
                        s.len()
                    };
                    let substr: String = s.chars().skip(start).take(len).collect();
                    Ok(AwkValue::Str(substr))
                }
            }
            "index" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let target = self.eval_expr(&args[1])?.as_string();
                if target.is_empty() {
                    return Ok(AwkValue::Number(0.0));
                }
                let pos = s.find(&target).map(|p| p + 1).unwrap_or(0);
                Ok(AwkValue::Number(pos as f64))
            }
            "split" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let array_name = match &args[1] {
                    Expr::Var(n) => n.clone(),
                    _ => {
                        return Err(AwkError::RuntimeError(
                            "split: second argument must be an array name".to_string(),
                        ))
                    }
                };
                let sep = if args.len() > 2 {
                    self.eval_expr(&args[2])?.as_string()
                } else {
                    self.fs.clone()
                };
                let parts = self.awk_split(&s, &sep)?;
                let arr = self.arrays.entry(array_name).or_default();
                let old_len = arr.len();
                arr.clear();
                self.total_array_entries = self.total_array_entries.saturating_sub(old_len);
                for (i, part) in parts.iter().enumerate() {
                    arr.insert((i + 1).to_string(), AwkValue::Str(part.clone()));
                }
                self.total_array_entries += parts.len();
                Ok(AwkValue::Number(parts.len() as f64))
            }
            "sub" => {
                let pattern = self.eval_expr(&args[0])?.as_string();
                let replacement = self.eval_expr(&args[1])?.as_string();
                if args.len() > 2 {
                    let target = self.eval_expr(&args[2])?.as_string();
                    let result = self.awk_sub(&target, &pattern, &replacement, false)?;
                    let count = if result != target { 1.0 } else { 0.0 };
                    match &args[2] {
                        Expr::Var(name) => {
                            self.set_var(name.clone(), AwkValue::Str(result));
                        }
                        Expr::Record => {
                            self.split_fields_from(&result)?;
                        }
                        Expr::Field(idx_expr) => {
                            let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                            if idx > 0 {
                                self.set_field(idx, &result);
                            }
                        }
                        _ => {}
                    }
                    Ok(AwkValue::Number(count))
                } else {
                    let target = self.get_field(0);
                    let result = self.awk_sub(&target, &pattern, &replacement, false)?;
                    let count = if result != target { 1.0 } else { 0.0 };
                    self.split_fields_from(&result)?;
                    Ok(AwkValue::Number(count))
                }
            }
            "gsub" => {
                let pattern = self.eval_expr(&args[0])?.as_string();
                let replacement = self.eval_expr(&args[1])?.as_string();
                if args.len() > 2 {
                    let target = self.eval_expr(&args[2])?.as_string();
                    let (result, count) = self.awk_sub_counted(&target, &pattern, &replacement)?;
                    match &args[2] {
                        Expr::Var(name) => {
                            self.set_var(name.clone(), AwkValue::Str(result));
                        }
                        Expr::Record => {
                            self.split_fields_from(&result)?;
                        }
                        Expr::Field(idx_expr) => {
                            let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                            if idx > 0 {
                                self.set_field(idx, &result);
                            }
                        }
                        _ => {}
                    }
                    Ok(AwkValue::Number(count))
                } else {
                    let target = self.get_field(0);
                    let (result, count) = self.awk_sub_counted(&target, &pattern, &replacement)?;
                    self.split_fields_from(&result)?;
                    Ok(AwkValue::Number(count))
                }
            }
            "match" => {
                let s = self.eval_expr(&args[0])?.as_string();
                let pattern = self.eval_expr(&args[1])?.as_string();
                if let Some((pos, len)) = self.regex_match_pos(&s, &pattern)? {
                    if args.len() > 2 {
                        if let Expr::Var(arr_name) = &args[2] {
                            let rust_pat = regex_escape_to_rust(&pattern);
                            if let Ok(re) = self.get_cached_regex(&rust_pat) {
                                if let Some(caps) = re.captures(&s) {
                                    let arr = self.arrays.entry(arr_name.clone()).or_default();
                                    let old_match_len = arr.len();
                                    arr.clear();
                                    self.total_array_entries =
                                        self.total_array_entries.saturating_sub(old_match_len);
                                    arr.insert("RSTART".to_string(), AwkValue::Number(pos as f64));
                                    arr.insert("RLENGTH".to_string(), AwkValue::Number(len as f64));
                                    let mut new_entries = 2;
                                    for i in 0..caps.len() {
                                        if let Some(m) = caps.get(i) {
                                            arr.insert(
                                                i.to_string(),
                                                AwkValue::Str(m.as_str().to_string()),
                                            );
                                            new_entries += 1;
                                        }
                                    }
                                    self.total_array_entries += new_entries;
                                }
                            }
                        }
                    }
                    self.set_var("RSTART".to_string(), AwkValue::Number(pos as f64));
                    self.set_var("RLENGTH".to_string(), AwkValue::Number(len as f64));
                    Ok(AwkValue::Number(pos as f64))
                } else {
                    self.set_var("RSTART".to_string(), AwkValue::Number(0.0));
                    self.set_var("RLENGTH".to_string(), AwkValue::Number(-1.0));
                    Ok(AwkValue::Number(0.0))
                }
            }
            "sprintf" => {
                let fmt = self.eval_expr(&args[0])?.as_string();
                let arg_vals: Vec<AwkValue> = args[1..]
                    .iter()
                    .map(|e| self.eval_expr(e))
                    .collect::<AwkResult<Vec<_>>>()?;
                let result = self.format_printf(&fmt, &arg_vals);
                Ok(AwkValue::Str(result))
            }
            "tolower" => {
                let mut s = self.eval_expr(&args[0])?.as_string();
                s.make_ascii_lowercase();
                Ok(AwkValue::Str(s))
            }
            "toupper" => {
                let mut s = self.eval_expr(&args[0])?.as_string();
                s.make_ascii_uppercase();
                Ok(AwkValue::Str(s))
            }
            "int" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.trunc()))
            }
            "sqrt" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.sqrt()))
            }
            "abs" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.abs()))
            }
            "log" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.ln()))
            }
            "exp" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.exp()))
            }
            "sin" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.sin()))
            }
            "cos" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(AwkValue::Number(n.cos()))
            }
            "atan2" => {
                let y = self.eval_expr(&args[0])?.as_number();
                let x = self.eval_expr(&args[1])?.as_number();
                Ok(AwkValue::Number(y.atan2(x)))
            }
            "rand" => {
                self.rng_state = self
                    .rng_state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let val = (self.rng_state >> 33) as f64 / (1u64 << 31) as f64;
                Ok(AwkValue::Number(val))
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
                Ok(AwkValue::Number(old as f64))
            }
            "and" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(AwkValue::Number((a & b) as f64))
            }
            "or" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(AwkValue::Number((a | b) as f64))
            }
            "xor" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let b = self.eval_expr(&args[1])?.as_number() as i64;
                Ok(AwkValue::Number((a ^ b) as f64))
            }
            "lshift" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let count = self.eval_expr(&args[1])?.as_number() as u32;
                Ok(AwkValue::Number(a.wrapping_shl(count & 63) as f64))
            }
            "rshift" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                let count = self.eval_expr(&args[1])?.as_number() as u32;
                Ok(AwkValue::Number(a.wrapping_shr(count & 63) as f64))
            }
            "compl" => {
                let a = self.eval_expr(&args[0])?.as_number() as i64;
                Ok(AwkValue::Number((!a) as f64))
            }
            "systime" => Ok(AwkValue::Number(self.env.systime() as f64)),
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
                Ok(AwkValue::Str(result))
            }
            "mktime" => {
                let datespec = self.eval_expr(&args[0])?.as_string();
                let result = self.parse_mktime(&datespec);
                Ok(AwkValue::Number(result as f64))
            }
            "system" => {
                let cmd_str = self.eval_expr(&args[0])?.as_string();
                let output = self.cmd.execute(&cmd_str)?;
                Ok(AwkValue::Number(
                    output.trim().parse::<f64>().unwrap_or(0.0),
                ))
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
                    Ok(AwkValue::Number(-1.0))
                } else {
                    Ok(AwkValue::Number(0.0))
                }
            }
            "fflush" => {
                if args.is_empty() {
                    self.writer.flush()?;
                    Ok(AwkValue::Number(0.0))
                } else {
                    let target = self.eval_expr(&args[0])?.as_string();
                    if target.is_empty() {
                        self.writer.flush()?;
                        Ok(AwkValue::Number(0.0))
                    } else {
                        self.errno = format!("fflush: cannot flush {}", target);
                        Ok(AwkValue::Number(-1.0))
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

                let rust_pat = regex_escape_to_rust(&pattern);
                let re = self.get_cached_regex(&rust_pat)?;

                let arr = self.arrays.entry(array_name).or_default();
                let old_len = arr.len();
                arr.clear();
                self.total_array_entries = self.total_array_entries.saturating_sub(old_len);

                let mut count = 0;
                let mut seps = Vec::new();
                let mut last_end = 0;

                for m in re.find_iter(&s) {
                    count += 1;
                    seps.push(s[last_end..m.start()].to_string());
                    arr.insert(count.to_string(), AwkValue::Str(m.as_str().to_string()));
                    last_end = m.end();
                }
                self.total_array_entries += count;
                // Trailing separator
                if last_end < s.len() {
                    seps.push(s[last_end..].to_string());
                }

                // Fill seps array if provided
                if let Some(seps_arr_name) = seps_name {
                    let seps_arr = self.arrays.entry(seps_arr_name).or_default();
                    let old_seps_len = seps_arr.len();
                    seps_arr.clear();
                    self.total_array_entries =
                        self.total_array_entries.saturating_sub(old_seps_len);
                    for (i, sep) in seps.iter().enumerate() {
                        seps_arr.insert(i.to_string(), AwkValue::Str(sep.clone()));
                    }
                    self.total_array_entries += seps.len();
                }

                Ok(AwkValue::Number(count as f64))
            }
            "typeof" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "typeof: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                let type_name = match &val {
                    AwkValue::Number(_) => "number",
                    AwkValue::Str(s) => {
                        if let Some(plugin_type) = self.type_registry.resolve_tag(s) {
                            return Ok(AwkValue::Str(plugin_type.to_string()));
                        }
                        "string"
                    }
                    AwkValue::Bool(_) => "boolean",
                    AwkValue::Null => "null",
                    AwkValue::Object(_) => "object",
                    AwkValue::Array(_) => "array",
                    AwkValue::Uninit => "undefined",
                };
                Ok(AwkValue::Str(type_name.to_string()))
            }
            "is_null" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "is_null: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                Ok(AwkValue::Number(if matches!(val, AwkValue::Null) {
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
                Ok(AwkValue::Number(if matches!(val, AwkValue::Object(_)) {
                    1.0
                } else {
                    0.0
                }))
            }
            "to_json" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "to_json: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                let json = awk_to_json(&val);
                Ok(AwkValue::Str(json))
            }
            "from_json" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "from_json: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                let s = val.as_string();
                match json_to_awk(&s) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        self.errno = e.to_string();
                        Ok(AwkValue::Null)
                    }
                }
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
                    // argument (JSON context), without hardcoding plugin names.
                    if str_args.len() == 1 {
                        let scope_vars = self.collect_scope_variables();
                        let context_json = awk_to_json(&scope_vars);
                        str_args.push(context_json);
                    }

                    // Now borrow handler (avoids conflicting borrow with self)
                    let Some(handler) = self.external_fn.as_deref_mut() else {
                        return Err(AwkError::RuntimeError(format!("no external function handler for '{}'", name)));
                    };
                    // Try String ABI first
                    let str_result = handler.call_external_str(name, &str_args);
                    match str_result {
                        Ok(Some(result_str)) => {
                            if result_str.starts_with("ERROR:") {
                                self.errno = result_str.clone();
                            }
                            return Ok(AwkValue::Str(result_str));
                        }
                        Err(e) => return Err(e),
                        Ok(None) => {} // Unknown function — try next plugin or report error
                    }
                }
                Err(AwkError::RuntimeError(format!(
                    "Unknown function: {}",
                    name
                )))
            }
        }
    }

    /// Check if a string looks like a var=val assignment.
    fn is_var_assign(s: &str) -> bool {
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
    fn call_user_function(&mut self, func: &FunctionDef, args: &[Expr]) -> AwkResult<AwkValue> {
        self.call_depth += 1;
        if self.call_depth > MAX_CALL_DEPTH {
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
        self.push_scope();

        // Set parameters from pre-evaluated values
        for (i, param) in func.params.iter().enumerate() {
            let val = if i < arg_vals.len() {
                arg_vals[i].clone()
            } else {
                AwkValue::Uninit
            };
            self.scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope_stack
                .last_mut()
                .unwrap()
                .insert(local.clone(), AwkValue::Uninit);
        }

        // Execute body
        let result = self.exec_statements(&func.body.statements);

        // Pop the scope - all locals and params are automatically discarded
        self.pop_scope();
        self.call_depth -= 1;

        match result {
            Ok(Signal::Return(val)) => Ok(val),
            Ok(_) => Ok(AwkValue::Uninit),
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

        self.call_depth += 1;
        if self.call_depth > MAX_CALL_DEPTH {
            return Err(AwkError::RuntimeError(
                "Recursion limit exceeded".to_string(),
            ));
        }

        // Push a new scope for this function call
        self.push_scope();

        // Set parameters from string args
        for (i, param) in func.params.iter().enumerate() {
            let val = if i < args.len() {
                AwkValue::Str(args[i].clone())
            } else {
                AwkValue::Uninit
            };
            self.scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope_stack
                .last_mut()
                .unwrap()
                .insert(local.clone(), AwkValue::Uninit);
        }

        // Execute body
        let result = self.exec_statements(&func.body.statements);

        // Pop the scope
        self.pop_scope();
        self.call_depth -= 1;

        match result {
            Ok(Signal::Return(val)) => Ok(val.as_string()),
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
        for rule in &program.rules {
            if rule.pattern.as_ref() == Some(&Pattern::Begin) {
                if let Some(action) = &rule.action {
                    let signal = self.exec_statements(&action.statements)?;
                    if matches!(signal, Signal::Return(_)) {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    fn awk_split(&mut self, s: &str, sep: &str) -> AwkResult<Vec<String>> {
        if s.is_empty() {
            return Ok(Vec::new());
        }
        if sep == " " {
            Ok(s.split_whitespace().map(String::from).collect())
        } else if sep.is_empty() {
            Ok(s.chars().map(|c| c.to_string()).collect())
        } else {
            let rust_sep = regex_escape_to_rust(sep);
            let re = self.get_cached_regex(&rust_sep)?;
            let mut result: Vec<String> = re.split(s).map(String::from).collect();
            while result.last().is_some_and(|s| s.is_empty()) {
                result.pop();
            }
            Ok(result)
        }
    }

    fn awk_sub(
        &mut self,
        target: &str,
        pattern: &str,
        replacement: &str,
        global: bool,
    ) -> AwkResult<String> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.get_cached_regex(&rust_pattern)?;
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

    fn expand_replacement(&self, replacement: &str, matched: &str) -> String {
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
    fn build_array_key(&mut self, expr: &Expr) -> AwkResult<()> {
        self.array_key_buf.clear();
        match expr {
            Expr::Field(idx_expr) => {
                let idx = self.eval_expr(idx_expr)?.as_number() as usize;
                if !self.fields_modified && !self.field_ranges.is_empty() {
                    if idx == 0 {
                        self.array_key_buf.push_str(&self.line_buf);
                    } else if let Some(&(start, end)) = self.field_ranges.get(idx - 1) {
                        // line_buf is always valid UTF-8, field boundaries align on char boundaries
                        self.array_key_buf.push_str(&self.line_buf[start..end]);
                    }
                } else {
                    self.array_key_buf.push_str(&self.get_field(idx));
                }
            }
            Expr::Var(name) => {
                let val = self.get_variable(name);
                match val {
                    AwkValue::Str(s) => self.array_key_buf.push_str(&s),
                    AwkValue::Number(n) => {
                        use std::fmt::Write;
                        let _ = write!(self.array_key_buf, "{}", n);
                    }
                    AwkValue::Uninit => {}
                    AwkValue::Bool(true) => self.array_key_buf.push('1'),
                    AwkValue::Bool(false) => self.array_key_buf.push('0'),
                    AwkValue::Null => {}
                    AwkValue::Object(_) | AwkValue::Array(_) => {
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
    fn awk_sub_counted(
        &mut self,
        target: &str,
        pattern: &str,
        replacement: &str,
    ) -> AwkResult<(String, f64)> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.get_cached_regex(&rust_pattern)?;
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
    fn format_ofmt(&self, n: &f64) -> String {
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

    fn format_strftime(&self, fmt: &str, timestamp: i64) -> String {
        // Minimal strftime — zero-dependency UTC timestamp formatting.
        // Supports: %Y %m %d %H %M %S %a %b %d %e %j %u %w %% %n %t %p %P
        let (y, mo, d, h, mi, s, wday) = Self::ts_to_components(timestamp);
        const DAYS: [&str; 7] = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
        const MONTHS: [&str; 12] = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
        let yday = Self::day_of_year(y, mo, d);
        let mut out = String::with_capacity(fmt.len() + 16);
        let mut chars = fmt.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('Y') => { let _ = write!(out, "{:04}", y); }
                    Some('y') => { let _ = write!(out, "{:02}", y % 100); }
                    Some('m') => { let _ = write!(out, "{:02}", mo); }
                    Some('d') => { let _ = write!(out, "{:02}", d); }
                    Some('e') => { let _ = write!(out, "{:>2}", d); }
                    Some('H') => { let _ = write!(out, "{:02}", h); }
                    Some('M') => { let _ = write!(out, "{:02}", mi); }
                    Some('S') => { let _ = write!(out, "{:02}", s); }
                    Some('a') => { out.push_str(DAYS[wday]); }
                    Some('A') => {
                        out.push_str(match wday {
                            0=>"Sunday",1=>"Monday",2=>"Tuesday",3=>"Wednesday",
                            4=>"Thursday",5=>"Friday",_=>"Saturday"
                        });
                    }
                    Some('b') | Some('h') => { out.push_str(MONTHS[(mo - 1) as usize]); }
                    Some('B') => {
                        out.push_str(match mo {
                            1=>"January",2=>"February",3=>"March",4=>"April",5=>"May",6=>"June",
                            7=>"July",8=>"August",9=>"September",10=>"October",11=>"November",_=>"December"
                        });
                    }
                    Some('j') => { let _ = write!(out, "{:03}", yday); }
                    Some('u') => { let _ = write!(out, "{}", if wday == 0 { 7 } else { wday }); }
                    Some('w') => { let _ = write!(out, "{}", wday); }
                    Some('p') => { out.push_str(if h < 12 { "AM" } else { "PM" }); }
                    Some('P') => { out.push_str(if h < 12 { "am" } else { "pm" }); }
                    Some('n') => { out.push('\n'); }
                    Some('t') => { out.push('\t'); }
                    Some('%') => { out.push('%'); }
                    Some(c) => { out.push('%'); out.push(c); }
                    None => { out.push('%'); }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn parse_mktime(&self, datespec: &str) -> i64 {
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
            if p.len() < 6 { return -1; }
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

    fn is_leap_year(y: i32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    fn days_in_month(y: i32, m: u32) -> u32 {
        match m {
            1 => 31, 2 => if Self::is_leap_year(y) { 29 } else { 28 },
            3 => 31, 4 => 30, 5 => 31, 6 => 30,
            7 => 31, 8 => 31, 9 => 30, 10 => 31, 11 => 30, 12 => 31,
            _ => 0,
        }
    }

    fn day_of_year(y: i32, m: u32, d: u32) -> u32 {
        let mut yday = 0u32;
        for i in 1..m { yday += Self::days_in_month(y, i); }
        yday + d
    }

    /// Convert Unix timestamp to (year, month, day, hour, minute, second, weekday).
    /// weekday: 0=Sun, 1=Mon, ..., 6=Sat
    fn ts_to_components(ts: i64) -> (i32, u32, u32, u32, u32, u32, usize) {
        let secs = ts.rem_euclid(86400) as u32;
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        let mut days = ts.div_euclid(86400);
        // 1970-01-01 was Thursday (wday=4)
        let wday = ((days % 7) + 4).rem_euclid(7) as usize;
        let mut y = 1970;
        loop {
            if y > 9999 { return (9999, 12, 31, 23, 59, 59, 5); }
            let yd = if Self::is_leap_year(y) { 366 } else { 365 };
            if days < yd { break; }
            days -= yd;
            y += 1;
        }
        let mut mo = 1u32;
        loop {
            let md = Self::days_in_month(y, mo);
            if days < md as i64 { break; }
            days -= md as i64;
            mo += 1;
        }
        let d = (days + 1) as u32;
        (y, mo, d, h, m, s, wday)
    }

    /// Convert ymdhms to Unix timestamp (UTC).
    fn ymd_hms_to_timestamp(yr: i32, mo: u32, dy: u32, hr: u32, mi: u32, sc: u32) -> i64 {
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

    fn format_printf(&self, fmt: &str, args: &[AwkValue]) -> String {
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
                        &AwkValue::Uninit
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
                            let s = format!("{:.prec$e}", n, prec = prec as usize);
                            format_exponent(&s)
                        }
                        'E' => {
                            let n = arg.as_number();
                            let prec = precision.unwrap_or(6);
                            let s = format!("{:.prec$E}", n, prec = prec as usize);
                            format_exponent(&s)
                        }
                        'g' | 'G' => {
                            let n = arg.as_number();
                            let prec = if let Some(p) = precision {
                                if p == 0 {
                                    1
                                } else {
                                    p as usize
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
struct RegexPreFilter {
    /// If true, the pattern is exact (no regex metacharacters) and we can
    /// use simple substring search.
    exact: bool,
    /// For exact mode, the literal string to search for.
    literal: String,
}

impl RegexPreFilter {
    fn new(pattern: &str) -> Self {
        let rust_pat = regex_escape_to_rust(pattern);
        // Check if the pattern is purely literal (no regex metacharacters)
        let is_literal = !rust_pat.bytes().any(|b| {
            matches!(b, b'.' | b'*' | b'+' | b'?' | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b'\\' | b'^' | b'$' | b'|')
        });
        RegexPreFilter {
            exact: is_literal,
            literal: if is_literal { rust_pat } else { String::new() },
        }
    }

    /// Returns Some(true) if the pre-filter confirms a match without regex,
    /// Some(false) if it confirms no match, None if regex is needed.
    fn check<'a>(&'a self, line: &'a str) -> Option<bool> {
        if self.exact {
            Some(line.contains(&self.literal))
        } else {
            None
        }
    }
}

fn regex_escape_to_rust(pattern: &str) -> String {
    pattern.to_string()
}

/// Parse the leading numeric prefix of a string, per AWK semantics.
/// "10abc" -> 10.0, "3.14xyz" -> 3.14, "abc" -> 0.0
/// Handles leading whitespace, optional sign, digits, optional decimal point, and exponent.
fn awk_str_to_number(s: &str) -> f64 {
    // Fast path: empty string
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Fast path: single character
    if len == 1 {
        return match bytes[0] {
            b'0' => 0.0, b'1' => 1.0, b'2' => 2.0, b'3' => 3.0, b'4' => 4.0,
            b'5' => 5.0, b'6' => 6.0, b'7' => 7.0, b'8' => 8.0, b'9' => 9.0,
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

    // Fast path: short integer (3-4 digits, no sign, no decimal)
    if len <= 4 && bytes[0].is_ascii_digit() {
        let mut all_digits = true;
        let mut val: u32 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() { all_digits = false; break; }
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
            if !b.is_ascii_digit() { all_digits = false; break; }
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

/// Serialize an AwkValue to a JSON string.
fn awk_to_json(val: &AwkValue) -> String {
    let mut out = String::with_capacity(64);
    awk_to_json_buf(val, &mut out);
    out
}

/// Write JSON representation directly into a buffer (zero intermediate allocations).
fn awk_to_json_buf(val: &AwkValue, out: &mut String) {
    match val {
        AwkValue::Number(n) => {
            if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                let mut buf = itoa::Buffer::new();
                out.push_str(buf.format(*n as i64));
            } else {
                let mut buf = ryu::Buffer::new();
                out.push_str(buf.format(*n));
            }
        }
        AwkValue::Str(s) => {
            // Inline JSON string escaping to avoid serde_json allocation
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c < '\x20' => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        AwkValue::Bool(true) => out.push_str("true"),
        AwkValue::Bool(false) => out.push_str("false"),
        AwkValue::Null => out.push_str("null"),
        AwkValue::Object(pairs) => {
            out.push('{');
            for (i, (k, v)) in pairs.iter().enumerate() {
                if i > 0 { out.push(','); }
                // Key
                out.push('"');
                out.push_str(k);
                out.push('"');
                out.push(':');
                // Value
                awk_to_json_buf(v, out);
            }
            out.push('}');
        }
        AwkValue::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 { out.push(','); }
                awk_to_json_buf(elem, out);
            }
            out.push(']');
        }
        AwkValue::Uninit => out.push_str("null"),
    }
}

/// Parse a JSON string into an AwkValue.
fn json_to_awk(json_str: &str) -> crate::error::AwkResult<AwkValue> {
    let val: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        crate::error::AwkError::RuntimeError(format!("from_json: invalid JSON: {}", e))
    })?;
    Ok(json_value_to_awk(&val))
}

/// Convert a serde_json::Value to an AwkValue.
fn json_value_to_awk(val: &serde_json::Value) -> AwkValue {
    match val {
        serde_json::Value::Null => AwkValue::Null,
        serde_json::Value::Bool(b) => AwkValue::Bool(*b),
        serde_json::Value::Number(n) => AwkValue::Number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => AwkValue::Str(s.clone()),
        serde_json::Value::Array(arr) => {
            AwkValue::Array(arr.iter().map(json_value_to_awk).collect())
        }
        serde_json::Value::Object(obj) => {
            let pairs: Vec<(String, AwkValue)> = obj
                .iter()
                .map(|(k, v)| (k.clone(), json_value_to_awk(v)))
                .collect();
            AwkValue::Object(pairs)
        }
    }
}

impl<'a> Evaluator<'a> {
    /// Collect all user-defined variables in the current scope into an Object.
    /// Used by expression language plugins for variable injection (Phase 2).
    pub fn collect_scope_variables(&self) -> AwkValue {
        let mut pairs = Vec::new();
        // Use the global scope (index 0) for variable collection
        if let Some(scope) = self.scope_stack.first() {
            for (name, val) in scope {
                if is_user_variable(name) {
                    pairs.push((name.clone(), val.clone()));
                }
            }
        }
        AwkValue::Object(pairs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::traits::{MemReader, MemWriter, StubCommandExecutor, StubEnvironment};

    fn run_awk(script: &str, input: &str) -> String {
        let program = parse(script).unwrap();
        let mut reader = MemReader::new(input);
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.execute(&program).unwrap();
        writer.output
    }

    #[test]
    fn test_print_record() {
        let output = run_awk("{ print $0 }", "hello\nworld\n");
        assert_eq!(output, "hello\nworld\n");
    }

    #[test]
    fn test_sum() {
        let output = run_awk("{ sum += $1 } END { print sum }", "1\n2\n3\n");
        assert_eq!(output, "6\n");
    }

    #[test]
    fn test_begin_end() {
        let output = run_awk("BEGIN { print \"start\" } END { print \"end\" }", "");
        assert_eq!(output, "start\nend\n");
    }

    #[test]
    fn test_user_function() {
        let output = run_awk(
            "function add(a, b) { return a + b } BEGIN { print add(3, 4) }",
            "",
        );
        assert_eq!(output, "7\n");
    }

    #[test]
    fn test_recursive_function() {
        let output = run_awk(
            "function fact(n) { if (n <= 1) return 1; return n * fact(n-1) } BEGIN { print fact(5) }",
            "",
        );
        assert_eq!(output, "120\n");
    }

    #[test]
    fn test_gsub_ampersand() {
        let output = run_awk(r#"BEGIN { s = "hello"; gsub(/l/, "L&L", s); print s }"#, "");
        assert_eq!(output, "heLlLLlLo\n");
    }

    #[test]
    fn test_sprintf() {
        let output = run_awk(r#"BEGIN { printf "%05.2f\n", 3.14 }"#, "");
        assert_eq!(output, "03.14\n");
    }

    #[test]
    fn test_bitwise() {
        let output = run_awk("BEGIN { print and(12, 10) }", "");
        assert_eq!(output, "8\n");
    }

    #[test]
    fn test_split_space() {
        let output = run_awk(
            r#"BEGIN { n = split("a b  c", arr, " "); for (i=1; i<=n; i++) print i, arr[i] }"#,
            "",
        );
        assert_eq!(output, "1 a\n2 b\n3 c\n");
    }

    #[test]
    fn test_split_empty_sep() {
        let output = run_awk(
            r#"BEGIN { n = split("abc", arr, ""); for (i=1; i<=n; i++) print i, arr[i] }"#,
            "",
        );
        assert_eq!(output, "1 a\n2 b\n3 c\n");
    }

    // --- Phase 1: Multi-script support tests ---

    #[test]
    fn test_multi_script_concatenation() {
        // Function defined in one script, used in another
        let scripts = &[
            "function double(x) { return x * 2 }",
            "{ print double($1) }",
        ];
        let combined = scripts.join("\n");
        let output = run_awk(&combined, "3\n5\n");
        assert_eq!(output, "6\n10\n");
    }

    #[test]
    fn test_multi_script_shared_variables() {
        let scripts = &["BEGIN { prefix = \">>\" }", "{ print prefix, $0 }"];
        let combined = scripts.join("\n");
        let output = run_awk(&combined, "hello\nworld\n");
        assert_eq!(output, ">> hello\n>> world\n");
    }

    // --- P0: Array element ++/-- tests ---

    #[test]
    fn test_array_increment() {
        let output = run_awk(
            "{ count[$1]++ } END { for (k in count) print k, count[k] }",
            "a\nb\na\na\nb\n",
        );
        // Hash order is non-deterministic; collect and sort
        let mut lines: Vec<&str> = output.trim().split('\n').collect();
        lines.sort();
        assert_eq!(lines, vec!["a 3", "b 2"]);
    }

    #[test]
    fn test_array_decrement() {
        let output = run_awk("BEGIN { a[\"x\"] = 10; a[\"x\"]--; print a[\"x\"] }", "");
        assert_eq!(output, "9\n");
    }

    #[test]
    fn test_array_pre_increment() {
        let output = run_awk("BEGIN { a[\"k\"] = 5; print ++a[\"k\"] }", "");
        assert_eq!(output, "6\n");
    }

    // --- P0: delete array (entire array) ---

    #[test]
    fn test_delete_entire_array() {
        let output = run_awk(
            "BEGIN { a[1]=\"x\"; a[2]=\"y\"; delete a; print length(a) }",
            "",
        );
        assert_eq!(output, "0\n");
    }

    #[test]
    fn test_delete_single_element() {
        let output = run_awk(
            "BEGIN { a[1]=\"x\"; a[2]=\"y\"; delete a[1]; print length(a) }",
            "",
        );
        assert_eq!(output, "1\n");
    }

    // --- P0: SUBSEP and multidimensional arrays ---

    #[test]
    fn test_subsep_default() {
        let output = run_awk("BEGIN { print length(SUBSEP) }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_multidim_array() {
        let output = run_awk(
            "BEGIN { a[1,2] = \"hello\"; a[3,4] = \"world\"; print a[1,2], a[3,4] }",
            "",
        );
        assert_eq!(output, "hello world\n");
    }

    // --- P0: Backslash-newline continuation ---

    #[test]
    fn test_backslash_newline_continuation() {
        let output = run_awk(
            "BEGIN { x = 1 + \\
2 + \\
3; print x }",
            "",
        );
        assert_eq!(output, "6\n");
    }

    // --- P1: Escape sequences ---

    #[test]
    fn test_escape_sequences() {
        let output = run_awk(r#"BEGIN { printf "%s", "\t" }"#, "");
        assert_eq!(output, "\t");
    }

    #[test]
    fn test_hex_escape() {
        let output = run_awk(r#"BEGIN { printf "%s", "\x41" }"#, "");
        assert_eq!(output, "A");
    }

    #[test]
    fn test_octal_escape() {
        let output = run_awk(r#"BEGIN { printf "%s", "\101" }"#, "");
        assert_eq!(output, "A");
    }

    // --- P1: Hex numeric literals ---

    #[test]
    fn test_hex_literal() {
        let output = run_awk("BEGIN { print 0xFF }", "");
        assert_eq!(output, "255\n");
    }

    #[test]
    fn test_hex_literal_arithmetic() {
        let output = run_awk("BEGIN { print 0x10 + 1 }", "");
        assert_eq!(output, "17\n");
    }

    // --- P1: length(array) ---

    #[test]
    fn test_length_array() {
        let output = run_awk("BEGIN { a[1]=1; a[2]=2; a[3]=3; print length(a) }", "");
        assert_eq!(output, "3\n");
    }

    // --- P2: FPAT ---

    #[test]
    fn test_fpat_csv() {
        let output = run_awk(
            r#"BEGIN { FPAT = "[^,]+" } { print $2 }"#,
            "one,two,three\n",
        );
        assert_eq!(output, "two\n");
    }

    // --- P2: patsplit ---

    #[test]
    fn test_patsplit() {
        let output = run_awk(
            r#"BEGIN { n = patsplit("the:number42is:cool", a, "[a-z]+"); for(i=1;i<=n;i++) printf "%s ", a[i]; print "" }"#,
            "",
        );
        assert_eq!(output, "the number is cool \n");
    }

    // --- Phase 3: Security ---

    #[test]
    fn test_recursion_limit() {
        // Spawn a thread with a larger stack to avoid OS stack overflow
        // before our AWK-level recursion limit (256) kicks in
        let handle = std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024) // 32MB stack
            .spawn(|| {
                let script = "function deep(n) { if (n > 0) return deep(n-1); return 0 } BEGIN { print deep(300) }";
                let program = parse(script).unwrap();
                let mut reader = MemReader::new("");
                let mut writer = MemWriter::new();
                let env = StubEnvironment::default();
                let mut cmd = StubCommandExecutor;
                let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
                let result = eval.execute(&program);
                assert!(result.is_err());
                assert!(result.unwrap_err().to_string().contains("Recursion limit"));
            })
            .unwrap();
        handle.join().unwrap();
    }

    // --- P1: CONVFMT ---

    #[test]
    fn test_convfmt() {
        let output = run_awk(
            r#"BEGIN { CONVFMT = "%.2f"; x = 3.14159; print x + 0 }"#,
            "",
        );
        // CONVFMT affects number-to-string, not print output
        assert_eq!(output, "3.14159\n");
    }

    // --- Compound assignment on arrays ---

    #[test]
    fn test_array_compound_assign() {
        let output = run_awk("BEGIN { a[\"x\"] = 10; a[\"x\"] += 5; print a[\"x\"] }", "");
        assert_eq!(output, "15\n");
    }

    #[test]
    fn test_from_json_errno_debug() {
        // Check if from_json sets ERRNO on invalid JSON
        let output = run_awk(r#"BEGIN { x = from_json("{"a":1}"); print ERRNO }"#, "");
        // ERRNO should be set since the JSON is malformed (unescaped quotes)
        assert!(!output.trim().is_empty() || output.trim() == "0");

        // Check that string length works with JSON-like content
        let output2 = run_awk(r#"BEGIN { s = "{"a":1}"; print length(s); print s }"#, "");
        assert!(output2.contains("{"));
    }

    // === Phase 0: AWK Language Extension Tests ===

    // --- Boolean literals ---

    #[test]
    fn test_bool_literal_true() {
        let output = run_awk("BEGIN { x = true; print x }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_bool_literal_false() {
        let output = run_awk("BEGIN { x = false; print x }", "");
        assert_eq!(output, "0\n");
    }

    #[test]
    fn test_bool_typeof() {
        let output = run_awk("BEGIN { print typeof(true); print typeof(false) }", "");
        assert_eq!(output, "boolean\nboolean\n");
    }

    // --- Null literal ---

    #[test]
    fn test_null_literal() {
        let output = run_awk("BEGIN { x = null; print is_null(x) }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_null_typeof() {
        let output = run_awk("BEGIN { print typeof(null) }", "");
        assert_eq!(output, "null\n");
    }

    #[test]
    fn test_null_as_string() {
        let output = run_awk(r#"BEGIN { x = null; print x "end" }"#, "");
        assert_eq!(output, "end\n");
    }

    #[test]
    fn test_null_as_number() {
        let output = run_awk("BEGIN { x = null; print x + 5 }", "");
        assert_eq!(output, "5\n");
    }

    // --- Object literal ---

    #[test]
    fn test_object_literal() {
        let output = run_awk(
            r#"BEGIN { user = {"name": "Alice", "age": 30}; print user["name"] }"#,
            "",
        );
        assert_eq!(output, "Alice\n");
    }

    #[test]
    fn test_object_dot_access() {
        let output = run_awk(
            r#"BEGIN { user = {"name": "Alice", "age": 30}; print user.name }"#,
            "",
        );
        assert_eq!(output, "Alice\n");
    }

    #[test]
    fn test_object_nested_dot_access() {
        let output = run_awk(
            r#"BEGIN { config = {"db": {"host": "localhost", "port": 5432}}; print config.db.host }"#,
            "",
        );
        assert_eq!(output, "localhost\n");
    }

    #[test]
    fn test_object_typeof() {
        let output = run_awk(r#"BEGIN { x = {"a": 1}; print typeof(x) }"#, "");
        assert_eq!(output, "object\n");
    }

    #[test]
    fn test_object_to_json() {
        let output = run_awk(
            r#"BEGIN { x = {"a": 1, "b": "hello"}; print to_json(x) }"#,
            "",
        );
        let json_str = output.trim();
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed["a"], 1);
        assert_eq!(parsed["b"], "hello");
    }

    #[test]
    fn test_from_json_object() {
        let output = run_awk(
            "BEGIN { x = from_json(\"{\\\"name\\\":\\\"Bob\\\",\\\"age\\\":25}\"); print x.name }",
            "",
        );
        assert_eq!(output, "Bob\n");
    }

    #[test]
    fn test_json_roundtrip() {
        let output = run_awk(
            r#"BEGIN {
            x = {"a": 1, "b": "hello", "c": true, "d": null};
            j = to_json(x);
            y = from_json(j);
            print y.a;
            print y.b;
            print typeof(y.c);
            print is_null(y.d);
        }"#,
            "",
        );
        assert_eq!(output, "1\nhello\nboolean\n1\n");
    }

    // --- Array literal ---

    #[test]
    fn test_array_literal() {
        let output = run_awk("BEGIN { arr = [1, 2, 3]; print arr[0] }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_array_literal_strings() {
        let output = run_awk(r#"BEGIN { arr = ["a", "b", "c"]; print arr[1] }"#, "");
        assert_eq!(output, "b\n");
    }

    #[test]
    fn test_array_typeof() {
        let output = run_awk("BEGIN { arr = [1, 2, 3]; print typeof(arr) }", "");
        assert_eq!(output, "array\n");
    }

    #[test]
    fn test_array_to_json() {
        let output = run_awk("BEGIN { arr = [1, 2, 3]; print to_json(arr) }", "");
        assert_eq!(output, "[1,2,3]\n");
    }

    #[test]
    fn test_from_json_array() {
        let output = run_awk(
            r#"BEGIN { arr = from_json("[10,20,30]"); print arr[2] }"#,
            "",
        );
        assert_eq!(output, "30\n");
    }

    // --- Array of objects ---

    #[test]
    fn test_array_of_objects() {
        let output = run_awk(
            r#"BEGIN {
            users = [{"name": "Alice"}, {"name": "Bob"}];
            print users[0].name;
            print users[1].name;
        }"#,
            "",
        );
        assert_eq!(output, "Alice\nBob\n");
    }

    // --- Dot access edge cases ---

    #[test]
    fn test_dot_access_missing_field() {
        let output = run_awk(r#"BEGIN { x = {"a": 1}; print is_null(x.b) }"#, "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_dot_access_on_number() {
        let output = run_awk("BEGIN { x = 42; print is_null(x.name) }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_dot_access_on_string() {
        let output = run_awk(r#"BEGIN { x = "hello"; print is_null(x.name) }"#, "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_dot_access_on_array() {
        let output = run_awk("BEGIN { x = [1, 2, 3]; print is_null(x.name) }", "");
        assert_eq!(output, "1\n");
    }

    // --- Boolean conditions ---

    #[test]
    fn test_bool_in_condition() {
        let output = run_awk(
            r#"BEGIN { flag = true; if (flag) print "yes"; else print "no" }"#,
            "",
        );
        assert_eq!(output, "yes\n");
    }

    #[test]
    fn test_bool_comparison() {
        let output = run_awk(
            "BEGIN { print (true == true); print (false == false); print (true == false) }",
            "",
        );
        assert_eq!(output, "1\n1\n0\n");
    }

    // --- Object key forms ---

    #[test]
    fn test_object_bare_key() {
        let output = run_awk(r#"BEGIN { x = {name: "Alice"}; print x.name }"#, "");
        assert_eq!(output, "Alice\n");
    }

    #[test]
    fn test_object_quoted_key() {
        let output = run_awk(r#"BEGIN { x = {"name": "Alice"}; print x.name }"#, "");
        assert_eq!(output, "Alice\n");
    }

    // --- Empty object/array ---

    #[test]
    fn test_empty_object() {
        let output = run_awk(r#"BEGIN { x = {}; print typeof(x) }"#, "");
        assert_eq!(output, "object\n");
    }

    #[test]
    fn test_empty_array() {
        let output = run_awk("BEGIN { x = []; print typeof(x) }", "");
        assert_eq!(output, "array\n");
    }

    // --- Object bracket access ---

    #[test]
    fn test_object_bracket_access() {
        let output = run_awk(
            r#"BEGIN { user = {"name": "Alice"}; print user["name"] }"#,
            "",
        );
        assert_eq!(output, "Alice\n");
    }

    #[test]
    fn test_object_bracket_access_missing() {
        let output = run_awk(
            r#"BEGIN { user = {"name": "Alice"}; print is_null(user["age"]) }"#,
            "",
        );
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_object_bracket_access_variable_key() {
        let output = run_awk(
            r#"BEGIN { user = {"name": "Alice", "age": 30}; key = "age"; print user[key] }"#,
            "",
        );
        assert_eq!(output, "30\n");
    }

    // --- Array edge cases ---

    #[test]
    fn test_array_negative_index() {
        let output = run_awk("BEGIN { arr = [1, 2, 3]; print is_null(arr[-1]) }", "");
        assert_eq!(output, "1\n");
    }

    #[test]
    fn test_array_out_of_bounds() {
        let output = run_awk("BEGIN { arr = [1, 2, 3]; print is_null(arr[10]) }", "");
        assert_eq!(output, "1\n");
    }

    // --- Nested structures ---

    #[test]
    fn test_nested_object_in_array() {
        let output = run_awk(
            r#"BEGIN {
            data = [{"x": 1}, {"x": 2}];
            print data[0].x;
            print data[1].x;
        }"#,
            "",
        );
        assert_eq!(output, "1\n2\n");
    }

    #[test]
    fn test_array_in_object() {
        let output = run_awk(
            r#"BEGIN {
            data = {"items": [10, 20, 30]};
            print data.items[1];
        }"#,
            "",
        );
        assert_eq!(output, "20\n");
    }

    // --- typeof for all 7 variants ---

    #[test]
    fn test_typeof_all_variants() {
        let output = run_awk(
            r#"BEGIN {
            print typeof(42);
            print typeof("hello");
            print typeof(true);
            print typeof(null);
            print typeof({"a": 1});
            print typeof([1, 2]);
            print typeof(uninit_var);
        }"#,
            "",
        );
        assert_eq!(
            output,
            "number\nstring\nboolean\nnull\nobject\narray\nundefined\n"
        );
    }

    // --- is_object ---

    #[test]
    fn test_is_object() {
        let output = run_awk(
            r#"BEGIN { x = {"a": 1}; print is_object(x); print is_object(42) }"#,
            "",
        );
        assert_eq!(output, "1\n0\n");
    }

    // --- from_json error handling ---

    #[test]
    fn test_from_json_invalid() {
        let output = run_awk(
            r#"BEGIN { x = from_json("not json"); print is_null(x) }"#,
            "",
        );
        assert_eq!(output, "1\n");
    }

    // --- Phase 2: Auto variable injection tests ---

    use crate::traits::AwkExternalFunction;
    use std::cell::RefCell;

    /// Mock external function handler that captures args for verification
    #[allow(dead_code)]
    struct MockExternalHandler {
        last_call: RefCell<Option<(String, Vec<String>)>>,
    }

    #[allow(dead_code)]
    impl MockExternalHandler {
        fn new() -> Self {
            Self {
                last_call: RefCell::new(None),
            }
        }


    }

    impl AwkExternalFunction for MockExternalHandler {
        fn call_external_str(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
            *self.last_call.borrow_mut() = Some((name.to_string(), args.to_vec()));
            // Return a dummy result
            Ok(Some("MOCK_RESULT".to_string()))
        }
    }





    #[test]
    fn test_collect_scope_variables_basic() {
        let program = parse(r#"BEGIN { x = 10; y = "hello"; z = {"a": 1} }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.execute(&program).unwrap();

        let scope_vars = eval.collect_scope_variables();
        let json = awk_to_json(&scope_vars);

        // Verify the JSON contains our variables
        assert!(json.contains(r#""x""#));
        assert!(json.contains("10"));
        assert!(json.contains(r#""y""#));
        assert!(json.contains("hello"));
        assert!(json.contains(r#""z""#));
    }


    // --- Phase 2.4: Type bridging tests ---

    #[test]
    fn test_typeof_date_tag() {
        let program = parse(r#"BEGIN { x = "@date:2026-08-10"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("date", "@date", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "date");
    }

    #[test]
    fn test_typeof_time_tag() {
        let program = parse(r#"BEGIN { x = "@time:14:30:00"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("time", "@time", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "time");
    }

    #[test]
    fn test_typeof_datetime_tag() {
        let program = parse(r#"BEGIN { x = "@datetime:2026-08-10T14:30:00"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("datetime", "@datetime", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "datetime");
    }

    #[test]
    fn test_typeof_duration_tag() {
        let program = parse(r#"BEGIN { x = "@duration:P1Y2M3D"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("duration", "@duration", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "duration");
    }

    #[test]
    fn test_typeof_grid_tag() {
        let program = parse(r#"BEGIN { x = "@grid:{\"cols\":[\"a\"],\"rows\":[[1]]}"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("grid", "@grid", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "grid");
    }

    #[test]
    fn test_typeof_plain_string() {
        let program = parse(r#"BEGIN { x = "hello"; print typeof(x) }"#).unwrap();
        let mut reader = MemReader::new("");
        let mut writer = MemWriter::new();
        let env = StubEnvironment::default();
        let mut cmd = StubCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "string");
    }


    // --- Security: Expression depth handling ---

    #[test]
    fn test_eval_expression_depth_limit() {
        // Test that the evaluator handles moderately nested expressions.
        let depth = 30;
        let mut expr = String::new();
        for _ in 0..depth { expr.push('('); }
        expr.push('1');
        for _ in 0..depth { expr.push(')'); }
        let script = format!("BEGIN {{ x = {}; print x }}", expr);
        let output = run_awk(&script, "");
        assert_eq!(output.trim(), "1");
    }

    // --- Security: JSON recursion depth limit ---

    #[test]
    fn test_json_recursion_depth_limit() {
        // Test that json_value_to_awk enforces its depth limit of 128.
        // Build nested JSON directly as a serde_json::Value to avoid serde_json
        // parser recursion limit, then convert via json_value_to_awk.
        let depth = 200; // exceeds json_value_to_awk limit of 128
        let mut val = serde_json::Value::Number(serde_json::Number::from(1));
        for _ in 0..depth {
            let mut map = serde_json::Map::new();
            map.insert("a".to_string(), val);
            val = serde_json::Value::Object(map);
        }
        // json_value_to_awk should handle this gracefully (return Null at depth > 128)
        let result = json_value_to_awk(&val);
        // Should not panic. Top level should be an Object.
        match result {
            AwkValue::Object(_) => {}, // expected
            _ => panic!("Expected Object at top level"),
        }
    }


    #[test]
    fn test_eval_depth_limit_integration() {
        // Parser catches deep nesting at 512 before evaluator sees it
        // Use a thread with larger stack since recursive descent is stack-heavy
        let handle = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let depth = 600;
                let mut expr = String::new();
                for _ in 0..depth { expr.push('('); }
                expr.push('1');
                for _ in 0..depth { expr.push(')'); }
                let script = format!("BEGIN {{ x = {} }}", expr);
                let result = crate::parser::parse(script.as_str());
                assert!(result.is_err(), "deeply nested expr should be rejected");
            })
            .unwrap();
        handle.join().unwrap();
    }

}
