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

// Sub-modules for modular architecture
pub mod scope;
pub mod regex_cache;
pub mod field_access;
pub mod builtins;
pub mod security;
pub mod input;
pub mod output;
pub mod wit_format_bridge;
// HashMap replaced with FxHashMap for arrays
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write;
use std::rc::Rc;

use rustc_hash::FxHashMap;


use crate::ast::*;
use crate::error::{AwkError, AwkResult};
use crate::traits::{
    AwkCommandExecutor, AwkEnvironment, FunctionDispatcher, AwkReader, AwkWriter,
};
use crate::types::PluginTypeRegistry;
use crate::eval::builtins::BuiltinFunctions;

/// The AWK virtual machine / evaluator.
pub struct Evaluator<'a> {
    reader: &'a mut dyn AwkReader,
    writer: &'a mut dyn AwkWriter,
    env: &'a dyn AwkEnvironment,
    cmd: &'a mut dyn AwkCommandExecutor,

    // Scope and variable management
    scope: crate::eval::scope::ScopeManager,
    // Field splitting and access
    field: crate::eval::field_access::FieldAccessor,
    // PropertyTree representation for multi-format support (JSON, XML, YAML, TOML)
    property_tree: Option<crate::types::PropertyTree>,
    // Format registry for multi-format support
    format_registry: crate::format_registry::FormatRegistry,
    // Output format selection
    output_format: Option<String>,
    // Whether the program uses PropertyTree-native features (DotAccess, IndexExpr).
    // When false, we skip structured data auto-detection entirely for better performance.
    uses_json_features: bool,
    containers_possible: bool,
    // Format auto-detection enabled. Disabled when FS/RS explicitly set by user.
    // Even when enabled, detection is skipped if first byte isn't a structured-data marker.
    format_auto: bool,
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

    // Security limits and auditing
    security: crate::eval::security::SecurityManager,

    // Regex compilation cache
    regex: crate::eval::regex_cache::RegexCache,

    // Range pattern state: (rule_index, active)
    range_active: Vec<bool>,

    // File record number (reset per file)
    fnr: usize,

    // Reusable buffer for print/printf output (avoids per-statement allocation)
    print_buf: String,
    // Reusable buffer for array key construction (avoids String alloc on field-access keys)
    array_key_buf: String,
    // Reusable part buffer for split() (avoids Vec alloc per call)
    split_parts: Vec<String>,
    // Reusable buffer for fast integer formatting (itoa)
    num_buf: itoa::Buffer,
    /// True if the program ever accesses fields ($1.., NF, etc.) — skip re-split after gsub/sub otherwise
    fields_needed: bool,

    // External function handler (for Wasm extensions)
    external_fn: Option<Box<dyn FunctionDispatcher>>,

    // ARGV/ARGC support
    argc: usize,
    argv: Vec<String>,

    // Total array entries across all arrays (for memory limit enforcement)
    total_array_entries: usize,

    // Open file targets for print redirect FD limit
    open_files: HashSet<String>,

    // Compliance: Security profile for configurable limits
    security_profile: SecurityProfile,

    // Compliance: Audit event log (ISO 27001 A.12.4, SOC 2 CC7.2, HIPAA 164.312(b))
    audit_log: Vec<AuditEvent>,

    // Compliance: Estimated memory usage tracking (bytes)
    estimated_memory: usize,

    // Compliance: Total input bytes processed (for audit trail)
    total_input_bytes: usize,

    // Compliance: Execution start time (for timeout enforcement)
    // Note: std::time::Instant is not available on wasm32; use a counter instead
    #[cfg(not(target_arch = "wasm32"))]
    exec_start_time: std::time::Instant,
    #[cfg(target_arch = "wasm32")]
    exec_start_counter: u64,

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
/// Maximum loop iterations before aborting (prevent infinite loops in sandboxed mode).
const MAX_LOOP_ITERATIONS: usize = 100_000_000;
// Re-export security constants as the single source of truth
use crate::eval::security::{
    MAX_CALL_DEPTH, MAX_EXPR_DEPTH, MAX_FIELDS, MAX_OPEN_FILES, MAX_OUTPUT_BYTES, MAX_REGEX_PATTERN_LEN,
};
// PropertyTree parsing security limits are defined in crate::types (MAX_PT_*).

/// Thread-local cache of pre-computed integer key strings "1" through "2048".
/// Avoids per-call String allocation for split() and array operations.
use std::sync::OnceLock;
static INT_KEY_TABLE: OnceLock<Vec<String>> = OnceLock::new();

/// Get an integer key string, using a shared precomputed table for 1..=2048.
#[inline(always)]
fn int_key(n: usize) -> String {
    if (1..=2048).contains(&n) {
        let table = INT_KEY_TABLE.get_or_init(|| {
            let mut v = Vec::with_capacity(2049);
            v.push(String::new()); // 0-index placeholder
            for i in 1..=2048 {
                v.push(i.to_string());
            }
            v
        });
        table[n].clone()
    } else {
        n.to_string()
    }
}



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

/// Audit event types for compliance logging.
/// Maps to: ISO 27001 A.12.4 (Logging), SOC 2 CC7.2 (System Monitoring),
/// HIPAA 164.312(b) (Audit Controls)
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// A security limit was hit and execution was aborted
    LimitViolation { limit_name: String, limit_value: usize, actual_value: usize },
    /// A sandbox violation was attempted (e.g., system() call)
    SandboxViolation { action: String },
    /// Execution timeout reached
    ExecutionTimeout { elapsed_secs: u64 },
    /// Memory limit approached or exceeded
    MemoryLimitExceeded { estimated_bytes: usize, limit_bytes: usize },
    /// Input record processed (for audit trail)
    RecordProcessed { record_number: usize, input_bytes: usize },
    /// Execution completed
    ExecutionComplete { records_processed: usize, output_bytes: usize, total_input_bytes: usize },
}

/// AWK values - everything is either a number or a string.
#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    Str(String),
    Uninit,
    Bool(bool),
    Null,
    Object(Vec<(String, Value)>),
    Array(Vec<Value>),
}

impl Value {
    /// Look up a field in an Object by name. Returns None if not an Object or field missing.
    #[must_use]
    pub fn object_get(&self, field: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == field).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_number(&self) -> f64 {
        match self {
            Value::Number(n) => *n,
            Value::Str(s) => awk_str_to_number(s),
            Value::Uninit => 0.0,
            Value::Bool(true) => 1.0,
            Value::Bool(false) => 0.0,
            Value::Null => 0.0,
            Value::Object(_) => 0.0,
            Value::Array(_) => 0.0,
        }
    }

    /// Zero-copy string conversion: returns Cow<str> to avoid allocation when possible.
    /// For Str variant, returns a borrowed reference. For Number, allocates only when needed.
    #[inline]
    pub fn as_cow_str(&self) -> Cow<'_, str> {
        match self {
            Value::Str(s) => Cow::Borrowed(s.as_str()),
            Value::Number(n) => {
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
            Value::Uninit | Value::Null => Cow::Borrowed(""),
            Value::Bool(true) => Cow::Borrowed("1"),
            Value::Bool(false) => Cow::Borrowed("0"),
            Value::Object(_) | Value::Array(_) => Cow::Owned(serialize_for_output(self)),
        }
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Value::Number(n) => {
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
            Value::Str(s) => s.clone(),
            Value::Uninit => String::new(),
            Value::Bool(true) => "1".to_string(),
            Value::Bool(false) => "0".to_string(),
            Value::Null => String::new(),
            Value::Object(_) | Value::Array(_) => serialize_for_output(self),
        }
    }

    /// Write value as string directly into a buffer (zero-allocation for numbers).
    /// This is the hot path for print statements.
    #[inline]
    pub fn write_to_buf(&self, buf: &mut String) {
        match self {
            Value::Number(n) => {
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
            Value::Str(s) => buf.push_str(s),
            Value::Uninit => {}
            Value::Bool(true) => buf.push('1'),
            Value::Bool(false) => buf.push('0'),
            Value::Null => {}
            Value::Object(_) | Value::Array(_) => buf.push_str(&serialize_for_output(self)),
        }
    }

    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Number(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty() && s != "0",
            Value::Uninit => false,
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Object(_) => true,
            Value::Array(_) => true,
        }
    }

    /// Convert Value to PropertyTree
    pub fn to_property_tree(&self) -> crate::types::PropertyTree {
        use crate::types::{PropertyTree, Number};
        
        match self {
            Value::Null => PropertyTree::Null,
            Value::Bool(b) => PropertyTree::Bool(*b),
            Value::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    PropertyTree::Number(Number::Integer(*n as i64))
                } else {
                    PropertyTree::Number(Number::Float(*n))
                }
            }
            Value::Str(s) => PropertyTree::String(s.clone()),
            Value::Uninit => PropertyTree::Null,
            Value::Object(pairs) => {
                let pt_pairs: Vec<(String, PropertyTree)> = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_property_tree()))
                    .collect();
                PropertyTree::Object(pt_pairs)
            }
            Value::Array(items) => {
                let pt_items: Vec<PropertyTree> = items
                    .iter()
                    .map(|v| v.to_property_tree())
                    .collect();
                PropertyTree::Array(pt_items)
            }
        }
    }
    
    /// Convert PropertyTree to Value
    pub fn from_property_tree(pt: &crate::types::PropertyTree) -> Self {
        use crate::types::PropertyTree;
        
        match pt {
            PropertyTree::Null => Value::Null,
            PropertyTree::Bool(b) => Value::Bool(*b),
            PropertyTree::Number(n) => Value::Number(n.as_f64()),
            PropertyTree::String(s) => Value::Str(s.clone()),
            PropertyTree::Array(items) => {
                let awk_items: Vec<Value> = items
                    .iter()
                    .map(Value::from_property_tree)
                    .collect();
                Value::Array(awk_items)
            }
            PropertyTree::Object(pairs) => {
                let awk_pairs: Vec<(String, Value)> = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from_property_tree(v)))
                    .collect();
                Value::Object(awk_pairs)
            }
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Bool(true), Value::Number(n)) => *n == 1.0,
            (Value::Bool(false), Value::Number(n)) => *n == 0.0,
            (Value::Number(n), Value::Bool(true)) => *n == 1.0,
            (Value::Number(n), Value::Bool(false)) => *n == 0.0,
            (Value::Null, Value::Str(s)) => s.is_empty(),
            (Value::Str(s), Value::Null) => s.is_empty(),
            (Value::Null, Value::Number(n)) => *n == 0.0,
            (Value::Number(n), Value::Null) => *n == 0.0,
            _ => {
                if matches!(self, Value::Number(_)) || matches!(other, Value::Number(_)) {
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
enum EvalSignal {
    None,
    Next,
    NextFile,
    Break,
    Continue,
    Return(Value),
}

impl<'a> Evaluator<'a> {
    pub fn new(
        reader: &'a mut dyn AwkReader,
        writer: &'a mut dyn AwkWriter,
        env: &'a dyn AwkEnvironment,
        cmd: &'a mut dyn AwkCommandExecutor,
    ) -> Self {
        let mut format_registry = crate::format_registry::FormatRegistry::new();
        format_registry.register(Box::new(crate::eval::input::BuiltinJsonFormat));
        format_registry.register(Box::new(crate::eval::input::BuiltinXmlFormat));
        format_registry.register(Box::new(crate::eval::input::BuiltinYamlFormat));
        format_registry.register(Box::new(crate::eval::input::BuiltinCsvFormat));
        Self {
            reader,
            writer,
            env,
            cmd,
            scope: crate::eval::scope::ScopeManager::new(),
            field: crate::eval::field_access::FieldAccessor::new(),
            property_tree: None,
            format_registry,
            output_format: None,
            uses_json_features: false,
            containers_possible: false,
            format_auto: true,
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
            security: crate::eval::security::SecurityManager::new(),
            regex: crate::eval::regex_cache::RegexCache::new(),
            range_active: Vec::new(),
            fnr: 0,
            print_buf: String::with_capacity(256),
            array_key_buf: String::with_capacity(64),
            split_parts: Vec::new(),
            num_buf: itoa::Buffer::new(),
            fields_needed: true,
            external_fn: None,
            argc: 0,
            argv: Vec::new(),
            total_array_entries: 0,
            open_files: HashSet::new(),
            security_profile: SecurityProfile::default(),
            audit_log: Vec::new(),
            estimated_memory: 0,
            total_input_bytes: 0,
            errno: String::new(),
            argv_index: 1,
            #[cfg(not(target_arch = "wasm32"))]
            exec_start_time: std::time::Instant::now(),
            #[cfg(target_arch = "wasm32")]
            exec_start_counter: 0,
            type_registry: PluginTypeRegistry::new(),
        }
    }

    /// Set an external function handler for Wasm host extensions.
    pub fn set_external_function_handler(&mut self, handler: Box<dyn FunctionDispatcher>) {
        self.external_fn = Some(handler);
    }

    /// Register a WIT format plugin into the format registry.
    ///
    /// Format plugins implement the `FormatDispatcher` trait and provide
    /// custom format detection, parsing, and serialization capabilities.
    /// They are inserted into the registry sorted by priority (lower = higher priority).
    ///
    /// # Example
    /// ```ignore
    /// use wawk_core::eval::wit_format_bridge::WitFormatDispatcher;
    /// eval.register_format_plugin(WitFormatDispatcher::new(
    ///     "toml".to_string(),
    ///     my_handler,
    ///     20,
    /// ));
    /// ```
    pub fn register_format_plugin(&mut self, plugin: Box<dyn crate::traits::FormatDispatcher>) {
        self.format_registry.register(plugin);
    }

    pub fn set_fs(&mut self, fs: String) {
        self.fs = fs;
        self.format_auto = false;
    }

    /// Set a variable in the global scope (used by CLI -v assignments).
    pub fn set_variable(&mut self, name: String, value: String) {
        match name.as_str() {
            "FS" => { self.fs = value.clone(); self.format_auto = false; }
            "OFS" => self.ofs = value.clone(),
            "ORS" => self.ors = value.clone(),
            "RS" => { self.rs = value.clone(); self.format_auto = false; }
            "OUTPUT_FORMAT" => {
                self.output_format = if value.is_empty() { None } else { Some(value.clone()) };
            }
            "NF" => self.nf = value.parse().unwrap_or(0),
            "NR" => self.nr = value.parse().unwrap_or(0),
            "FNR" => self.fnr = value.parse().unwrap_or(0),
            "FILENAME" => self.filename = value.clone(),
            _ => {}
        }
        self.scope.scope_stack[0].insert(name, Value::Str(value));
    }

    /// Set ARGV/ARGC values (program arguments).
    pub fn set_argv(&mut self, args: Vec<String>) {
        self.argc = args.len();
        self.argv = args;
    }



    /// Get regex cache statistics (debug builds only).
    pub fn regex_cache_stats(&self) -> (usize, usize, usize) {
        // Return placeholder stats since RegexCache doesn't expose hit/miss counts
        (0, 0, self.regex.len())
    }

    /// Get a variable, walking the scope stack from innermost to outermost.
    /// Special built-in variables are handled first.
    fn get_variable(&self, name: &str) -> Value {
        match name {
            "NR" => Value::Number(self.nr as f64),
            "NF" => Value::Number(self.nf as f64),
            "FNR" => Value::Number(self.fnr as f64),
            "FS" => Value::Str(self.fs.clone()),
            "RS" => Value::Str(self.rs.clone()),
            "OFS" => Value::Str(self.ofs.clone()),
            "ORS" => Value::Str(self.ors.clone()),
            "OUTPUT_FORMAT" => Value::Str(self.output_format.clone().unwrap_or_default()),
            "FILENAME" => Value::Str(self.filename.clone()),
            "SUBSEP" => Value::Str(self.subsep.clone()),
            "FPAT" => Value::Str(self.fpat.clone()),
            "OFMT" => Value::Str(self.ofmt.clone()),
            "CONVFMT" => Value::Str(self.convfmt.clone()),
            "ARGC" => Value::Number(self.argc as f64),
            "ERRNO" => Value::Str(self.errno.clone()),
            _ => {
                for scope in self.scope.scope_stack.iter().rev() {
                    if let Some(val) = scope.get(name) {
                        return val.clone();
                    }
                }
                Value::Uninit
            }
        }
    }



    /// Check if a program uses PropertyTree-native features (DotAccess, IndexExpr).
    /// When false, we can skip structured data auto-detection for every record.
    fn program_uses_json_features(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_uses = rule.pattern.as_ref().map_or(false, |p| Self::pattern_uses_json(p));
            let action_uses = rule.action.as_ref()
                .map(|a| Self::block_uses_json(&a.statements))
                .unwrap_or(false);
            pattern_uses || action_uses
        })
    }

    fn pattern_uses_json(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_uses_json(expr),
            Pattern::Range(start, end) => {
                Self::pattern_uses_json(start) || Self::pattern_uses_json(end)
            }
        }
    }

    fn block_uses_json(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_uses_json)
    }

    fn stmt_uses_json(stmt: &Statement) -> bool {
        match stmt {
            Statement::Expr(expr) => Self::expr_uses_json(expr),
            Statement::Print(exprs) => exprs.iter().any(Self::expr_uses_json),
            Statement::Printf(fmt, args) => Self::expr_uses_json(fmt) || args.iter().any(Self::expr_uses_json),
            Statement::PrintRedirect(exprs, _, target) => {
                exprs.iter().any(Self::expr_uses_json) || Self::expr_uses_json(target)
            }
            Statement::PrintfRedirect(fmt, args, _, target) => {
                Self::expr_uses_json(fmt) || args.iter().any(Self::expr_uses_json) || Self::expr_uses_json(target)
            }
            Statement::Assign(_, value) => Self::expr_uses_json(value),
            Statement::CompoundAssign(_, _, value) => Self::expr_uses_json(value),
            Statement::ArrayAssign(_, idx, value) => Self::expr_uses_json(idx) || Self::expr_uses_json(value),
            Statement::FieldAssign(_, _) => false,
            Statement::If(cond, then_s, else_s) => {
                Self::expr_uses_json(cond) || Self::stmt_uses_json(then_s)
                    || else_s.as_ref().is_some_and(|s| Self::stmt_uses_json(s))
            }
            Statement::While(cond, body) => Self::expr_uses_json(cond) || Self::stmt_uses_json(body),
            Statement::For(init, cond, incr, body) => {
                init.as_ref().is_some_and(|s| Self::stmt_uses_json(s))
                    || cond.as_ref().is_some_and(|e| Self::expr_uses_json(e))
                    || incr.as_ref().is_some_and(|e| Self::expr_uses_json(e))
                    || Self::stmt_uses_json(body)
            }
            Statement::ForIn(_, _, body) => Self::stmt_uses_json(body),
            Statement::Block(stmts) => stmts.iter().any(Self::stmt_uses_json),
            Statement::Return(expr) => expr.as_ref().is_some_and(Self::expr_uses_json),
            _ => false,
        }
    }

    fn expr_uses_json(expr: &Expr) -> bool {
        match expr {
            Expr::DotAccess(_, _) | Expr::IndexExpr(_, _) => true,
            Expr::Field(_) | Expr::Record => false,
            Expr::Number(_) | Expr::String(_) | Expr::Var(_) | Expr::BoolLit(_) | Expr::NullLit => false,
            Expr::BinOp(l, _, r) => Self::expr_uses_json(l) || Self::expr_uses_json(r),
            Expr::UnaryOp(_, e) => Self::expr_uses_json(e),
            Expr::FuncCall(_, args) => args.iter().any(Self::expr_uses_json),
            Expr::ArrayAccess(_, idx) => Self::expr_uses_json(idx),
            Expr::Match(e, _) | Expr::NotMatch(e, _) => Self::expr_uses_json(e),
            Expr::Ternary(c, t, f) => Self::expr_uses_json(c) || Self::expr_uses_json(t) || Self::expr_uses_json(f),
            Expr::Concat(exprs) => exprs.iter().any(Self::expr_uses_json),
            Expr::PostIncrement(e, _) | Expr::PreIncrement(e, _) => Self::expr_uses_json(e),
            Expr::AssignExpr(_, e) => Self::expr_uses_json(e),
            Expr::ObjectLit(pairs) => pairs.iter().any(|(_, e)| Self::expr_uses_json(e)),
            Expr::ArrayLit(exprs) => exprs.iter().any(Self::expr_uses_json),
            Expr::GetlineExpr(_, _) => false,
        }
    }

    /// True if any expression in the program can produce a container value
    /// (ObjectLit / ArrayLit). When false, scope variables can never shadow
    /// array names, so container-shadow scope scans can be skipped.
    fn program_has_container_literals(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_has = rule.pattern.as_ref().map_or(false, |p| Self::pattern_has_container(p));
            let action_has = rule.action.as_ref()
                .map(|a| Self::block_has_container(&a.statements))
                .unwrap_or(false);
            pattern_has || action_has
        }) || program
            .functions
            .iter()
            .any(|f| Self::block_has_container(&f.body.statements))
    }

    fn pattern_has_container(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_has_container(expr),
            Pattern::Range(start, end) => {
                Self::pattern_has_container(start) || Self::pattern_has_container(end)
            }
        }
    }

    fn block_has_container(stmts: &[Statement]) -> bool {
        stmts.iter().any(Self::stmt_has_container)
    }

    fn stmt_has_container(stmt: &Statement) -> bool {
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
            Statement::While(c, b) => {
                Self::expr_has_container(c) || Self::stmt_has_container(b)
            }
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

    fn expr_has_container(expr: &Expr) -> bool {
        match expr {
            Expr::ObjectLit(_) | Expr::ArrayLit(_) => true,
            Expr::BinOp(l, _, r) => Self::expr_has_container(l) || Self::expr_has_container(r),
            Expr::UnaryOp(_, e) => Self::expr_has_container(e),
            Expr::FuncCall(name, args) => {
                name == "from_json" || args.iter().any(Self::expr_has_container)
            }
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

    fn program_needs_fields(program: &Program) -> bool {
        program.rules.iter().any(|rule| {
            let pattern_needs = rule.pattern.as_ref().map_or(false, |p| Self::pattern_needs_fields(p));
            let action_needs = rule.action.as_ref()
                .map(|a| Self::block_needs_fields(&a.statements))
                .unwrap_or(false);
            pattern_needs || action_needs
        })
    }

    fn pattern_needs_fields(pat: &Pattern) -> bool {
        match pat {
            Pattern::Begin | Pattern::End | Pattern::Regex(_) => false,
            Pattern::Expression(expr) => Self::expr_needs_fields(expr),
            Pattern::Range(start, end) => {
                Self::pattern_needs_fields(start) || Self::pattern_needs_fields(end)
            }
        }
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
            Expr::Field(_) => true,
            Expr::Record => false, // $0 doesn't need field splitting
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

    /// Get a variable as f64 directly (avoids cloning Value).
    #[inline(always)]
    fn get_variable_f64(&self, name: &str) -> f64 {
        for scope in self.scope.scope_stack.iter().rev() {
            if let Some(val) = scope.get(name) {
                return val.as_number();
            }
        }
        0.0
    }

    // === Compliance: Security/Audit API ===

    /// Set the security profile for this evaluator instance.
    pub fn set_security_profile(&mut self, profile: SecurityProfile) {
        self.security_profile = profile;
    }

    /// Get the current security profile.
    pub fn security_profile(&self) -> &SecurityProfile {
        &self.security_profile
    }

    /// Get the audit log (ISO 27001 A.12.4, SOC 2 CC7.2, HIPAA 164.312(b)).
    pub fn audit_log(&self) -> &[AuditEvent] {
        &self.audit_log
    }

    /// Get estimated memory usage in bytes.
    pub fn estimated_memory(&self) -> usize {
        self.estimated_memory
    }

    /// Get total input bytes processed.
    pub fn total_input_bytes(&self) -> usize {
        self.total_input_bytes
    }

    /// Get total output bytes written.
    pub fn total_output_bytes(&self) -> usize {
        self.security.output_bytes
    }

    /// Get total records processed.
    pub fn total_records(&self) -> usize {
        self.nr
    }

    /// Generate a compliance summary report.
    pub fn compliance_summary(&self) -> String {
        #[cfg(not(target_arch = "wasm32"))]
        let elapsed = self.exec_start_time.elapsed().as_secs();
        #[cfg(target_arch = "wasm32")]
        let elapsed = 0u64;
        let mut r = String::from("=== Wawk Compliance Report ===\n");
        r.push_str(&format!("Execution time: {}s\n", elapsed));
        r.push_str(&format!("Records processed: {}\n", self.nr));
        r.push_str(&format!("Input bytes: {}\n", self.total_input_bytes));
        r.push_str(&format!("Output bytes: {}\n", self.security.output_bytes));
        r.push_str(&format!("Estimated memory: {} bytes\n", self.estimated_memory));
        r.push_str(&format!("Audit events: {}\n", self.audit_log.len()));
        for (i, event) in self.audit_log.iter().enumerate() {
            r.push_str(&format!("  [{}] {:?}\n", i + 1, event));
        }
        r.push_str(&format!("Security profile: max_exec={}s, max_mem={} bytes, audit={}\n",
            self.security_profile.max_execution_secs,
            self.security_profile.max_memory_bytes,
            self.security_profile.audit_enabled));
        r
    }

    pub fn execute(&mut self, program: &Program) -> AwkResult<()> {
        // Compliance: Reset execution timer and audit state
        #[cfg(not(target_arch = "wasm32"))]
        { self.exec_start_time = std::time::Instant::now(); }
        #[cfg(target_arch = "wasm32")]
        { self.exec_start_counter = 0; }
        self.audit_log.clear();
        self.estimated_memory = 0;
        self.total_input_bytes = 0;
        for func in &program.functions {
            self.functions
                .insert(func.name.clone(), Rc::new(func.clone()));
        }

        // Detect if program uses PropertyTree-native features (skip structured data parsing if not)
        self.uses_json_features = Self::program_uses_json_features(program);

        // Detect if any scope variable can ever hold a container. When false,
        // container-shadow scope scans in array fast paths are skipped.
        // Must be set BEFORE BEGIN blocks execute.
        self.containers_possible =
            self.uses_json_features || Self::program_has_container_literals(program);

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

        self.range_active = vec![false; program.rules.len()];

        let needs_fields = Self::program_needs_fields(program);
        self.fields_needed = needs_fields;

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

        // has_line_patterns removed — precompiled regex uses &self.field.line_buf directly

        // Single-hot-rule detection: if exactly one rule is neither BEGIN nor END,
        // dispatch directly per record without the rules loop.
        let single_hot_rule: Option<usize> = {
            let mut hot: Option<usize> = None;
            let mut count = 0usize;
            for (i, rule) in program.rules.iter().enumerate() {
                match &rule.pattern {
                    Some(Pattern::Begin) | Some(Pattern::End) => {}
                    _ => {
                        count += 1;
                        hot = Some(i);
                    }
                }
            }
            if count == 1 {
                let idx = hot.unwrap();
                // Range patterns carry cross-record state — keep general path
                match &program.rules[idx].pattern {
                    Some(Pattern::Range(_, _)) => None,
                    _ => hot,
                }
            } else { None }
        };

        // ARGV-driven main loop: iterate over files in ARGV
        loop {
            while self.reader.read_line_into(&mut self.field.line_buf)? {
                if self.field.line_buf.len() > 16_777_216 {
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

                // Compliance: Check execution timeout every 1024 records (amortize syscall cost)
                #[cfg(not(target_arch = "wasm32"))]
                if self.security_profile.max_execution_secs > 0 && (self.nr & 1023) == 0 {
                    let elapsed = self.exec_start_time.elapsed().as_secs();
                    if elapsed > self.security_profile.max_execution_secs {
                        self.security.record_audit(AuditEvent::ExecutionTimeout { elapsed_secs: elapsed });
                        return Err(AwkError::RuntimeError(format!(
                            "Execution timeout exceeded ({}s limit)",
                            self.security_profile.max_execution_secs
                        )));
                    }
                }
                // wasm32 has no wall clock: enforce a deterministic record budget.
                // Conservative assumption: >= 100k records/sec sustained throughput,
                // so each allowed second maps to 100k records.
                #[cfg(target_arch = "wasm32")]
                if self.security_profile.max_execution_secs > 0 {
                    self.exec_start_counter += 1;
                    let budget = self.security_profile.max_execution_secs.saturating_mul(100_000);
                    if self.exec_start_counter > budget {
                        self.security.record_audit(AuditEvent::ExecutionTimeout { elapsed_secs: self.security_profile.max_execution_secs });
                        return Err(AwkError::RuntimeError(format!(
                            "Execution record budget exceeded ({} record limit for {}s)",
                            budget, self.security_profile.max_execution_secs
                        )));
                    }
                }

                // Compliance: Track input bytes for audit trail
                self.total_input_bytes += self.field.line_buf.len();

                // Security: Amortized memory limit check (every 1024 records)
                if self.security_profile.max_memory_bytes > 0 && (self.nr & 1023) == 0 {
                    self.estimated_memory = self.field.line_buf.capacity()
                        + self.total_array_entries * 64
                        + self.open_files.len() * 512
                        + self.security.output_bytes;
                    if self.estimated_memory > self.security_profile.max_memory_bytes {
                        self.security.record_audit(AuditEvent::MemoryLimitExceeded {
                            estimated_bytes: self.estimated_memory,
                            limit_bytes: self.security_profile.max_memory_bytes,
                        });
                        return Err(AwkError::RuntimeError(format!(
                            "Memory limit exceeded ({} bytes used, {} bytes limit)",
                            self.estimated_memory, self.security_profile.max_memory_bytes
                        )));
                    }
                }

                // Format-agnostic auto-detection via FormatRegistry.
                // Fast-path: skip entire detection if format_auto disabled (FS/RS explicitly set)
                // or if the first byte isn't a structured-data marker ({, [, <, -).
                // This eliminates per-record trait dispatch for plain text input.
                {
                    let first_byte = self.field.line_buf.as_bytes().first().copied().unwrap_or(0);
                    let could_be_structured = self.format_auto && matches!(first_byte, b'{' | b'[' | b'<' | b'-');
                    if could_be_structured {
                        if let Some(result) = self.format_registry.detect_and_parse(&self.field.line_buf) {
                            match result {
                                Ok((tree, _format_name)) => {
                                    self.nf = tree.len();
                                    if let crate::types::PropertyTree::Array(ref arr) = tree {
                                        self.field.fields.clear();
                                        self.field.fields.push(String::new());
                                        for elem in arr {
                                            self.field.fields.push(serialize_for_output(&Value::from_property_tree(elem)));
                                        }
                                        self.field.fields_modified = true;
                                    }
                                    self.property_tree = Some(tree);
                                }
                                Err(_) => {
                                    self.property_tree = None;
                                    if needs_fields { self.split_fields_inplace()?; }
                                }
                            }
                        } else {
                            self.property_tree = None;
                            if needs_fields { self.split_fields_inplace()?; }
                        }
                    } else {
                        self.property_tree = None;
                        if needs_fields { self.split_fields_inplace()?; }
                    }
                }

                // Clone line_buf for pattern matching only when needed (borrow checker)
                // line_buf is borrowed directly for precompiled regex (zero-copy)

                if let Some(hot_idx) = single_hot_rule {
                    // Fast path: single hot rule — skip rules-loop dispatch
                    let rule = &program.rules[hot_idx];
                    let matches = match &rule.pattern {
                        None => true,
                        Some(Pattern::Regex(_)) => {
                            if let Some(Some(pf)) = pre_filters.get(hot_idx) {
                                if let Some(result) = pf.check(&self.field.line_buf) {
                                    result
                                } else if let Some(Some(re)) = precompiled.get(hot_idx) {
                                    re.is_match(&self.field.line_buf)
                                } else {
                                    false
                                }
                            } else if let Some(Some(re)) = precompiled.get(hot_idx) {
                                re.is_match(&self.field.line_buf)
                            } else {
                                false
                            }
                        }
                        Some(Pattern::Expression(expr)) => self.eval_expr(expr)?.is_truthy(),
                        _ => true,
                    };
                    if matches {
                        if let Some(action) = &rule.action {
                            let signal = self.exec_statements(&action.statements)?;
                            if matches!(signal, EvalSignal::NextFile) {
                                self.fnr = 0;
                                self.reader.skip_to_next_file();
                            } else if matches!(signal, EvalSignal::Return(_)) {
                                return Ok(());
                            }
                        } else if let Some(ref pt) = self.property_tree {
                            let val = Value::from_property_tree(pt);
                            let json_str = crate::eval::output::serialize_output(
                                &val, &self.format_registry, self.output_format.as_deref()
                            ).unwrap_or_else(|| serialize_for_output(&val));
                            self.security.output_bytes = self.security.output_bytes.saturating_add(json_str.len() + self.ors.len());
                            if self.security.output_bytes > MAX_OUTPUT_BYTES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Output size limit exceeded ({} MB max)",
                                    MAX_OUTPUT_BYTES / (1024 * 1024)
                                )));
                            }
                            self.writer.write_str(&json_str)?;
                            self.writer.write_str(&self.ors)?;
                        } else {
                            self.security.output_bytes += self.field.line_buf.len() + self.ors.len();
                            if (self.nr & 1023) == 0 && self.security.output_bytes > MAX_OUTPUT_BYTES {
                                return Err(AwkError::RuntimeError(format!(
                                    "Output size limit exceeded ({} MB max)",
                                    MAX_OUTPUT_BYTES / (1024 * 1024)
                                )));
                            }
                            self.writer.write_str(&self.field.line_buf)?;
                            self.writer.write_str(&self.ors)?;
                        }
                    }
                } else {

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
                                if let Some(result) = pf.check(&self.field.line_buf) {
                                    result
                                } else if let Some(Some(re)) = precompiled.get(rule_idx) {
                                    re.is_match(&self.field.line_buf)
                                } else {
                                    let re_str = match &rule.pattern {
                                        Some(Pattern::Regex(s)) => s.as_str(),
                                        _ => unreachable!(),
                                    };
                                    match regex::Regex::new(re_str) {
                                        Ok(re) => re.is_match(&self.field.line_buf),
                                        Err(_) => false,
                                    }
                                }
                            } else if let Some(Some(re)) = precompiled.get(rule_idx) {
                                re.is_match(&self.field.line_buf)
                            } else {
                                // Fallback: compile inline (avoids &mut self cache conflict)
                                let re_str = match &rule.pattern {
                                    Some(Pattern::Regex(s)) => s.as_str(),
                                    _ => unreachable!(),
                                };
                                match regex::Regex::new(re_str) {
                                    Ok(re) => re.is_match(&self.field.line_buf),
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
                            let line = std::mem::take(&mut self.field.line_buf);
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
                            self.field.line_buf = line;
                            result
                        }
                        _ => true,
                    };

                    if matches {
                        if let Some(action) = &rule.action {
                            let signal = self.exec_statements(&action.statements)?;
                            if matches!(signal, EvalSignal::Next) {
                                break;
                            }
                            if matches!(signal, EvalSignal::NextFile) {
                                self.fnr = 0;
                                self.reader.skip_to_next_file();
                                break;
                            }
                            if matches!(signal, EvalSignal::Return(_)) {
                                return Ok(());
                            }
                        } else {
                            // Default action: print record
                            if let Some(ref pt) = self.property_tree {
                                let val = Value::from_property_tree(pt);
                                let json_str = crate::eval::output::serialize_output(
                                    &val, &self.format_registry, self.output_format.as_deref()
                                ).unwrap_or_else(|| serialize_for_output(&val));
                                self.security.output_bytes = self.security.output_bytes.saturating_add(json_str.len() + self.ors.len());
                                if self.security.output_bytes > MAX_OUTPUT_BYTES {
                                    return Err(AwkError::RuntimeError(format!(
                                        "Output size limit exceeded ({} MB max)",
                                        MAX_OUTPUT_BYTES / (1024 * 1024)
                                    )));
                                }
                                self.writer.write_str(&json_str)?;
                                self.writer.write_str(&self.ors)?;
                            } else {
                                self.writer.write_str(&self.field.line_buf)?;
                                self.writer.write_str(&self.ors)?;
                            }
                        }
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
                self.scope.set_var(var_name, Value::Str(var_val));
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
                    if matches!(signal, EvalSignal::Return(_)) {
                        return Ok(());
                    }
                }
            }
        }

        // Compliance: Record execution completion (once, at program end)
        self.security.record_audit(AuditEvent::ExecutionComplete {
            records_processed: self.nr,
            output_bytes: self.security.output_bytes,
            total_input_bytes: self.total_input_bytes,
        });

        Ok(())
    }

    /// Split fields from `line_buf` in place (zero-copy: field ranges index into line_buf).
    /// Used by the main execute loop where line_buf already holds the current record.
    #[inline(always)]
    fn split_fields_inplace(&mut self) -> AwkResult<()> {
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
                        self.field.fields.push(line[last_end..m.start()].to_string());
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
                "Field count {} exceeds maximum allowed ({})", self.field.fields.len(), MAX_FIELDS
            )));
        }
        Ok(())
    }

    /// Split an arbitrary string into fields, storing result in line_buf.
    /// Used by getline, sub/gsub when target is $0.
    #[inline]
    fn split_fields_from(&mut self, line: &str) -> AwkResult<()> {
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
    fn is_literal_pattern_str(pattern: &str) -> bool {
        !pattern.bytes().any(Self::is_regex_metachar)
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
        let re = self.regex.get_or_compile(pattern)?;
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

    fn pattern_matches(&mut self, pattern: &Pattern, line: &str) -> AwkResult<bool> {
        match pattern {
            Pattern::Regex(re) => self.matches_regex(line, re),
            Pattern::Expression(_) => self.matches_regex(line, ""),
            _ => Ok(false),
        }
    }

    fn regex_match_pos(&mut self, text: &str, pattern: &str) -> AwkResult<Option<(usize, usize)>> {
        let rust_pattern = regex_escape_to_rust(pattern);
        let re = self.regex.get_or_compile(&rust_pattern)?;
        Ok(re.find(text).map(|m| (m.start() + 1, m.end() - m.start())))
    }

    #[inline(always)]
    fn exec_statements(&mut self, stmts: &[Statement]) -> AwkResult<EvalSignal> {
        for stmt in stmts {
            let signal = self.exec_statement(stmt)?;
            if !matches!(signal, EvalSignal::None) {
                return Ok(signal);
            }
        }
        Ok(EvalSignal::None)
    }

    fn exec_statement(&mut self, stmt: &Statement) -> AwkResult<EvalSignal> {
        match stmt {
            Statement::Print(exprs) => {
                if exprs.is_empty() {
                    // Fast path for bare `print`
                    if let Some(ref pt) = self.property_tree {
                        let val = Value::from_property_tree(pt);
                        let json_str = crate::eval::output::serialize_output(
                            &val, &self.format_registry, self.output_format.as_deref()
                        ).unwrap_or_else(|| serialize_for_output(&val));
                        self.security.output_bytes = self.security.output_bytes.saturating_add(json_str.len() + self.ors.len());
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
                    self.security.output_bytes = self.security.output_bytes.saturating_add(self.field.line_buf.len() + self.ors.len());
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
                                &val, &self.format_registry, self.output_format.as_deref()
                            ).unwrap_or_else(|| serialize_for_output(&val));
                            self.security.output_bytes = self.security.output_bytes.saturating_add(json_str.len() + self.ors.len());
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
                        self.security.output_bytes = self.security.output_bytes.saturating_add(self.field.line_buf.len() + self.ors.len());
                        self.writer.write_str(&self.field.line_buf)?;
                        self.writer.write_str(&self.ors)?;
                        return Ok(EvalSignal::None);
                    }
                    // Ultra-fast path: `print $N` single constant field — zero-copy direct write
                    if let Expr::Field(idx_expr) = &exprs[0] {
                        if let Expr::Number(n) = idx_expr.as_ref() {
                            if !self.field.fields_modified && !self.field.field_ranges.is_empty() && self.property_tree.is_none() {
                                let idx = *n as usize;
                                if idx > 0 {
                                    if let Some(&(start, end)) = self.field.field_ranges.get(idx - 1) {
                                        self.security.output_bytes = self.security.output_bytes.saturating_add((end - start) + self.ors.len());
                                        self.writer.write_str(&self.field.line_buf[start..end])?;
                                        self.writer.write_str(&self.ors)?;
                                        return Ok(EvalSignal::None);
                                    }
                                    // Out-of-range field: print empty + ORS
                                    self.security.output_bytes = self.security.output_bytes.saturating_add(self.ors.len());
                                    if (self.nr & 1023) == 0 && self.security.output_bytes > MAX_OUTPUT_BYTES {
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
                if !self.field.fields_modified && !self.field.field_ranges.is_empty() && self.property_tree.is_none() {
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
                                        if let Some(&(start, end)) = self.field.field_ranges.get(idx - 1) {
                                            self.print_buf.push_str(&self.field.line_buf[start..end]);
                                            continue;
                                        }
                                    }
                                }
                                // Fallback: evaluate index expression with overflow protection
                                let idx_f64 = self.eval_expr(idx_expr)?.as_number().max(0.0);
                                let idx = if idx_f64 > MAX_FIELDS as f64 { MAX_FIELDS } else { idx_f64 as usize };
                                if idx > 0 {
                                    if let Some(&(start, end)) = self.field.field_ranges.get(idx - 1) {
                                        self.print_buf.push_str(&self.field.line_buf[start..end]);
                                    }
                                }
                            }
                        }
                        self.security.output_bytes = self.security.output_bytes.saturating_add(self.print_buf.len() + self.ors.len());
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
                                        Some(v @ Value::Object(_))
                                        | Some(v @ Value::Array(_)) => {
                                            let s = crate::eval::output::serialize_output(
                                                v, &self.format_registry, self.output_format.as_deref()
                                            ).unwrap_or_else(|| serialize_for_output(v));
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
                                        container_shadow = matches!(v, Value::Array(_) | Value::Object(_));
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
                                        self.array_key_buf.push_str(self.num_buf.format(*n as usize));
                                        true
                                    }
                                    Expr::Var(vn) => {
                                        let iv = self.get_variable(vn);
                                        match &iv {
                                            Value::Number(n) if *n >= 0.0 && (*n as usize) as f64 == *n => {
                                                self.array_key_buf.clear();
                                                self.array_key_buf.push_str(self.num_buf.format(*n as usize));
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
                                        Some(Value::Str(s)) => { self.print_buf.push_str(s); }
                                        Some(Value::Number(n)) => {
                                            if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                                                let s = self.num_buf.format(*n as i64);
                                                self.print_buf.push_str(s);
                                            } else {
                                                self.print_buf.push_str(&self.format_ofmt(n));
                                            }
                                        }
                                        Some(Value::Bool(true)) => { self.print_buf.push('1'); }
                                        Some(Value::Bool(false)) => { self.print_buf.push('0'); }
                                        Some(v @ Value::Object(_)) | Some(v @ Value::Array(_)) => {
                                            let s = crate::eval::output::serialize_output(
                                                v, &self.format_registry, self.output_format.as_deref()
                                            ).unwrap_or_else(|| serialize_for_output(v));
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
                        Value::Str(s) => self.print_buf.push_str(s),
                        Value::Uninit => {}
                        Value::Bool(true) => self.print_buf.push('1'),
                        Value::Bool(false) => self.print_buf.push('0'),
                        Value::Null => {}
                        Value::Object(_) | Value::Array(_) => {
                            let s = crate::eval::output::serialize_output(
                                &val, &self.format_registry, self.output_format.as_deref()
                            ).unwrap_or_else(|| serialize_for_output(&val));
                            self.print_buf.push_str(&s)
                        }
                    }
                }
                // Track output size for security limit
                self.security.output_bytes = self.security.output_bytes.saturating_add(self.print_buf.len() + self.ors.len());
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
                self.security.output_bytes = self.security.output_bytes.saturating_add(output.len());
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
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => return Ok(signal),
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
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => return Ok(signal),
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
                    self.scope.arrays
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
                        EvalSignal::Next | EvalSignal::NextFile | EvalSignal::Return(_) => return Ok(signal),
                        EvalSignal::None => {}
                    }
                }
                Ok(EvalSignal::None)
            }
            Statement::Block(stmts) => self.exec_statements(stmts),
            Statement::Assign(name, value) => {
                let val = self.eval_expr(value)?;
                match name.as_str() {
                    "FS" => { self.fs = val.as_string(); self.format_auto = false; }
                    "RS" => { self.rs = val.as_string(); self.format_auto = false; }
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
                let idx = if idx_f64 > MAX_FIELDS as f64 { MAX_FIELDS } else { idx_f64 as usize };
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
                            let idx = if *n > MAX_FIELDS as f64 { MAX_FIELDS } else { n.max(0.0) as usize };
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
                                    "NR" | "NF" | "FNR" | "FS" | "RS" | "OFS" | "ORS"
                                        | "FILENAME" | "SUBSEP" | "FPAT" | "OFMT"
                                        | "CONVFMT" | "ARGC" | "ERRNO"
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
                                        self.scope.scope_stack[0].insert(name.clone(), Value::Number(result));
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
                        "NR" | "NF" | "FNR" | "FS" | "RS" | "OFS" | "ORS"
                            | "FILENAME" | "SUBSEP" | "FPAT" | "OFMT"
                            | "CONVFMT" | "ARGC" | "ERRNO"
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
                let new_val = if *is_inc { current + 1.0 } else { current - 1.0 };
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
                        "attempt to modify read-only array {}", array_name
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
                        "attempt to modify read-only array {}", array_name
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
                            Value::Str(s) => self.print_buf.push_str(s),
                            Value::Uninit => {}
                            Value::Bool(true) => self.print_buf.push('1'),
                            Value::Bool(false) => self.print_buf.push('0'),
                            Value::Null => {}
                            Value::Object(_) | Value::Array(_) => {
                                let s = crate::eval::output::serialize_output(
                                    &val, &self.format_registry, self.output_format.as_deref()
                                ).unwrap_or_else(|| serialize_for_output(&val));
                                self.print_buf.push_str(&s)
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
                self.security.output_bytes = self.security.output_bytes.saturating_add(output.len());
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

    #[inline(always)]
    fn eval_expr(&mut self, expr: &Expr) -> AwkResult<Value> {
        // Skip depth check for leaf nodes — they can't cause stack overflow
        // since they don't recursively call eval_expr.
        if expr.is_leaf() {
            return self.eval_expr_inner(expr);
        }
        self.security.expr_depth += 1;
        if self.security.expr_depth > MAX_EXPR_DEPTH {
            self.security.expr_depth -= 1;
            return Err(AwkError::RuntimeError("expression nesting too deep".to_string()));
        }
        let result = self.eval_expr_inner(expr);
        self.security.expr_depth -= 1;
        result
    }

    fn eval_expr_inner(&mut self, expr: &Expr) -> AwkResult<Value> {
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
                let idx = if idx_f64 > MAX_FIELDS as f64 { MAX_FIELDS } else { idx_f64 as usize };
                if let Some(ref pt) = self.property_tree {
                    match pt {
                        crate::types::PropertyTree::Object(pairs) => {
                            if idx == 0 { Ok(Value::from_property_tree(pt)) }
                            else if idx <= pairs.len() { Ok(Value::from_property_tree(&pairs[idx - 1].1)) }
                            else { Ok(Value::Str(String::new())) }
                        }
                        crate::types::PropertyTree::Array(arr) => {
                            if idx == 0 { Ok(Value::from_property_tree(pt)) }
                            else if idx <= arr.len() { Ok(Value::from_property_tree(&arr[idx - 1])) }
                            else { Ok(Value::Str(String::new())) }
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
                        self.scope.arrays
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
                        self.scope.arrays
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
                                return Ok(self.scope.arrays.get(name)
                                    .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                                    .cloned()
                                    .unwrap_or(Value::Uninit));
                            }
                        }
                        let key = val.as_string();
                        self.scope.arrays.get(name).and_then(|arr| arr.get(&key)).cloned()
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
                            self.scope.arrays
                                .get(name)
                                .and_then(|arr| arr.get(self.array_key_buf.as_str()))
                                .cloned()
                        } else if let Expr::Number(n) = idx.as_ref() {
                            // Fast path: numeric literal - zero-alloc lookup via itoa buffer
                            let mut buf = itoa::Buffer::new();
                            let key = buf.format(*n as usize);
                            self.scope.arrays.get(name).and_then(|arr| arr.get(key)).cloned()
                        } else {
                            let val = self.eval_expr(idx)?;
                            // Fast path: numeric index -> use int_key cache (avoid String alloc)
                            if let Value::Number(n) = &val {
                                let i = *n as usize;
                                if *n >= 0.0 && i as f64 == *n {
                                    let mut buf = itoa::Buffer::new();
                                    let key = buf.format(i);
                                    return Ok(self.scope.arrays.get(name)
                                        .and_then(|arr| arr.get(key))
                                        .cloned()
                                        .unwrap_or(Value::Uninit));
                                }
                            }
                            let key = val.as_string();
                            self.scope.arrays.get(name).and_then(|arr| arr.get(&key)).cloned()
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
                            "NR" | "NF" | "FNR" | "FS" | "RS" | "OFS" | "ORS"
                                | "FILENAME" | "SUBSEP" | "FPAT" | "OFMT"
                                | "CONVFMT" | "ARGC" | "ERRNO"
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
                            let n = if *fn_ > MAX_FIELDS as f64 { MAX_FIELDS } else { *fn_ as usize };
                            let fbytes: Option<&[u8]> = if !self.field.fields_modified {
                                if n == 0 {
                                    Some(self.field.line_buf.as_bytes())
                                } else if !self.field.field_ranges.is_empty() {
                                    self.field.field_ranges
                                        .get(n - 1)
                                        .map(|&(start, end)| &self.field.line_buf.as_bytes()[start..end])
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(fbytes) = fbytes {
                                // Safe UTF-8 conversion (fbytes is from line_buf which is always valid UTF-8)
                                if let Ok(key) = std::str::from_utf8(fbytes) {
                                if let Some(arr) = self.scope.arrays.get_mut(arr_name.as_str()) {
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
                                "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                                "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                        return Ok(pt.get_field(field).map(Value::from_property_tree).unwrap_or(Value::Null));
                    }
                }
                // Chained access: $1.field (evaluate idx BEFORE borrowing property_tree)
                if let Expr::Field(ref idx_expr) = obj_expr.as_ref() {
                    // Clamp field index to prevent overflow from very large f64 values
                    let idx_f64 = self.eval_expr(idx_expr)?.as_number().max(0.0);
                    let idx = if idx_f64 > MAX_FIELDS as f64 { MAX_FIELDS } else { idx_f64 as usize };
                    if let Some(ref pt) = self.property_tree {
                        let result = match pt {
                            crate::types::PropertyTree::Object(pairs) => {
                                if idx == 0 { pt.get_field(field).cloned() }
                                else if idx <= pairs.len() { pairs[idx - 1].1.get_field(field).cloned() }
                                else { None }
                            }
                            crate::types::PropertyTree::Array(arr) => {
                                if idx == 0 { pt.get_field(field).cloned() }
                                else if idx <= arr.len() { arr[idx - 1].get_field(field).cloned() }
                                else { None }
                            }
                            _ => None,
                        };
                        return Ok(result.map(|v| Value::from_property_tree(&v)).unwrap_or(Value::Null));
                    }
                }
                let obj = self.eval_expr(obj_expr)?;
                match obj {
                    Value::Object(_) => {
                        Ok(obj.object_get(field).cloned().unwrap_or(Value::Null))
                    }
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
                                if i < 0 { return Ok(Value::Null); }
                                return Ok(arr.get(i as usize).map(Value::from_property_tree).unwrap_or(Value::Null));
                            }
                            crate::types::PropertyTree::Object(_) => {
                                let key = idx_val.as_string();
                                return Ok(pt.get_field(&key).map(Value::from_property_tree).unwrap_or(Value::Null));
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

    fn apply_binop(&self, left: Value, op: BinOp, right: Value) -> AwkResult<Value> {
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

    fn eval_func_call(&mut self, name: &str, args: &[Expr]) -> AwkResult<Value> {
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
                        Ok(Value::Number(std::str::from_utf8(bytes).map(|s| s.chars().count()).unwrap_or(bytes.len()) as f64))
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
                                return Ok(Value::Number(std::str::from_utf8(bytes).map(|s| s.chars().count()).unwrap_or(bytes.len()) as f64));
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
                let start = if start_raw < 1 { 0 } else { (start_raw - 1) as usize };
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
                                    .to_string()
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
                    return Err(AwkError::RuntimeError("attempt to write to read-only array ENVIRON".to_string()));
                }
                // Ultra-fast path for split($0, a, " ") when $0 has no whitespace:
                // Avoid take+restore by cloning line_buf directly into array
                if is_record_arg && sep.as_ref() == " "
                    && !self.field.line_buf.is_empty()
                    && !has_whitespace(self.field.line_buf.as_bytes())
                {
                    let plen = self.field.line_buf.len();
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                                arr.insert("1".to_string(), Value::Str(self.field.line_buf.clone()));
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
                if sep.as_ref() == " "
                    && !s.is_empty()
                    && !has_whitespace(s.as_bytes())
                {
                    let plen = s.len();
                    if self.total_array_entries + 1 > MAX_TOTAL_ARRAY_ENTRIES {
                        return Err(AwkError::RuntimeError(format!(
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                    self.split_parts.extend(s.split_whitespace().map(String::from));
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
                        "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                                    let arr = self.scope.arrays.entry(arr_name.clone()).or_default();
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
                                    if self.total_array_entries + new_entries > MAX_TOTAL_ARRAY_ENTRIES {
                                        return Err(AwkError::RuntimeError(format!(
                                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
                                        )));
                                    }
                                    self.total_array_entries += new_entries;
                                }
                            }
                        }
                    }
                    self.scope.set_var("RSTART".to_string(), Value::Number(pos as f64));
                    self.scope.set_var("RLENGTH".to_string(), Value::Number(len as f64));
                    Ok(Value::Number(pos as f64))
                } else {
                    self.scope.set_var("RSTART".to_string(), Value::Number(0.0));
                    self.scope.set_var("RLENGTH".to_string(), Value::Number(-1.0));
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
            "int" => Ok(Value::Number(BuiltinFunctions::int(self.eval_expr(&args[0])?.as_number()))),
            "sqrt" => Ok(Value::Number(BuiltinFunctions::sqrt(self.eval_expr(&args[0])?.as_number()))),
            "abs" => {
                let n = self.eval_expr(&args[0])?.as_number();
                Ok(Value::Number(n.abs()))
            }
            "log" => Ok(Value::Number(BuiltinFunctions::log(self.eval_expr(&args[0])?.as_number()))),
            "exp" => Ok(Value::Number(BuiltinFunctions::exp(self.eval_expr(&args[0])?.as_number()))),
            "sin" => Ok(Value::Number(BuiltinFunctions::sin(self.eval_expr(&args[0])?.as_number()))),
            "cos" => Ok(Value::Number(BuiltinFunctions::cos(self.eval_expr(&args[0])?.as_number()))),
            "atan2" => Ok(Value::Number(BuiltinFunctions::atan2(self.eval_expr(&args[0])?.as_number(), self.eval_expr(&args[1])?.as_number()))),
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
                Ok(Value::Number(
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
                    return Err(AwkError::RuntimeError("attempt to write to read-only array ENVIRON".to_string()));
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
                        "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                            "Array size limit exceeded ({} entries max)", MAX_TOTAL_ARRAY_ENTRIES
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
                        if let Some(plugin_type) = self.type_registry.resolve_tag(s) {
                            return Ok(Value::Str(plugin_type.to_string()));
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
            "to_json" => {
                if args.is_empty() {
                    return Err(AwkError::RuntimeError(
                        "to_json: requires 1 argument".to_string(),
                    ));
                }
                let val = self.eval_expr(&args[0])?;
                let json = serialize_for_output(&val);
                Ok(Value::Str(json))
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
                        Ok(Value::Null)
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
                        let context_json = serialize_for_output(&scope_vars);
                        str_args.push(context_json);
                    }

                    // Now borrow handler (avoids conflicting borrow with self)
                    let Some(handler) = self.external_fn.as_deref_mut() else {
                        return Err(AwkError::RuntimeError(format!("no external function handler for '{}'", name)));
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
    fn call_user_function(&mut self, func: &FunctionDef, args: &[Expr]) -> AwkResult<Value> {
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
            self.scope.scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope.scope_stack
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
            self.scope.scope_stack
                .last_mut()
                .unwrap()
                .insert(param.clone(), val);
        }

        // Set local variables
        for local in &func.locals {
            self.scope.scope_stack
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
        self.uses_json_features = Self::program_uses_json_features(program);
        self.containers_possible =
            self.uses_json_features || Self::program_has_container_literals(program);
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
            let re = self.regex.get_or_compile(&rust_sep)?;
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
                if !self.field.fields_modified && !self.field.field_ranges.is_empty() {
                    if idx == 0 {
                        self.array_key_buf.push_str(&self.field.line_buf);
                    } else if let Some(&(start, end)) = self.field.field_ranges.get(idx - 1) {
                        // line_buf is always valid UTF-8, field boundaries align on char boundaries
                        self.array_key_buf.push_str(&self.field.line_buf[start..end]);
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
    fn awk_sub_counted(
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

    fn format_printf(&self, fmt: &str, args: &[Value]) -> String {
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
fn has_whitespace(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| WS_TABLE[b as usize])
}

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

    // Fast path: short integer (3-5 digits, no sign, no decimal)
    if (3..=5).contains(&len) && bytes[0].is_ascii_digit() {
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

/// Serialize a Value to JSON string (fallback for output pipeline).
/// Defined in output module; re-exported here for use by Value methods.
pub(crate) use crate::eval::output::serialize_for_output;

/// Parse JSON string into Value via PropertyTree (single source of truth).
/// Defined in input module; re-exported here for use by builtin functions.
pub(crate) use crate::eval::input::json_to_awk;

impl<'a> Evaluator<'a> {
    /// Collect all user-defined variables in the current scope into an Object.
    /// Used by expression language plugins for variable injection (Phase 2).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::traits::{BufferedReader, BufferedWriter, BlockedCommandExecutor, SandboxEnvironment};

    fn run_awk(script: &str, input: &str) -> String {
        let program = parse(script).unwrap();
        let mut reader = BufferedReader::new(input);
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
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
            .stack_size(64 * 1024 * 1024) // 64MB stack (debug mode needs more)
            .spawn(|| {
                let script = "function deep(n) { if (n > 0) return deep(n-1); return 0 } BEGIN { print deep(260) }";
                let program = parse(script).unwrap();
                let mut reader = BufferedReader::new("");
                let mut writer = BufferedWriter::new();
                let env = SandboxEnvironment::default();
                let mut cmd = BlockedCommandExecutor;
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

    use crate::traits::{FunctionDispatcher, PluginCapability};
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

    impl PluginCapability for MockExternalHandler {
        fn capability_name(&self) -> &'static str { "function_dispatch" }
    }

    impl FunctionDispatcher for MockExternalHandler {
        fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
            *self.last_call.borrow_mut() = Some((name.to_string(), args.to_vec()));
            // Return a dummy result
            Ok(Some("MOCK_RESULT".to_string()))
        }
    }





    #[test]
    fn test_collect_scope_variables_basic() {
        let program = parse(r#"BEGIN { x = 10; y = "hello"; z = {"a": 1} }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.execute(&program).unwrap();

        let scope_vars = eval.collect_scope_variables();
        let json = serialize_for_output(&scope_vars);

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
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("date", "@date", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "date");
    }

    #[test]
    fn test_typeof_time_tag() {
        let program = parse(r#"BEGIN { x = "@time:14:30:00"; print typeof(x) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("time", "@time", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "time");
    }

    #[test]
    fn test_typeof_datetime_tag() {
        let program = parse(r#"BEGIN { x = "@datetime:2026-08-10T14:30:00"; print typeof(x) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("datetime", "@datetime", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "datetime");
    }

    #[test]
    fn test_typeof_duration_tag() {
        let program = parse(r#"BEGIN { x = "@duration:P1Y2M3D"; print typeof(x) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("duration", "@duration", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "duration");
    }

    #[test]
    fn test_typeof_grid_tag() {
        let program = parse(r#"BEGIN { x = "@grid:{\"cols\":[\"a\"],\"rows\":[[1]]}"; print typeof(x) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        eval.type_registry.register("grid", "@grid", "test");
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "grid");
    }

    #[test]
    fn test_typeof_plain_string() {
        let program = parse(r#"BEGIN { x = "hello"; print typeof(x) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
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
        let depth = 200;
        let mut val = serde_json::Value::Number(serde_json::Number::from(1));
        for _ in 0..depth {
            let mut map = serde_json::Map::new();
            map.insert("a".to_string(), val);
            val = serde_json::Value::Object(map);
        }
        let json_str = serde_json::to_string(&val).unwrap();
        let result = crate::types::PropertyTree::from_json(&json_str);
        assert!(result.is_err(), "Expected error for depth > MAX_PT_NESTING_DEPTH");
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


    // --- Phase 2: PropertyTree-Native Core tests ---

    #[test]
    fn test_json_object_dot_access() {
        let output = run_awk(r#"{ print $.name, $.age }"#, r#"{"name": "Alice", "age": 30}"#);
        assert_eq!(output.trim(), "Alice 30");
    }


    #[test]
    fn test_awkvalue_to_property_tree() {
        use crate::types::PropertyTree;
        
        // Test Null
        let awk_null = Value::Null;
        let pt = awk_null.to_property_tree();
        assert!(pt.is_null());
        
        // Test Bool
        let awk_bool = Value::Bool(true);
        let pt = awk_bool.to_property_tree();
        assert!(matches!(pt, PropertyTree::Bool(true)));
        
        // Test Number (integer)
        let awk_num = Value::Number(42.0);
        let pt = awk_num.to_property_tree();
        assert!(pt.is_number());
        assert_eq!(pt.as_f64(), 42.0);
        
        // Test String
        let awk_str = Value::Str("hello".to_string());
        let pt = awk_str.to_property_tree();
        assert!(pt.is_string());
        assert_eq!(pt.as_str(), "hello");
        
        // Test Array
        let awk_arr = Value::Array(vec![Value::Number(1.0), Value::Number(2.0)]);
        let pt = awk_arr.to_property_tree();
        assert!(pt.is_array());
        assert_eq!(pt.len(), 2);
        
        // Test Object
        let awk_obj = Value::Object(vec![
            ("name".to_string(), Value::Str("Alice".to_string())),
        ]);
        let pt = awk_obj.to_property_tree();
        assert!(pt.is_object());
        assert_eq!(pt.len(), 1);
    }
    
    #[test]
    fn test_property_tree_to_awkvalue() {
        use crate::types::PropertyTree;
        
        // Test Null
        let pt = PropertyTree::Null;
        let awk = Value::from_property_tree(&pt);
        assert!(matches!(awk, Value::Null));
        
        // Test Bool
        let pt = PropertyTree::Bool(true);
        let awk = Value::from_property_tree(&pt);
        assert!(matches!(awk, Value::Bool(true)));
        
        // Test Number
        let pt = PropertyTree::integer(42);
        let awk = Value::from_property_tree(&pt);
        assert_eq!(awk.as_number(), 42.0);
        
        // Test String
        let pt = PropertyTree::string("hello");
        let awk = Value::from_property_tree(&pt);
        assert_eq!(awk.as_string(), "hello");
        
        // Test Array
        let pt = PropertyTree::array(vec![PropertyTree::integer(1), PropertyTree::integer(2)]);
        let awk = Value::from_property_tree(&pt);
        assert!(matches!(awk, Value::Array(_)));
        
        // Test Object
        let pt = PropertyTree::object(vec![
            ("name".to_string(), PropertyTree::string("Alice")),
        ]);
        let awk = Value::from_property_tree(&pt);
        assert!(matches!(awk, Value::Object(_)));
    }
    
    #[test]
    fn test_roundtrip_conversion() {
        // Test Value -> PropertyTree -> Value
        let original = Value::Object(vec![
            ("name".to_string(), Value::Str("Alice".to_string())),
            ("age".to_string(), Value::Number(30.0)),
            ("active".to_string(), Value::Bool(true)),
        ]);
        
        let pt = original.to_property_tree();
        let roundtrip = Value::from_property_tree(&pt);
        
        assert_eq!(original, roundtrip);
    }

    #[test]
    fn test_json_object_positional_access() {
        let output = run_awk(r#"{ print $1, $2, $3 }"#, r#"{"name": "Alice", "age": 30, "city": "Berlin"}"#);
        assert_eq!(output.trim(), "30 Berlin Alice");
    }

    #[test]
    fn test_json_array_positional_access() {
        let output = run_awk(r#"{ print $1, $2, $3 }"#, r#"[10, 20, 30]"#);
        assert_eq!(output.trim(), "10 20 30");
    }

    #[test]
    fn test_json_nested_dot_access() {
        let output = run_awk(r#"{ print $.address.city }"#, r#"{"name": "Alice", "address": {"city": "Berlin"}}"#);
        assert_eq!(output.trim(), "Berlin");
    }

    #[test]
    fn test_json_field_then_dot_access() {
        let output = run_awk(r#"{ print $1.name }"#, r#"[{"name": "Alice"}, {"name": "Bob"}]"#);
        assert_eq!(output.trim(), "Alice");
    }

    #[test]
    fn test_json_print_record_serializes() {
        let output = run_awk(r#"{ print $0 }"#, r#"{"name": "Alice", "age": 30}"#);
        let out = output.trim();
        assert!(out.contains(r#""name""#));
        assert!(out.contains(r#""Alice""#));
        assert!(out.contains("30"));
    }

    #[test]
    fn test_json_nf_object() {
        let output = run_awk(r#"{ print NF }"#, r#"{"a": 1, "b": 2, "c": 3}"#);
        assert_eq!(output.trim(), "3");
    }

    #[test]
    fn test_json_nf_array() {
        let output = run_awk(r#"{ print NF }"#, r#"[10, 20, 30, 40, 50]"#);
        assert_eq!(output.trim(), "5");
    }

    #[test]
    fn test_mixed_json_and_text_records() {
        let input = "hello world
{\"name\": \"Alice\"}
foo bar";
        let output = run_awk(r#"{ print typeof($0) }"#, input);
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "string");
        assert_eq!(lines[1], "object");
        assert_eq!(lines[2], "string");
    }

    #[test]
    fn test_text_mode_still_works_json() {
        let output = run_awk(r#"{ print $0 }"#, "hello world");
        assert_eq!(output.trim(), "hello world");
    }

    #[test]
    fn test_json_typeof_fields() {
        let output = run_awk(r#"{ print typeof($.name), typeof($.age) }"#, r#"{"name": "Alice", "age": 30}"#);
        assert_eq!(output.trim(), "string number");
    }

}
