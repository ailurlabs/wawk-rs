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
pub mod builtins;
pub mod field_access;
pub mod input;
pub mod output;
pub mod regex_cache;
pub mod scope;
pub mod security;
pub mod wit_format_bridge;

// New sub-modules extracted from mod.rs
pub mod expressions;
pub mod functions;
pub mod helpers;
pub mod statements;
pub mod value;

// Re-export types that were moved to sub-modules
pub use value::Value;
pub use helpers::SecurityProfile;
use helpers::regex_escape_to_rust;
use crate::eval::output::serialize_for_output;
use helpers::RegexPreFilter;
// HashMap replaced with FxHashMap for arrays
use std::collections::HashSet;
use std::fmt::Write;
use std::rc::Rc;

use rustc_hash::FxHashMap;

use crate::ast::*;
use crate::error::{AwkError, AwkResult};
use crate::eval::builtins::BuiltinFunctions;
use crate::traits::{AwkCommandExecutor, AwkEnvironment, AwkReader, AwkWriter, FunctionDispatcher};
use crate::types::ExtensionTypeRegistry;

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
    uses_property_tree_features: bool,
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

    // ERRNO: set on I/O failures, extension errors, etc.
    errno: String,

    // Current index into ARGV for file iteration
    argv_index: usize,

    // Extension type registry for extension-provided types
    pub type_registry: ExtensionTypeRegistry,
}

/// Maximum total array entries across all arrays.
/// WASM default: 1M. Increase for native builds.
const MAX_TOTAL_ARRAY_ENTRIES: usize = 1_000_000;
/// Maximum loop iterations before aborting (prevent infinite loops in sandboxed mode).
const MAX_LOOP_ITERATIONS: usize = 100_000_000;
// Re-export security constants as the single source of truth
use crate::eval::security::{
    MAX_CALL_DEPTH, MAX_EXPR_DEPTH, MAX_FIELDS, MAX_OPEN_FILES, MAX_OUTPUT_BYTES,
    MAX_REGEX_PATTERN_LEN,
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
pub enum AuditEvent {
    /// A security limit was hit and execution was aborted
    LimitViolation {
        limit_name: String,
        limit_value: usize,
        actual_value: usize,
    },
    /// A sandbox violation was attempted (e.g., system() call)
    SandboxViolation { action: String },
    /// Execution timeout reached
    ExecutionTimeout { elapsed_secs: u64 },
    /// Memory limit approached or exceeded
    MemoryLimitExceeded {
        estimated_bytes: usize,
        limit_bytes: usize,
    },
    /// Input record processed (for audit trail)
    RecordProcessed {
        record_number: usize,
        input_bytes: usize,
    },
    /// Execution completed
    ExecutionComplete {
        records_processed: usize,
        output_bytes: usize,
        total_input_bytes: usize,
    },
}

/// AWK values - everything is either a number or a string.
#[derive(Debug, Clone)]
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
            uses_property_tree_features: false,
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
            type_registry: ExtensionTypeRegistry::new(),
        }
    }

    /// Set an external function handler for Wasm host extensions.
    pub fn set_external_function_handler(&mut self, handler: Box<dyn FunctionDispatcher>) {
        self.external_fn = Some(handler);
    }

    /// Register a WIT format extension into the format registry.
    ///
    /// Format extensions implement the `FormatDispatcher` trait and provide
    /// custom format detection, parsing, and serialization capabilities.
    /// They are inserted into the registry sorted by priority (lower = higher priority).
    ///
    /// # Example
    /// ```ignore
    /// use wawk_core::eval::wit_format_bridge::WitFormatDispatcher;
    /// eval.register_format_extension(WitFormatDispatcher::new(
    ///     "toml".to_string(),
    ///     my_handler,
    ///     20,
    /// ));
    /// ```
    pub fn register_format_extension(&mut self, extension: Box<dyn crate::traits::FormatDispatcher>) {
        self.format_registry.register(extension);
    }

    pub fn set_fs(&mut self, fs: String) {
        self.fs = fs;
        self.format_auto = false;
    }

    /// Set a variable in the global scope (used by CLI -v assignments).
    pub fn set_variable(&mut self, name: String, value: String) {
        match name.as_str() {
            "FS" => {
                self.fs = value.clone();
                self.format_auto = false;
            }
            "OFS" => self.ofs = value.clone(),
            "ORS" => self.ors = value.clone(),
            "RS" => {
                self.rs = value.clone();
                self.format_auto = false;
            }
            "OUTPUT_FORMAT" => {
                self.output_format = if value.is_empty() {
                    None
                } else {
                    Some(value.clone())
                };
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
        r.push_str(&format!(
            "Estimated memory: {} bytes\n",
            self.estimated_memory
        ));
        r.push_str(&format!("Audit events: {}\n", self.audit_log.len()));
        for (i, event) in self.audit_log.iter().enumerate() {
            r.push_str(&format!("  [{}] {:?}\n", i + 1, event));
        }
        r.push_str(&format!(
            "Security profile: max_exec={}s, max_mem={} bytes, audit={}\n",
            self.security_profile.max_execution_secs,
            self.security_profile.max_memory_bytes,
            self.security_profile.audit_enabled
        ));
        r
    }

    pub fn execute(&mut self, program: &Program) -> AwkResult<()> {
        // Compliance: Reset execution timer and audit state
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.exec_start_time = std::time::Instant::now();
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.exec_start_counter = 0;
        }
        self.audit_log.clear();
        self.estimated_memory = 0;
        self.total_input_bytes = 0;
        for func in &program.functions {
            self.functions
                .insert(func.name.clone(), Rc::new(func.clone()));
        }

        // Detect if program uses PropertyTree-native features (skip structured data parsing if not)
        self.uses_property_tree_features = Self::program_uses_property_tree_features(program);

        // Detect if any scope variable can ever hold a container. When false,
        // container-shadow scope scans in array fast paths are skipped.
        // Must be set BEFORE BEGIN blocks execute.
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
            } else {
                None
            }
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
                        self.security.record_audit(AuditEvent::ExecutionTimeout {
                            elapsed_secs: elapsed,
                        });
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
                    let budget = self
                        .security_profile
                        .max_execution_secs
                        .saturating_mul(100_000);
                    if self.exec_start_counter > budget {
                        self.security.record_audit(AuditEvent::ExecutionTimeout {
                            elapsed_secs: self.security_profile.max_execution_secs,
                        });
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
                    let could_be_structured =
                        self.format_auto && matches!(first_byte, b'{' | b'[' | b'<' | b'-');
                    if could_be_structured {
                        if let Some(result) =
                            self.format_registry.detect_and_parse(&self.field.line_buf)
                        {
                            match result {
                                Ok((tree, _format_name)) => {
                                    self.nf = tree.len();
                                    if let crate::types::PropertyTree::Array(ref arr) = tree {
                                        self.field.fields.clear();
                                        self.field.fields.push(String::new());
                                        for elem in arr {
                                            self.field.fields.push(serialize_for_output(
                                                &Value::from_property_tree(elem),
                                            ));
                                        }
                                        self.field.fields_modified = true;
                                    }
                                    self.property_tree = Some(tree);
                                }
                                Err(_) => {
                                    self.property_tree = None;
                                    if needs_fields {
                                        self.split_fields_inplace()?;
                                    }
                                }
                            }
                        } else {
                            self.property_tree = None;
                            if needs_fields {
                                self.split_fields_inplace()?;
                            }
                        }
                    } else {
                        self.property_tree = None;
                        if needs_fields {
                            self.split_fields_inplace()?;
                        }
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
                        } else {
                            self.security.output_bytes +=
                                self.field.line_buf.len() + self.ors.len();
                            if (self.nr & 1023) == 0
                                && self.security.output_bytes > MAX_OUTPUT_BYTES
                            {
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
                                let active =
                                    self.range_active.get(rule_idx).copied().unwrap_or(false);
                                // Use mem::take to avoid clone: take ownership of line_buf temporarily
                                let line = std::mem::take(&mut self.field.line_buf);
                                let result = if !active {
                                    let start_matches = self.pattern_matches(start_pat, &line)?;
                                    if start_matches {
                                        self.range_active[rule_idx] = true;
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    let end_matches = self.pattern_matches(end_pat, &line)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use crate::traits::{
        BlockedCommandExecutor, BufferedReader, BufferedWriter, SandboxEnvironment,
    };

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

    // --- Phase 2: Auto variable injection tests ---

    use crate::traits::{FunctionDispatcher, ExtensionCapability};
    use std::cell::RefCell;

    /// Mock external function handler that captures args for verification
    struct MockExternalHandler {
        last_call: RefCell<Option<(String, Vec<String>)>>,
    }

    impl MockExternalHandler {
        fn new() -> Self {
            Self {
                last_call: RefCell::new(None),
            }
        }
    }

    impl ExtensionCapability for MockExternalHandler {
        fn capability_name(&self) -> &'static str {
            "function_dispatch"
        }
    }

    impl FunctionDispatcher for MockExternalHandler {
        fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
            *self.last_call.borrow_mut() = Some((name.to_string(), args.to_vec()));
            // Return a dummy result
            Ok(Some("MOCK_RESULT".to_string()))
        }
    }

    /// Mock handler that captures dispatch calls for verification.
    /// Qualified calls arrive as "ns.fn" in the name parameter.
    struct RoutingMockHandler {
        known_functions: Vec<String>,
        calls: std::rc::Rc<RefCell<Vec<String>>>,
    }

    impl RoutingMockHandler {
        fn new(known_functions: &[&str]) -> Self {
            Self {
                known_functions: known_functions.iter().map(|s| s.to_string()).collect(),
                calls: std::rc::Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn calls(&self) -> std::rc::Rc<RefCell<Vec<String>>> {
            self.calls.clone()
        }
    }

    impl ExtensionCapability for RoutingMockHandler {
        fn capability_name(&self) -> &'static str {
            "function_dispatch"
        }
    }

    impl FunctionDispatcher for RoutingMockHandler {
        fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
            self.calls.borrow_mut().push(format!("dispatch:{}", name));
            if self.known_functions.iter().any(|f| f == name) {
                return Ok(Some(format!("result:{}({})", name, args.join(","))));
            }
            Ok(None)
        }
    }

    #[test]
    fn test_qualified_call_routes_via_dispatch() {
        let program = parse(r#"BEGIN { print ns_a.fn1(1, 2) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        let handler = RoutingMockHandler::new(&["ns_a.fn1"]);
        let calls = handler.calls();
        eval.set_external_function_handler(Box::new(handler));
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "result:ns_a.fn1(1,2)");
        assert!(calls.borrow().contains(&"dispatch:ns_a.fn1".to_string()));
    }

    #[test]
    fn test_qualified_call_unknown_function_errors() {
        // Qualified call to an unknown function returns an error.
        let program = parse(r#"BEGIN { print ns_a.fn1(1, 2) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        let handler = RoutingMockHandler::new(&["ns_a.other_fn"]);
        eval.set_external_function_handler(Box::new(handler));
        let result = eval.execute(&program);
        assert!(result.is_err(), "expected error, got output: {}", writer.output);
    }

    #[test]
    fn test_qualified_call_different_namespace() {
        // Test with a different namespace name
        let program = parse(r#"BEGIN { print ns_b.fn2(7) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        let handler = RoutingMockHandler::new(&["ns_b.fn2"]);
        let calls = handler.calls();
        eval.set_external_function_handler(Box::new(handler));
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "result:ns_b.fn2(7)");
        assert!(calls.borrow().contains(&"dispatch:ns_b.fn2".to_string()));
    }

    #[test]
    fn test_qualified_call_default_handler_composite_name() {
        // Handlers receive the qualified name "namespace.function" as a single string.
        let program = parse(r#"BEGIN { print ns_a.fn1(1, 2) }"#).unwrap();
        let mut reader = BufferedReader::new("");
        let mut writer = BufferedWriter::new();
        let env = SandboxEnvironment::default();
        let mut cmd = BlockedCommandExecutor;
        let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);
        let handler = MockExternalHandler::new();
        eval.set_external_function_handler(Box::new(handler));
        eval.execute(&program).unwrap();
        assert_eq!(writer.output.trim(), "MOCK_RESULT");
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
        let program =
            parse(r#"BEGIN { x = "@datetime:2026-08-10T14:30:00"; print typeof(x) }"#).unwrap();
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
        let program =
            parse(r#"BEGIN { x = "@grid:{\"cols\":[\"a\"],\"rows\":[[1]]}"; print typeof(x) }"#)
                .unwrap();
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
        for _ in 0..depth {
            expr.push('(');
        }
        expr.push('1');
        for _ in 0..depth {
            expr.push(')');
        }
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
        let result = crate::eval::input::json_parse(&json_str);
        assert!(
            result.is_err(),
            "Expected error for depth > MAX_PT_NESTING_DEPTH"
        );
    }

    #[test]
    fn test_eval_depth_limit_integration() {
        // Parser catches deep nesting at 512 before evaluator sees it
        // Use a thread with larger stack since recursive descent is stack-heavy
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let depth = 600;
                let mut expr = String::new();
                for _ in 0..depth {
                    expr.push('(');
                }
                expr.push('1');
                for _ in 0..depth {
                    expr.push(')');
                }
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
        let output = run_awk(
            r#"{ print $.name, $.age }"#,
            r#"{"name": "Alice", "age": 30}"#,
        );
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
        let awk_obj = Value::Object(vec![("name".to_string(), Value::Str("Alice".to_string()))]);
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
        let pt = PropertyTree::object(vec![("name".to_string(), PropertyTree::string("Alice"))]);
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
        let output = run_awk(
            r#"{ print $1, $2, $3 }"#,
            r#"{"name": "Alice", "age": 30, "city": "Berlin"}"#,
        );
        assert_eq!(output.trim(), "30 Berlin Alice");
    }

    #[test]
    fn test_json_array_positional_access() {
        let output = run_awk(r#"{ print $1, $2, $3 }"#, r#"[10, 20, 30]"#);
        assert_eq!(output.trim(), "10 20 30");
    }

    #[test]
    fn test_json_nested_dot_access() {
        let output = run_awk(
            r#"{ print $.address.city }"#,
            r#"{"name": "Alice", "address": {"city": "Berlin"}}"#,
        );
        assert_eq!(output.trim(), "Berlin");
    }

    #[test]
    fn test_json_field_then_dot_access() {
        let output = run_awk(
            r#"{ print $1.name }"#,
            r#"[{"name": "Alice"}, {"name": "Bob"}]"#,
        );
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
        let output = run_awk(
            r#"{ print typeof($.name), typeof($.age) }"#,
            r#"{"name": "Alice", "age": 30}"#,
        );
        assert_eq!(output.trim(), "string number");
    }
}
