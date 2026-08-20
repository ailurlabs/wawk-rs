//! wawk-core: A modern, Wasm-portable AWK engine.
//!
//! This crate provides a pure AWK interpreter with trait-based I/O,
//! designed to compile to WebAssembly without any OS dependencies.
//!
//! # Quick Start
//!
//! ```rust
//! use wawk_core::WawkEngine;
//! use wawk_core::traits::{MemReader, MemWriter, StubEnvironment, StubCommandExecutor};
//!
//! let engine = WawkEngine::new();
//! let mut reader = MemReader::new("hello\nworld\n");
//! let mut writer = MemWriter::new();
//! let env = StubEnvironment::default();
//! let mut cmd = StubCommandExecutor;
//!
//! engine.execute("{ print $0 }", &mut reader, &mut writer, &env, &mut cmd).unwrap();
//! assert_eq!(writer.output, "hello\nworld\n");
//! ```
pub mod ast;
pub mod error;
pub mod eval;
pub mod lexer;
pub mod parser;
pub mod preprocessor;
pub mod traits;
pub mod types;
// ── Plugin subsystem ──────────────────────────────────────────────────
pub mod plugin_meta;
pub mod plugin_resolver;
pub mod plugin_loader;



/// Transform HTTP request headers into AWK ENVIRON entries.
///
/// Header names are uppercased, hyphens replaced with underscores, and
/// prefixed with `HTTP_` — mirroring the CGI / PHP convention so AWK
/// scripts can read them as `ENVIRON["HTTP_AUTHORIZATION"]` etc.
///
/// This helper is intentionally feature-independent so any runtime that
/// embeds wawk-core (HTTP server, edge worker, cloud function) can inject
/// headers before AWK execution without pulling in any optional
/// feature.
pub fn http_headers_to_environ(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let key = format!(
                "HTTP_{}",
                name.to_ascii_uppercase().replace('-', "_")
            );
            (key, value.clone())
        })
        .collect()
}

/// An `AwkEnvironment` that layers extra variables (typically HTTP headers
/// injected via `http_headers_to_environ`) on top of an inner environment.
///
/// Use this to expose request-scoped context to AWK scripts.
pub struct HttpHeaderEnvironment {
    inner: Box<dyn traits::AwkEnvironment>,
    extras: Vec<(String, String)>,
}

impl HttpHeaderEnvironment {
    pub fn new(inner: Box<dyn traits::AwkEnvironment>, extras: Vec<(String, String)>) -> Self {
        Self { inner, extras }
    }

    /// Convenience: build from raw HTTP headers (applies the HTTP_ prefix
    /// transform automatically).
    pub fn from_http_headers(
        inner: Box<dyn traits::AwkEnvironment>,
        headers: &[(String, String)],
    ) -> Self {
        Self {
            inner,
            extras: http_headers_to_environ(headers),
        }
    }
}

impl traits::AwkEnvironment for HttpHeaderEnvironment {
    fn get_env(&self, name: &str) -> Option<String> {
        if let Some((_, v)) = self.extras.iter().find(|(k, _)| k == name) {
            return Some(v.clone());
        }
        self.inner.get_env(name)
    }

    fn systime(&self) -> i64 {
        self.inner.systime()
    }

    fn all_env_vars(&self) -> Vec<(String, String)> {
        let mut vars = self.inner.all_env_vars();
        vars.extend(self.extras.iter().cloned());
        vars
    }
}

use error::AwkResult;
use eval::Evaluator;
use parser::parse;
use traits::{
    AwkCommandExecutor, AwkEnvironment, AwkExternalFunction, AwkReader, AwkWriter, IncludeResolver,
};

/// High-level AWK engine that encapsulates parsing and evaluation.
///
/// This provides a clean API for embedding wawk in other applications
/// (e.g., web servers, edge runtimes) without exposing the internal AST or trait wiring.
#[derive(Default)]
pub struct WawkEngine {
    /// Optional field separator override (set via -F flag).
    field_separator: Option<String>,
    /// Optional variable assignments (set via -v flags).
    pre_assignments: Vec<(String, String)>,
}

impl WawkEngine {
    /// Create a new engine with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            field_separator: None,
            pre_assignments: Vec::new(),
        }
    }

    /// Set the field separator (equivalent to awk's -F flag).
    pub fn set_field_separator(&mut self, fs: impl Into<String>) -> &mut Self {
        self.field_separator = Some(fs.into());
        self
    }

    /// Add a variable assignment (equivalent to awk's -v flag).
    pub fn assign_variable(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> &mut Self {
        self.pre_assignments.push((name.into(), value.into()));
        self
    }

    /// Execute an AWK script with the given input, reader, writer, environment, and command executor.
    ///
    /// This is the primary execution method. It:
    /// 1. Parses the script into an AST
    /// 2. Creates an evaluator with the provided I/O traits
    /// 3. Applies any field separator or variable assignments
    /// 4. Executes the program
    ///
    /// # Errors
    /// Returns `AwkError::ParseError` if the script has syntax errors.
    /// Returns `AwkError::RuntimeError` for runtime errors (division by zero, etc.).
    /// Returns `AwkError::IoError` for I/O errors from the reader/writer.
    pub fn execute(
        &self,
        script: &str,
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
    ) -> AwkResult<()> {
        let program = parse(script)?;
        let mut eval = Evaluator::new(reader, writer, env, cmd);

        if let Some(ref fs) = self.field_separator {
            eval.set_fs(fs.clone());
        }
        for (name, value) in &self.pre_assignments {
            eval.set_variable(name.clone(), value.clone());
        }

        eval.execute(&program)
    }

    /// Execute an AWK script with an external function handler.
    ///
    /// This enables host-provided functions (e.g., Wasm host dispatch,
    /// external service calls) to be called from within AWK as if they were regular functions.
    /// The handler is tried for any function call that isn't a built-in or
    /// user-defined function.
    pub fn execute_with_handler(
        &self,
        script: &str,
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
        handler: Box<dyn AwkExternalFunction>,
    ) -> AwkResult<()> {
        let program = parse(script)?;
        let mut eval = Evaluator::new(reader, writer, env, cmd);

        if let Some(ref fs) = self.field_separator {
            eval.set_fs(fs.clone());
        }
        for (name, value) in &self.pre_assignments {
            eval.set_variable(name.clone(), value.clone());
        }

        eval.set_external_function_handler(handler);
        eval.execute(&program)
    }

    /// Convenience method: execute a script and return the output as a String.
    ///
    /// This creates in-memory reader/writer stubs internally, making it
    /// ideal for stateless, one-shot executions (e.g., from a server handler).
    ///
    /// # Errors
    /// Same as `execute()`.
    pub fn exec(
        &self,
        script: &str,
        input: &str,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
    ) -> AwkResult<String> {
        let mut reader = traits::MemReader::new(input);
        let mut writer = traits::MemWriter::new();
        self.execute(script, &mut reader, &mut writer, env, cmd)?;
        Ok(writer.output)
    }

    /// Invoke a named AWK function from a script with string arguments.
    ///
    /// This is the **Host-driven pure function** API. It:
    /// 1. Parses the AWK script
    /// 2. Creates an evaluator with the external function handler
    /// 3. Registers all function definitions (no BEGIN/END execution)
    /// 4. Calls the named function with the provided string arguments
    /// 5. Returns the function's return value as a String
    ///
    /// This enables Nginx-style event routing where the Host owns the event loop
    /// and AWK acts as a stateless routing function library.
    ///
    /// # Errors
    /// Returns `AwkError::ParseError` if the script has syntax errors.
    /// Returns `AwkError::RuntimeError` if the function is undefined or execution fails.
    pub fn invoke_function(
        &self,
        script: &str,
        function_name: &str,
        args: &[String],
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
        handler: Box<dyn AwkExternalFunction>,
    ) -> AwkResult<String> {
        let program = parse(script)?;
        let mut reader = traits::MemReader::new("");
        let mut writer = traits::MemWriter::new();
        let mut eval = Evaluator::new(&mut reader, &mut writer, env, cmd);

        if let Some(ref fs) = self.field_separator {
            eval.set_fs(fs.clone());
        }
        for (name, value) in &self.pre_assignments {
            eval.set_variable(name.clone(), value.clone());
        }

        eval.set_external_function_handler(handler);
        eval.register_functions(&program);
        eval.execute_begin_blocks(&program)?;
        eval.call_function(function_name, args)
    }

    /// Execute multiple AWK scripts concatenated together (POSIX `-f` semantics).
    ///
    /// POSIX AWK specifies that when multiple scripts are provided (via `-f file1 -f file2`
    /// or combined inline/file sources), they are concatenated with newline separators
    /// before parsing. This enables library patterns where helper functions are defined
    /// in separate files.
    ///
    /// # Example
    /// ```rust
    /// use wawk_core::WawkEngine;
    /// use wawk_core::traits::{MemReader, MemWriter, StubEnvironment, StubCommandExecutor};
    ///
    /// let engine = WawkEngine::new();
    /// let lib_script = "function double(x) { return x * 2 }";
    /// let main_script = "{ print double($1) }";
    ///
    /// let mut reader = MemReader::new("5\n10\n");
    /// let mut writer = MemWriter::new();
    /// let env = StubEnvironment::default();
    /// let mut cmd = StubCommandExecutor;
    ///
    /// engine.execute_scripts(
    ///     &[lib_script, main_script],
    ///     &mut reader, &mut writer, &env, &mut cmd
    /// ).unwrap();
    /// assert_eq!(writer.output, "10\n20\n");
    /// ```
    ///
    /// # Errors
    /// Returns `AwkError::ParseError` if any script has syntax errors.
    /// Returns `AwkError::RuntimeError` for runtime errors.
    pub fn execute_scripts(
        &self,
        scripts: &[&str],
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
    ) -> AwkResult<()> {
        let combined = scripts.join("\n");
        self.execute(&combined, reader, writer, env, cmd)
    }

    /// Execute multiple AWK scripts with an external function handler.
    ///
    /// Combines multi-script support with external function dispatch capability.
    pub fn execute_scripts_with_handler(
        &self,
        scripts: &[&str],
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
        handler: Box<dyn AwkExternalFunction>,
    ) -> AwkResult<()> {
        let combined = scripts.join("\n");
        self.execute_with_handler(&combined, reader, writer, env, cmd, handler)
    }

    /// Execute an AWK script with `@include` directive support.
    ///
    /// Before parsing, the script is preprocessed to expand any `@include "path"`
    /// directives using the provided resolver. This enables gawk-compatible
    /// library inclusion patterns.
    ///
    /// # Include Semantics
    /// - `@include "path"` must appear at the top level (not inside functions/rules)
    /// - Includes are expanded recursively up to 16 levels deep
    /// - Circular includes are detected and produce an error
    /// - The resolver controls how paths are mapped to content
    ///
    /// # Errors
    /// Returns `AwkError::RuntimeError` if include resolution fails or cycles are detected.
    /// Returns `AwkError::ParseError` if the expanded script has syntax errors.
    pub fn execute_with_includes(
        &self,
        script: &str,
        resolver: &dyn IncludeResolver,
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
    ) -> AwkResult<()> {
        let expanded = preprocessor::preprocess(script, resolver)?;
        self.execute(&expanded, reader, writer, env, cmd)
    }

    /// Execute an AWK script with both `@include` support and an external function handler.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_includes_and_handler(
        &self,
        script: &str,
        resolver: &dyn IncludeResolver,
        reader: &mut dyn AwkReader,
        writer: &mut dyn AwkWriter,
        env: &dyn AwkEnvironment,
        cmd: &mut dyn AwkCommandExecutor,
        handler: Box<dyn AwkExternalFunction>,
    ) -> AwkResult<()> {
        let expanded = preprocessor::preprocess(script, resolver)?;
        self.execute_with_handler(&expanded, reader, writer, env, cmd, handler)
    }

    /// Parse a script without executing it. Useful for syntax checking.
    ///
    /// # Errors
    /// Returns `AwkError::ParseError` if the script has syntax errors.
    pub fn check_syntax(script: &str) -> AwkResult<()> {
        parse(script)?;
        Ok(())
    }
}

/// Convenience function: execute an AWK script with input and return the output.
///
/// Uses default stub environment and command executor (no time, no env vars, no commands).
/// For more control, use `WawkEngine` directly.
///
/// # Errors
/// Returns `Err` if parsing or execution fails.
pub fn exec_awk(script: &str, input: &str) -> AwkResult<String> {
    let engine = WawkEngine::new();
    let env = traits::StubEnvironment::default();
    let mut cmd = traits::StubCommandExecutor;
    engine.exec(script, input, &env, &mut cmd)
}
