//! Trait abstractions for I/O and environment operations.
//!
//! These traits decouple `wawk-core` from any concrete I/O implementation,
//! enabling future Wasm sandbox execution where the host provides I/O.

use crate::error::AwkResult;

/// Trait for reading input lines.
///
/// In CLI mode, this reads from stdin or files.
/// In Wasm mode, the host provides the input.
pub trait AwkReader {
    /// Read the next line of input. Returns `None` when input is exhausted.
    fn read_line(&mut self) -> AwkResult<Option<String>>;

    /// Zero-copy line reading: reads the next line into a reusable buffer.
    /// Returns `true` if a line was read, `false` if input is exhausted.
    /// The buffer is cleared before reading. Default falls back to `read_line()`.
    fn read_line_into(&mut self, buf: &mut String) -> AwkResult<bool> {
        buf.clear();
        match self.read_line()? {
            Some(line) => {
                buf.push_str(&line);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Open a named file/data-source for reading (for ARGV-driven file iteration).
    /// After this call, read_line()/read_line_into() read from the new file.
    /// Returns Err if the file cannot be opened.
    fn open_file(&mut self, _filename: &str) -> AwkResult<()> {
        Err(crate::error::AwkError::RuntimeError(
            "open_file not supported".to_string(),
        ))
    }

    /// Read the next line from a named file (for `getline < file`).
    /// The implementation should keep the file open between calls.
    /// Returns `None` when the file is exhausted.
    fn read_file_line(&mut self, _filename: &str) -> AwkResult<Option<String>> {
        Ok(None)
    }

    /// Close a file that was opened for reading.
    fn close_file(&mut self, _filename: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Skip all remaining lines in the current input source (for `nextfile`).
    /// In a multi-file setup, this advances to the next file.
    fn skip_to_next_file(&mut self) {}

    /// Get the name of the current file being read (for FILENAME variable).
    fn current_filename(&self) -> String {
        String::new()
    }

    /// Check if the filename has changed since the last call (for FILENAME tracking).
    /// Returns `Some(filename)` if changed, `None` if not. Default: always returns None.
    /// Implementations should track a dirty flag to avoid allocating a String per line.
    fn filename_if_changed(&mut self) -> Option<String> {
        None
    }
}

/// Trait for writing output.
///
/// In CLI mode, this writes to stdout/stderr or files.
/// In Wasm mode, the host collects the output.
pub trait AwkWriter {
    /// Write a line of output (with newline).
    fn write_line(&mut self, output: &str) -> AwkResult<()>;

    /// Write a string without trailing newline.
    fn write_str(&mut self, output: &str) -> AwkResult<()>;

    /// Write a line to a named file (truncate mode).
    fn write_file_line(&mut self, _filename: &str, _output: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Write a string to a named file (truncate mode).
    fn write_file_str(&mut self, _filename: &str, _output: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Write a line to a named file (append mode).
    fn append_file_line(&mut self, _filename: &str, _output: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Write a string to a named file (append mode).
    fn append_file_str(&mut self, _filename: &str, _output: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Close a file that was opened for writing.
    fn close_file(&mut self, _filename: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Flush any buffered output. Default: no-op.
    fn flush(&mut self) -> AwkResult<()> {
        Ok(())
    }
}

/// Trait for accessing environment state.
///
/// Provides access to things like the current time, environment variables,
/// and other external state that may be restricted in a sandbox.
pub trait AwkEnvironment {
    /// Get an environment variable by name.
    fn get_env(&self, name: &str) -> Option<String>;

    /// Get the current timestamp (seconds since epoch).
    fn systime(&self) -> i64;

    /// Get all environment variables (for `for (x in ENVIRON)`).
    /// Returns a Vec of (key, value) pairs.
    fn all_env_vars(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// Trait for executing external commands.
///
/// In CLI mode, this uses `std::process::Command`.
/// In Wasm mode, the host can choose to block these or provide custom routing.
pub trait AwkCommandExecutor {
    /// Execute a command and return its stdout.
    fn execute(&mut self, cmd: &str) -> AwkResult<String>;

    /// Read the next line from a pipe opened for reading (`getline | "cmd"`).
    /// Returns `None` when the command's output is exhausted.
    fn read_pipe_line(&mut self, _cmd: &str) -> AwkResult<Option<String>> {
        Ok(None)
    }

    /// Write a string to a pipe opened for writing (`print | "cmd"`).
    fn write_pipe(&mut self, _cmd: &str, _output: &str) -> AwkResult<()> {
        Ok(())
    }

    /// Close a pipe (either read or write).
    fn close_pipe(&mut self, _cmd: &str) -> AwkResult<()> {
        Ok(())
    }
}

/// A simple buffered reader for testing.
#[derive(Debug, Default)]
pub struct BufferedReader {
    lines: Vec<String>,
    pos: usize,
}

impl BufferedReader {
    #[must_use]
    pub fn new(input: &str) -> Self {
        Self {
            lines: input.lines().map(String::from).collect(),
            pos: 0,
        }
    }
}

impl AwkReader for BufferedReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        if self.pos < self.lines.len() {
            let line = self.lines[self.pos].clone();
            self.pos += 1;
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }
}

/// Zero-copy in-memory reader over an owned buffer.
///
/// Unlike `BufferedReader` (which pre-splits input into `Vec<String>` and clones
/// each line on read), this reader scans for newlines on demand and copies
/// only the current line into the caller's buffer. This avoids hundreds of
/// thousands of small heap allocations on large inputs.
///
/// Semantics match `BufferedReader` (i.e. `str::lines()`): both `\n` and `\r\n`
/// terminators are stripped, a final line without terminator is returned,
/// and a trailing newline does not produce an empty final record.
pub struct SliceReader {
    input: String,
    pos: usize,
}

impl SliceReader {
    #[must_use]
    pub fn new(input: String) -> Self {
        Self { input, pos: 0 }
    }
}

impl AwkReader for SliceReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        let mut buf = String::new();
        if self.read_line_into(&mut buf)? {
            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }

    fn read_line_into(&mut self, buf: &mut String) -> AwkResult<bool> {
        buf.clear();
        if self.pos >= self.input.len() {
            return Ok(false);
        }
        let rest = &self.input[self.pos..];
        let (end, advance) = match rest.find('\n') {
            Some(nl) => (nl, nl + 1),
            None => (rest.len(), rest.len()),
        };
        let mut line_end = end;
        if line_end > 0 && rest.as_bytes()[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        // Safe: rest is &str (valid UTF-8) and line_end sits on a char boundary
        // (newline position or end of string), so the slice is valid UTF-8.
        buf.push_str(&rest[..line_end]);
        self.pos += advance;
        Ok(true)
    }
}

/// A simple buffered writer for testing.
#[derive(Debug, Default)]
pub struct BufferedWriter {
    pub output: String,
}

impl BufferedWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            output: String::new(),
        }
    }
}

impl AwkWriter for BufferedWriter {
    fn write_line(&mut self, output: &str) -> AwkResult<()> {
        self.output.push_str(output);
        self.output.push('\n');
        Ok(())
    }

    fn write_str(&mut self, output: &str) -> AwkResult<()> {
        self.output.push_str(output);
        Ok(())
    }
}

/// A sandbox environment for testing and sandboxed execution.
#[derive(Debug, Default)]
pub struct SandboxEnvironment {
    pub time: i64,
}

impl AwkEnvironment for SandboxEnvironment {
    fn get_env(&self, _name: &str) -> Option<String> {
        None
    }

    fn systime(&self) -> i64 {
        self.time
    }
}

#[cfg(not(target_arch = "wasm32"))]
/// A real environment that reads actual OS environment variables and system clock.
/// Use this as the inner environment for runtimes that have OS access (wawk-wasi).
#[derive(Debug, Default)]
pub struct SystemEnvironment;

#[cfg(not(target_arch = "wasm32"))]
impl AwkEnvironment for SystemEnvironment {
    fn get_env(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn systime(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn all_env_vars(&self) -> Vec<(String, String)> {
        std::env::vars().collect()
    }
}

/// A blocked command executor that returns errors for all operations.
/// Used for testing and Wasm sandbox mode.
#[derive(Debug, Default)]
pub struct BlockedCommandExecutor;

impl AwkCommandExecutor for BlockedCommandExecutor {
    fn execute(&mut self, _cmd: &str) -> AwkResult<String> {
        Err(crate::error::AwkError::RuntimeError(
            "system() is not available in the WASM sandbox. Use a WIT plugin for host-provided command execution.".to_string()
        ))
    }
}

/// Trait for resolving `@include` directives in AWK scripts.
///
/// When the preprocessor encounters `@include "path"`, it calls this resolver
/// to load the included file's content. This decouples file loading from the
/// core engine, enabling different strategies for different environments:
/// - Native CLI: read from filesystem
/// - Wasm sandbox: host-provided virtual filesystem
/// - Browser: fetch from URL or bundled scripts
pub trait IncludeResolver {
    /// Resolve an include path and return its content.
    ///
    /// # Arguments
    /// * `path` - The path specified in `@include "path"`
    ///
    /// # Returns
    /// The content of the included file as a string.
    ///
    /// # Errors
    /// Returns an error if the file cannot be found or read.
    fn resolve(&self, path: &str) -> AwkResult<String>;
}

/// A sandbox include resolver that rejects all includes.
/// Used in sandboxed environments where `@include` is not supported.
#[derive(Debug, Default)]
pub struct SandboxIncludeResolver;

impl IncludeResolver for SandboxIncludeResolver {
    fn resolve(&self, path: &str) -> AwkResult<String> {
        Err(crate::error::AwkError::RuntimeError(format!(
            "@include not available in this environment: {}",
            path
        )))
    }
}

/// Base trait for all plugin capabilities.
///
/// Maps to the WIT `wawk:plugins` package. Both `FunctionDispatcher` and
/// `FormatDispatcher` extend this trait, showing they are both ways to
/// extend AWK through the unified WIT plugin system.
pub trait PluginCapability {
    /// The capability identifier, matching `PluginMeta.capabilities` values.
    /// E.g., "function_dispatch", "format_handler".
    fn capability_name(&self) -> &'static str;
}

/// Trait for function dispatch capability.
///
/// When the evaluator encounters a function call that is neither a built-in
/// nor a user-defined function, it checks this handler. This enables
/// Wasm host extensions to add custom AWK functions.
///
/// Implementors override `dispatch` to handle function names.
/// Return `Ok(Some(result))` if handled, `Ok(None)` if the function
/// is unknown (the host will try the next plugin).
///
/// Maps to WIT interface: `wawk:plugins/external-functions`
pub trait FunctionDispatcher: PluginCapability {
    /// Dispatch a function call with string arguments.
    ///
    /// Returns `Ok(Some(result_string))` if the function was handled,
    /// `Ok(None)` if the function is unknown to this handler.
    /// The result is always a string; the evaluator handles numeric conversion.
    fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
        let _ = (name, args);
        Ok(None) // Default: not handled
    }
}


/// Trait for format dispatcher capability.
///
/// Format dispatchers provide format detection, parsing, and serialization.
/// They convert between text format and PropertyTree.
///
/// Convention-based via `__detect__`, `__parse__`, `__serialize__` functions.
pub trait FormatDispatcher: PluginCapability + Send + Sync {
    /// Format name (e.g., "json", "csv")
    fn name(&self) -> &str;
    
    /// Detect if input matches this format
    fn detect(&self, input: &str) -> bool;
    
    /// Parse input into PropertyTree
    fn parse(&self, input: &str) -> crate::error::AwkResult<crate::types::PropertyTree>;
    
    /// Serialize PropertyTree to this format
    fn serialize(&self, tree: &crate::types::PropertyTree) -> Option<String>;
    
    /// Priority (lower = higher priority)
    fn priority(&self) -> u32 { 100 }
}
