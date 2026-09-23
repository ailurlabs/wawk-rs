//! wawk-wasi — WASM component CLI for wawk-core.
//!
//! A WASM component composable with WIT plugins via `wac plug`.
//! Runs under wasmtime with full WASI support.
//!
//! # Usage
//! ```bash
//! # Bare mode
//! wasmtime run wawk_wasi.wasm -- -e 'BEGIN { print "hello" }'
//!
//! # With plugins
//! wac plug --plug wawk-hello.wasm wawk_wasi.wasm -o composed.wasm
//! wasmtime run composed.wasm -- -e 'BEGIN { print greet("world") }'
//! ```

use std::io::{self, BufRead, Read, Write};

use wawk_core::error::AwkResult;
use wawk_core::eval::Evaluator;
use wawk_core::parser;
use wawk_core::preprocessor;
use wawk_core::traits::{
    AwkCommandExecutor, AwkEnvironment, AwkReader, AwkWriter, IncludeResolver,
};

wit_bindgen::generate!({
    world: "cli-runner",
    path: "wit",
    generate_all,
});

/// Maximum script size: 1 MB.
const MAX_SCRIPT_SIZE: usize = 1_048_576;

// ============================================================================
// WIT Plugin Dispatcher
// ============================================================================


// ============================================================================
// Buffered stdout Writer
// ============================================================================

struct StreamWriter {
    out: io::BufWriter<io::Stdout>,
}

impl StreamWriter {
    fn new() -> Self {
        Self {
            out: io::BufWriter::with_capacity(64 * 1024, io::stdout()),
        }
    }
}

impl AwkWriter for StreamWriter {
    fn write_line(&mut self, output: &str) -> AwkResult<()> {
        self.out
            .write_all(output.as_bytes())
            .map_err(|e| wawk_core::error::AwkError::RuntimeError(e.to_string()))?;
        self.out
            .write_all(b"\n")
            .map_err(|e| wawk_core::error::AwkError::RuntimeError(e.to_string()))?;
        Ok(())
    }

    fn write_str(&mut self, output: &str) -> AwkResult<()> {
        self.out
            .write_all(output.as_bytes())
            .map_err(|e| wawk_core::error::AwkError::RuntimeError(e.to_string()))?;
        Ok(())
    }

    fn flush(&mut self) -> AwkResult<()> {
        self.out
            .flush()
            .map_err(|e| wawk_core::error::AwkError::RuntimeError(e.to_string()))?;
        Ok(())
    }
}

// ============================================================================
// Sandboxed Environment
// ============================================================================

struct SandboxedEnvironment;

impl AwkEnvironment for SandboxedEnvironment {
    fn get_env(&self, _name: &str) -> Option<String> {
        None
    }

    fn systime(&self) -> i64 {
        0
    }
}

// ============================================================================
// Blocked Command Executor
// ============================================================================

struct BlockedCommandExecutor;

impl AwkCommandExecutor for BlockedCommandExecutor {
    fn execute(&mut self, _cmd: &str) -> AwkResult<String> {
        Err(wawk_core::error::AwkError::RuntimeError(
            "system() is not available in the WASM sandbox. Use a WIT plugin for host-provided command execution.".to_string()
        ))
    }

    fn read_pipe_line(&mut self, _cmd: &str) -> AwkResult<Option<String>> {
        Err(wawk_core::error::AwkError::RuntimeError(
            "command pipes are not available in the WASM sandbox".to_string(),
        ))
    }

    fn write_pipe(&mut self, _cmd: &str, _output: &str) -> AwkResult<()> {
        Err(wawk_core::error::AwkError::RuntimeError(
            "command pipes are not available in the WASM sandbox".to_string(),
        ))
    }
}

// ============================================================================
// Filesystem Include Resolver
// ============================================================================

/// Resolves @include paths from the WASI filesystem.
struct FsIncludeResolver;

impl IncludeResolver for FsIncludeResolver {
    fn resolve(&self, path: &str) -> AwkResult<String> {
        // Security: reject path traversal attempts
        if path.contains("..") || path.starts_with('/') || path.starts_with('\\') {
            return Err(wawk_core::error::AwkError::RuntimeError(format!(
                "@include path rejected (traversal attempt): {}",
                path
            )));
        }
        std::fs::read_to_string(path).map_err(|e| {
            wawk_core::error::AwkError::RuntimeError(format!(
                "@include failed for '{}': {}",
                path, e
            ))
        })
    }
}

// ============================================================================
// Helper: configure evaluator with optional plugin dispatcher
// ============================================================================

fn configure_eval(_eval: &mut Evaluator<'_>) {
}

// ============================================================================
// Help text
// ============================================================================

fn print_help() {
    eprintln!("wawk - WASM-portable AWK implementation");
    eprintln!();
    eprintln!("Usage: wawk [options] 'program' [file...]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -F fs         set field separator");
    eprintln!("  -v var=val    assign variable before execution");
    eprintln!("  -f progfile   read program from file");
    eprintln!("  -e program    specify program as argument");
    eprintln!("  -h, --help    show this help message");
    eprintln!();
}

// ============================================================================
// CLI argument parsing (extracted for testability)
// ============================================================================

#[derive(Debug)]
struct CliArgs {
    script_files: Vec<String>,
    script_text: Option<String>,
    vars: Vec<(String, String)>,
    input_files: Vec<String>,
    field_separator: Option<String>,
    show_help: bool,
}

/// Parse CLI arguments from a slice of strings (args[0] is program name).
fn parse_args(args: &[String]) -> CliArgs {
    let mut script_files: Vec<String> = Vec::new();
    let mut script_text: Option<String> = None;
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut input_files: Vec<String> = Vec::new();
    let mut field_separator: Option<String> = None;
    let mut show_help = false;
    let mut i = 1; // skip program name

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                show_help = true;
                break;
            }
            "-F" => {
                i += 1;
                if i < args.len() {
                    field_separator = Some(args[i].clone());
                } else {
                    eprintln!("Error: -F requires an argument");
                    std::process::exit(1);
                }
            }
            s if s.starts_with("-F") && s.len() > 2 => {
                field_separator = Some(s[2..].to_string());
            }
            "-f" => {
                i += 1;
                if i < args.len() {
                    script_files.push(args[i].clone());
                } else {
                    eprintln!("Error: -f requires a filename argument");
                    std::process::exit(1);
                }
            }
            "-e" => {
                i += 1;
                if i < args.len() {
                    script_text = Some(args[i].clone());
                } else {
                    eprintln!("Error: -e requires a program argument");
                    std::process::exit(1);
                }
            }
            "-v" => {
                i += 1;
                if i < args.len() {
                    if let Some(eq) = args[i].find('=') {
                        vars.push((args[i][..eq].to_string(), args[i][eq + 1..].to_string()));
                    }
                }
            }
            s if s.starts_with("-v") && s.len() > 2 => {
                let v = &s[2..];
                if let Some(eq) = v.find('=') {
                    vars.push((v[..eq].to_string(), v[eq + 1..].to_string()));
                }
            }
            s if s == "---wawk-multi---" => {
                // Legacy multi-script protocol marker — store as script_text,
                // main() will detect and handle it.
                script_text = Some(s.to_string());
            }
            s if script_text.is_none() && script_files.is_empty() => {
                // First positional arg = script text
                script_text = Some(s.to_string());
            }
            s => {
                // Remaining positional args = input files
                input_files.push(s.to_string());
            }
        }
        i += 1;
    }

    CliArgs {
        script_files,
        script_text,
        vars,
        input_files,
        field_separator,
        show_help,
    }
}

// ============================================================================
// Main
// ============================================================================

// ============================================================================
// WASM Component Export
// ============================================================================

struct WawkCli;

impl exports::wasi::cli::run::Guest for WawkCli {
    fn run() -> Result<(), ()> {
        main_inner();
        Ok(())
    }
}

export!(WawkCli);

// ============================================================================
// CLI Entry Point
// ============================================================================

fn main_inner() {
    let args: Vec<String> = std::env::args().collect();
    let cli = parse_args(&args);

    if cli.show_help {
        print_help();
        return;
    }

    // Handle legacy multi-script protocol
    if let Some(ref s) = cli.script_text {
        if s == "---wawk-multi---" {
            let buf_reader = io::BufReader::with_capacity(64 * 1024, io::stdin());
            let mut rest = String::new();
            let mut limited = buf_reader.take(64 * 1024 * 1024);
            limited.read_to_string(&mut rest).unwrap_or_else(|e| {
                eprintln!("Error reading stdin: {}", e);
                std::process::exit(1);
            });
            let mut all_input = s.clone();
            all_input.push('\n');
            all_input.push_str(&rest);
            run_multi(&all_input);
            return;
        }
    }

    let script_files = cli.script_files;
    let script_text = cli.script_text;
    let vars = cli.vars;
    let input_files = cli.input_files;
    let field_separator = cli.field_separator;

    // Resolve script
    let program_str = if !script_files.is_empty() {
        let mut combined = String::new();
        for f in &script_files {
            match std::fs::read_to_string(f) {
                Ok(content) => {
                    if !combined.is_empty() {
                        combined.push('\n');
                    }
                    combined.push_str(&content);
                }
                Err(_e) => {
                    eprintln!("Error reading script file");
                    std::process::exit(1);
                }
            }
        }
        combined
    } else if let Some(text) = &script_text {
        text.clone()
    } else {
        // Read script from stdin (first line)
        let mut buf_reader = io::BufReader::with_capacity(64 * 1024, io::stdin());
        let mut first_line = String::new();
        match buf_reader.read_line(&mut first_line) {
            Ok(0) => {
                eprintln!("Error: No AWK program provided.");
                std::process::exit(1);
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading stdin: {}", e);
                std::process::exit(1);
            }
        }
        if first_line.ends_with('\n') {
            first_line.pop();
            if first_line.ends_with('\r') {
                first_line.pop();
            }
        }
        if first_line.len() > MAX_SCRIPT_SIZE {
            eprintln!(
                "Error: script exceeds maximum size of {} bytes",
                MAX_SCRIPT_SIZE
            );
            std::process::exit(1);
        }
        // If no input files, stream stdin
        if input_files.is_empty() {
            run_streaming(&first_line, buf_reader);
            return;
        }
        first_line
    };

    if program_str.is_empty() {
        eprintln!("Error: empty AWK program");
        std::process::exit(1);
    }

    // If we have input files, use multi-file mode
    if !input_files.is_empty() {
        run_with_files(&program_str, &vars, &input_files, &field_separator);
    } else {
        run_single(&program_str, &vars, &field_separator);
    }
}

/// Run with a script and stdin (no input files).
fn run_single(program_str: &str, vars: &[(String, String)], field_separator: &Option<String>) {
    let resolver = FsIncludeResolver;
    let expanded = match preprocessor::preprocess(program_str, &resolver) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Include error: {}", e);
            std::process::exit(1);
        }
    };
    let program = match parser::parse(&expanded) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Read all stdin into memory for processing
    let mut stdin_content = String::new();
    io::stdin()
        .read_to_string(&mut stdin_content)
        .unwrap_or_else(|e| {
            eprintln!("wawk: error reading stdin: {}", e);
            std::process::exit(1);
        });

    let mut reader = wawk_core::traits::SliceReader::new(stdin_content);
    let mut writer = StreamWriter::new();
    let env = SandboxedEnvironment;
    let mut cmd = BlockedCommandExecutor;
    let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);

    configure_eval(&mut eval);

    for (k, v) in vars {
        eval.set_variable(k.clone(), v.clone());
    }
    if let Some(ref fs) = field_separator {
        eval.set_variable("FS".to_string(), fs.clone());
    }

    if let Err(e) = eval.execute(&program) {
        eprintln!("Runtime error: {}", e);
        std::process::exit(1);
    }
    io::stdout().flush().ok();
}

/// Run with input files from WASI filesystem.
fn run_with_files(
    program_str: &str,
    vars: &[(String, String)],
    input_files: &[String],
    field_separator: &Option<String>,
) {
    let resolver = FsIncludeResolver;
    let expanded = match preprocessor::preprocess(program_str, &resolver) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Include error: {}", e);
            std::process::exit(1);
        }
    };
    let program = match parser::parse(&expanded) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Read all input files into memory
    let mut files = std::collections::HashMap::new();
    let mut file_order = Vec::new();
    for fname in input_files {
        match std::fs::read_to_string(fname) {
            Ok(content) => {
                if content.len() > 256 * 1024 * 1024 {
                    // 256 MB max input file
                    eprintln!(
                        "wawk: input file '{}' too large ({} bytes, max 256 MB)",
                        fname,
                        content.len()
                    );
                    continue;
                }
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                files.insert(fname.clone(), lines);
                file_order.push(fname.clone());
            }
            Err(e) => {
                eprintln!("wawk: can't open file '{}': {}", fname, e);
                continue;
            }
        }
    }

    let mut reader = WasiFileReader::new(files, &file_order);
    let mut writer = StreamWriter::new();
    let env = SandboxedEnvironment;
    let mut cmd = BlockedCommandExecutor;
    let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);

    configure_eval(&mut eval);

    // Set up ARGV: ARGV[0] = "wawk", ARGV[1..] = input_files
    let mut argv = vec!["wawk".to_string()];
    argv.extend(file_order.iter().cloned());
    eval.set_argv(argv);

    // Apply -v vars
    for (k, v) in vars {
        eval.set_variable(k.clone(), v.clone());
    }
    if let Some(ref fs) = field_separator {
        eval.set_variable("FS".to_string(), fs.clone());
    }

    if let Err(e) = eval.execute(&program) {
        eprintln!("Runtime error: {}", e);
        std::process::exit(1);
    }
    io::stdout().flush().ok();
}

/// Run in streaming mode: script is known, data streams from stdin.
fn run_streaming(program_str: &str, buf_reader: io::BufReader<io::Stdin>) {
    // Expand @include directives
    let resolver = FsIncludeResolver;
    let expanded = match preprocessor::preprocess(program_str, &resolver) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Include error: {}", e);
            std::process::exit(1);
        }
    };

    let program = match parser::parse(&expanded) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Wrap the BufReader (which already consumed the first line) for streaming.
    let mut reader = StreamingReader::new(buf_reader);
    let mut writer = StreamWriter::new();
    let env = SandboxedEnvironment;
    let mut cmd = BlockedCommandExecutor;

    let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);

    configure_eval(&mut eval);

    if let Err(e) = eval.execute(&program) {
        eprintln!("Runtime error: {}", e);
        std::process::exit(1);
    }

    io::stdout().flush().ok();
}

/// Run in multi-script mode: all input is buffered.
fn run_multi(all_input: &str) {
    let (program_str, input_data) = parse_multi_script(all_input, MAX_SCRIPT_SIZE);

    // Expand @include directives
    let resolver = FsIncludeResolver;
    let expanded = match preprocessor::preprocess(&program_str, &resolver) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Include error: {}", e);
            std::process::exit(1);
        }
    };

    let program = match parser::parse(&expanded) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            std::process::exit(1);
        }
    };

    let mut reader = BufferedMemReader::new(&input_data);
    let mut writer = StreamWriter::new();
    let env = SandboxedEnvironment;
    let mut cmd = BlockedCommandExecutor;

    let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);

    configure_eval(&mut eval);

    if let Err(e) = eval.execute(&program) {
        eprintln!("Runtime error: {}", e);
        std::process::exit(1);
    }

    io::stdout().flush().ok();
}

// ============================================================================
// Streaming Reader (wraps BufReader<Stdin>)
// ============================================================================

struct StreamingReader {
    buf_reader: io::BufReader<io::Stdin>,
    line_buf: String,
    done: bool,
}

impl StreamingReader {
    fn new(buf_reader: io::BufReader<io::Stdin>) -> Self {
        Self {
            buf_reader,
            line_buf: String::new(),
            done: false,
        }
    }
}

impl AwkReader for StreamingReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        if self.done {
            return Ok(None);
        }
        self.line_buf.clear();
        match self.buf_reader.read_line(&mut self.line_buf) {
            Ok(0) => {
                self.done = true;
                Ok(None)
            }
            Ok(_) => {
                if self.line_buf.ends_with('\n') {
                    self.line_buf.pop();
                    if self.line_buf.ends_with('\r') {
                        self.line_buf.pop();
                    }
                }
                Ok(Some(self.line_buf.clone()))
            }
            Err(e) => Err(wawk_core::error::AwkError::RuntimeError(e.to_string())),
        }
    }

    fn read_line_into(&mut self, buf: &mut String) -> AwkResult<bool> {
        if self.done {
            return Ok(false);
        }
        buf.clear();
        // Fast line reader: memchr-based newline scan over fill_buf chunks.
        // SAFETY: bytes are validated as UTF-8 over the completed line before
        // we expose the String (same semantics as BufRead::read_line).
        let v = unsafe { buf.as_mut_vec() };
        loop {
            let (consumed, found_nl) = {
                let fill = self
                    .buf_reader
                    .fill_buf()
                    .map_err(|e| wawk_core::error::AwkError::RuntimeError(e.to_string()))?;
                if fill.is_empty() {
                    (0usize, false)
                } else if let Some(i) = memchr::memchr(b'\n', fill) {
                    v.extend_from_slice(&fill[..i]);
                    (i + 1, true)
                } else {
                    v.extend_from_slice(fill);
                    (fill.len(), false)
                }
            };
            if found_nl {
                self.buf_reader.consume(consumed);
                if v.last() == Some(&b'\r') {
                    v.pop();
                }
                if std::str::from_utf8(v).is_err() {
                    return Err(wawk_core::error::AwkError::RuntimeError(
                        "invalid UTF-8 in input record".to_string(),
                    ));
                }
                return Ok(true);
            }
            if consumed == 0 {
                self.done = true;
                if v.is_empty() {
                    return Ok(false);
                }
                if std::str::from_utf8(v).is_err() {
                    return Err(wawk_core::error::AwkError::RuntimeError(
                        "invalid UTF-8 in input record".to_string(),
                    ));
                }
                return Ok(true);
            }
            self.buf_reader.consume(consumed);
        }
    }

    fn current_filename(&self) -> String {
        "<stdin>".to_string()
    }

    fn filename_if_changed(&mut self) -> Option<String> {
        None
    }
}

// ============================================================================
// BufferedMemReader (for multi-script mode)
// ============================================================================

struct BufferedMemReader {
    input: String,
    line_starts: Vec<usize>,
    pos: usize,
    filename_reported: bool,
}

impl BufferedMemReader {
    fn new(input: &str) -> Self {
        let mut line_starts = vec![0usize];
        for (i, b) in input.bytes().enumerate() {
            if b == b'\n' && i + 1 < input.len() {
                line_starts.push(i + 1);
            }
        }
        Self {
            input: input.to_string(),
            line_starts,
            pos: 0,
            filename_reported: false,
        }
    }

    fn current_line(&self) -> Option<&str> {
        if self.pos >= self.line_starts.len() {
            return None;
        }
        let start = self.line_starts[self.pos];
        let end = if self.pos + 1 < self.line_starts.len() {
            let next_start = self.line_starts[self.pos + 1];
            if next_start > start && self.input.as_bytes()[next_start - 1] == b'\n' {
                next_start - 1
            } else {
                next_start
            }
        } else {
            let bytes = self.input.as_bytes();
            if bytes.last() == Some(&b'\n') {
                bytes.len() - 1
            } else {
                bytes.len()
            }
        };
        if start <= end && end <= self.input.len() {
            Some(&self.input[start..end])
        } else {
            Some("")
        }
    }
}

impl AwkReader for BufferedMemReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        Ok(self.current_line().map(|s| s.to_string())).map(|opt| {
            if opt.is_some() {
                self.pos += 1;
            }
            opt
        })
    }

    fn read_line_into(&mut self, buf: &mut String) -> AwkResult<bool> {
        buf.clear();
        if let Some(line) = self.current_line() {
            buf.push_str(line);
            self.pos += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn current_filename(&self) -> String {
        "<stdin>".to_string()
    }

    fn filename_if_changed(&mut self) -> Option<String> {
        if !self.filename_reported {
            self.filename_reported = true;
            Some("<stdin>".to_string())
        } else {
            None
        }
    }
}

// ============================================================================
// Multi-File Reader (WASI filesystem)
// ============================================================================

struct WasiFileReader {
    /// Named file contents (filename -> lines)
    files: std::collections::HashMap<String, Vec<String>>,
    /// ARGV file names in order
    file_order: Vec<String>,
    /// Current file index in file_order
    current_file_idx: usize,
    /// Current line index within current file
    current_line_idx: usize,
    /// Current filename (for FILENAME tracking)
    current_name: String,
    /// Whether filename change has been reported
    filename_dirty: bool,
    /// Separate file cursors for getline < "file"
    getline_cursors: std::collections::HashMap<String, usize>,
}

impl WasiFileReader {
    fn new(files: std::collections::HashMap<String, Vec<String>>, file_order: &[String]) -> Self {
        let initial_idx = file_order.len(); // Start past the end — ARGV loop will open files
        Self {
            files,
            file_order: file_order.to_vec(),
            current_file_idx: initial_idx,
            current_line_idx: 0,
            current_name: String::new(),
            filename_dirty: true,
            getline_cursors: std::collections::HashMap::new(),
        }
    }

    fn open_file_by_name(&mut self, name: &str) -> AwkResult<()> {
        if !self.files.contains_key(name) {
            return Err(wawk_core::error::AwkError::RuntimeError(format!(
                "file not found: {}",
                name
            )));
        }
        self.current_name = name.to_string();
        self.current_line_idx = 0;
        // Find the index in file_order
        if let Some(idx) = self.file_order.iter().position(|f| f == name) {
            self.current_file_idx = idx;
        }
        self.filename_dirty = true;
        Ok(())
    }

    fn current_line(&self) -> Option<&str> {
        let fname = self.file_order.get(self.current_file_idx)?;
        let lines = self.files.get(fname)?;
        if self.current_line_idx < lines.len() {
            Some(&lines[self.current_line_idx])
        } else {
            None
        }
    }
}

impl AwkReader for WasiFileReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        let fname = match self.file_order.get(self.current_file_idx) {
            Some(f) => f,
            None => return Ok(None),
        };
        let lines = match self.files.get(fname) {
            Some(l) => l,
            None => return Ok(None),
        };
        if self.current_line_idx < lines.len() {
            let line = lines[self.current_line_idx].clone();
            self.current_line_idx += 1;
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }

    fn read_line_into(&mut self, buf: &mut String) -> AwkResult<bool> {
        buf.clear();
        if let Some(line) = self.current_line() {
            buf.push_str(line);
            self.current_line_idx += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn open_file(&mut self, filename: &str) -> AwkResult<()> {
        self.open_file_by_name(filename)
    }

    fn read_file_line(&mut self, filename: &str) -> AwkResult<Option<String>> {
        let cursor = self
            .getline_cursors
            .entry(filename.to_string())
            .or_insert(0);
        if let Some(lines) = self.files.get(filename) {
            if *cursor < lines.len() {
                let line = lines[*cursor].clone();
                *cursor += 1;
                return Ok(Some(line));
            }
        }
        Ok(None)
    }

    fn close_file(&mut self, filename: &str) -> AwkResult<()> {
        self.getline_cursors.remove(filename);
        Ok(())
    }

    fn skip_to_next_file(&mut self) {
        if self.current_file_idx + 1 < self.file_order.len() {
            self.current_file_idx += 1;
            self.current_name = self.file_order[self.current_file_idx].clone();
            self.current_line_idx = 0;
            self.filename_dirty = true;
        }
    }

    fn current_filename(&self) -> String {
        self.current_name.clone()
    }

    fn filename_if_changed(&mut self) -> Option<String> {
        if self.filename_dirty {
            self.filename_dirty = false;
            Some(self.current_name.clone())
        } else {
            None
        }
    }
}

// ============================================================================
// Protocol parsers
// ============================================================================

fn parse_multi_script(all_input: &str, max_size: usize) -> (String, String) {
    let mut scripts: Vec<String> = Vec::new();
    let mut current_script = String::new();
    let mut input_data = String::new();
    let mut in_input = false;
    let mut in_script = false;

    for line in all_input.lines().skip(1) {
        if line == "---INPUT---" {
            if in_script && !current_script.is_empty() {
                scripts.push(current_script.clone());
                current_script.clear();
            }
            in_input = true;
            in_script = false;
            continue;
        }
        if line == "---SCRIPT---" {
            if in_script && !current_script.is_empty() {
                scripts.push(current_script.clone());
                current_script.clear();
            }
            in_script = true;
            continue;
        }

        if in_input {
            if !input_data.is_empty() {
                input_data.push('\n');
            }
            input_data.push_str(line);
        } else if in_script {
            if !current_script.is_empty() {
                current_script.push('\n');
            }
            current_script.push_str(line);
        }
    }

    if in_script && !current_script.is_empty() {
        scripts.push(current_script);
    }

    if scripts.is_empty() {
        eprintln!("Error: No scripts found in multi-script protocol.");
        std::process::exit(1);
    }

    let combined = scripts.join("\n");
    if combined.len() > max_size {
        eprintln!(
            "Error: combined scripts exceed maximum size of {} bytes",
            max_size
        );
        std::process::exit(1);
    }

    (combined, input_data)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Helper: build args slice from string literals
    fn make_args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // ----------------------------------------------------------------
    // CLI argument parsing tests
    // ----------------------------------------------------------------

    #[test]
    fn test_parse_args_help_long() {
        let args = make_args(&["wawk", "--help"]);
        let cli = parse_args(&args);
        assert!(cli.show_help);
    }

    #[test]
    fn test_parse_args_help_short() {
        let args = make_args(&["wawk", "-h"]);
        let cli = parse_args(&args);
        assert!(cli.show_help);
    }

    #[test]
    fn test_parse_args_script_text() {
        let args = make_args(&["wawk", "{ print $1 }"]);
        let cli = parse_args(&args);
        assert!(!cli.show_help);
        assert_eq!(cli.script_text, Some("{ print $1 }".to_string()));
        assert!(cli.input_files.is_empty());
    }

    #[test]
    fn test_parse_args_script_and_files() {
        let args = make_args(&["wawk", "{ print }", "a.txt", "b.txt"]);
        let cli = parse_args(&args);
        assert_eq!(cli.script_text, Some("{ print }".to_string()));
        assert_eq!(cli.input_files, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn test_parse_args_f_flag() {
        let args = make_args(&["wawk", "-f", "prog.awk", "data.txt"]);
        let cli = parse_args(&args);
        assert_eq!(cli.script_files, vec!["prog.awk"]);
        assert_eq!(cli.input_files, vec!["data.txt"]);
        assert!(cli.script_text.is_none());
    }

    #[test]
    fn test_parse_args_e_flag() {
        let args = make_args(&["wawk", "-e", "BEGIN { print 1 }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.script_text, Some("BEGIN { print 1 }".to_string()));
    }

    #[test]
    fn test_parse_args_v_flag_separate() {
        let args = make_args(&["wawk", "-v", "x=10", "{ print x }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.vars, vec![("x".to_string(), "10".to_string())]);
        assert_eq!(cli.script_text, Some("{ print x }".to_string()));
    }

    #[test]
    fn test_parse_args_v_flag_attached() {
        let args = make_args(&["wawk", "-vx=42", "{ print x }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.vars, vec![("x".to_string(), "42".to_string())]);
    }

    #[test]
    fn test_parse_args_multiple_v() {
        let args = make_args(&["wawk", "-v", "a=1", "-vb=2", "{ print }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.vars.len(), 2);
        assert_eq!(cli.vars[0], ("a".to_string(), "1".to_string()));
        assert_eq!(cli.vars[1], ("b".to_string(), "2".to_string()));
    }

    #[test]
    fn test_parse_args_field_separator_separate() {
        let args = make_args(&["wawk", "-F", ":", "{ print $1 }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.field_separator, Some(":".to_string()));
    }

    #[test]
    fn test_parse_args_field_separator_attached() {
        let args = make_args(&["wawk", "-F,", "{ print $1 }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.field_separator, Some(",".to_string()));
    }

    #[test]
    fn test_parse_args_combined() {
        let args = make_args(&["wawk", "-F", "\t", "-v", "n=5", "-f", "prog.awk", "in.txt"]);
        let cli = parse_args(&args);
        assert_eq!(cli.field_separator, Some("\t".to_string()));
        assert_eq!(cli.vars, vec![("n".to_string(), "5".to_string())]);
        assert_eq!(cli.script_files, vec!["prog.awk"]);
        assert_eq!(cli.input_files, vec!["in.txt"]);
    }

    #[test]
    fn test_parse_args_no_args() {
        let args = make_args(&["wawk"]);
        let cli = parse_args(&args);
        assert!(!cli.show_help);
        assert!(cli.script_text.is_none());
        assert!(cli.script_files.is_empty());
        assert!(cli.input_files.is_empty());
        assert!(cli.vars.is_empty());
        assert!(cli.field_separator.is_none());
    }

    // ----------------------------------------------------------------
    // WasiFileReader tests
    // ----------------------------------------------------------------

    fn make_reader(files: Vec<(&str, &str)>) -> WasiFileReader {
        let mut map = HashMap::new();
        let mut order = Vec::new();
        for (name, content) in files {
            // Split content into lines like run_with_files does
            let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            map.insert(name.to_string(), lines);
            order.push(name.to_string());
        }
        let mut reader = WasiFileReader::new(map, &order);
        // Open the first file
        if !reader.file_order.is_empty() {
            let first = reader.file_order[0].clone();
            reader.open_file_by_name(&first).unwrap();
        }
        reader
    }

    #[test]
    fn test_reader_single_file() {
        let mut reader = make_reader(vec![("test.txt", "hello\nworld\n")]);
        assert_eq!(reader.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("world".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_empty_file() {
        let mut reader = make_reader(vec![("empty.txt", "")]);
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_no_trailing_newline() {
        let mut reader = make_reader(vec![("test.txt", "line1\nline2")]);
        assert_eq!(reader.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_crlf_handling() {
        let mut reader = make_reader(vec![("test.txt", "hello\r\nworld\r\n")]);
        assert_eq!(reader.read_line().unwrap(), Some("hello".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("world".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_multi_file() {
        let mut reader = make_reader(vec![("a.txt", "a1\na2\n"), ("b.txt", "b1\n")]);
        // Read from first file
        assert_eq!(reader.read_line().unwrap(), Some("a1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("a2".to_string()));
        assert_eq!(reader.read_line().unwrap(), None); // end of a.txt

        // Skip to next file
        reader.skip_to_next_file();
        assert_eq!(reader.read_line().unwrap(), Some("b1".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_read_line_into() {
        let mut reader = make_reader(vec![("test.txt", "alpha\nbeta\n")]);
        let mut buf = String::new();
        assert!(reader.read_line_into(&mut buf).unwrap());
        assert_eq!(buf, "alpha");
        assert!(reader.read_line_into(&mut buf).unwrap());
        assert_eq!(buf, "beta");
        assert!(!reader.read_line_into(&mut buf).unwrap());
    }

    #[test]
    fn test_reader_open_file_by_name() {
        let mut reader = make_reader(vec![("first.txt", "f1\n"), ("second.txt", "s1\ns2\n")]);
        // Open second file directly
        reader.open_file_by_name("second.txt").unwrap();
        assert_eq!(reader.read_line().unwrap(), Some("s1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("s2".to_string()));
    }

    #[test]
    fn test_reader_missing_file_error() {
        let mut reader = make_reader(vec![("exists.txt", "data\n")]);
        let result = reader.open_file_by_name("nonexistent.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_reader_filename_tracking() {
        let mut reader = make_reader(vec![("myfile.txt", "data\n")]);
        reader.open_file_by_name("myfile.txt").unwrap();
        // filename_if_changed should report on first call after open
        assert_eq!(reader.filename_if_changed(), Some("myfile.txt".to_string()));
        // Second call returns None
        assert_eq!(reader.filename_if_changed(), None);
    }

    #[test]
    fn test_reader_read_file_line() {
        let mut reader = make_reader(vec![("a.txt", "a1\na2\n"), ("b.txt", "b1\n")]);
        // Read from file "b.txt" via read_file_line (separate cursor)
        assert_eq!(
            reader.read_file_line("b.txt").unwrap(),
            Some("b1".to_string())
        );
        assert_eq!(reader.read_file_line("b.txt").unwrap(), None);
        // "a.txt" should still be readable independently
        assert_eq!(
            reader.read_file_line("a.txt").unwrap(),
            Some("a1".to_string())
        );
    }

    #[test]
    fn test_reader_close_file() {
        let mut reader = make_reader(vec![("test.txt", "line1\nline2\n")]);
        // Read one line via read_file_line
        assert_eq!(
            reader.read_file_line("test.txt").unwrap(),
            Some("line1".to_string())
        );
        // Close resets cursor
        reader.close_file("test.txt").unwrap();
        assert_eq!(
            reader.read_file_line("test.txt").unwrap(),
            Some("line1".to_string())
        );
    }

    // ----------------------------------------------------------------
    // BufferedMemReader tests (multi-script mode)
    // ----------------------------------------------------------------

    #[test]
    fn test_mem_reader_basic() {
        let mut reader = BufferedMemReader::new("line1\nline2\nline3");
        assert_eq!(reader.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line3".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_mem_reader_empty() {
        let mut reader = BufferedMemReader::new("");
        // Empty string: one empty line
        let line = reader.read_line().unwrap();
        // Either Some("") or None is acceptable for empty input
        if let Some(s) = line {
            assert_eq!(s, "");
        }
    }

    #[test]
    fn test_mem_reader_read_line_into() {
        let mut reader = BufferedMemReader::new("abc\ndef");
        let mut buf = String::new();
        assert!(reader.read_line_into(&mut buf).unwrap());
        assert_eq!(buf, "abc");
        assert!(reader.read_line_into(&mut buf).unwrap());
        assert_eq!(buf, "def");
        assert!(!reader.read_line_into(&mut buf).unwrap());
    }

    // ----------------------------------------------------------------
    // parse_multi_script tests
    // ----------------------------------------------------------------

    #[test]
    fn test_parse_multi_script_basic() {
        let input = "---wawk-multi---\n---SCRIPT---\n{ print }\n---INPUT---\nhello\nworld\n";
        let (program, data) = parse_multi_script(input, MAX_SCRIPT_SIZE);
        assert_eq!(program, "{ print }");
        assert_eq!(data, "hello\nworld");
    }

    #[test]
    fn test_parse_multi_script_multiple_scripts() {
        let input = "---wawk-multi---\n---SCRIPT---\nBEGIN { x=1 }\n---SCRIPT---\n{ print x }\n---INPUT---\ndata\n";
        let (program, data) = parse_multi_script(input, MAX_SCRIPT_SIZE);
        assert!(program.contains("BEGIN { x=1 }"));
        assert!(program.contains("{ print x }"));
        assert_eq!(data, "data");
    }

    #[test]
    fn test_parse_multi_script_no_input() {
        let input = "---wawk-multi---\n---SCRIPT---\nBEGIN { print 42 }\n";
        let (program, data) = parse_multi_script(input, MAX_SCRIPT_SIZE);
        assert_eq!(program, "BEGIN { print 42 }");
        assert_eq!(data, "");
    }

    // ----------------------------------------------------------------
    // Edge case tests
    // ----------------------------------------------------------------

    #[test]
    fn test_single_char_field_separator() {
        let args = make_args(&["wawk", "-F,", "{ print $1 }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.field_separator, Some(",".to_string()));
    }

    #[test]
    fn test_tab_field_separator() {
        let args = make_args(&["wawk", "-F\t", "{ print }"]);
        let cli = parse_args(&args);
        assert_eq!(cli.field_separator, Some("\t".to_string()));
    }

    #[test]
    fn test_reader_crlf_single_line() {
        let mut reader = make_reader(vec![("test.txt", "only\r\n")]);
        assert_eq!(reader.read_line().unwrap(), Some("only".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_empty_lines() {
        let mut reader = make_reader(vec![("test.txt", "\n\n\n")]);
        assert_eq!(reader.read_line().unwrap(), Some("".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_reader_single_field_line() {
        let mut reader = make_reader(vec![("test.txt", "singlefield\n")]);
        assert_eq!(reader.read_line().unwrap(), Some("singlefield".to_string()));
    }

    #[test]
    fn test_v_flag_with_equals_in_value() {
        let args = make_args(&["wawk", "-v", "x=a=b", "{ print }"]);
        let cli = parse_args(&args);
        // Should split on first '=' only
        assert_eq!(cli.vars, vec![("x".to_string(), "a=b".to_string())]);
    }

    #[test]
    fn test_multiple_script_files() {
        let args = make_args(&["wawk", "-f", "a.awk", "-f", "b.awk"]);
        let cli = parse_args(&args);
        assert_eq!(cli.script_files, vec!["a.awk", "b.awk"]);
    }
}
