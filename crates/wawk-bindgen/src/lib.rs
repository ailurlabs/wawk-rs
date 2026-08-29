//! wawk-bindgen: Browser-compatible AWK engine via wasm-bindgen.
//!
//! This crate provides a JS-friendly API for running AWK scripts in the browser
//! or Node.js. It uses `wawk-core` with in-memory trait implementations — no OS
//! dependencies.
//!

use wasm_bindgen::prelude::*;

use wawk_core::error::AwkResult;
use wawk_core::eval::Evaluator;
use wawk_core::traits::SandboxIncludeResolver;
use wawk_core::traits::{
    AwkCommandExecutor, AwkEnvironment, AwkReader, AwkWriter,
};
use wawk_core::{parser, preprocessor};

/// Maximum script size (1MB) to prevent DoS
const MAX_SCRIPT_SIZE: usize = 1_048_576;
/// Maximum input size (10MB) to prevent DoS
const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;


// ============================================================================
// In-memory Reader
// ============================================================================

struct WebReader {
    lines: Vec<String>,
    pos: usize,
}

impl WebReader {
    fn new(input: &str) -> Self {
        Self {
            lines: input.lines().map(String::from).collect(),
            pos: 0,
        }
    }
}

impl AwkReader for WebReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        if self.pos < self.lines.len() {
            let line = self.lines[self.pos].clone();
            self.pos += 1;
            Ok(Some(line))
        } else {
            Ok(None)
        }
    }

    fn current_filename(&self) -> String {
        "<input>".to_string()
    }
}

// ============================================================================
// In-memory Writer
// ============================================================================

struct WebWriter {
    output: String,
}

impl WebWriter {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }
}

impl AwkWriter for WebWriter {
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

// ============================================================================
// Sandboxed Environment (no access to OS env vars)
// ============================================================================

struct WebEnvironment;

impl AwkEnvironment for WebEnvironment {
    fn get_env(&self, _name: &str) -> Option<String> {
        None // Sandboxed — no env vars in browser
    }

    fn systime(&self) -> i64 {
        #[cfg(target_arch = "wasm32")]
        {
            (js_sys::Date::now() / 1000.0) as i64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            0
        }
    }
}

// ============================================================================
// Blocked Command Executor (no system() in browser)
// ============================================================================

struct WebCommandExecutor;

impl AwkCommandExecutor for WebCommandExecutor {
    fn execute(&mut self, _cmd: &str) -> AwkResult<String> {
        Err(wawk_core::error::AwkError::RuntimeError(
            "system() is not available in the WASM sandbox. Use a WIT plugin for host-provided command execution.".to_string()
        ))
    }
}

// ============================================================================
// Evaluator factory — shared setup with plugin bridge
// ============================================================================

/// Create a fully-wired Evaluator with the JS plugin bridge attached.
fn create_evaluator<'a>(
    reader: &'a mut WebReader,
    writer: &'a mut WebWriter,
    env: &'a WebEnvironment,
    cmd: &'a mut WebCommandExecutor,
) -> wawk_core::eval::Evaluator<'a> {
    wawk_core::eval::Evaluator::new(reader, writer, env, cmd)
}

// ============================================================================

// ============================================================================
// Public API
// ============================================================================

/// Execute an AWK script with the given input data and return the output.
///
/// Plugin functions (e.g. `greet()`) are available if WIT plugins
/// are loaded by the JS host (auto-discovered from `plugins/` directory).
///
/// # Arguments
/// * `script` - The AWK program to execute
/// * `input` - The input data (newline-separated records)
///
/// # Returns
/// The output of the AWK script, or an error message prefixed with `"Error: "`.
#[wasm_bindgen]
pub fn exec_awk(script: &str, input: &str) -> String {
    if script.len() > MAX_SCRIPT_SIZE {
        return format!(
            "Error: script exceeds maximum size of {} bytes",
            MAX_SCRIPT_SIZE
        );
    }
    if input.len() > MAX_INPUT_SIZE {
        return format!(
            "Error: input exceeds maximum size of {} bytes",
            MAX_INPUT_SIZE
        );
    }
    match exec_awk_inner(script, input) {
        Ok(output) => output,
        Err(e) => format!("Error: {}", e),
    }
}

fn exec_awk_inner(script: &str, input: &str) -> Result<String, String> {
    // Preprocess to handle @plugin and @include directives
    let expanded = wawk_core::preprocessor::preprocess(script, &wawk_core::traits::SandboxIncludeResolver)
        .map_err(|e| e.to_string())?;
    let program = wawk_core::parser::parse(&expanded).map_err(|e| e.to_string())?;

    let mut reader = WebReader::new(input);
    let mut writer = WebWriter::new();
    let env = WebEnvironment;
    let mut cmd = WebCommandExecutor;

    let mut eval = create_evaluator(&mut reader, &mut writer, &env, &mut cmd);

    eval.execute(&program).map_err(|e| e.to_string())?;

    Ok(writer.output)
}

/// Execute an AWK script with a custom field separator.
///
/// # Arguments
/// * `script` - The AWK program to execute
/// * `input` - The input data
/// * `fs` - The field separator
#[wasm_bindgen]
pub fn exec_awk_with_fs(script: &str, input: &str, fs: &str) -> String {
    if script.len() > MAX_SCRIPT_SIZE {
        return format!(
            "Error: script exceeds maximum size of {} bytes",
            MAX_SCRIPT_SIZE
        );
    }
    if input.len() > MAX_INPUT_SIZE {
        return format!(
            "Error: input exceeds maximum size of {} bytes",
            MAX_INPUT_SIZE
        );
    }
    match exec_awk_with_fs_inner(script, input, fs) {
        Ok(output) => output,
        Err(e) => format!("Error: {}", e),
    }
}

fn exec_awk_with_fs_inner(script: &str, input: &str, fs: &str) -> Result<String, String> {
    let expanded = wawk_core::preprocessor::preprocess(script, &wawk_core::traits::SandboxIncludeResolver)
        .map_err(|e| e.to_string())?;
    let program = wawk_core::parser::parse(&expanded).map_err(|e| e.to_string())?;

    let mut reader = WebReader::new(input);
    let mut writer = WebWriter::new();
    let env = WebEnvironment;
    let mut cmd = WebCommandExecutor;

    let mut eval = create_evaluator(&mut reader, &mut writer, &env, &mut cmd);

    eval.set_fs(fs.to_string());
    eval.execute(&program).map_err(|e| e.to_string())?;

    Ok(writer.output)
}

/// Execute multiple AWK scripts concatenated together (POSIX `-f` semantics).
///
/// # Arguments
/// * `scripts` - Array of AWK script strings to concatenate and execute
/// * `input` - The input data (newline-separated records)
#[wasm_bindgen]
pub fn exec_awk_multi(scripts: Vec<String>, input: &str) -> String {
    let total_script_size: usize = scripts.iter().map(|s| s.len()).sum();
    if total_script_size > MAX_SCRIPT_SIZE {
        return format!(
            "Error: combined scripts exceed maximum size of {} bytes",
            MAX_SCRIPT_SIZE
        );
    }
    if input.len() > MAX_INPUT_SIZE {
        return format!(
            "Error: input exceeds maximum size of {} bytes",
            MAX_INPUT_SIZE
        );
    }
    match exec_awk_multi_inner(&scripts, input) {
        Ok(output) => output,
        Err(e) => format!("Error: {}", e),
    }
}

fn exec_awk_multi_inner(scripts: &[String], input: &str) -> Result<String, String> {
    let combined: String = scripts
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    let expanded = wawk_core::preprocessor::preprocess(&combined, &wawk_core::traits::SandboxIncludeResolver)
        .map_err(|e| e.to_string())?;
    let program = wawk_core::parser::parse(&expanded).map_err(|e| e.to_string())?;

    let mut reader = WebReader::new(input);
    let mut writer = WebWriter::new();
    let env = WebEnvironment;
    let mut cmd = WebCommandExecutor;

    let mut eval = create_evaluator(&mut reader, &mut writer, &env, &mut cmd);

    eval.execute(&program).map_err(|e| e.to_string())?;

    Ok(writer.output)
}

// ============================================================================
// Host-provided file reader (for multi-input from JS/browser)
// ============================================================================

use std::collections::HashMap;

struct HostReader {
    files: HashMap<String, Vec<String>>,
    file_order: Vec<String>,
    current_file_idx: usize,
    current_line_idx: usize,
    current_name: String,
    filename_dirty: bool,
    getline_cursors: HashMap<String, usize>,
}

impl HostReader {
    fn new(files_json: &str) -> Self {
        let files = parse_files_json(files_json);
        let file_order: Vec<String> = files.keys().cloned().collect();
        let first_name = file_order.first().cloned().unwrap_or_default();
        let filename_dirty = !file_order.is_empty();
        Self {
            files,
            file_order,
            current_file_idx: 0,
            current_line_idx: 0,
            current_name: first_name,
            filename_dirty,
            getline_cursors: HashMap::new(),
        }
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

impl AwkReader for HostReader {
    fn read_line(&mut self) -> AwkResult<Option<String>> {
        let fname = match self.file_order.get(self.current_file_idx) {
            Some(f) => f.clone(),
            None => return Ok(None),
        };
        let lines = match self.files.get(&fname) {
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
        if !self.files.contains_key(filename) {
            return Err(wawk_core::error::AwkError::RuntimeError(format!(
                "file not found: {}",
                filename
            )));
        }
        self.current_name = filename.to_string();
        self.current_line_idx = 0;
        if let Some(idx) = self.file_order.iter().position(|f| f == filename) {
            self.current_file_idx = idx;
        }
        self.filename_dirty = true;
        Ok(())
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

/// Simple JSON parser for {"filename": "content\n..."} format.
/// Handles escaped characters including \\, \", \n, \t, \r within string values.
fn parse_files_json(json: &str) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return result;
    }
    // Inner content between outermost { and }
    let inner = match find_matching_brace(trimmed) {
        Some(s) => s,
        None => return result,
    };
    let mut chars = inner.chars().peekable();
    loop {
        // Skip whitespace and commas
        while chars.peek().is_some_and(|c| " \t\n\r,".contains(*c)) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        // Parse key
        let key = match parse_json_string(&mut chars) {
            Some(k) => k,
            None => break,
        };
        // Skip colon
        while chars.peek().is_some_and(|c| " \t\n\r:".contains(*c)) {
            chars.next();
        }
        // Parse value
        let value = match parse_json_string(&mut chars) {
            Some(v) => v,
            None => break,
        };
        let lines: Vec<String> = value.lines().map(|s| s.to_string()).collect();
        result.insert(key, lines);
    }
    result
}

/// Find the content between the outermost matching braces.
/// Returns the inner slice (excluding the outer { and }).
fn find_matching_brace(s: &str) -> Option<&str> {
    let start = s.find('{')? + 1;
    let bytes = s.as_bytes();
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escape = false;
    for i in start..bytes.len() {
        if escape {
            escape = false;
            continue;
        }
        match bytes[i] {
            b'\\' if in_string => escape = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => depth += 1,
            b'}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_json_string(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<String> {
    // Skip to opening quote
    while chars.peek().is_some_and(|c| c.is_whitespace()) {
        chars.next();
    }
    if chars.next()? != '"' {
        return None;
    }
    let mut result = String::new();
    loop {
        match chars.next()? {
            '"' => return Some(result),
            '\\' => match chars.next()? {
                'n' => result.push('\n'),
                't' => result.push('\t'),
                'r' => result.push('\r'),
                '\\' => result.push('\\'),
                '"' => result.push('"'),
                c => {
                    result.push('\\');
                    result.push(c);
                }
            },
            c => result.push(c),
        }
    }
}

/// Execute AWK with multiple input files (WASM-native embedder API).
///
/// # Arguments
/// * `script` - The AWK program text
/// * `input` - Single stdin-like input (used if files_json is empty)
/// * `argv_json` - JSON array of ARGV[1..] entries: `["file1.csv", "x=5", "file2.txt"]`
/// * `files_json` - JSON object mapping filenames to content: `{"file1.csv": "a,b\n1,2\n"}`
#[wasm_bindgen]
pub fn exec_awk_with_files(
    script: &str,
    _input: &str,
    argv_json: &str,
    files_json: &str,
) -> String {
    if script.len() > MAX_SCRIPT_SIZE {
        return format!(
            "Error: script exceeds maximum size of {} bytes",
            MAX_SCRIPT_SIZE
        );
    }
    let expanded = match preprocessor::preprocess(script, &SandboxIncludeResolver) {
        Ok(s) => s,
        Err(e) => return format!("Include error: {}\n", e),
    };
    let program = match parser::parse(&expanded) {
        Ok(p) => p,
        Err(e) => return format!("Parse error: {}\n", e),
    };

    let mut reader = HostReader::new(files_json);
    let mut writer = WebWriter::new();
    let env = WebEnvironment;
    let mut cmd = WebCommandExecutor;
    let mut eval = Evaluator::new(&mut reader, &mut writer, &env, &mut cmd);

    // Set up ARGV
    let mut argv = vec!["wawk".to_string()];
    let argv_entries = parse_argv_json(argv_json);
    argv.extend(argv_entries);
    eval.set_argv(argv);

    match eval.execute(&program) {
        Ok(()) => writer.output,
        Err(e) => format!("Runtime error: {}\n", e),
    }
}

fn parse_argv_json(json: &str) -> Vec<String> {
    let trimmed = json.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Vec::new();
    }
    let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
    let mut result = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| " \t\n\r,".contains(*c)) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        match parse_json_string(&mut chars) {
            Some(s) => result.push(s),
            None => break,
        }
    }
    result
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // exec_awk: basic AWK execution
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_hello_world() {
        let result = exec_awk("BEGIN { print \"hello world\" }", "");
        assert_eq!(result, "hello world\n");
    }

    #[test]
    fn test_exec_awk_field_access() {
        let result = exec_awk("{ print $1, $3 }", "alice 25 engineer\nbob 30 designer");
        assert_eq!(result, "alice engineer\nbob designer\n");
    }

    #[test]
    fn test_exec_awk_arithmetic() {
        let result = exec_awk("{ print $1 + $2 }", "10 20\n3 7");
        assert_eq!(result, "30\n10\n");
    }

    #[test]
    fn test_exec_awk_begin_end_blocks() {
        let result = exec_awk(
            "BEGIN { print \"start\" } { print $0 } END { print \"end\" }",
            "line1\nline2",
        );
        assert_eq!(result, "start\nline1\nline2\nend\n");
    }

    #[test]
    fn test_exec_awk_pattern_matching() {
        let result = exec_awk(
            "/error/ { print NR, $0 }",
            "info\nerror: disk full\nwarn\nerror: timeout",
        );
        assert_eq!(result, "2 error: disk full\n4 error: timeout\n");
    }

    #[test]
    fn test_exec_awk_empty_input() {
        let result = exec_awk("{ print $0 }", "");
        assert_eq!(result, "");
    }

    #[test]
    fn test_exec_awk_empty_input_with_begin() {
        let result = exec_awk("BEGIN { print \"ok\" }", "");
        assert_eq!(result, "ok\n");
    }

    #[test]
    fn test_exec_awk_nr_variable() {
        let result = exec_awk("{ print NR, $0 }", "a\nb\nc");
        assert_eq!(result, "1 a\n2 b\n3 c\n");
    }

    #[test]
    fn test_exec_awk_nf_variable() {
        let result = exec_awk("{ print NF }", "a b c\nx y");
        assert_eq!(result, "3\n2\n");
    }

    // ------------------------------------------------------------------------
    // exec_awk_with_fs: custom field separator
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_with_fs_comma() {
        let result = exec_awk_with_fs("{ print $2 }", "alice,25,engineer\nbob,30,designer", ",");
        assert_eq!(result, "25\n30\n");
    }

    #[test]
    fn test_exec_awk_with_fs_tab() {
        let result = exec_awk_with_fs("{ print $1 \"-\" $2 }", "a\tb\nc\td", "\t");
        assert_eq!(result, "a-b\nc-d\n");
    }

    #[test]
    fn test_exec_awk_with_fs_colon() {
        let result = exec_awk_with_fs("{ print $NF }", "root:x:0:0:root:/root:/bin/bash", ":");
        assert_eq!(result, "/bin/bash\n");
    }

    // ------------------------------------------------------------------------
    // exec_awk_multi: multiple script concatenation
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_multi_basic() {
        let scripts = vec![
            "BEGIN { x = 0 }".to_string(),
            "{ x += $1 }".to_string(),
            "END { print x }".to_string(),
        ];
        let result = exec_awk_multi(scripts, "10\n20\n30");
        assert_eq!(result, "60\n");
    }

    #[test]
    fn test_exec_awk_multi_single_script() {
        let scripts = vec!["{ print $1 * 2 }".to_string()];
        let result = exec_awk_multi(scripts, "5\n10");
        assert_eq!(result, "10\n20\n");
    }

    #[test]
    fn test_exec_awk_multi_empty_scripts() {
        let scripts: Vec<String> = vec![];
        let result = exec_awk_multi(scripts, "hello");
        assert!(result.starts_with("Error:") || result.is_empty());
    }

    // ------------------------------------------------------------------------
    // Error handling
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_invalid_script() {
        let result = exec_awk("BEGIN { print \"unterminated }", "hello");
        assert!(result.starts_with("Error:"), "Expected error, got: {}", result);
    }

    #[test]
    fn test_exec_awk_syntax_error() {
        let result = exec_awk("{ if (} }", "");
        assert!(result.starts_with("Error:"), "Expected error, got: {}", result);
    }

    #[test]
    fn test_exec_awk_system_blocked() {
        let result = exec_awk("BEGIN { system(\"echo hi\") }", "");
        assert!(
            result.contains("not available") || result.contains("Error"),
            "Expected sandbox error, got: {}",
            result,
        );
    }

    // ------------------------------------------------------------------------
    // Size limits
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_oversized_script() {
        let big_script = "BEGIN { print \"x\" }".to_string() + &" ".repeat(MAX_SCRIPT_SIZE);
        let result = exec_awk(&big_script, "");
        assert!(
            result.contains("script exceeds maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    #[test]
    fn test_exec_awk_oversized_input() {
        let big_input = "x".repeat(MAX_INPUT_SIZE + 1);
        let result = exec_awk("{ print $0 }", &big_input);
        assert!(
            result.contains("input exceeds maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    #[test]
    fn test_exec_awk_with_fs_oversized_script() {
        let big_script = " ".repeat(MAX_SCRIPT_SIZE + 1);
        let result = exec_awk_with_fs(&big_script, "data", ",");
        assert!(
            result.contains("script exceeds maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    #[test]
    fn test_exec_awk_multi_oversized_scripts() {
        let scripts = vec![" ".repeat(MAX_SCRIPT_SIZE / 2 + 1); 3];
        let result = exec_awk_multi(scripts, "data");
        assert!(
            result.contains("combined scripts exceed maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    #[test]
    fn test_exec_awk_oversized_input_with_fs() {
        let big_input = "y".repeat(MAX_INPUT_SIZE + 1);
        let result = exec_awk_with_fs("{ print $0 }", &big_input, ",");
        assert!(
            result.contains("input exceeds maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    #[test]
    fn test_exec_awk_oversized_input_multi() {
        let big_input = "z".repeat(MAX_INPUT_SIZE + 1);
        let scripts = vec!["{ print $0 }".to_string()];
        let result = exec_awk_multi(scripts, &big_input);
        assert!(
            result.contains("input exceeds maximum size"),
            "Expected size error, got: {}",
            result,
        );
    }

    // ------------------------------------------------------------------------
    // WebReader unit tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_web_reader_reads_lines() {
        let mut reader = WebReader::new("line1\nline2\nline3");
        assert_eq!(reader.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line3".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_web_reader_empty_input() {
        let mut reader = WebReader::new("");
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_web_reader_single_line() {
        let mut reader = WebReader::new("only");
        assert_eq!(reader.read_line().unwrap(), Some("only".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_web_reader_current_filename() {
        let reader = WebReader::new("data");
        assert_eq!(reader.current_filename(), "<input>");
    }

    // ------------------------------------------------------------------------
    // WebWriter unit tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_web_writer_collects_output() {
        let mut writer = WebWriter::new();
        writer.write_line("hello").unwrap();
        writer.write_line("world").unwrap();
        assert_eq!(writer.output, "hello\nworld\n");
    }

    #[test]
    fn test_web_writer_write_str() {
        let mut writer = WebWriter::new();
        writer.write_str("no").unwrap();
        writer.write_str("newline").unwrap();
        assert_eq!(writer.output, "nonewline");
    }

    #[test]
    fn test_web_writer_empty() {
        let writer = WebWriter::new();
        assert_eq!(writer.output, "");
    }

    #[test]
    fn test_web_writer_mixed() {
        let mut writer = WebWriter::new();
        writer.write_line("line").unwrap();
        writer.write_str("partial").unwrap();
        assert_eq!(writer.output, "line\npartial");
    }

    // ------------------------------------------------------------------------
    // JSON parsing: parse_argv_json
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_argv_json_empty_array() {
        let result = parse_argv_json("[]");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_argv_json_empty_string() {
        let result = parse_argv_json("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_argv_json_entries() {
        let result = parse_argv_json("[\"file1.csv\", \"x=5\"]");
        assert_eq!(result, vec!["file1.csv", "x=5"]);
    }

    #[test]
    fn test_parse_argv_json_single_entry() {
        let result = parse_argv_json("[\"only\"]");
        assert_eq!(result, vec!["only"]);
    }

    // ------------------------------------------------------------------------
    // HostReader tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_host_reader_empty_files() {
        let mut reader = HostReader::new("{}");
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_host_reader_single_file() {
        let mut reader = HostReader::new("{\"test.txt\": \"line1\\nline2\"}");
        assert_eq!(reader.read_line().unwrap(), Some("line1".to_string()));
        assert_eq!(reader.read_line().unwrap(), Some("line2".to_string()));
        assert_eq!(reader.read_line().unwrap(), None);
    }

    #[test]
    fn test_host_reader_filename() {
        let reader = HostReader::new("{\"data.csv\": \"a,b\"}");
        let fname = reader.current_filename();
        assert!(!fname.is_empty());
    }

    // ------------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_exec_awk_string_concatenation() {
        let result = exec_awk("{ print $1 \" \" $2 }", "hello world");
        assert_eq!(result, "hello world\n");
    }

    #[test]
    fn test_exec_awk_if_else() {
        let result = exec_awk(
            "{ if ($1 > 5) print \"big\"; else print \"small\" }",
            "10\n3",
        );
        assert_eq!(result, "big\nsmall\n");
    }

    #[test]
    fn test_exec_awk_for_loop() {
        let result = exec_awk("BEGIN { for (i = 0; i < 3; i++) print i }", "");
        assert_eq!(result, "0\n1\n2\n");
    }

    #[test]
    fn test_exec_awk_while_loop() {
        let result = exec_awk("BEGIN { x = 10; while (x > 0) { x -= 3 }; print x }", "");
        assert_eq!(result, "-2\n");
    }

    #[test]
    fn test_exec_awk_array_usage() {
        let result = exec_awk(
            "BEGIN { a[1]=\"x\"; a[2]=\"y\"; print a[1], a[2] }",
            "",
        );
        assert_eq!(result, "x y\n");
    }

    #[test]
    fn test_exec_awk_length_function() {
        let result = exec_awk("{ print length($0) }", "hello\nhi");
        assert_eq!(result, "5\n2\n");
    }

    #[test]
    fn test_exec_awk_sub_function() {
        let result = exec_awk("{ sub(/o/, \"0\"); print }", "foo\nbar");
        assert_eq!(result, "f0o\nbar\n");
    }

    #[test]
    fn test_exec_awk_with_files_basic() {
        let result = exec_awk_with_files(
            "{ print $0 }",
            "",
            "[]",
            "{\"input.txt\": \"hello\\nworld\"}",
        );
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }
}
