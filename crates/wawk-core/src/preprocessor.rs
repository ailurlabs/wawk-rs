//! Preprocessor for AWK scripts.
//!
//! Handles:
//! - `@include "path"` directives (gawk-compatible): expands included files
//! - `@plugin "name"` directives: rewrites function calls to use plugin prefix
//!
//! # @plugin Directive
//!
//! When `@plugin "formula"` is active, unqualified function calls like `Date(...)`
//! are rewritten to `formula_Date(...)`. This enables multi-plugin scripts where
//! different plugins may define same-named functions without conflict.
//!
//! Built-in AWK functions and user-defined functions (declared with `function`
//! keyword) are never rewritten.

use std::collections::HashSet;

use crate::error::{AwkError, AwkResult};
use crate::traits::IncludeResolver;

/// Maximum include nesting depth to prevent infinite recursion.
const MAX_INCLUDE_DEPTH: usize = 16;

/// AWK built-in function names that should never be rewritten by @plugin.
const BUILTIN_FUNCTIONS: &[&str] = &[
    // Arithmetic
    "atan2", "cos", "exp", "int", "log", "rand", "sin", "sqrt", "srand",
    // String
    "gsub", "index", "length", "match", "split", "sprintf", "sub", "substr", "tolower", "toupper",
    // I/O
    "close", "fflush", "getline", "next", "nextfile", "print", "printf", "system",
    // Type/info
    "typeof", "strftime", "mktime", "systime",
    // Array
    "delete", "in", "asorti", "asort",
    // Misc
    "and", "compl", "lshift", "or", "rshift", "xor",
    "bindtextdomain", "dcgettext", "dcngettext",
];

/// Preprocess an AWK script, expanding `@include` and `@plugin` directives.
pub fn preprocess(script: &str, resolver: &dyn IncludeResolver) -> AwkResult<String> {
    let mut visited = HashSet::new();
    visited.insert("<main>".to_string());
    let expanded = expand_includes(script, resolver, &mut visited, 0)?;
    apply_plugin_directives(&expanded)
}

/// Preprocess with a named source.
pub fn preprocess_named(
    script: &str,
    source_name: &str,
    resolver: &dyn IncludeResolver,
) -> AwkResult<String> {
    let mut visited = HashSet::new();
    visited.insert(source_name.to_string());
    let expanded = expand_includes(script, resolver, &mut visited, 0)?;
    apply_plugin_directives(&expanded)
}

fn expand_includes(
    script: &str,
    resolver: &dyn IncludeResolver,
    visited: &mut HashSet<String>,
    depth: usize,
) -> AwkResult<String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(AwkError::RuntimeError(format!(
            "@include nesting too deep (max {} levels)",
            MAX_INCLUDE_DEPTH
        )));
    }

    let mut output = String::with_capacity(script.len());

    for line in script.lines() {
        let trimmed = line.trim();

        // Safe: AWK has no multi-line strings, so @include inside a string literal
        // would appear on its own line starting with @include, which would not be
        // valid AWK string syntax. Line-by-line processing is sufficient.
        if let Some(path) = parse_include_directive(trimmed) {
            if visited.contains(path) {
                output.push_str("# @include \"");
                output.push_str(path);
                output.push_str("\" (already included)\n");
                continue;
            }

            visited.insert(path.to_string());

            let content = resolver.resolve(path)?;
            let expanded = expand_includes(&content, resolver, visited, depth + 1)?;
            output.push_str(&expanded);
            if !expanded.ends_with('\n') {
                output.push('\n');
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    Ok(output)
}

/// Apply @plugin directive rewriting.
///
/// Two-pass approach:
/// 1. Collect user-defined function names (from `function` keyword)
/// 2. Rewrite function calls based on active @plugin binding
fn apply_plugin_directives(script: &str) -> AwkResult<String> {
    // Pass 1: collect user-defined function names
    let user_fns = collect_user_functions(script);

    // Build built-in set
    let builtin_set: HashSet<&str> = BUILTIN_FUNCTIONS.iter().copied().collect();

    // Pass 2: process @plugin directives and rewrite function calls
    let mut output = String::with_capacity(script.len());
    let mut current_plugin: Option<String> = None;

    for line in script.lines() {
        let trimmed = line.trim();

        // Check for @plugin directive
        if let Some(plugin_name) = parse_plugin_directive(trimmed) {
            current_plugin = Some(plugin_name);
            // Emit as comment (preserves line numbering)
            output.push_str("# @plugin set\n");
            continue;
        }

        // If no plugin active, pass through unchanged
        let Some(ref plugin) = current_plugin else {
            output.push_str(line);
            output.push('\n');
            continue;
        };

        // Rewrite function calls in this line
        let rewritten = rewrite_line_with_plugin_prefix(line, plugin, &builtin_set, &user_fns);
        output.push_str(&rewritten);
        output.push('\n');
    }

    Ok(output)
}

/// Collect all user-defined function names from the script.
fn collect_user_functions(script: &str) -> HashSet<String> {
    let mut fns = HashSet::new();
    for line in script.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("function") {
            if let Some(rest) = rest.strip_prefix(|c: char| c.is_ascii_whitespace()) {
                // Extract function name (up to '(')
                let name = rest.trim_start().split('(').next().unwrap_or("").trim();
                if !name.is_empty() && is_valid_identifier(name) {
                    fns.insert(name.to_string());
                }
            }
        }
    }
    fns
}

/// Check if a string is a valid AWK identifier.
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse `@plugin "name"` directive. Returns the plugin name.
fn parse_plugin_directive(line: &str) -> Option<String> {
    let rest = line.strip_prefix("@plugin")?;

    // Must be followed by whitespace
    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }

    let rest = rest.trim();

    // Extract quoted name
    if rest.starts_with('"') && rest.len() >= 2 {
        let inner = &rest[1..];
        if let Some(end) = inner.find('"') {
            let name = &inner[..end];
            if !name.is_empty() {
                // Validate plugin name: only alphanumeric, hyphens, underscores
                if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return None;
                }
                return Some(name.to_string());
            }
        }
    }

    None
}

/// Rewrite function calls in a line to add plugin prefix.
///
/// Only rewrites identifiers that:
/// - Are followed by `(` (function call syntax)
/// - Are not AWK built-in functions
/// - Are not user-defined functions
/// - Are not inside string literals
/// - Don't already have the plugin prefix
fn rewrite_line_with_plugin_prefix(
    line: &str,
    plugin: &str,
    builtins: &HashSet<&str>,
    user_fns: &HashSet<String>,
) -> String {
    let prefix = format!("{}_", plugin);
    let mut result = String::with_capacity(line.len() + 16);
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_string = false;

    while i < len {
        let c = chars[i];

        // Track string literals (don't rewrite inside strings)
        if c == '"' {
            // Count consecutive backslashes before this quote
            let mut backslash_count = 0;
            let mut k = i;
            while k > 0 {
                k -= 1;
                if chars[k] == '\\' {
                    backslash_count += 1;
                } else {
                    break;
                }
            }
            if backslash_count % 2 == 0 {
                // Even backslashes = quote is NOT escaped, toggle string state
                in_string = !in_string;
            }
            result.push(c);
            i += 1;
            continue;
        }

        if in_string {
            result.push(c);
            i += 1;
            continue;
        }

        // Check for identifier followed by '('
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();

            // Skip whitespace after identifier
            let mut j = i;
            while j < len && chars[j].is_ascii_whitespace() {
                j += 1;
            }

            // Check if followed by '('
            if j < len && chars[j] == '(' {
                // It's a function call — check if it should be rewritten
                let is_builtin = builtins.contains(ident.as_str());
                let is_user_fn = user_fns.contains(&ident);
                let already_prefixed = ident.starts_with(&prefix);

                if !is_builtin && !is_user_fn && !already_prefixed {
                    result.push_str(&prefix);
                }
            }

            result.push_str(&ident);
        } else {
            result.push(c);
            i += 1;
        }
    }

    result
}

/// Parse an `@include "path"` directive from a line.
fn parse_include_directive(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("@include")?;

    if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }

    let rest = rest.trim();

    if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        let path = &rest[1..rest.len() - 1];
        if path.is_empty() {
            return None;
        }
        return Some(path);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapResolver {
        files: HashMap<String, String>,
    }

    impl MapResolver {
        fn new() -> Self {
            Self { files: HashMap::new() }
        }

        fn add(&mut self, path: &str, content: &str) -> &mut Self {
            self.files.insert(path.to_string(), content.to_string());
            self
        }
    }

    impl IncludeResolver for MapResolver {
        fn resolve(&self, path: &str) -> AwkResult<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| AwkError::RuntimeError(format!("file not found: {}", path)))
        }
    }

    // ---- @include tests (preserved from original) ----

    #[test]
    fn test_no_includes() {
        let resolver = MapResolver::new();
        let script = "BEGIN { print \"hello\" }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("BEGIN { print \"hello\" }"));
    }

    #[test]
    fn test_simple_include() {
        let mut resolver = MapResolver::new();
        resolver.add("lib.awk", "function double(x) { return x * 2 }");

        let script = "@include \"lib.awk\"\n{ print double($1) }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("function double(x) { return x * 2 }"));
        assert!(result.contains("{ print double($1) }"));
    }

    #[test]
    fn test_nested_include() {
        let mut resolver = MapResolver::new();
        resolver.add("base.awk", "function add(a, b) { return a + b }");
        resolver.add(
            "math.awk",
            "@include \"base.awk\"\nfunction mul(a, b) { return a * b }",
        );

        let script = "@include \"math.awk\"\nBEGIN { print mul(3, add(1, 2)) }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("function add(a, b) { return a + b }"));
        assert!(result.contains("function mul(a, b) { return a * b }"));
    }

    #[test]
    fn test_circular_include_is_idempotent() {
        let mut resolver = MapResolver::new();
        resolver.add("a.awk", "@include \"b.awk\"\nfunction fa() { return 1 }");
        resolver.add("b.awk", "@include \"a.awk\"\nfunction fb() { return 2 }");

        let script = "@include \"a.awk\"\nBEGIN { print fa(), fb() }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("function fa()"));
        assert!(result.contains("function fb()"));
    }

    #[test]
    fn test_max_depth_exceeded() {
        let mut resolver = MapResolver::new();
        for i in 0..20 {
            let content = format!("@include \"{}.awk\"\n", i + 1);
            resolver.add(&format!("{}.awk", i), &content);
        }
        resolver.add("20.awk", "# end");

        let script = "@include \"0.awk\"";
        let result = preprocess(script, &resolver);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nesting too deep"));
    }

    #[test]
    fn test_missing_file_error() {
        let resolver = MapResolver::new();
        let script = "@include \"nonexistent.awk\"";
        let result = preprocess(script, &resolver);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_include_directive() {
        assert_eq!(parse_include_directive("@include \"foo.awk\""), Some("foo.awk"));
        assert_eq!(parse_include_directive("@include"), None);
        assert_eq!(parse_include_directive("@include \"\""), None);
        assert_eq!(parse_include_directive("@includefile \"x\""), None);
    }

    // ---- @plugin directive tests ----

    #[test]
    fn test_parse_plugin_directive() {
        assert_eq!(
            parse_plugin_directive("@plugin \"formula\""),
            Some("formula".to_string())
        );
        assert_eq!(
            parse_plugin_directive("@plugin \"test-cel\""),
            Some("test-cel".to_string())
        );
        assert_eq!(parse_plugin_directive("@plugin \"\""), None);
        assert_eq!(parse_plugin_directive("@plugin"), None);
        assert_eq!(parse_plugin_directive("@pluginfoo \"x\""), None);
    }

    #[test]
    fn test_plugin_rewrites_function_calls() {
        let resolver = MapResolver::new();
        let script = "@plugin \"formula\"\nBEGIN { x = Date(2024, 1, 1) }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("formula_Date(2024, 1, 1)"), "got: {}", result);
    }

    #[test]
    fn test_plugin_does_not_rewrite_builtins() {
        let resolver = MapResolver::new();
        let script = "@plugin \"formula\"\nBEGIN { print length(\"hello\") }";
        let result = preprocess(script, &resolver).unwrap();
        // print and length should NOT be prefixed
        assert!(result.contains("print length("), "got: {}", result);
        assert!(!result.contains("formula_print"), "got: {}", result);
        assert!(!result.contains("formula_length"), "got: {}", result);
    }

    #[test]
    fn test_plugin_does_not_rewrite_user_functions() {
        let resolver = MapResolver::new();
        let script = "function myHelper(x) { return x + 1 }\n@plugin \"formula\"\nBEGIN { print myHelper(5) }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("myHelper(5)"), "got: {}", result);
        assert!(!result.contains("formula_myHelper"), "got: {}", result);
    }

    #[test]
    fn test_plugin_scoping() {
        let resolver = MapResolver::new();
        let script = "@plugin \"formula\"\nBEGIN { x = Date(2024,1,1) }\n@plugin \"cel\"\nBEGIN { y = eval(\"1+1\") }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("formula_Date("), "got: {}", result);
        assert!(result.contains("cel_eval("), "got: {}", result);
        // Ensure cross-contamination doesn't happen
        assert!(!result.contains("cel_Date("), "got: {}", result);
        assert!(!result.contains("formula_eval("), "got: {}", result);
    }

    #[test]
    fn test_no_plugin_passthrough() {
        let resolver = MapResolver::new();
        let script = "BEGIN { x = Date(2024,1,1) }";
        let result = preprocess(script, &resolver).unwrap();
        // Without @plugin, no rewriting
        assert!(result.contains("Date(2024,1,1)"), "got: {}", result);
        assert!(!result.contains("formula_Date"), "got: {}", result);
    }

    #[test]
    fn test_plugin_does_not_rewrite_inside_strings() {
        let resolver = MapResolver::new();
        let script = "@plugin \"formula\"\nBEGIN { print \"Date(2024)\" }";
        let result = preprocess(script, &resolver).unwrap();
        // Date inside a string should NOT be rewritten
        assert!(result.contains("\"Date(2024)\""), "got: {}", result);
    }

    #[test]
    fn test_plugin_already_prefixed_not_doubled() {
        let resolver = MapResolver::new();
        let script = "@plugin \"formula\"\nBEGIN { x = formula_Date(2024,1,1) }";
        let result = preprocess(script, &resolver).unwrap();
        // Should NOT become formula_formula_Date
        assert!(result.contains("formula_Date("), "got: {}", result);
        assert!(!result.contains("formula_formula_"), "got: {}", result);
    }

    #[test]
    fn test_collect_user_functions() {
        let script = "function foo(x) { return x }\nfunction bar(a, b) { return a + b }\nBEGIN { print foo(1) }";
        let fns = collect_user_functions(script);
        assert!(fns.contains("foo"));
        assert!(fns.contains("bar"));
        assert!(!fns.contains("print"));
    }

    // ---- Security-focused tests ----

    #[test]
    fn test_escaped_quote_handling() {
        let builtins: HashSet<&str> = HashSet::new();
        let user_fns: HashSet<String> = HashSet::new();
        // \\" means escaped backslash followed by real quote
        let line = r#"x = "test\\"; Date(2024)"#;
        let result = rewrite_line_with_plugin_prefix(line, "formula", &builtins, &user_fns);
        // Date after the string should be rewritten
        assert!(result.contains("formula_Date"), "got: {}", result);
    }

    #[test]
    fn test_plugin_name_validation() {
        // Valid names
        assert!(parse_plugin_directive("@plugin \"formula\"").is_some());
        assert!(parse_plugin_directive("@plugin \"test-cel\"").is_some());
        assert!(parse_plugin_directive("@plugin \"my_plugin\"").is_some());

        // Invalid names
        assert!(parse_plugin_directive("@plugin \"foo bar\"").is_none());
        assert!(parse_plugin_directive("@plugin \"foo;bar\"").is_none());
        assert!(parse_plugin_directive("@plugin \"foo\\\"bar\"").is_none());
    }

    #[test]
    fn test_double_backslash_string_boundary() {
        let builtins: HashSet<&str> = HashSet::new();
        let user_fns: HashSet<String> = HashSet::new();
        // String with escaped backslash at end: "test\\"
        // The quote after \ is a REAL quote (not escaped)
        let line = r#"print "test\\"; Foo(1)"#;
        let result = rewrite_line_with_plugin_prefix(line, "p", &builtins, &user_fns);
        // Foo is outside string, should be rewritten
        assert!(result.contains("p_Foo"), "got: {}", result);
    }

    #[test]
    fn test_plugin_directive_rejects_special_chars() {
        assert!(parse_plugin_directive("@plugin \"foo.bar\"").is_none());
        assert!(parse_plugin_directive("@plugin \"foo bar\"").is_none());
        assert!(parse_plugin_directive("@plugin \"foo/bar\"").is_none());
        assert!(parse_plugin_directive("@plugin \"\"").is_none());
    }
}
