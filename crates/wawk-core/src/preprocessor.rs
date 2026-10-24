//! Preprocessor for AWK scripts.
//!
//! Handles:
//! - `@include "path"` directives (gawk-compatible): expands included files
//! - `@extension "name"` directives: preserved as inert comments and not semantically processed
//!

use crate::error::{AwkError, AwkResult};
use crate::traits::IncludeResolver;

/// Maximum include nesting depth to prevent infinite recursion.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Result of preprocessing: expanded script.
#[derive(Debug, Clone)]
pub struct PreprocessResult {
    pub script: String,
}

/// Preprocess an AWK script, expanding `@include` directives.
pub fn preprocess(script: &str, resolver: &dyn IncludeResolver) -> AwkResult<String> {
    let mut chain = vec!["<main>".to_string()];
    let expanded = expand_includes(script, resolver, &mut chain, 0)?;
    apply_extension_directives(&expanded)
}

/// Preprocess with a named source.
pub fn preprocess_named(
    script: &str,
    source_name: &str,
    resolver: &dyn IncludeResolver,
) -> AwkResult<String> {
    let mut chain = vec![source_name.to_string()];
    let expanded = expand_includes(script, resolver, &mut chain, 0)?;
    apply_extension_directives(&expanded)
}

/// Preprocess an AWK script, expanding `@include` directives.
/// Returns the expanded script wrapped in a PreprocessResult.
pub fn preprocess_with_meta(
    script: &str,
    resolver: &dyn IncludeResolver,
) -> AwkResult<PreprocessResult> {
    let mut chain = vec!["<main>".to_string()];
    let expanded = expand_includes(script, resolver, &mut chain, 0)?;
    apply_extension_directives_with_meta(&expanded)
}

/// Preprocess with a named source. Returns expanded script.
pub fn preprocess_named_with_meta(
    script: &str,
    source_name: &str,
    resolver: &dyn IncludeResolver,
) -> AwkResult<PreprocessResult> {
    let mut chain = vec![source_name.to_string()];
    let expanded = expand_includes(script, resolver, &mut chain, 0)?;
    apply_extension_directives_with_meta(&expanded)
}

/// Convert @extension directives to inert comments.
///
/// All other lines pass through unchanged. Directives are emitted as comments
/// so the parser never sees them and line numbers are preserved.
fn apply_extension_directives_with_meta(script: &str) -> AwkResult<PreprocessResult> {
    let mut output = String::with_capacity(script.len());

    for line in script.lines() {
        let trimmed = line.trim();

        // @extension directive: convert to inert comment
        if trimmed.starts_with("@extension") {
            output.push_str(&format!("# {}\n", trimmed));
            continue;
        }

        output.push_str(line);
        output.push('\n');
    }

    Ok(PreprocessResult {
        script: output,
    })
}

fn expand_includes(
    script: &str,
    resolver: &dyn IncludeResolver,
    chain: &mut Vec<String>,
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
            // E1: Cycle detection — check if path is already in the current include chain.
            // This detects cycles at any depth and reports the full cycle path.
            if let Some(cycle_start) = chain.iter().position(|p| p == path) {
                let cycle_path: Vec<&str> = chain[cycle_start..].iter().map(|s| s.as_str()).collect();
                let mut cycle_desc = cycle_path.join(" -> ");
                cycle_desc.push_str(" -> ");
                cycle_desc.push_str(path);
                return Err(AwkError::RuntimeError(format!(
                    "@include cycle detected: {}",
                    cycle_desc
                )));
            }

            // Push onto chain (backtracking: removed after processing)
            chain.push(path.to_string());

            let content = resolver.resolve(path)?;
            let expanded = expand_includes(&content, resolver, chain, depth + 1)?;
            output.push_str(&expanded);
            if !expanded.ends_with('\n') {
                output.push('\n');
            }

            // Backtrack: remove from chain so diamond patterns work
            // (A→B→D and A→C→D is OK — D is processed twice)
            chain.pop();
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    Ok(output)
}

/// Apply @extension directive handling (no rewriting, backward-compatible API).
fn apply_extension_directives(script: &str) -> AwkResult<String> {
    apply_extension_directives_with_meta(script).map(|result| result.script)
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
            Self {
                files: HashMap::new(),
            }
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

    // ---- @include tests ----

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
    fn test_direct_cycle_detected() {
        // E1-T1: Direct cycle: A includes A -> error
        let mut resolver = MapResolver::new();
        resolver.add("a.awk", "@include \"a.awk\"\nfunction fa() { return 1 }");

        let script = "@include \"a.awk\"";
        let result = preprocess(script, &resolver);
        assert!(result.is_err(), "direct cycle should be detected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cycle detected"), "error should mention cycle: {}", err);
        assert!(err.contains("a.awk"), "error should include file name: {}", err);
    }

    #[test]
    fn test_indirect_cycle_detected() {
        // E1-T2: Indirect cycle: A->B->C->A -> error with full path
        let mut resolver = MapResolver::new();
        resolver.add("a.awk", "@include \"b.awk\"\nfunction fa() { return 1 }");
        resolver.add("b.awk", "@include \"c.awk\"\nfunction fb() { return 2 }");
        resolver.add("c.awk", "@include \"a.awk\"\nfunction fc() { return 3 }");

        let script = "@include \"a.awk\"";
        let result = preprocess(script, &resolver);
        assert!(result.is_err(), "indirect cycle should be detected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cycle detected"), "error should mention cycle: {}", err);
        assert!(err.contains("a.awk -> b.awk -> c.awk -> a.awk"),
                "error should include full cycle path: {}", err);
    }

    #[test]
    fn test_diamond_pattern_ok() {
        // E1-T3: Diamond (non-cycle): A->B, A->C, B->D, C->D -> OK (D processed twice)
        let mut resolver = MapResolver::new();
        resolver.add("d.awk", "function fd() { return 4 }");
        resolver.add("b.awk", "@include \"d.awk\"\nfunction fb() { return 2 }");
        resolver.add("c.awk", "@include \"d.awk\"\nfunction fc() { return 3 }");
        resolver.add("a.awk", "@include \"b.awk\"\n@include \"c.awk\"\nfunction fa() { return 1 }");

        let script = "@include \"a.awk\"\nBEGIN { print fa() }";
        let result = preprocess(script, &resolver);
        assert!(result.is_ok(), "diamond pattern should not be treated as cycle: {:?}", result.err());
        let expanded = result.unwrap();
        // D should appear twice (once via B, once via C)
        assert_eq!(expanded.matches("function fd()").count(), 2,
                   "D should be processed twice in diamond pattern");
        assert!(expanded.contains("function fb()"));
        assert!(expanded.contains("function fc()"));
    }

    #[test]
    fn test_deep_nesting_no_cycle() {
        // E1-T4: Deep nesting: A->B->C->D->E (no cycle) -> OK
        let mut resolver = MapResolver::new();
        resolver.add("e.awk", "function fe() { return 5 }");
        resolver.add("d.awk", "@include \"e.awk\"\nfunction fd() { return 4 }");
        resolver.add("c.awk", "@include \"d.awk\"\nfunction fc() { return 3 }");
        resolver.add("b.awk", "@include \"c.awk\"\nfunction fb() { return 2 }");
        resolver.add("a.awk", "@include \"b.awk\"\nfunction fa() { return 1 }");

        let script = "@include \"a.awk\"";
        let result = preprocess(script, &resolver);
        assert!(result.is_ok(), "deep nesting without cycle should succeed: {:?}", result.err());
        let expanded = result.unwrap();
        assert!(expanded.contains("function fa()"));
        assert!(expanded.contains("function fb()"));
        assert!(expanded.contains("function fc()"));
        assert!(expanded.contains("function fd()"));
        assert!(expanded.contains("function fe()"));
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
        assert_eq!(
            parse_include_directive("@include \"foo.awk\""),
            Some("foo.awk")
        );
        assert_eq!(parse_include_directive("@include"), None);
        assert_eq!(parse_include_directive("@include \"\""), None);
        assert_eq!(parse_include_directive("@includefile \"x\""), None);
    }

    // ---- @extension directive tests ----

    #[test]
    fn test_extension_directive_preserved_as_comment() {
        let resolver = MapResolver::new();
        let script = "@extension \"foo\"\nBEGIN { x = 1 }";
        let result = preprocess(script, &resolver).unwrap();
        assert!(result.contains("# @extension \"foo\""), "got: {}", result);
    }
}
