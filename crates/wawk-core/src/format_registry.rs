//! Format Registry — manages format handlers for multi-format I/O.
//!
//! The `FormatRegistry` holds a collection of `FormatDispatcher` implementations
//! and provides format detection and serialization capabilities. Format
//! handlers route through the host-supplied dispatcher.

use crate::error::AwkResult;
use crate::traits::FormatDispatcher;
use crate::types::PropertyTree;

/// Registry that manages format handlers for multi-format input/output.
///
/// Handlers are sorted by priority (lower number = higher priority).
/// Detection iterates handlers in priority order and returns the first match.
pub struct FormatRegistry {
    extensions: Vec<Box<dyn FormatDispatcher>>,
}

impl FormatRegistry {
    /// Create an empty format registry.
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    /// Register a format extension. Extensions are re-sorted by priority after insertion.
    pub fn register(&mut self, extension: Box<dyn FormatDispatcher>) {
        self.extensions.push(extension);
        self.extensions.sort_by_key(|p| p.priority());
    }

    /// Detect the format of `input` and parse it if a extension matches.
    ///
    /// Returns `Some(Ok((tree, format_name)))` if a extension detected and parsed successfully.
    /// Returns `Some(Err(...))` if a extension detected but parsing failed.
    /// Returns `None` if no extension matched.
    pub fn detect_and_parse(&self, input: &str) -> Option<AwkResult<(PropertyTree, String)>> {
        for extension in &self.extensions {
            if extension.detect(input) {
                return Some(
                    extension
                        .parse(input)
                        .map(|pt| (pt, extension.name().to_string())),
                );
            }
        }
        None
    }

    /// Serialize a `PropertyTree` to a specific format (or the first available).
    ///
    /// If `format` is `Some(name)`, only the extension with that name is used.
    /// If `format` is `None`, extensions are tried in priority order.
    pub fn serialize(&self, tree: &PropertyTree, format: Option<&str>) -> Option<String> {
        if let Some(name) = format {
            for extension in &self.extensions {
                if extension.name() == name {
                    return extension.serialize(tree);
                }
            }
        }
        // Fallback: try all extensions in priority order
        for extension in &self.extensions {
            if let Some(output) = extension.serialize(tree) {
                return Some(output);
            }
        }
        None
    }

    /// Look up a format handler by namespace.
    pub fn get_by_namespace(&self, namespace: &str) -> Option<&dyn FormatDispatcher> {
        self.extensions.iter().find(|p| p.namespace() == namespace).map(|p| p.as_ref())
    }

    /// Returns a slice of all registered extensions.
    pub fn extensions(&self) -> &[Box<dyn FormatDispatcher>] {
        &self.extensions
    }

    /// Returns the number of registered extensions.
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    /// Returns true if no extensions are registered.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }
}

impl Default for FormatRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = FormatRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.detect_and_parse("{}").is_none());
    }


// ── B3 Test Mocks ──────────────────────────────────────────────

/// Mock that always detects and parses successfully.
struct MockSuccessExtension {
    name: String,
    priority: u32,
}

impl crate::traits::ExtensionCapability for MockSuccessExtension {
    fn capability_name(&self) -> &'static str { "extension_formats" }
}

impl FormatDispatcher for MockSuccessExtension {
    fn namespace(&self) -> &str { &self.name }
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { true }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        Ok(PropertyTree::String("parsed_ok".to_string()))
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that detects but returns a parse error.
struct MockErrorExtension {
    name: String,
    priority: u32,
}

impl crate::traits::ExtensionCapability for MockErrorExtension {
    fn capability_name(&self) -> &'static str { "extension_formats" }
}

impl FormatDispatcher for MockErrorExtension {
    fn namespace(&self) -> &str { &self.name }
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { true }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        Err(crate::error::AwkError::RuntimeError("mock parse error".to_string()))
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that never detects (passes through to next extension).
struct MockNoDetectExtension {
    name: String,
    priority: u32,
}

impl crate::traits::ExtensionCapability for MockNoDetectExtension {
    fn capability_name(&self) -> &'static str { "extension_formats" }
}

impl FormatDispatcher for MockNoDetectExtension {
    fn namespace(&self) -> &str { &self.name }
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { false }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        unreachable!("parse should not be called when detect returns false")
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that detects only JSON-like input (starts with `{`).
struct MockJsonLikeExtension {
    name: String,
    priority: u32,
}

impl crate::traits::ExtensionCapability for MockJsonLikeExtension {
    fn capability_name(&self) -> &'static str { "extension_formats" }
}

impl FormatDispatcher for MockJsonLikeExtension {
    fn namespace(&self) -> &str { &self.name }
    fn name(&self) -> &str { &self.name }
    fn detect(&self, input: &str) -> bool {
        input.trim().starts_with('{')
    }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        Ok(PropertyTree::String("json_like_parsed".to_string()))
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

// ── B3 Tests (Lyra spec requirements 1-6) ──────────────────────

/// B3-T1: Format extension successfully parses input -> used.
/// Requirement: "Format extension successfully parses input -> used"
#[test]
fn test_b3_format_extension_successfully_parses() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockSuccessExtension {
        name: "mock_success".to_string(),
        priority: 10,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "detect_and_parse should return Some when extension detects");
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.0, PropertyTree::String("parsed_ok".to_string()));
    assert_eq!(parsed.1, "mock_success");
}

/// B3-T2: Format extension returns Err -> error propagated.
/// Requirement: "Format extension returns Err(...) -> error propagated"
#[test]
fn test_b3_format_extension_error_propagated() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockErrorExtension {
        name: "mock_error".to_string(),
        priority: 10,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "detect_and_parse should return Some when extension detects");
    let err = result.unwrap().expect_err("parse should fail");
    match err {
        crate::error::AwkError::RuntimeError(msg) => {
            assert!(msg.contains("mock parse error"), "error message should match, got: {}", msg);
        }
        other => panic!("Expected RuntimeError, got: {:?}", other),
    }
}

/// B3-T3: All format extensions return no-detect -> None (default parsing).
/// Requirement: "If all format extensions return Ok(None), fall back to default parsing"
/// Note: detect_and_parse returns None when no extension detects, signaling caller
/// to use default parsing.
#[test]
fn test_b3_all_extensions_no_detect_falls_to_default() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockNoDetectExtension {
        name: "no_detect_1".to_string(),
        priority: 10,
    }));
    registry.register(Box::new(MockNoDetectExtension {
        name: "no_detect_2".to_string(),
        priority: 20,
    }));

    let result = registry.detect_and_parse("plain text input");
    assert!(result.is_none(), "detect_and_parse should return None when no extension detects (caller uses default parsing)");
}

/// B3-T4: First extension doesn't detect, second does -> second is used.
/// Requirement: "If format extension returns Ok(None), try next format extension"
/// Note: In our API, detect()=false means "try next". This tests priority ordering.
#[test]
fn test_b3_first_no_detect_second_succeeds() {
    let mut registry = FormatRegistry::new();
    // Higher priority (lower number) but doesn't detect
    registry.register(Box::new(MockNoDetectExtension {
        name: "no_detect".to_string(),
        priority: 10,
    }));
    // Lower priority (higher number) but detects
    registry.register(Box::new(MockSuccessExtension {
        name: "success".to_string(),
        priority: 20,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "second extension should detect");
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "success", "second extension should be used");
}

/// B3-T5: Priority ordering - lower priority number = tried first.
#[test]
fn test_b3_priority_ordering() {
    let mut registry = FormatRegistry::new();
    // Both detect, but different priorities
    registry.register(Box::new(MockSuccessExtension {
        name: "low_priority".to_string(),
        priority: 50,
    }));
    registry.register(Box::new(MockSuccessExtension {
        name: "high_priority".to_string(),
        priority: 5,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some());
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "high_priority", "higher priority (lower number) extension should be tried first");
}

/// B3-T6: Selective detection - only matching extension is used.
#[test]
fn test_b3_selective_detection() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockJsonLikeExtension {
        name: "json_like".to_string(),
        priority: 10,
    }));
    registry.register(Box::new(MockSuccessExtension {
        name: "catch_all".to_string(),
        priority: 100,
    }));

    // JSON-like input should be caught by json_like extension
    let json_result = registry.detect_and_parse("{\"key\": \"value\"}");
    assert!(json_result.is_some());
    let parsed = json_result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "json_like");

    // Non-JSON input should fall through to catch_all
    let text_result = registry.detect_and_parse("plain text");
    assert!(text_result.is_some());
    let parsed = text_result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "catch_all");
}

/// B3-T7: Empty registry returns None (default parsing).
#[test]
fn test_b3_empty_registry_returns_none() {
    let registry = FormatRegistry::new();
    let result = registry.detect_and_parse("{\"key\": \"value\"}");
    assert!(result.is_none(), "empty registry should return None (default parsing)");
}

/// B3-T8: Error from higher-priority extension is NOT swallowed by lower-priority extension.
/// When a extension detects but fails to parse, the error propagates immediately.
#[test]
fn test_b3_error_not_swallowed_by_fallthrough() {
    let mut registry = FormatRegistry::new();
    // High priority: detects but errors
    registry.register(Box::new(MockErrorExtension {
        name: "error_extension".to_string(),
        priority: 10,
    }));
    // Low priority: would succeed if tried
    registry.register(Box::new(MockSuccessExtension {
        name: "success_extension".to_string(),
        priority: 50,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some());
    assert!(result.unwrap().is_err(), "error from detecting extension should propagate, not fall through");
}


/// Test get_by_namespace lookup.
#[test]
fn test_get_by_namespace() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockSuccessExtension {
        name: "alpha".to_string(),
        priority: 10,
    }));
    registry.register(Box::new(MockJsonLikeExtension {
        name: "beta".to_string(),
        priority: 20,
    }));

    let found = registry.get_by_namespace("alpha");
    assert!(found.is_some(), "should find extension by namespace");
    assert_eq!(found.unwrap().name(), "alpha");

    let found = registry.get_by_namespace("beta");
    assert!(found.is_some(), "should find second extension by namespace");
    assert_eq!(found.unwrap().name(), "beta");

    let not_found = registry.get_by_namespace("nonexistent");
    assert!(not_found.is_none(), "should return None for unknown namespace");
}

}