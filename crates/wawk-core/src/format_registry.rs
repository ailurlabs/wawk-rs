//! Format Registry - manages format plugins for multi-format I/O.
//!
//! The `FormatRegistry` holds a collection of `FormatDispatcher` implementations
//! and provides format detection and serialization capabilities.

use crate::error::AwkResult;
use crate::traits::FormatDispatcher;
use crate::types::PropertyTree;

/// Registry that manages format plugins for multi-format input/output.
///
/// Plugins are sorted by priority (lower number = higher priority).
/// Detection iterates plugins in priority order and returns the first match.
pub struct FormatRegistry {
    plugins: Vec<Box<dyn FormatDispatcher>>,
}

impl FormatRegistry {
    /// Create an empty format registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Register a format plugin. Plugins are re-sorted by priority after insertion.
    pub fn register(&mut self, plugin: Box<dyn FormatDispatcher>) {
        self.plugins.push(plugin);
        self.plugins.sort_by_key(|p| p.priority());
    }

    /// Detect the format of `input` and parse it if a plugin matches.
    ///
    /// Returns `Some(Ok((tree, format_name)))` if a plugin detected and parsed successfully.
    /// Returns `Some(Err(...))` if a plugin detected but parsing failed.
    /// Returns `None` if no plugin matched.
    pub fn detect_and_parse(&self, input: &str) -> Option<AwkResult<(PropertyTree, String)>> {
        for plugin in &self.plugins {
            if plugin.detect(input) {
                return Some(
                    plugin
                        .parse(input)
                        .map(|pt| (pt, plugin.name().to_string())),
                );
            }
        }
        None
    }

    /// Serialize a `PropertyTree` to a specific format (or the first available).
    ///
    /// If `format` is `Some(name)`, only the plugin with that name is used.
    /// If `format` is `None`, plugins are tried in priority order.
    pub fn serialize(&self, tree: &PropertyTree, format: Option<&str>) -> Option<String> {
        if let Some(name) = format {
            for plugin in &self.plugins {
                if plugin.name() == name {
                    return plugin.serialize(tree);
                }
            }
        }
        // Fallback: try all plugins in priority order
        for plugin in &self.plugins {
            if let Some(output) = plugin.serialize(tree) {
                return Some(output);
            }
        }
        None
    }

    /// Returns a slice of all registered plugins.
    pub fn plugins(&self) -> &[Box<dyn FormatDispatcher>] {
        &self.plugins
    }

    /// Returns the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Returns true if no plugins are registered.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
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
struct MockSuccessPlugin {
    name: String,
    priority: u32,
}

impl crate::traits::PluginCapability for MockSuccessPlugin {
    fn capability_name(&self) -> &'static str { "format_handler" }
}

impl FormatDispatcher for MockSuccessPlugin {
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { true }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        Ok(PropertyTree::String("parsed_ok".to_string()))
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that detects but returns a parse error.
struct MockErrorPlugin {
    name: String,
    priority: u32,
}

impl crate::traits::PluginCapability for MockErrorPlugin {
    fn capability_name(&self) -> &'static str { "format_handler" }
}

impl FormatDispatcher for MockErrorPlugin {
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { true }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        Err(crate::error::AwkError::RuntimeError("mock parse error".to_string()))
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that never detects (passes through to next plugin).
struct MockNoDetectPlugin {
    name: String,
    priority: u32,
}

impl crate::traits::PluginCapability for MockNoDetectPlugin {
    fn capability_name(&self) -> &'static str { "format_handler" }
}

impl FormatDispatcher for MockNoDetectPlugin {
    fn name(&self) -> &str { &self.name }
    fn detect(&self, _input: &str) -> bool { false }
    fn parse(&self, _input: &str) -> AwkResult<PropertyTree> {
        unreachable!("parse should not be called when detect returns false")
    }
    fn serialize(&self, _tree: &PropertyTree) -> Option<String> { None }
    fn priority(&self) -> u32 { self.priority }
}

/// Mock that detects only JSON-like input (starts with `{`).
struct MockJsonLikePlugin {
    name: String,
    priority: u32,
}

impl crate::traits::PluginCapability for MockJsonLikePlugin {
    fn capability_name(&self) -> &'static str { "format_handler" }
}

impl FormatDispatcher for MockJsonLikePlugin {
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

/// B3-T1: Format plugin successfully parses input -> used.
/// Requirement: "Format plugin successfully parses input -> used"
#[test]
fn test_b3_format_plugin_successfully_parses() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockSuccessPlugin {
        name: "mock_success".to_string(),
        priority: 10,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "detect_and_parse should return Some when plugin detects");
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.0, PropertyTree::String("parsed_ok".to_string()));
    assert_eq!(parsed.1, "mock_success");
}

/// B3-T2: Format plugin returns Err -> error propagated.
/// Requirement: "Format plugin returns Err(...) -> error propagated"
#[test]
fn test_b3_format_plugin_error_propagated() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockErrorPlugin {
        name: "mock_error".to_string(),
        priority: 10,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "detect_and_parse should return Some when plugin detects");
    let err = result.unwrap().expect_err("parse should fail");
    match err {
        crate::error::AwkError::RuntimeError(msg) => {
            assert!(msg.contains("mock parse error"), "error message should match, got: {}", msg);
        }
        other => panic!("Expected RuntimeError, got: {:?}", other),
    }
}

/// B3-T3: All format plugins return no-detect -> None (default parsing).
/// Requirement: "If all format plugins return Ok(None), fall back to default parsing"
/// Note: detect_and_parse returns None when no plugin detects, signaling caller
/// to use default parsing.
#[test]
fn test_b3_all_plugins_no_detect_falls_to_default() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockNoDetectPlugin {
        name: "no_detect_1".to_string(),
        priority: 10,
    }));
    registry.register(Box::new(MockNoDetectPlugin {
        name: "no_detect_2".to_string(),
        priority: 20,
    }));

    let result = registry.detect_and_parse("plain text input");
    assert!(result.is_none(), "detect_and_parse should return None when no plugin detects (caller uses default parsing)");
}

/// B3-T4: First plugin doesn't detect, second does -> second is used.
/// Requirement: "If format plugin returns Ok(None), try next format plugin"
/// Note: In our API, detect()=false means "try next". This tests priority ordering.
#[test]
fn test_b3_first_no_detect_second_succeeds() {
    let mut registry = FormatRegistry::new();
    // Higher priority (lower number) but doesn't detect
    registry.register(Box::new(MockNoDetectPlugin {
        name: "no_detect".to_string(),
        priority: 10,
    }));
    // Lower priority (higher number) but detects
    registry.register(Box::new(MockSuccessPlugin {
        name: "success".to_string(),
        priority: 20,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some(), "second plugin should detect");
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "success", "second plugin should be used");
}

/// B3-T5: Priority ordering - lower priority number = tried first.
#[test]
fn test_b3_priority_ordering() {
    let mut registry = FormatRegistry::new();
    // Both detect, but different priorities
    registry.register(Box::new(MockSuccessPlugin {
        name: "low_priority".to_string(),
        priority: 50,
    }));
    registry.register(Box::new(MockSuccessPlugin {
        name: "high_priority".to_string(),
        priority: 5,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some());
    let parsed = result.unwrap().expect("parse should succeed");
    assert_eq!(parsed.1, "high_priority", "higher priority (lower number) plugin should be tried first");
}

/// B3-T6: Selective detection - only matching plugin is used.
#[test]
fn test_b3_selective_detection() {
    let mut registry = FormatRegistry::new();
    registry.register(Box::new(MockJsonLikePlugin {
        name: "json_like".to_string(),
        priority: 10,
    }));
    registry.register(Box::new(MockSuccessPlugin {
        name: "catch_all".to_string(),
        priority: 100,
    }));

    // JSON-like input should be caught by json_like plugin
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

/// B3-T8: Error from higher-priority plugin is NOT swallowed by lower-priority plugin.
/// When a plugin detects but fails to parse, the error propagates immediately.
#[test]
fn test_b3_error_not_swallowed_by_fallthrough() {
    let mut registry = FormatRegistry::new();
    // High priority: detects but errors
    registry.register(Box::new(MockErrorPlugin {
        name: "error_plugin".to_string(),
        priority: 10,
    }));
    // Low priority: would succeed if tried
    registry.register(Box::new(MockSuccessPlugin {
        name: "success_plugin".to_string(),
        priority: 50,
    }));

    let result = registry.detect_and_parse("any input");
    assert!(result.is_some());
    assert!(result.unwrap().is_err(), "error from detecting plugin should propagate, not fall through");
}

}
