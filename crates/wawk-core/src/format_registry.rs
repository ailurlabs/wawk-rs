//! Format Registry - manages format plugins for multi-format I/O.
//!
//! The `FormatRegistry` holds a collection of `FormatDispatcher` implementations
//! and provides format detection and serialization capabilities.

use crate::traits::FormatDispatcher;
use crate::types::PropertyTree;
use crate::error::AwkResult;

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
        Self { plugins: Vec::new() }
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
                return Some(plugin.parse(input).map(|pt| (pt, plugin.name().to_string())));
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
}
