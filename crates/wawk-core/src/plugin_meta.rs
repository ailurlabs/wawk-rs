//! Plugin metadata parsing.
//!
//! Plugins declare metadata via the `__meta__` handler convention.
//! This module parses the JSON response into a structured type.
//!
//! The expanded metadata enables:
//! - Auto-discovery of plugin functions (no trial-and-error dispatch)
//! - Capability-based routing (find plugins by capability tag)
//! - Auto-registration of MCP tools/resources/prompts
//! - Type awareness for scoped type registries

use serde::Deserialize;

/// Metadata returned by a plugin `__meta__` handler.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginMeta {
    /// Plugin identity (e.g., "test-formula"). Used for dependency resolution
    /// and logging. Opaque to the host -- no special meaning.
    pub name: String,

    /// Plugin version (semver). Used for compatibility checks.
    pub version: String,

    /// Dependencies on other plugins. The host resolves these generically.
    #[serde(default)]
    pub requires: Vec<String>,

    /// Optional human-readable description. For logging and UI display.
    #[serde(default)]
    pub description: Option<String>,

    // -- Expanded fields (all optional with serde defaults) --

    /// List of function names this plugin exposes.
    /// Enables auto-discovery: host builds function->plugin index for O(1) dispatch.
    #[serde(default)]
    pub functions: Vec<String>,

    /// Capability tags for capability-based routing.
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Custom types this plugin defines.
    #[serde(default)]
    pub types: Vec<String>,

    /// Function names that should receive auto-injected scope context.
    /// When called with 1 arg from AWK, scope variables are auto-appended as JSON.
    #[serde(default)]
    pub auto_context_functions: Vec<String>,

    /// WIT interface version for compatibility checking.
    #[serde(default)]
    pub api_version: Option<String>,

    /// Plugin author. For display and attribution.
    #[serde(default)]
    pub author: Option<String>,

    /// Plugin homepage URL. For documentation and support.
    #[serde(default)]
    pub homepage: Option<String>,
}

/// Result of querying a plugin for its metadata.
#[derive(Debug)]
pub enum MetaResult {
    Ok(Box<PluginMeta>),
    ParseError(String),
    NotAvailable,
}

/// Parse a `__meta__` JSON response string into a `PluginMeta`.
pub fn parse_meta(json: &str) -> MetaResult {
    match serde_json::from_str::<PluginMeta>(json) {
        Ok(meta) => {
            if meta.name.is_empty() {
                return MetaResult::ParseError("name is required and must be non-empty".into());
            }
            if meta.version.is_empty() {
                return MetaResult::ParseError("version is required and must be non-empty".into());
            }
            MetaResult::Ok(Box::new(meta))
        }
        Err(e) => MetaResult::ParseError(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_meta() {
        let json = r#"{"name": "test-hello", "version": "0.1.0"}"#;
        match parse_meta(json) {
            MetaResult::Ok(m) => {
                assert_eq!(m.name, "test-hello");
                assert_eq!(m.version, "0.1.0");
                assert!(m.requires.is_empty());
                assert!(m.description.is_none());
                assert!(m.functions.is_empty());
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn parse_full_expanded_meta() {
        let json = r#"{
            "name": "test-formula",
            "version": "0.2.0",
            "requires": ["test-helper"],
            "description": "Spreadsheet formula evaluation",
            "api_version": "1.0",
            "functions": ["SUM", "AVERAGE", "VLOOKUP"],
            "capabilities": ["formula_eval", "date_functions"],
            "types": ["CalcValue", "Date"],
            "auto_context_functions": ["formula_eval"],
            "author": "Ailur Labs",
            "homepage": "https://example.com"
        }"#;
        match parse_meta(json) {
            MetaResult::Ok(m) => {
                assert_eq!(m.name, "test-formula");
                assert_eq!(m.version, "0.2.0");
                assert_eq!(m.requires, vec!["test-helper"]);
                assert_eq!(m.api_version.as_deref(), Some("1.0"));
                assert_eq!(m.functions, vec!["SUM", "AVERAGE", "VLOOKUP"]);
                assert_eq!(m.capabilities, vec!["formula_eval", "date_functions"]);
                assert_eq!(m.types, vec!["CalcValue", "Date"]);
                assert_eq!(m.auto_context_functions, vec!["formula_eval"]);
                assert_eq!(m.author.as_deref(), Some("Ailur Labs"));
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn parse_missing_name() {
        let json = r#"{"version": "0.1.0"}"#;
        assert!(matches!(parse_meta(json), MetaResult::ParseError(_)));
    }

    #[test]
    fn parse_empty_name() {
        let json = r#"{"name": "", "version": "0.1.0"}"#;
        assert!(matches!(parse_meta(json), MetaResult::ParseError(_)));
    }

    #[test]
    fn parse_invalid_json() {
        assert!(matches!(parse_meta("not json"), MetaResult::ParseError(_)));
    }

    #[test]
    fn parse_multiple_requires() {
        let json = r#"{"name": "test-geo", "version": "1.0.0", "requires": ["test-auth", "test-cache"]}"#;
        match parse_meta(json) {
            MetaResult::Ok(m) => assert_eq!(m.requires, vec!["test-auth", "test-cache"]),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn parse_plugin_with_functions() {
        let json = r#"{"name": "test-hash", "version": "0.2.0", "functions": ["sha256", "md5"], "capabilities": ["hashing"]}"#;
        match parse_meta(json) {
            MetaResult::Ok(m) => {
                assert_eq!(m.functions, vec!["sha256", "md5"]);
                assert_eq!(m.capabilities, vec!["hashing"]);
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }
}
