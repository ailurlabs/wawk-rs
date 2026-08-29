//! Output format serialization pipeline.
//!
//! Converts Value → PropertyTree → format-specific string via FormatRegistry.
//! When an output format is set (via OUTPUT_FORMAT variable), uses the matching
//! format dispatcher. Falls back to JSON (the default serialization).

use crate::format_registry::FormatRegistry;
use crate::eval::Value;

/// Serialize a Value for output, using the output format if set.
///
/// Returns `Some(string)` if the value is a container (Object/Array) and
/// a format handler produced output. Returns `None` for scalar values
/// (let normal print handle them) or if no handler matched.
pub fn serialize_output(
    val: &Value,
    registry: &FormatRegistry,
    output_format: Option<&str>,
) -> Option<String> {
    if !matches!(val, Value::Object(_) | Value::Array(_)) {
        return None; // Let normal print handle scalars
    }
    let tree = val.to_property_tree();
    registry.serialize(&tree, output_format)
}

/// Serialize a Value to JSON string. Single source of truth for JSON serialization.
/// Delegates to PropertyTree::to_json() to avoid duplicating serialization logic.
/// Used as fallback when no format-specific output is configured.
pub fn serialize_for_output(val: &Value) -> String {
    let tree = val.to_property_tree();
    tree.to_json()
}
