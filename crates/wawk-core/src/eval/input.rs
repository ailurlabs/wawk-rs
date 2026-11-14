//! Input format detection and parsing pipeline.
//!
//! Routes input through FormatRegistry for multi-format support.
//! Contains built-in format handlers compiled for performance.

use super::Value;
use crate::error::AwkResult;
use crate::traits::{FormatDispatcher, ExtensionCapability};
use crate::types::PropertyTree;

/// Built-in JSON format handler.
/// Compiled-in for performance (hot path: every record).
pub struct BuiltinJsonFormat;

impl ExtensionCapability for BuiltinJsonFormat {
    fn capability_name(&self) -> &'static str {
        "extension_formats"
    }
}

impl FormatDispatcher for BuiltinJsonFormat {
    fn namespace(&self) -> &str {
        "json"
    }

    fn name(&self) -> &str {
        "json"
    }

    fn detect(&self, input: &str) -> bool {
        let trimmed = input.trim_start();
        trimmed.starts_with('{') || trimmed.starts_with('[')
    }

    fn parse(&self, input: &str) -> AwkResult<PropertyTree> {
        json_parse(input)
    }

    fn serialize(&self, tree: &PropertyTree) -> Option<String> {
        Some(json_serialize(tree))
    }

    fn priority(&self) -> u32 {
        10
    } // Highest priority
}

/// Parse JSON string into Value via PropertyTree (single source of truth).
/// Delegates to json_parse() for parsing, then converts to Value.
pub fn json_to_awk(json_str: &str) -> AwkResult<Value> {
    let tree = json_parse(json_str)?;
    Ok(Value::from_property_tree(&tree))
}


// -- JSON encode/decode (single source of truth for JSON logic) --
// Moved from PropertyTree methods to keep the core data type format-agnostic.

/// Parse a JSON string into a PropertyTree.
/// Includes security limits to prevent DoS in WASM sandbox environments.
pub(crate) fn json_parse(json_str: &str) -> crate::error::AwkResult<PropertyTree> {
    use crate::types::MAX_PT_NESTING_DEPTH;
    // Pre-scan nesting depth before serde_json parses (prevents stack overflow)
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    for ch in json_str.as_bytes() {
        match ch {
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_PT_NESTING_DEPTH {
                    return Err(crate::error::AwkError::RuntimeError(format!(
                        "PropertyTree nesting depth exceeds limit ({} max)",
                        MAX_PT_NESTING_DEPTH
                    )));
                }
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| crate::error::AwkError::RuntimeError(format!("Invalid JSON: {}", e)))?;
    json_value_to_pt(&val, 0)
}

/// Serialize a PropertyTree to a JSON string.
pub(crate) fn json_serialize(pt: &PropertyTree) -> String {
    let v = pt_to_json_value(pt);
    serde_json::to_string(&v).unwrap_or_else(|_| "null".to_string())
}

/// Convert serde_json::Value to PropertyTree with security limits.
fn json_value_to_pt(
    val: &serde_json::Value,
    depth: usize,
) -> crate::error::AwkResult<PropertyTree> {
    use crate::types::{Number, MAX_PT_NESTING_DEPTH, MAX_PT_OBJECT_KEYS, MAX_PT_KEY_LENGTH, MAX_PT_ARRAY_LENGTH};
    if depth > MAX_PT_NESTING_DEPTH {
        return Err(crate::error::AwkError::RuntimeError(format!(
            "PropertyTree nesting depth exceeds limit ({} max)",
            MAX_PT_NESTING_DEPTH
        )));
    }
    Ok(match val {
        serde_json::Value::Null => PropertyTree::Null,
        serde_json::Value::Bool(b) => PropertyTree::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PropertyTree::Number(Number::Integer(i))
            } else if let Some(f) = n.as_f64() {
                PropertyTree::Number(Number::Float(f))
            } else {
                PropertyTree::Null
            }
        }
        serde_json::Value::String(s) => PropertyTree::String(s.clone()),
        serde_json::Value::Array(arr) => {
            if arr.len() > MAX_PT_ARRAY_LENGTH {
                return Err(crate::error::AwkError::RuntimeError(format!(
                    "PropertyTree array length exceeds limit ({} max, got {})",
                    MAX_PT_ARRAY_LENGTH,
                    arr.len()
                )));
            }
            let mut items = Vec::with_capacity(arr.len());
            for elem in arr {
                items.push(json_value_to_pt(elem, depth + 1)?);
            }
            PropertyTree::Array(items)
        }
        serde_json::Value::Object(obj) => {
            if obj.len() > MAX_PT_OBJECT_KEYS {
                return Err(crate::error::AwkError::RuntimeError(format!(
                    "PropertyTree object key count exceeds limit ({} max, got {})",
                    MAX_PT_OBJECT_KEYS,
                    obj.len()
                )));
            }
            let mut pairs = Vec::with_capacity(obj.len());
            for (k, v) in obj {
                if k.len() > MAX_PT_KEY_LENGTH {
                    return Err(crate::error::AwkError::RuntimeError(format!(
                        "PropertyTree key length exceeds limit ({} max, got {})",
                        MAX_PT_KEY_LENGTH,
                        k.len()
                    )));
                }
                pairs.push((k.clone(), json_value_to_pt(v, depth + 1)?));
            }
            PropertyTree::Object(pairs)
        }
    })
}

/// Convert PropertyTree to serde_json::Value for serialization.
fn pt_to_json_value(pt: &PropertyTree) -> serde_json::Value {
    use crate::types::Number;
    match pt {
        PropertyTree::Null => serde_json::Value::Null,
        PropertyTree::Bool(b) => serde_json::Value::Bool(*b),
        PropertyTree::Number(Number::Integer(i)) => serde_json::Value::Number((*i).into()),
        PropertyTree::Number(Number::Float(f)) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        PropertyTree::String(s) => serde_json::Value::String(s.clone()),
        PropertyTree::Array(items) => {
            serde_json::Value::Array(items.iter().map(pt_to_json_value).collect())
        }
        PropertyTree::Object(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                map.insert(k.clone(), pt_to_json_value(v));
            }
            serde_json::Value::Object(map)
        }
    }
}
