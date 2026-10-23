//! Input format detection and parsing pipeline.
//!
//! Routes input through FormatRegistry for multi-format support.
//! Contains built-in format handlers compiled for performance.

use super::Value;
use crate::error::{AwkError, AwkResult};
use crate::traits::{FormatDispatcher, PluginCapability};
use crate::types::PropertyTree;

/// Built-in JSON format handler.
/// Compiled-in for performance (hot path: every record).
pub struct BuiltinJsonFormat;

impl PluginCapability for BuiltinJsonFormat {
    fn capability_name(&self) -> &'static str {
        "format_handler"
    }
}

impl FormatDispatcher for BuiltinJsonFormat {
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

/// Built-in CSV format handler.
/// Adapted from eval/format.rs CSV parsing.
pub struct BuiltinCsvFormat;

impl PluginCapability for BuiltinCsvFormat {
    fn capability_name(&self) -> &'static str {
        "format_handler"
    }
}

impl FormatDispatcher for BuiltinCsvFormat {
    fn name(&self) -> &str {
        "csv"
    }

    fn detect(&self, input: &str) -> bool {
        // Single-pass: count commas on first line and verify consistency.
        // Avoids allocating a Vec<&str> for all lines.
        let mut lines = input.lines();
        let first_line = match lines.next() {
            Some(l) => l,
            None => return false,
        };
        let first_commas = first_line.matches(',').count();
        if first_commas == 0 {
            return false;
        }
        // Need at least 2 lines for valid CSV
        let mut has_second = false;
        for line in lines {
            has_second = true;
            if line.matches(',').count() != first_commas {
                return false;
            }
        }
        has_second
    }

    fn parse(&self, input: &str) -> AwkResult<PropertyTree> {
        let lines: Vec<&str> = input.lines().collect();
        if lines.is_empty() {
            return Ok(PropertyTree::Array(vec![]));
        }
        let headers: Vec<String> = lines[0].split(',').map(|s| s.trim().to_string()).collect();
        let mut rows = Vec::new();
        for line in &lines[1..] {
            let values: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
            let pairs: Vec<(String, PropertyTree)> = headers
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    (
                        h.clone(),
                        PropertyTree::String(values.get(i).cloned().unwrap_or_default()),
                    )
                })
                .collect();
            rows.push(PropertyTree::Object(pairs));
        }
        Ok(PropertyTree::Array(rows))
    }

    fn serialize(&self, tree: &PropertyTree) -> Option<String> {
        match tree {
            PropertyTree::Array(rows) => {
                let mut out = String::new();
                // Header row from first object's keys
                if let Some(PropertyTree::Object(first)) = rows.first() {
                    let headers: Vec<&str> = first.iter().map(|(k, _)| k.as_str()).collect();
                    out.push_str(&headers.join(","));
                    out.push('\n');
                    // Data rows
                    for row in rows {
                        if let PropertyTree::Object(pairs) = row {
                            let vals: Vec<String> =
                                pairs.iter().map(|(_, v)| v.as_str().to_string()).collect();
                            out.push_str(&vals.join(","));
                            out.push('\n');
                        }
                    }
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn priority(&self) -> u32 {
        50
    }
}

/// Built-in XML format handler.
/// Adapted from eval/format.rs XML parsing.
pub struct BuiltinXmlFormat;

impl PluginCapability for BuiltinXmlFormat {
    fn capability_name(&self) -> &'static str {
        "format_handler"
    }
}

impl FormatDispatcher for BuiltinXmlFormat {
    fn name(&self) -> &str {
        "xml"
    }

    fn detect(&self, input: &str) -> bool {
        let trimmed = input.trim();
        trimmed.starts_with("<?xml") || trimmed.starts_with('<')
    }

    fn parse(&self, input: &str) -> AwkResult<PropertyTree> {
        use quick_xml::events::Event;
        use quick_xml::Reader;
        let mut reader = Reader::from_str(input);
        let mut stack: Vec<(String, Vec<(String, PropertyTree)>)> = Vec::new();
        let mut text = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    stack.push((name, Vec::new()));
                    text.clear();
                }
                Ok(Event::End(ref _e)) => {
                    if let Some((tag, children)) = stack.pop() {
                        let node = if children.is_empty() && !text.is_empty() {
                            PropertyTree::String(text.clone())
                        } else {
                            PropertyTree::Object(children)
                        };
                        if let Some(parent) = stack.last_mut() {
                            parent.1.push((tag, node));
                        } else {
                            return Ok(node);
                        }
                    }
                    text.clear();
                }
                Ok(Event::Text(ref e)) => {
                    // Append text segments (handles split text events)
                    text.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(AwkError::RuntimeError(format!("XML parse error: {}", e))),
                _ => {}
            }
        }
        if let Some((_, mut children)) = stack.pop() {
            if children.len() == 1 {
                Ok(children.pop().unwrap().1)
            } else {
                Ok(PropertyTree::Object(children))
            }
        } else {
            Err(AwkError::RuntimeError("Empty XML".into()))
        }
    }

    fn serialize(&self, _tree: &PropertyTree) -> Option<String> {
        None // XML serialization not yet implemented
    }

    fn priority(&self) -> u32 {
        30
    }
}

/// Built-in YAML format handler.
/// Uses serde_yaml for parsing.
pub struct BuiltinYamlFormat;

impl PluginCapability for BuiltinYamlFormat {
    fn capability_name(&self) -> &'static str {
        "format_handler"
    }
}

impl FormatDispatcher for BuiltinYamlFormat {
    fn name(&self) -> &str {
        "yaml"
    }

    fn detect(&self, input: &str) -> bool {
        let trimmed = input.trim();
        // Only detect YAML with explicit document start marker (---).
        // Single-line YAML detection is too error-prone with regular text.
        trimmed.starts_with("---")
    }

    fn parse(&self, input: &str) -> AwkResult<PropertyTree> {
        match serde_yaml::from_str::<serde_yaml::Value>(input) {
            Ok(value) => Ok(yaml_to_pt(&value)),
            Err(e) => Err(AwkError::RuntimeError(format!("YAML parse error: {}", e))),
        }
    }

    fn serialize(&self, _tree: &PropertyTree) -> Option<String> {
        None // YAML serialization not yet implemented
    }

    fn priority(&self) -> u32 {
        40
    }
}

/// Convert serde_yaml::Value to PropertyTree.
fn yaml_to_pt(value: &serde_yaml::Value) -> PropertyTree {
    use crate::types::Number;
    match value {
        serde_yaml::Value::Null => PropertyTree::Null,
        serde_yaml::Value::Bool(b) => PropertyTree::Bool(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PropertyTree::Number(Number::Integer(i))
            } else if let Some(f) = n.as_f64() {
                PropertyTree::Number(Number::Float(f))
            } else {
                PropertyTree::Null
            }
        }
        serde_yaml::Value::String(s) => PropertyTree::String(s.clone()),
        serde_yaml::Value::Sequence(arr) => {
            PropertyTree::Array(arr.iter().map(yaml_to_pt).collect())
        }
        serde_yaml::Value::Mapping(obj) => PropertyTree::Object(
            obj.iter()
                .filter_map(|(k, v)| k.as_str().map(|k| (k.to_string(), yaml_to_pt(v))))
                .collect(),
        ),
        _ => PropertyTree::Null,
    }
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
