//! Value type for the AWK evaluator.

use std::borrow::Cow;
use super::helpers::awk_str_to_number;
use crate::eval::output::serialize_for_output;

#[derive(Clone, Debug)]
pub enum Value {
    Number(f64),
    Str(String),
    Uninit,
    Bool(bool),
    Null,
    Object(Vec<(String, Value)>),
    Array(Vec<Value>),
}

impl Value {
    /// Look up a field in an Object by name. Returns None if not an Object or field missing.
    #[must_use]
    pub fn object_get(&self, field: &str) -> Option<&Value> {
        match self {
            Value::Object(pairs) => pairs.iter().find(|(k, _)| k == field).map(|(_, v)| v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_number(&self) -> f64 {
        match self {
            Value::Number(n) => *n,
            Value::Str(s) => awk_str_to_number(s),
            Value::Uninit => 0.0,
            Value::Bool(true) => 1.0,
            Value::Bool(false) => 0.0,
            Value::Null => 0.0,
            Value::Object(_) => 0.0,
            Value::Array(_) => 0.0,
        }
    }

    /// Zero-copy string conversion: returns Cow<str> to avoid allocation when possible.
    /// For Str variant, returns a borrowed reference. For Number, allocates only when needed.
    #[inline]
    pub fn as_cow_str(&self) -> Cow<'_, str> {
        match self {
            Value::Str(s) => Cow::Borrowed(s.as_str()),
            Value::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    let mut buf = itoa::Buffer::new();
                    Cow::Owned(buf.format(*n as i64).to_string())
                } else if !n.is_finite() {
                    Cow::Borrowed(if n.is_nan() {
                        "nan"
                    } else if n.is_sign_positive() {
                        "inf"
                    } else {
                        "-inf"
                    })
                } else {
                    let mut buf = ryu::Buffer::new();
                    Cow::Owned(buf.format(*n).to_string())
                }
            }
            Value::Uninit | Value::Null => Cow::Borrowed(""),
            Value::Bool(true) => Cow::Borrowed("1"),
            Value::Bool(false) => Cow::Borrowed("0"),
            Value::Object(_) | Value::Array(_) => Cow::Owned(serialize_for_output(self)),
        }
    }

    #[must_use]
    pub fn as_string(&self) -> String {
        match self {
            Value::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    // Fast path: use itoa for integer formatting
                    let mut buf = itoa::Buffer::new();
                    buf.format(*n as i64).to_string()
                } else if !n.is_finite() {
                    if n.is_nan() {
                        "nan".to_string()
                    } else if n.is_sign_positive() {
                        "inf".to_string()
                    } else {
                        "-inf".to_string()
                    }
                } else {
                    // Fast path: use ryu for float formatting
                    let mut buf = ryu::Buffer::new();
                    buf.format(*n).to_string()
                }
            }
            Value::Str(s) => s.clone(),
            Value::Uninit => String::new(),
            Value::Bool(true) => "1".to_string(),
            Value::Bool(false) => "0".to_string(),
            Value::Null => String::new(),
            Value::Object(_) | Value::Array(_) => serialize_for_output(self),
        }
    }

    /// Write value as string directly into a buffer (zero-allocation for numbers).
    /// This is the hot path for print statements.
    #[inline]
    pub fn write_to_buf(&self, buf: &mut String) {
        match self {
            Value::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    let mut ibuf = itoa::Buffer::new();
                    buf.push_str(ibuf.format(*n as i64));
                } else if !n.is_finite() {
                    if n.is_nan() {
                        buf.push_str("nan");
                    } else if n.is_sign_positive() {
                        buf.push_str("inf");
                    } else {
                        buf.push_str("-inf");
                    }
                } else {
                    let mut fbuf = ryu::Buffer::new();
                    buf.push_str(fbuf.format(*n));
                }
            }
            Value::Str(s) => buf.push_str(s),
            Value::Uninit => {}
            Value::Bool(true) => buf.push('1'),
            Value::Bool(false) => buf.push('0'),
            Value::Null => {}
            Value::Object(_) | Value::Array(_) => buf.push_str(&serialize_for_output(self)),
        }
    }

    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Number(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty() && s != "0",
            Value::Uninit => false,
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Object(_) => true,
            Value::Array(_) => true,
        }
    }

    /// Convert Value to PropertyTree
    pub fn to_property_tree(&self) -> crate::types::PropertyTree {
        use crate::types::{Number, PropertyTree};

        match self {
            Value::Null => PropertyTree::Null,
            Value::Bool(b) => PropertyTree::Bool(*b),
            Value::Number(n) => {
                if n.is_finite() && *n == (*n as i64) as f64 && n.abs() < 1e15 {
                    PropertyTree::Number(Number::Integer(*n as i64))
                } else {
                    PropertyTree::Number(Number::Float(*n))
                }
            }
            Value::Str(s) => PropertyTree::String(s.clone()),
            Value::Uninit => PropertyTree::Null,
            Value::Object(pairs) => {
                let pt_pairs: Vec<(String, PropertyTree)> = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_property_tree()))
                    .collect();
                PropertyTree::Object(pt_pairs)
            }
            Value::Array(items) => {
                let pt_items: Vec<PropertyTree> =
                    items.iter().map(|v| v.to_property_tree()).collect();
                PropertyTree::Array(pt_items)
            }
        }
    }

    /// Convert PropertyTree to Value
    pub fn from_property_tree(pt: &crate::types::PropertyTree) -> Self {
        use crate::types::PropertyTree;

        match pt {
            PropertyTree::Null => Value::Null,
            PropertyTree::Bool(b) => Value::Bool(*b),
            PropertyTree::Number(n) => Value::Number(n.as_f64()),
            PropertyTree::String(s) => Value::Str(s.clone()),
            PropertyTree::Array(items) => {
                let awk_items: Vec<Value> = items.iter().map(Value::from_property_tree).collect();
                Value::Array(awk_items)
            }
            PropertyTree::Object(pairs) => {
                let awk_pairs: Vec<(String, Value)> = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from_property_tree(v)))
                    .collect();
                Value::Object(awk_pairs)
            }
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            (Value::Object(a), Value::Object(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Bool(true), Value::Number(n)) => *n == 1.0,
            (Value::Bool(false), Value::Number(n)) => *n == 0.0,
            (Value::Number(n), Value::Bool(true)) => *n == 1.0,
            (Value::Number(n), Value::Bool(false)) => *n == 0.0,
            (Value::Null, Value::Str(s)) => s.is_empty(),
            (Value::Str(s), Value::Null) => s.is_empty(),
            (Value::Null, Value::Number(n)) => *n == 0.0,
            (Value::Number(n), Value::Null) => *n == 0.0,
            _ => {
                if matches!(self, Value::Number(_)) || matches!(other, Value::Number(_)) {
                    self.as_number() == other.as_number()
                } else {
                    self.as_string() == other.as_string()
                }
            }
        }
    }
}
