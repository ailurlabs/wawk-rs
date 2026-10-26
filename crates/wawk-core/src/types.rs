use rustc_hash::FxHashMap;

use std::borrow::Cow;

// PropertyTree parsing security limits (WASM sandbox).
// These prevent DoS via deeply nested or oversized structured data inputs.
pub const MAX_PT_NESTING_DEPTH: usize = 64;
pub const MAX_PT_OBJECT_KEYS: usize = 10_000;
pub const MAX_PT_KEY_LENGTH: usize = 1_000;
pub const MAX_PT_ARRAY_LENGTH: usize = 100_000;

/// Number type that preserves integer vs float distinction
#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    Integer(i64),
    Float(f64),
}

impl Number {
    pub fn as_f64(&self) -> f64 {
        match self {
            Number::Integer(n) => *n as f64,
            Number::Float(n) => *n,
        }
    }

    pub fn is_integer(&self) -> bool {
        matches!(self, Number::Integer(_))
    }
}

impl From<i64> for Number {
    fn from(n: i64) -> Self {
        Number::Integer(n)
    }
}

impl From<f64> for Number {
    fn from(n: f64) -> Self {
        Number::Float(n)
    }
}

/// Generic property tree node for hierarchical data
///
/// This is the core data model for all format handlers (JSON, XML, YAML, TOML).
/// It preserves type information and format-specific metadata for lossless round-tripping.
#[derive(Debug, Clone, Default)]
pub enum PropertyTree {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<PropertyTree>),
    Object(Vec<(String, PropertyTree)>), // Ordered, preserves insertion order
}

impl PropertyTree {
    /// Create a null value
    pub fn null() -> Self {
        Self::Null
    }

    /// Create a boolean value
    pub fn bool(b: bool) -> Self {
        Self::Bool(b)
    }

    /// Create an integer number
    pub fn integer(n: i64) -> Self {
        Self::Number(Number::Integer(n))
    }

    /// Create a float number
    pub fn float(n: f64) -> Self {
        Self::Number(Number::Float(n))
    }

    /// Create a string value
    pub fn string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }

    /// Create an array value
    pub fn array(items: Vec<PropertyTree>) -> Self {
        Self::Array(items)
    }

    /// Create an object value
    pub fn object(fields: Vec<(String, PropertyTree)>) -> Self {
        Self::Object(fields)
    }

    /// Get a field value by name (for Object nodes)
    pub fn get_field(&self, field: &str) -> Option<&PropertyTree> {
        match self {
            PropertyTree::Object(pairs) => pairs.iter().find(|(k, _)| k == field).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Get a field value by index (for Array nodes)
    pub fn get_index(&self, index: usize) -> Option<&PropertyTree> {
        match self {
            PropertyTree::Array(items) => items.get(index),
            _ => None,
        }
    }

    /// Check if this is an object
    pub fn is_object(&self) -> bool {
        matches!(self, PropertyTree::Object(_))
    }

    /// Check if this is an array
    pub fn is_array(&self) -> bool {
        matches!(self, PropertyTree::Array(_))
    }

    /// Check if this is a string
    pub fn is_string(&self) -> bool {
        matches!(self, PropertyTree::String(_))
    }

    /// Check if this is a number
    pub fn is_number(&self) -> bool {
        matches!(self, PropertyTree::Number(_))
    }

    /// Check if this is null
    pub fn is_null(&self) -> bool {
        matches!(self, PropertyTree::Null)
    }

    /// Convert to string representation
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            PropertyTree::String(s) => Cow::Borrowed(s.as_str()),
            PropertyTree::Number(n) => Cow::Owned(match n {
                Number::Integer(i) => i.to_string(),
                Number::Float(f) => {
                    if f.is_finite() && *f == (*f as i64) as f64 && f.abs() < 1e15 {
                        format!("{}", *f as i64)
                    } else {
                        format!("{}", f)
                    }
                }
            }),
            PropertyTree::Bool(b) => Cow::Owned(b.to_string()),
            PropertyTree::Null => Cow::Borrowed("null"),
            _ => Cow::Borrowed(""),
        }
    }

    /// Convert to f64
    pub fn as_f64(&self) -> f64 {
        match self {
            PropertyTree::Number(n) => n.as_f64(),
            PropertyTree::String(s) => s.parse::<f64>().unwrap_or(0.0),
            PropertyTree::Bool(true) => 1.0,
            PropertyTree::Bool(false) | PropertyTree::Null => 0.0,
            _ => 0.0,
        }
    }

    /// Get the number of children (object fields or array elements)
    pub fn len(&self) -> usize {
        match self {
            PropertyTree::Object(pairs) => pairs.len(),
            PropertyTree::Array(items) => items.len(),
            _ => 0,
        }
    }

    /// Check if this is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

}



impl PartialEq for PropertyTree {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Object(a), Self::Object(b)) => a == b,
            _ => false,
        }
    }
}

/// Registry for extension-provided types.
/// Extensions register type tags (e.g., "@date", "@grid") and the engine
/// recognizes them for typeof() and display purposes.
pub struct ExtensionTypeRegistry {
    tag_to_type: FxHashMap<String, String>,
}

impl ExtensionTypeRegistry {
    pub fn new() -> Self {
        Self {
            tag_to_type: FxHashMap::default(),
        }
    }

    /// Register a extension-provided type.
    pub fn register(&mut self, type_name: &str, type_tag: &str, _provider: &str) {
        self.tag_to_type
            .insert(type_tag.to_string(), type_name.to_string());
    }

    /// Check if a string value is a tagged extension type.
    /// Returns the type name if recognized, None otherwise.
    pub fn resolve_tag(&self, value: &str) -> Option<&str> {
        if !value.starts_with('@') {
            return None;
        }
        if let Some(colon_pos) = value.find(':') {
            let tag = &value[..colon_pos];
            self.tag_to_type.get(tag).map(|s| s.as_str())
        } else {
            None
        }
    }
}

impl Default for ExtensionTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_tree_null() {
        let tree = PropertyTree::null();
        assert!(tree.is_null());
        assert!(!tree.is_object());
        assert!(!tree.is_array());
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_property_tree_bool() {
        let tree = PropertyTree::bool(true);
        assert!(matches!(tree, PropertyTree::Bool(true)));
        assert_eq!(tree.as_f64(), 1.0);
    }

    #[test]
    fn test_property_tree_integer() {
        let tree = PropertyTree::integer(42);
        assert!(tree.is_number());
        assert_eq!(tree.as_f64(), 42.0);
        if let PropertyTree::Number(Number::Integer(n)) = tree {
            assert_eq!(n, 42);
        } else {
            panic!("Expected integer");
        }
    }

    #[test]
    fn test_property_tree_float() {
        let tree = PropertyTree::float(std::f64::consts::PI);
        assert!(tree.is_number());
        assert!((tree.as_f64() - std::f64::consts::PI).abs() < f64::EPSILON);
    }

    #[test]
    fn test_property_tree_string() {
        let tree = PropertyTree::string("hello");
        assert!(tree.is_string());
        assert_eq!(tree.as_str(), "hello");
    }

    #[test]
    fn test_property_tree_array() {
        let tree = PropertyTree::array(vec![
            PropertyTree::integer(1),
            PropertyTree::integer(2),
            PropertyTree::integer(3),
        ]);
        assert!(tree.is_array());
        assert_eq!(tree.len(), 3);
        assert!(!tree.is_empty());

        assert_eq!(tree.get_index(0).unwrap().as_f64(), 1.0);
        assert_eq!(tree.get_index(1).unwrap().as_f64(), 2.0);
        assert_eq!(tree.get_index(2).unwrap().as_f64(), 3.0);
        assert!(tree.get_index(3).is_none());
    }

    #[test]
    fn test_property_tree_object() {
        let tree = PropertyTree::object(vec![
            ("name".to_string(), PropertyTree::string("Alice")),
            ("age".to_string(), PropertyTree::integer(30)),
        ]);
        assert!(tree.is_object());
        assert_eq!(tree.len(), 2);

        let name = tree.get_field("name").unwrap();
        assert_eq!(name.as_str(), "Alice");

        let age = tree.get_field("age").unwrap();
        assert_eq!(age.as_f64(), 30.0);

        assert!(tree.get_field("missing").is_none());
    }

    #[test]
    fn test_property_tree_nested() {
        let tree = PropertyTree::object(vec![(
            "user".to_string(),
            PropertyTree::object(vec![
                ("name".to_string(), PropertyTree::string("Bob")),
                (
                    "address".to_string(),
                    PropertyTree::object(vec![(
                        "city".to_string(),
                        PropertyTree::string("Berlin"),
                    )]),
                ),
            ]),
        )]);

        let user = tree.get_field("user").unwrap();
        let name = user.get_field("name").unwrap();
        assert_eq!(name.as_str(), "Bob");

        let address = user.get_field("address").unwrap();
        let city = address.get_field("city").unwrap();
        assert_eq!(city.as_str(), "Berlin");
    }

    #[test]
    fn test_property_tree_equality() {
        let a = PropertyTree::integer(42);
        let b = PropertyTree::integer(42);
        let c = PropertyTree::integer(43);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_property_tree_default() {
        let tree = PropertyTree::default();
        assert!(tree.is_null());
    }

    #[test]
    fn test_number_conversions() {
        let int_num = Number::from(42i64);
        assert!(int_num.is_integer());
        assert_eq!(int_num.as_f64(), 42.0);

        let float_num = Number::from(std::f64::consts::PI);
        assert!(!float_num.is_integer());
        assert!((float_num.as_f64() - std::f64::consts::PI).abs() < f64::EPSILON);
    }
}
