use std::collections::HashMap;

/// Registry for plugin-provided types.
/// Plugins register type tags (e.g., "@date", "@grid") and the engine
/// recognizes them for typeof() and display purposes.
pub struct PluginTypeRegistry {
    tag_to_type: HashMap<String, String>,
}

impl PluginTypeRegistry {
    pub fn new() -> Self {
        Self {
            tag_to_type: HashMap::new(),
        }
    }

    /// Register a plugin-provided type.
    pub fn register(&mut self, type_name: &str, type_tag: &str, _provider: &str) {
        self.tag_to_type
            .insert(type_tag.to_string(), type_name.to_string());
    }

    /// Check if a string value is a tagged plugin type.
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

impl Default for PluginTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
