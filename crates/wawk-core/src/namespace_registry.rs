//! Namespace registry for plugin function scoping.
//!
//! Each plugin declares a namespace in its metadata. The registry maps
//! namespace names to plugin indices and supports:
//! - Default namespace resolution (unqualified calls)
//! - Qualified resolution (namespace.func())
//! - Collision detection (two plugins claiming the same namespace)

use rustc_hash::FxHashMap;

/// Registry mapping namespace names to plugin indices.
#[derive(Debug, Default)]
pub struct NamespaceRegistry {
    /// namespace name -> plugin index in the plugin registry
    namespaces: FxHashMap<String, usize>,
    /// Active default namespace (set via @plugin directive)
    default_namespace: Option<String>,
}

impl NamespaceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            namespaces: FxHashMap::default(),
            default_namespace: None,
        }
    }

    /// Register a namespace for a plugin. Returns Err if the namespace
    /// is already claimed by a different plugin.
    pub fn register(&mut self, namespace: &str, plugin_idx: usize) -> Result<(), String> {
        if let Some(&existing) = self.namespaces.get(namespace) {
            if existing != plugin_idx {
                return Err(format!(
                    "namespace '{}' already registered by plugin index {}, cannot reassign to {}",
                    namespace, existing, plugin_idx
                ));
            }
            return Ok(());
        }
        self.namespaces.insert(namespace.to_string(), plugin_idx);
        Ok(())
    }

    /// Set the default namespace for unqualified function resolution.
    pub fn set_default(&mut self, namespace: &str) {
        self.default_namespace = Some(namespace.to_string());
    }

    /// Clear the default namespace.
    pub fn clear_default(&mut self) {
        self.default_namespace = None;
    }

    /// Get the current default namespace, if any.
    pub fn default_namespace(&self) -> Option<&str> {
        self.default_namespace.as_deref()
    }

    /// Resolve an unqualified function name. First checks the default namespace.
    /// Returns (namespace, plugin_idx) if found.
    pub fn resolve(&self, _name: &str) -> Option<(String, usize)> {
        if let Some(ref default_ns) = self.default_namespace {
            if let Some(&idx) = self.namespaces.get(default_ns) {
                return Some((default_ns.clone(), idx));
            }
        }
        None
    }

    /// Resolve a qualified namespace.func() call.
    /// Returns the plugin index if the namespace is registered.
    pub fn resolve_qualified(&self, ns: &str, _name: &str) -> Option<usize> {
        self.namespaces.get(ns).copied()
    }

    /// Check if a namespace is registered.
    pub fn has_namespace(&self, ns: &str) -> bool {
        self.namespaces.contains_key(ns)
    }

    /// Get the plugin index for a namespace.
    pub fn get_plugin_idx(&self, ns: &str) -> Option<usize> {
        self.namespaces.get(ns).copied()
    }

    /// Get all registered namespace names.
    pub fn namespace_names(&self) -> Vec<&str> {
        self.namespaces.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_resolve() {
        let mut reg = NamespaceRegistry::new();
        assert!(reg.register("formula", 0).is_ok());
        assert!(reg.register("crypto", 1).is_ok());
        assert_eq!(reg.resolve_qualified("formula", "sum"), Some(0));
        assert_eq!(reg.resolve_qualified("crypto", "sha256"), Some(1));
        assert_eq!(reg.resolve_qualified("unknown", "foo"), None);
    }

    #[test]
    fn test_collision_detection() {
        let mut reg = NamespaceRegistry::new();
        assert!(reg.register("formula", 0).is_ok());
        let result = reg.register("formula", 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already registered"));
    }

    #[test]
    fn test_same_plugin_reregister() {
        let mut reg = NamespaceRegistry::new();
        assert!(reg.register("formula", 0).is_ok());
        assert!(reg.register("formula", 0).is_ok());
    }

    #[test]
    fn test_default_namespace() {
        let mut reg = NamespaceRegistry::new();
        reg.register("formula", 0).unwrap();
        reg.set_default("formula");
        assert_eq!(reg.default_namespace(), Some("formula"));
        let resolved = reg.resolve("sum");
        assert!(resolved.is_some());
        let (ns, idx) = resolved.unwrap();
        assert_eq!(ns, "formula");
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_clear_default() {
        let mut reg = NamespaceRegistry::new();
        reg.register("formula", 0).unwrap();
        reg.set_default("formula");
        reg.clear_default();
        assert_eq!(reg.default_namespace(), None);
        assert!(reg.resolve("sum").is_none());
    }

    #[test]
    fn test_has_namespace() {
        let mut reg = NamespaceRegistry::new();
        reg.register("formula", 0).unwrap();
        assert!(reg.has_namespace("formula"));
        assert!(!reg.has_namespace("crypto"));
    }

    #[test]
    fn test_namespace_names() {
        let mut reg = NamespaceRegistry::new();
        reg.register("formula", 0).unwrap();
        reg.register("crypto", 1).unwrap();
        let mut names = reg.namespace_names();
        names.sort();
        assert_eq!(names, vec!["crypto", "formula"]);
    }
}
