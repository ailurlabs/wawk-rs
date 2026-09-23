//! wawk-PLUGINNAME — PLUGIN_DESCRIPTION
//!
//! ## Plugin Convention
//!
//! - `__meta__` returns JSON metadata with optional `requires` for dependencies
//! - Unknown functions return empty string (let other plugins handle them)
//!

wit_bindgen::generate!({
    path: "wit",
    world: "external-functions",
});

// ============================================================================
// Plugin Core Logic
// ============================================================================

/// Plugin dispatch — routes function calls to implementations.
fn plugin_call(name: &str, args: &[String]) -> Option<String> {
    match name {
        // Plugin metadata — required by all plugins
        "__meta__" => {
            // Add "requires": [...] to declare dependencies on other plugins
            Some(r#"{"name":"wawk-PLUGINNAME","version":"0.1.0","description":"PLUGIN_DESCRIPTION"}"#.to_string())
        }

        // === Plugin functions below ===

        // Example function: replace with your plugin's actual functions
        "PLUGINNAME_hello" => {
            let who = args.first().map(|s| s.as_str()).unwrap_or("world");
            Some(format!("Hello from PLUGINNAME: {}", who))
        }

        _ => None, // Unknown function — let other plugins handle it
    }
}

// ============================================================================
// WIT Guest Implementation (wasm32 only)
// ============================================================================

#[cfg(target_arch = "wasm32")]
struct WawkPlugin;

#[cfg(target_arch = "wasm32")]
impl Guest for WawkPlugin {
    fn call(name: String, args: Vec<String>) -> Option<String> {
        plugin_call(&name, &args)
    }
}

#[cfg(target_arch = "wasm32")]
export!(WawkPlugin);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_returns_metadata() {
        let result = plugin_call("__meta__", &[]);
        assert!(result.is_some());
        let json = result.unwrap();
        assert!(json.contains("wawk-PLUGINNAME"));
        assert!(json.contains("0.1.0"));
    }

    #[test]
    fn test_hello_function() {
        let result = plugin_call("PLUGINNAME_hello", &["world".to_string()]);
        assert_eq!(result, Some("Hello from PLUGINNAME: world".to_string()));
    }

    #[test]
    fn test_hello_default_arg() {
        let result = plugin_call("PLUGINNAME_hello", &[]);
        assert_eq!(result, Some("Hello from PLUGINNAME: world".to_string()));
    }

    #[test]
    fn test_unknown_function_returns_none() {
        let result = plugin_call("nonexistent_function", &["data".to_string()]);
        assert!(result.is_none());
    }
}
