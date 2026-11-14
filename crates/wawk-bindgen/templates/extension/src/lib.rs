//! wawk-EXTENSIONNAME — EXTENSION_DESCRIPTION
//!
//! ## Extension Convention
//!
//! - `__meta__` returns JSON metadata with optional `requires` for dependencies
//! - Unknown functions return empty string (let other extensions handle them)
//!

wit_bindgen::generate!({
    path: "wit",
    world: "wawk-extension",
});

// ============================================================================
// Extension Core Logic
// ============================================================================

/// Extension dispatch — routes function calls to implementations.
fn extension_call(name: &str, args: &[String]) -> Option<String> {
    match name {
        // Extension metadata — required by all extensions
        "__meta__" => {
            // Add "requires": [...] to declare dependencies on other extensions
            Some(r#"{"name":"wawk-EXTENSIONNAME","version":"0.1.0","description":"EXTENSION_DESCRIPTION"}"#.to_string())
        }

        // === Extension functions below ===

        // Example function: replace with your extension's actual functions
        "EXTENSIONNAME_hello" => {
            let who = args.first().map(|s| s.as_str()).unwrap_or("world");
            Some(format!("Hello from EXTENSIONNAME: {}", who))
        }

        _ => None, // Unknown function — let other extensions handle it
    }
}

// ============================================================================
// WIT Guest Implementation (wasm32 only)
// ============================================================================

#[cfg(target_arch = "wasm32")]
struct WawkExtension;

#[cfg(target_arch = "wasm32")]
impl exports::wawk::extensions::extensionname_functions::Guest for WawkExtension {
    fn call(name: String, args: Vec<String>) -> Option<String> {
        extension_call(&name, &args)
    }
}

#[cfg(target_arch = "wasm32")]
export!(WawkExtension);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_returns_metadata() {
        let result = extension_call("__meta__", &[]);
        assert!(result.is_some());
        let json = result.unwrap();
        assert!(json.contains("wawk-EXTENSIONNAME"));
        assert!(json.contains("0.1.0"));
    }

    #[test]
    fn test_hello_function() {
        let result = extension_call("EXTENSIONNAME_hello", &["world".to_string()]);
        assert_eq!(result, Some("Hello from EXTENSIONNAME: world".to_string()));
    }

    #[test]
    fn test_hello_default_arg() {
        let result = extension_call("EXTENSIONNAME_hello", &[]);
        assert_eq!(result, Some("Hello from EXTENSIONNAME: world".to_string()));
    }

    #[test]
    fn test_unknown_function_returns_none() {
        let result = extension_call("nonexistent_function", &["data".to_string()]);
        assert!(result.is_none());
    }
}
