//! Bridge between FormatDispatcher trait and WIT external-functions.
//!
//! Allows Wasm plugins to provide format detection/parsing/serialization
//! via the existing WIT plugin bridge. Format plugins use convention-based
//! function names: `__detect__`, `__parse__`, `__serialize__`.

use std::sync::Mutex;

use crate::error::{AwkError, AwkResult};
use crate::traits::{FormatDispatcher, FunctionDispatcher};
use crate::types::PropertyTree;

/// A FormatDispatcher that delegates to a WIT function handler.
///
/// This bridges the format plugin system with the existing WIT plugin bridge.
/// The WIT plugin exports `__detect__`, `__parse__`, `__serialize__` functions
/// via the `external-functions` interface.
///
/// The handler is wrapped in a `Mutex` because `FormatDispatcher` methods
/// take `&self` while `FunctionDispatcher::dispatch` requires `&mut self`.
pub struct WitFormatDispatcher {
    name: String,
    handler: Mutex<Box<dyn FunctionDispatcher + Send + Sync>>,
    priority: u32,
}

impl WitFormatDispatcher {
    /// Create a new WIT format dispatcher.
    ///
    /// # Arguments
    /// * `name` - The format name (e.g., "xml", "yaml")
    /// * `handler` - A FunctionDispatcher that handles `__detect__`, `__parse__`, `__serialize__`
    /// * `priority` - Detection priority (lower = higher priority)
    pub fn new(name: String, handler: Box<dyn FunctionDispatcher + Send + Sync>, priority: u32) -> Self {
        Self { name, handler: Mutex::new(handler), priority }
    }
}

impl crate::traits::PluginCapability for WitFormatDispatcher {
    fn capability_name(&self) -> &'static str {
        "format_handler"
    }
}

impl FormatDispatcher for WitFormatDispatcher {
    fn name(&self) -> &str {
        &self.name
    }

    fn detect(&self, input: &str) -> bool {
        let mut handler = self.handler.lock().unwrap();
        match handler.dispatch("__detect__", &[input.to_string()]) {
            Ok(Some(result)) => result == self.name,
            _ => false,
        }
    }

    fn parse(&self, input: &str) -> AwkResult<PropertyTree> {
        let mut handler = self.handler.lock().unwrap();
        match handler.dispatch("__parse__", &[input.to_string()]) {
            Ok(Some(json)) => PropertyTree::from_json(&json)
                .map_err(|e| AwkError::RuntimeError(format!("WIT format parse error: {}", e))),
            Ok(None) => Err(AwkError::RuntimeError(
                "WIT format plugin returned None".into(),
            )),
            Err(e) => Err(e),
        }
    }

    fn serialize(&self, tree: &PropertyTree) -> Option<String> {
        let json = tree.to_json();
        let mut handler = self.handler.lock().unwrap();
        match handler.dispatch("__serialize__", &[json]) {
            Ok(Some(result)) => Some(result),
            _ => None,
        }
    }

    fn priority(&self) -> u32 {
        self.priority
    }
}
