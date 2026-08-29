//! Variable scoping and management for AWK execution.
//!
//! Handles scope stack operations, variable access, and array management.

use rustc_hash::FxHashMap;
use super::Value;
use crate::error::AwkResult;

pub struct ScopeManager {
    pub scope_stack: Vec<FxHashMap<String, Value>>,
    pub arrays: FxHashMap<String, FxHashMap<String, Value>>,
}

impl ScopeManager {
    pub fn new() -> Self {
        Self {
            scope_stack: vec![FxHashMap::default()],
            arrays: FxHashMap::default(),
        }
    }

    pub fn push_scope(&mut self) {
        self.scope_stack.push(FxHashMap::default());
    }

    pub fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    pub fn get_variable(&self, name: &str) -> Value {
        for scope in self.scope_stack.iter().rev() {
            if let Some(val) = scope.get(name) {
                return val.clone();
            }
        }
        Value::Uninit
    }

    pub fn get_variable_f64(&self, name: &str) -> f64 {
        self.get_variable(name).as_number()
    }

    pub fn set_var(&mut self, name: String, value: Value) {
        if let Some(scope) = self.scope_stack.last_mut() {
            scope.insert(name, value);
        }
    }

    pub fn set_var_str(&mut self, name: &str, value: Value) {
        self.set_var(name.to_string(), value);
    }

    pub fn array_insert(&mut self, arr_name: &str, key: String, val: Value) -> AwkResult<()> {
        let arr = self.arrays.entry(arr_name.to_string()).or_default();
        arr.insert(key, val);
        Ok(())
    }

    pub fn array_len(&self, arr_name: &str) -> usize {
        self.arrays.get(arr_name).map(|arr| arr.len()).unwrap_or(0)
    }

    pub fn array_contains(&self, arr_name: &str, key: &str) -> bool {
        self.arrays.get(arr_name).map(|arr| arr.contains_key(key)).unwrap_or(false)
    }

    pub fn delete_array(&mut self, arr_name: &str) {
        self.arrays.remove(arr_name);
    }

    pub fn delete_array_element(&mut self, arr_name: &str, key: &str) {
        if let Some(arr) = self.arrays.get_mut(arr_name) {
            arr.remove(key);
        }
    }

    pub fn array_keys(&self, arr_name: &str) -> Vec<String> {
        self.arrays.get(arr_name).map(|arr| arr.keys().cloned().collect()).unwrap_or_default()
    }
}

impl Default for ScopeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_stack() {
        let mut mgr = ScopeManager::new();
        
        // Set in global scope
        mgr.set_var("x".to_string(), Value::Number(42.0));
        assert_eq!(mgr.get_variable("x").as_number(), 42.0);
        
        // Push new scope
        mgr.push_scope();
        mgr.set_var("x".to_string(), Value::Number(100.0));
        assert_eq!(mgr.get_variable("x").as_number(), 100.0);
        
        // Pop scope
        mgr.pop_scope();
        assert_eq!(mgr.get_variable("x").as_number(), 42.0);
    }

    #[test]
    fn test_array_operations() {
        let mut mgr = ScopeManager::new();
        
        mgr.array_insert("arr", "key1".to_string(), Value::Number(1.0)).unwrap();
        mgr.array_insert("arr", "key2".to_string(), Value::Number(2.0)).unwrap();
        
        assert_eq!(mgr.array_len("arr"), 2);
        assert!(mgr.array_contains("arr", "key1"));
        assert!(!mgr.array_contains("arr", "key3"));
        
        mgr.delete_array_element("arr", "key1");
        assert_eq!(mgr.array_len("arr"), 1);
        
        mgr.delete_array("arr");
        assert_eq!(mgr.array_len("arr"), 0);
    }
}
