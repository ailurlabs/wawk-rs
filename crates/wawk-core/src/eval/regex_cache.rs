//! Regex compilation, caching, and pattern matching for AWK.

use regex::Regex;
use rustc_hash::FxHashMap;
use crate::error::{AwkResult, AwkError};

const REGEX_CACHE_SIZE: usize = 512;

pub struct RegexCache {
    pub cache: FxHashMap<String, Regex>,
    access_order: Vec<String>,
}

impl RegexCache {
    pub fn new() -> Self {
        Self {
            cache: FxHashMap::default(),
            access_order: Vec::new(),
        }
    }

    pub fn get_or_compile(&mut self, pattern: &str) -> AwkResult<&Regex> {
        if self.cache.contains_key(pattern) {
            if let Some(pos) = self.access_order.iter().position(|p| p == pattern) {
                self.access_order.remove(pos);
            }
            self.access_order.push(pattern.to_string());
            return Ok(self.cache.get(pattern).unwrap());
        }

        let regex = Regex::new(pattern).map_err(|e| {
            AwkError::RuntimeError(format!("Invalid regex '{}': {}", pattern, e))
        })?;

        if self.cache.len() >= REGEX_CACHE_SIZE {
            if let Some(oldest) = self.access_order.first().cloned() {
                self.cache.remove(&oldest);
                self.access_order.remove(0);
            }
        }

        self.access_order.push(pattern.to_string());
        self.cache.insert(pattern.to_string(), regex);

        Ok(self.cache.get(pattern).unwrap())
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.access_order.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for RegexCache {
    fn default() -> Self {
        Self::new()
    }
}
