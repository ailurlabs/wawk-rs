//! Plugin dependency resolution.
//!
//! Given a set of plugin metadata, builds a dependency graph and produces
//! a topological ordering. Plugins with unsatisfied dependencies are
//! reported as skipped (not errored) — the host logs a warning and
//! continues without them.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::plugin_meta::PluginMeta;

/// A plugin that has been resolved and is ready for activation.
#[derive(Debug)]
pub struct ResolvedPlugin {
    pub meta: PluginMeta,
    /// Index into the activation order (0 = first).
    pub order: usize,
}

/// Result of resolving a set of plugins.
#[derive(Debug)]
pub struct ResolutionResult {
    /// Plugins that are fully resolved, in dependency order.
    pub active: Vec<ResolvedPlugin>,
    /// Plugins that were skipped because a dependency is missing.
    pub skipped: Vec<SkippedPlugin>,
}

/// A plugin that could not be activated.
#[derive(Debug)]
pub struct SkippedPlugin {
    pub meta: PluginMeta,
    pub reason: String,
}

/// Resolve plugin dependencies and produce an activation order.
///
/// Plugins with no unmet dependencies are activated first (dependencies before
/// dependents). Plugins with missing dependencies are skipped with a warning.
///
/// Cycle detection: if a dependency cycle is found, all plugins in the cycle
/// are skipped.
pub fn resolve(plugins: Vec<PluginMeta>) -> ResolutionResult {
    let name_to_meta: HashMap<&str, &PluginMeta> = plugins
        .iter()
        .map(|m| (m.name.as_str(), m))
        .collect();

    // in_degree[X] = number of X's dependencies that exist in the plugin set
    let mut in_deg: HashMap<&str, usize> = HashMap::new();
    for m in &plugins {
        in_deg.entry(&m.name).or_insert(0);
    }
    for m in &plugins {
        for dep in &m.requires {
            if name_to_meta.contains_key(dep.as_str()) {
                *in_deg.entry(m.name.as_str()).or_insert(0) += 1;
            }
        }
    }

    // Kahn's algorithm: start with nodes that have 0 in-degree (no deps)
    let mut queue: VecDeque<&str> = VecDeque::new();
    for (&name, &deg) in &in_deg {
        if deg == 0 {
            queue.push_back(name);
        }
    }

    let mut order: Vec<&str> = Vec::new();
    while let Some(name) = queue.pop_front() {
        order.push(name);
        // For each plugin that depends on `name`, decrement its in_degree
        for m in &plugins {
            if m.requires.iter().any(|r| r == name) {
                if let Some(deg) = in_deg.get_mut(m.name.as_str()) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(&m.name);
                    }
                }
            }
        }
    }

    let ordered_set: HashSet<&str> = order.iter().copied().collect();
    let mut active = Vec::new();
    let mut skipped = Vec::new();

    // Add ordered plugins (deps satisfied, no cycle)
    for (idx, &name) in order.iter().enumerate() {
        let meta = name_to_meta[name].clone();
        let missing: Vec<String> = meta.requires.iter()
            .filter(|r| !name_to_meta.contains_key(r.as_str()))
            .cloned()
            .collect();
        if missing.is_empty() {
            active.push(ResolvedPlugin { meta, order: idx });
        } else {
            skipped.push(SkippedPlugin {
                meta,
                reason: format!("missing dependencies: {}", missing.join(", ")),
            });
        }
    }

    // Skip cycle members
    for m in &plugins {
        if !ordered_set.contains(m.name.as_str())
            && !skipped.iter().any(|s| s.meta.name == m.name)
        {
            skipped.push(SkippedPlugin {
                meta: m.clone(),
                reason: "dependency cycle detected".into(),
            });
        }
    }

    ResolutionResult { active, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, requires: &[&str]) -> PluginMeta {
        PluginMeta {
            name: name.into(),
            version: "0.1.0".into(),
            requires: requires.iter().map(|s| s.to_string()).collect(),
            description: None,
            functions: Vec::new(),
            capabilities: Vec::new(),
            types: Vec::new(),
            auto_context_functions: Vec::new(),
            api_version: None,
            author: None,
            homepage: None,
        }
    }

    #[test]
    fn no_deps() {
        let result = resolve(vec![meta("a", &[]), meta("b", &[])]);
        assert_eq!(result.active.len(), 2);
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn simple_chain() {
        let result = resolve(vec![
            meta("c", &["b"]),
            meta("a", &[]),
            meta("b", &["a"]),
        ]);
        assert_eq!(result.active.len(), 3);
        assert!(result.skipped.is_empty());
        let names: Vec<&str> = result.active.iter().map(|p| p.meta.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|&x| x == n).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }

    #[test]
    fn missing_dep_skipped() {
        let result = resolve(vec![
            meta("a", &[]),
            meta("b", &["missing"]),
        ]);
        assert_eq!(result.active.len(), 1);
        assert_eq!(result.active[0].meta.name, "a");
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].meta.name, "b");
    }

    #[test]
    fn cycle_detected() {
        let result = resolve(vec![
            meta("a", &["b"]),
            meta("b", &["a"]),
        ]);
        // Both in cycle should be skipped
        assert_eq!(result.active.len(), 0);
        assert_eq!(result.skipped.len(), 2);
    }

    #[test]
    fn diamond_deps() {
        let result = resolve(vec![
            meta("d", &["b", "c"]),
            meta("a", &[]),
            meta("b", &["a"]),
            meta("c", &["a"]),
        ]);
        assert_eq!(result.active.len(), 4);
        let names: Vec<&str> = result.active.iter().map(|p| p.meta.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|&x| x == n).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("a") < pos("c"));
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn empty_input() {
        let result = resolve(vec![]);
        assert!(result.active.is_empty());
        assert!(result.skipped.is_empty());
    }
}
