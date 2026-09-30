//! Plugin dependency resolution.
//!
//! Given a set of plugin metadata, builds a dependency graph and produces
//! a topological ordering. Plugins with unsatisfied dependencies are
//! reported as skipped (not errored) — the host logs a warning and
//! continues without them.

use crate::plugin_meta::PluginMeta;
use std::collections::{HashMap, HashSet, VecDeque};

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
    let name_to_meta: HashMap<&str, &PluginMeta> =
        plugins.iter().map(|m| (m.name.as_str(), m)).collect();

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

    // Kahn's algorithm: start with nodes that have 0 in-degree (no deps).
    // Iterate `plugins` (stable registration order) rather than the `in_deg`
    // HashMap: std HashMap uses RandomState, so iterating it would make the
    // tie-break order among dependency-free plugins -- and therefore the
    // round-robin dispatch order -- non-deterministic across process runs.
    let mut queue: VecDeque<&str> = VecDeque::new();
    for m in &plugins {
        if in_deg.get(m.name.as_str()) == Some(&0) {
            queue.push_back(m.name.as_str());
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
    // Names confirmed active so far. Because `order` is topological
    // (dependencies before dependents), a single pass cascades skips
    // transitively: if B is skipped, any C that requires B finds B absent
    // from `active_names` and is skipped in turn (fixes the cascade gap where
    // a dependent of a resolution-skipped plugin still activated).
    let mut active_names: HashSet<&str> = HashSet::new();

    // Add ordered plugins (deps satisfied, no cycle)
    for (idx, &name) in order.iter().enumerate() {
        let meta = name_to_meta[name].clone();
        // Dependencies that are not loaded at all.
        let missing: Vec<String> = meta
            .requires
            .iter()
            .filter(|r| !name_to_meta.contains_key(r.as_str()))
            .cloned()
            .collect();
        // Dependencies that exist in the set but were skipped, so they will
        // never be initialized — dependents must be skipped too.
        let skipped_deps: Vec<String> = meta
            .requires
            .iter()
            .filter(|r| {
                name_to_meta.contains_key(r.as_str()) && !active_names.contains(r.as_str())
            })
            .cloned()
            .collect();
        if missing.is_empty() && skipped_deps.is_empty() {
            active_names.insert(name);
            active.push(ResolvedPlugin { meta, order: idx });
        } else {
            // E2: Specific error message per missing/skipped dependency
            let plugin_name = meta.name.clone();
            let mut reasons: Vec<String> = missing
                .iter()
                .map(|dep| format!("Plugin '{}' requires '{}' but '{}' is not loaded", plugin_name, dep, dep))
                .collect();
            reasons.extend(skipped_deps.iter().map(|dep| {
                format!(
                    "Plugin '{}' requires '{}' but '{}' was skipped (its own dependencies are unsatisfied)",
                    plugin_name, dep, dep
                )
            }));
            skipped.push(SkippedPlugin {
                meta,
                reason: reasons.join("; "),
            });
        }
    }

    // E2: Skip cycle members with full cycle path in error message
    // Find actual cycles by tracing dependency chains
    let cycle_members: Vec<&PluginMeta> = plugins
        .iter()
        .filter(|m| !ordered_set.contains(m.name.as_str()) && !skipped.iter().any(|s| s.meta.name == m.name))
        .collect();
    
    for m in cycle_members {
        // Trace the cycle path starting from this plugin
        let mut path = vec![m.name.as_str()];
        let mut current = m.name.as_str();
        let mut found_cycle = false;
        
        // Follow dependencies until we find a node already in our path
        for _ in 0..plugins.len() {
            if let Some(dep_meta) = name_to_meta.get(current) {
                // Find first dependency that's also a cycle member
                for dep in &dep_meta.requires {
                    if name_to_meta.contains_key(dep.as_str()) && !ordered_set.contains(dep.as_str()) {
                        if path.contains(&dep.as_str()) {
                            // Found the cycle - build the path description
                            let cycle_start = path.iter().position(|&p| p == dep.as_str()).unwrap();
                            let cycle_path: Vec<&str> = path[cycle_start..].to_vec();
                            let mut desc = cycle_path.join(" → ");
                            desc.push_str(" → ");
                            desc.push_str(dep);
                            found_cycle = true;
                            skipped.push(SkippedPlugin {
                                meta: m.clone(),
                                reason: format!("Circular dependency: {}", desc),
                            });
                            break;
                        }
                        path.push(dep.as_str());
                        current = dep.as_str();
                        break;
                    }
                }
                if found_cycle {
                    break;
                }
            } else {
                break;
            }
        }
        
        // Fallback if we couldn't trace the cycle
        if !found_cycle && !skipped.iter().any(|s| s.meta.name == m.name) {
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
            namespace: None,
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
        let result = resolve(vec![meta("c", &["b"]), meta("a", &[]), meta("b", &["a"])]);
        assert_eq!(result.active.len(), 3);
        assert!(result.skipped.is_empty());
        let names: Vec<&str> = result.active.iter().map(|p| p.meta.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|&x| x == n).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }

    #[test]
    fn missing_dep_skipped() {
        let result = resolve(vec![meta("a", &[]), meta("b", &["missing"])]);
        assert_eq!(result.active.len(), 1);
        assert_eq!(result.active[0].meta.name, "a");
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].meta.name, "b");
    }

    #[test]
    fn cycle_detected() {
        let result = resolve(vec![meta("a", &["b"]), meta("b", &["a"])]);
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

    // E2: Enhanced tests per Lyra spec

    #[test]
    fn e2_missing_dep_specific_error() {
        // E2: "Plugin 'formula' requires 'crypto' but 'crypto' is not loaded"
        let result = resolve(vec![
            meta("formula", &["crypto"]),
        ]);
        assert_eq!(result.active.len(), 0);
        assert_eq!(result.skipped.len(), 1);
        let reason = &result.skipped[0].reason;
        assert!(reason.contains("Plugin 'formula' requires 'crypto'"), 
                "error should be specific: {}", reason);
        assert!(reason.contains("'crypto' is not loaded"), 
                "error should mention not loaded: {}", reason);
    }

    #[test]
    fn e2_circular_dep_full_path() {
        // E2: "Circular dependency: formula → crypto → formula"
        let result = resolve(vec![
            meta("formula", &["crypto"]),
            meta("crypto", &["formula"]),
        ]);
        assert_eq!(result.active.len(), 0);
        assert_eq!(result.skipped.len(), 2);
        // At least one should have the full cycle path
        let has_cycle_path = result.skipped.iter().any(|s| {
            s.reason.contains("Circular dependency:") && 
            s.reason.contains("→")
        });
        assert!(has_cycle_path, "should have full cycle path: {:?}", 
                result.skipped.iter().map(|s| &s.reason).collect::<Vec<_>>());
    }

    #[test]
    fn e2_chain_loads_in_order() {
        // E2: Chain A→B→C → loads in order C, B, A
        let result = resolve(vec![
            meta("a", &["b"]),
            meta("b", &["c"]),
            meta("c", &[]),
        ]);
        assert_eq!(result.active.len(), 3);
        let names: Vec<&str> = result.active.iter().map(|p| p.meta.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|&x| x == n).unwrap();
        // c should load first (no deps), then b, then a
        assert!(pos("c") < pos("b"), "c should load before b");
        assert!(pos("b") < pos("a"), "b should load before a");
    }

    #[test]
    fn e2_diamond_loads_correctly() {
        // E2: Diamond A→B, A→C, B→D, C→D → loads D first, then B/C, then A
        let result = resolve(vec![
            meta("a", &["b", "c"]),
            meta("b", &["d"]),
            meta("c", &["d"]),
            meta("d", &[]),
        ]);
        assert_eq!(result.active.len(), 4);
        let names: Vec<&str> = result.active.iter().map(|p| p.meta.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|&x| x == n).unwrap();
        // d should load first
        assert!(pos("d") < pos("b"), "d should load before b");
        assert!(pos("d") < pos("c"), "d should load before c");
        // b and c should load before a
        assert!(pos("b") < pos("a"), "b should load before a");
        assert!(pos("c") < pos("a"), "c should load before a");
    }

    #[test]
    fn cascade_skip_to_transitive_dependents() {
        // F5 regression: c requires b, b requires a, a requires a dep that is
        // not loaded. a is skipped (missing dep) -> b must be skipped (its dep
        // a was skipped) -> c must be skipped (its dep b was skipped).
        // Previously only __init__ failures cascaded, so b and c wrongly
        // activated even though their dependencies never initialized.
        let result = resolve(vec![
            meta("a", &["ghost"]),
            meta("b", &["a"]),
            meta("c", &["b"]),
        ]);
        assert!(
            result.active.is_empty(),
            "no plugin should activate when the root dep is missing"
        );
        assert_eq!(result.skipped.len(), 3);
        let skipped_names: Vec<&str> =
            result.skipped.iter().map(|s| s.meta.name.as_str()).collect();
        for n in ["a", "b", "c"] {
            assert!(skipped_names.contains(&n), "{n} should be skipped");
        }
        let b = result.skipped.iter().find(|s| s.meta.name == "b").unwrap();
        assert!(
            b.reason.contains("'a' was skipped"),
            "b should report skipped dep a: {}",
            b.reason
        );
        let c = result.skipped.iter().find(|s| s.meta.name == "c").unwrap();
        assert!(
            c.reason.contains("'b' was skipped"),
            "c should report skipped dep b: {}",
            c.reason
        );
    }
}
