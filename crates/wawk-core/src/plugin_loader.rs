//! Plugin lifecycle loader: discovery → metadata → dependency resolution → init → dispatch.
//!
//! The `PluginLoader` aggregates multiple plugins behind a single
//! `AwkExternalFunction` handler. After dependency resolution, every plugin
//! receives an `__init__` call in dependency order for initialization.
//! Plugins without `__init__` are unaffected.

use rustc_hash::FxHashMap;
use std::sync::Arc;

use crate::error::AwkResult;
use crate::plugin_meta::PluginMeta;
use crate::plugin_resolver;
use crate::traits::AwkExternalFunction;

/// Dispatch callback: (function_name, args) -> result.
type DispatchFn = Arc<dyn Fn(&str, &[String]) -> AwkResult<Option<String>> + Send + Sync>;

/// A registered plugin: its metadata plus a dispatch callback.
///
/// The callback receives `(function_name, args)` and returns:
/// - `Ok(Some(result))` if handled
/// - `Ok(None)` if this plugin doesn't handle the function
/// - `Err(...)` on execution error
pub struct PluginEntry {
    pub meta: PluginMeta,
    pub dispatch: DispatchFn,
}

/// The central plugin lifecycle loader.
///
/// Implements `AwkExternalFunction` so it can be installed directly as the
/// evaluator's external function handler.
///
/// # Lifecycle
/// 1. `register()` — add plugins with metadata + dispatch
/// 2. `finalize()` — resolve deps, call `__init__` in order, build dispatch index
/// 3. `call_external_str()` — O(1) dispatch to the correct plugin
pub struct PluginLoader {
    /// Plugins in dependency order (after topological sort + init).
    plugins: Vec<PluginEntry>,
    /// function_name → index into `plugins` for O(1) dispatch.
    fn_index: FxHashMap<String, usize>,
    /// Aggregated auto-context functions from all active plugins.
    auto_ctx_fns: Vec<String>,
    /// Whether the loader has been finalized (resolved + indexed).
    finalized: bool,
    /// Pending registrations (before finalization).
    pending: Vec<PluginEntry>,
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginLoader {
    /// Create a new empty plugin loader.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            fn_index: FxHashMap::default(),
            auto_ctx_fns: Vec::new(),
            finalized: false,
            pending: Vec::new(),
        }
    }

    /// Register a plugin with its metadata and dispatch callback.
    ///
    /// Must be called before `finalize()`. Panics if already finalized.
    pub fn register(
        &mut self,
        meta: PluginMeta,
        dispatch: DispatchFn,
    ) {
        assert!(!self.finalized, "cannot register after finalize()");
        self.pending.push(PluginEntry { meta, dispatch });
    }

    /// Resolve dependencies, initialize plugins, build dispatch index.
    ///
    /// After this call, no more plugins can be registered.
    /// Returns warnings for any plugins that were skipped (missing deps,
    /// cycles, or init failures).
    ///
    /// # Init phase
    /// After dependency resolution, each active plugin receives an `__init__`
    /// call in dependency order (dependencies initialized before dependents).
    /// - `Ok(None)` → plugin has no init, treated as success
    /// - `Ok(Some(_))` → init succeeded
    /// - `Err(e)` → init failed, plugin is skipped with a warning
    pub fn finalize(&mut self) -> Vec<String> {
        assert!(!self.finalized, "already finalized");
        self.finalized = true;

        // Extract metas for dependency resolution
        let metas: Vec<PluginMeta> = self
            .pending
            .iter()
            .map(|p| clone_meta(&p.meta))
            .collect();

        // Resolve dependency order
        let resolution = plugin_resolver::resolve(metas);
        let mut warnings = Vec::new();

        for skipped in &resolution.skipped {
            warnings.push(format!(
                "plugin '{}' skipped: {}",
                skipped.meta.name, skipped.reason
            ));
        }

        // Reorder pending plugins according to resolution
        let mut ordered: Vec<PluginEntry> = Vec::with_capacity(resolution.active.len());
        for resolved in &resolution.active {
            if let Some(idx) = self
                .pending
                .iter()
                .position(|p| p.meta.name == resolved.meta.name)
            {
                ordered.push(self.pending.swap_remove(idx));
            }
        }

        // ── Init phase: call __init__ on each plugin in dependency order ──
        let mut init_ok: Vec<PluginEntry> = Vec::with_capacity(ordered.len());
        for entry in ordered {
            match (entry.dispatch)("__init__", &[]) {
                Ok(_) => init_ok.push(entry),
                Err(e) => {
                    warnings.push(format!(
                        "plugin '{}' skipped: __init__ failed: {}",
                        entry.meta.name, e
                    ));
                }
            }
        }

        // Build function → plugin index
        let mut fn_index: FxHashMap<String, usize> = FxHashMap::default();
        let mut auto_ctx_fns: Vec<String> = Vec::new();

        for (idx, entry) in init_ok.iter().enumerate() {
            for fn_name in &entry.meta.functions {
                fn_index.entry(fn_name.clone()).or_insert(idx);
            }
            auto_ctx_fns.extend(entry.meta.auto_context_functions.iter().cloned());
        }

        self.plugins = init_ok;
        self.fn_index = fn_index;
        self.auto_ctx_fns = auto_ctx_fns;
        self.pending.clear();

        warnings
    }

    /// Get the aggregated list of auto-context functions from all active plugins.
    pub fn auto_context_functions(&self) -> &[String] {
        &self.auto_ctx_fns
    }

    /// Get metadata for all active plugins (in dependency order).
    pub fn active_plugins(&self) -> Vec<&PluginMeta> {
        self.plugins.iter().map(|p| &p.meta).collect()
    }

    /// Find a plugin by name.
    pub fn find_plugin(&self, name: &str) -> Option<&PluginMeta> {
        self.plugins.iter().find(|p| p.meta.name == name).map(|p| &p.meta)
    }

    /// Find plugins that declare a specific capability.
    pub fn find_by_capability(&self, capability: &str) -> Vec<&PluginMeta> {
        self.plugins
            .iter()
            .filter(|p| p.meta.capabilities.iter().any(|c| c == capability))
            .map(|p| &p.meta)
            .collect()
    }

    /// Number of active plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are active.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

impl AwkExternalFunction for PluginLoader {
    fn call_external_str(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
        // O(1) dispatch via function index
        if let Some(&idx) = self.fn_index.get(name) {
            return (self.plugins[idx].dispatch)(name, args);
        }

        // Fallback: round-robin through plugins that don't declare functions
        // (or for functions not in the index)
        for entry in &self.plugins {
            if entry.meta.functions.is_empty() {
                match (entry.dispatch)(name, args)? {
                    Some(result) => return Ok(Some(result)),
                    None => continue,
                }
            }
        }

        Ok(None)
    }
}

/// Clone a PluginMeta (all fields are Clone-able).
fn clone_meta(m: &PluginMeta) -> PluginMeta {
    PluginMeta {
        name: m.name.clone(),
        version: m.version.clone(),
        requires: m.requires.clone(),
        description: m.description.clone(),
        functions: m.functions.clone(),
        capabilities: m.capabilities.clone(),
        types: m.types.clone(),
        auto_context_functions: m.auto_context_functions.clone(),
        api_version: m.api_version.clone(),
        author: m.author.clone(),
        homepage: m.homepage.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta(name: &str, functions: Vec<&str>) -> PluginMeta {
        PluginMeta {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            requires: vec![],
            description: None,
            functions: functions.iter().map(|s| s.to_string()).collect(),
            capabilities: vec![],
            types: vec![],
            auto_context_functions: vec![],
            api_version: None,
            author: None,
            homepage: None,
        }
    }

    fn make_meta_with_deps(
        name: &str,
        functions: Vec<&str>,
        deps: Vec<&str>,
    ) -> PluginMeta {
        PluginMeta {
            requires: deps.iter().map(|s| s.to_string()).collect(),
            ..make_meta(name, functions)
        }
    }

    fn noop_dispatch() -> DispatchFn {
        Arc::new(|_name, _args| Ok(None))
    }

    fn echo_dispatch(prefix: &str) -> DispatchFn {
        let p = prefix.to_string();
        Arc::new(move |name, args| {
            if args.is_empty() {
                Ok(Some(format!("{}:{}", p, name)))
            } else {
                Ok(Some(format!("{}:{}({})", p, name, args.join(","))))
            }
        })
    }

    fn init_echo_dispatch(prefix: &str) -> DispatchFn {
        let p = prefix.to_string();
        Arc::new(move |name, args| {
            if name == "__init__" {
                return Ok(Some(format!("{}:init_ok", p)));
            }
            if args.is_empty() {
                Ok(Some(format!("{}:{}", p, name)))
            } else {
                Ok(Some(format!("{}:{}({})", p, name, args.join(","))))
            }
        })
    }

    fn init_fail_dispatch(prefix: &str) -> DispatchFn {
        let p = prefix.to_string();
        Arc::new(move |name, _args| {
            if name == "__init__" {
                return Err(crate::error::AwkError::RuntimeError(format!("{}: init failed", p)));
            }
            Ok(None)
        })
    }

    #[test]
    fn test_empty_loader() {
        let mut loader = PluginLoader::new();
        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 0);
        assert!(loader.is_empty());
    }

    #[test]
    fn test_single_plugin_dispatch() {
        let mut loader = PluginLoader::new();
        let meta = make_meta("test-plugin", vec!["hello", "world"]);
        loader.register(meta, echo_dispatch("test"));
        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 1);

        let result = loader.call_external_str("hello", &["arg1".to_string()]).unwrap();
        assert_eq!(result, Some("test:hello(arg1)".to_string()));

        let result = loader.call_external_str("unknown", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_multi_plugin_dispatch() {
        let mut loader = PluginLoader::new();

        let meta_a = make_meta("plugin-a", vec!["fn_a1", "fn_a2"]);
        loader.register(meta_a, echo_dispatch("A"));

        let meta_b = make_meta("plugin-b", vec!["fn_b1"]);
        loader.register(meta_b, echo_dispatch("B"));

        loader.finalize();

        let result = loader.call_external_str("fn_a1", &[]).unwrap();
        assert_eq!(result, Some("A:fn_a1".to_string()));

        let result = loader.call_external_str("fn_b1", &[]).unwrap();
        assert_eq!(result, Some("B:fn_b1".to_string()));

        let result = loader.call_external_str("fn_c1", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_dependency_ordering() {
        let mut loader = PluginLoader::new();

        let meta_a = make_meta_with_deps("plugin-a", vec!["fn_a"], vec![]);
        let meta_b = make_meta_with_deps("plugin-b", vec!["fn_b"], vec!["plugin-a"]);

        loader.register(meta_b, echo_dispatch("B"));
        loader.register(meta_a, echo_dispatch("A"));

        let warnings = loader.finalize();
        assert!(warnings.is_empty());

        let active = loader.active_plugins();
        assert_eq!(active[0].name, "plugin-a");
        assert_eq!(active[1].name, "plugin-b");
    }

    #[test]
    fn test_missing_dependency_skipped() {
        let mut loader = PluginLoader::new();

        let meta = make_meta_with_deps("lonely", vec!["fn_x"], vec!["nonexistent"]);
        loader.register(meta, noop_dispatch());

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("lonely"));
        assert_eq!(loader.len(), 0);
    }

    #[test]
    fn test_auto_context_aggregation() {
        let mut loader = PluginLoader::new();

        let mut meta_a = make_meta("plugin-a", vec!["eval_a"]);
        meta_a.auto_context_functions = vec!["eval_a".to_string()];
        loader.register(meta_a, noop_dispatch());

        let mut meta_b = make_meta("plugin-b", vec!["eval_b"]);
        meta_b.auto_context_functions = vec!["eval_b".to_string()];
        loader.register(meta_b, noop_dispatch());

        loader.finalize();

        let ctx_fns = loader.auto_context_functions();
        assert_eq!(ctx_fns.len(), 2);
        assert!(ctx_fns.contains(&"eval_a".to_string()));
        assert!(ctx_fns.contains(&"eval_b".to_string()));
    }

    #[test]
    fn test_fallback_round_robin() {
        let mut loader = PluginLoader::new();

        let meta = make_meta("open-plugin", vec![]);
        loader.register(meta, echo_dispatch("open"));

        loader.finalize();

        let result = loader.call_external_str("anything", &["x".to_string()]).unwrap();
        assert_eq!(result, Some("open:anything(x)".to_string()));
    }

    #[test]
    fn test_capability_search() {
        let mut loader = PluginLoader::new();

        let mut meta = make_meta("formula", vec!["formula_eval"]);
        meta.capabilities = vec!["expression_eval".to_string(), "grid_operations".to_string()];
        loader.register(meta, noop_dispatch());

        let mut meta2 = make_meta("cel", vec!["cel_eval"]);
        meta2.capabilities = vec!["expression_eval".to_string()];
        loader.register(meta2, noop_dispatch());

        loader.finalize();

        let expr_plugins = loader.find_by_capability("expression_eval");
        assert_eq!(expr_plugins.len(), 2);

        let grid_plugins = loader.find_by_capability("grid_operations");
        assert_eq!(grid_plugins.len(), 1);
        assert_eq!(grid_plugins[0].name, "formula");
    }

    #[test]
    fn test_find_plugin_by_name() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("alpha", vec!["a1"]), noop_dispatch());
        loader.register(make_meta("beta", vec!["b1"]), noop_dispatch());
        loader.finalize();

        assert!(loader.find_plugin("alpha").is_some());
        assert!(loader.find_plugin("beta").is_some());
        assert!(loader.find_plugin("gamma").is_none());
    }

    #[test]
    #[should_panic(expected = "already finalized")]
    fn test_finalize_idempotent() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("p1", vec!["f1"]), noop_dispatch());
        loader.finalize();
        loader.finalize();
    }

    #[test]
    fn test_dispatch_after_finalize() {
        let mut loader = PluginLoader::new();
        let meta = make_meta("post-fin", vec!["compute"]);
        loader.register(meta, echo_dispatch("pf"));
        loader.finalize();

        let result = loader.call_external_str("compute", &["x".to_string()]).unwrap();
        assert_eq!(result, Some("pf:compute(x)".to_string()));

        let r2 = loader.call_external_str("compute", &[]).unwrap();
        assert_eq!(r2, Some("pf:compute".to_string()));
    }

    #[test]
    fn test_dispatch_unknown_function() {
        let mut loader = PluginLoader::new();
        let meta = make_meta("strict", vec!["known_fn"]);
        loader.register(meta, echo_dispatch("s"));
        loader.finalize();

        let result = loader.call_external_str("totally_unknown", &["a".to_string()]).unwrap();
        assert_eq!(result, None);

        let result = loader.call_external_str("", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_loader_dispatch() {
        let mut loader = PluginLoader::new();
        loader.finalize();

        let result = loader.call_external_str("anything", &["arg".to_string()]).unwrap();
        assert_eq!(result, None);

        let result = loader.call_external_str("", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_auto_context_functions_empty() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("plain-a", vec!["fn1"]), noop_dispatch());
        loader.register(make_meta("plain-b", vec!["fn2"]), noop_dispatch());
        loader.finalize();

        let ctx = loader.auto_context_functions();
        assert!(ctx.is_empty(), "expected empty auto_context_functions, got {:?}", ctx);
    }

    #[test]
    fn test_plugin_count() {
        let mut loader = PluginLoader::new();
        assert_eq!(loader.len(), 0);
        assert!(loader.is_empty());

        loader.register(make_meta("one", vec!["f1"]), noop_dispatch());
        loader.register(make_meta("two", vec!["f2"]), noop_dispatch());
        loader.register(make_meta("three", vec!["f3"]), noop_dispatch());

        assert_eq!(loader.len(), 0);

        loader.finalize();

        assert_eq!(loader.len(), 3);
        assert!(!loader.is_empty());
    }

    #[test]
    fn test_find_by_name_not_found() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("exists", vec!["f1"]), noop_dispatch());
        loader.finalize();

        assert!(loader.find_plugin("exists").is_some());
        assert_eq!(loader.find_plugin("exists").unwrap().name, "exists");
        assert!(loader.find_plugin("no_such_plugin").is_none());
        assert!(loader.find_plugin("").is_none());
        assert!(loader.find_plugin("EXISTS").is_none());
    }

    // ── __init__ lifecycle tests ──────────────────────────────────────

    #[test]
    fn test_init_called_on_all_plugins() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("plugin-a", vec!["fn_a"]), init_echo_dispatch("A"));
        loader.register(make_meta("plugin-b", vec!["fn_b"]), init_echo_dispatch("B"));

        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 2);

        let result = loader.call_external_str("fn_a", &[]).unwrap();
        assert_eq!(result, Some("A:fn_a".to_string()));
        let result = loader.call_external_str("fn_b", &[]).unwrap();
        assert_eq!(result, Some("B:fn_b".to_string()));
    }

    #[test]
    fn test_init_no_init_is_ok() {
        let mut loader = PluginLoader::new();
        // Plugin without __init__ (dispatch returns Ok(None) for __init__)
        loader.register(make_meta("no-init", vec!["fn_x"]), noop_dispatch());

        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 1);

        let result = loader.call_external_str("fn_x", &[]).unwrap();
        assert_eq!(result, None); // noop_dispatch returns Ok(None)
    }

    #[test]
    fn test_init_failure_skips_plugin() {
        let mut loader = PluginLoader::new();
        loader.register(make_meta("good", vec!["fn_g"]), init_echo_dispatch("G"));
        loader.register(make_meta("bad", vec!["fn_b"]), init_fail_dispatch("B"));

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bad"));
        assert!(warnings[0].contains("__init__ failed"));
        assert_eq!(loader.len(), 1);

        let result = loader.call_external_str("fn_g", &[]).unwrap();
        assert_eq!(result, Some("G:fn_g".to_string()));

        let result = loader.call_external_str("fn_b", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_init_dependency_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));

        let c_lic = counter.clone();
        let lic_dispatch: DispatchFn = Arc::new(move |name, _| {
            if name == "__init__" {
                let order = c_lic.fetch_add(1, Ordering::SeqCst);
                assert_eq!(order, 0, "wawk-lic should init first");
                return Ok(Some("lic:init_ok".into()));
            }
            Ok(None)
        });

        let c_crypto = counter.clone();
        let crypto_dispatch: DispatchFn = Arc::new(move |name, _| {
            if name == "__init__" {
                let order = c_crypto.fetch_add(1, Ordering::SeqCst);
                assert_eq!(order, 1, "wawk-crypto should init second");
                return Ok(Some("crypto:init_ok".into()));
            }
            Ok(None)
        });

        let mut loader = PluginLoader::new();
        // Register in reverse dependency order
        loader.register(
            make_meta_with_deps("wawk-crypto", vec!["encrypt"], vec!["wawk-lic"]),
            crypto_dispatch,
        );
        loader.register(
            make_meta("wawk-lic", vec!["activate"]),
            lic_dispatch,
        );

        let warnings = loader.finalize();
        assert!(warnings.is_empty());

        let active = loader.active_plugins();
        assert_eq!(active[0].name, "wawk-lic");
        assert_eq!(active[1].name, "wawk-crypto");
    }

    #[test]
    fn test_init_failure_with_dependent() {
        let mut loader = PluginLoader::new();

        loader.register(
            make_meta("wawk-lic", vec!["activate"]),
            init_fail_dispatch("lic"),
        );
        loader.register(
            make_meta_with_deps("wawk-crypto", vec!["encrypt"], vec!["wawk-lic"]),
            noop_dispatch(),
        );

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("wawk-lic"));
        // wawk-crypto still active (dep resolution passed; only init failed for lic)
        assert_eq!(loader.len(), 1);
        assert_eq!(loader.active_plugins()[0].name, "wawk-crypto");
    }
}
