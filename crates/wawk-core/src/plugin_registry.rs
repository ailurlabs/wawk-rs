//! Plugin lifecycle registry: discovery → metadata → dependency resolution → init → dispatch.
//!
//! The `PluginRegistry` aggregates multiple plugins behind a single
//! `FunctionDispatcher` handler. After dependency resolution, every plugin
//! receives an `__init__` call in dependency order for initialization.
//! Plugins without `__init__` are unaffected.

use rustc_hash::FxHashMap;
use std::sync::Arc;

use crate::error::AwkResult;
use crate::namespace_registry::NamespaceRegistry;
use crate::plugin_meta::PluginMeta;
use crate::plugin_resolver;
use crate::traits::{FunctionDispatcher, PluginCapability};

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
/// Implements `FunctionDispatcher` so it can be installed directly as the
/// evaluator's external function handler.
///
/// # Lifecycle
/// 1. `register()` — add plugins with metadata + dispatch
/// 2. `finalize()` — resolve deps, call `__init__` in order, build dispatch index
/// 3. `dispatch()` — O(1) dispatch to the correct plugin
pub struct PluginRegistry {
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
    /// Namespace registry: maps namespace names to plugin indices.
    pub namespace_registry: NamespaceRegistry,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Create a new empty plugin loader.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            fn_index: FxHashMap::default(),
            auto_ctx_fns: Vec::new(),
            finalized: false,
            pending: Vec::new(),
            namespace_registry: NamespaceRegistry::new(),
        }
    }

    /// Register a plugin with its metadata and dispatch callback.
    ///
    /// Must be called before `finalize()`. Panics if already finalized.
    pub fn register(&mut self, meta: PluginMeta, dispatch: DispatchFn) {
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
        let metas: Vec<PluginMeta> = self.pending.iter().map(|p| p.meta.clone()).collect();

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
        let mut init_failed: Vec<String> = Vec::new();
        for entry in ordered {
            match (entry.dispatch)("__init__", &[]) {
                Ok(_) => init_ok.push(entry),
                Err(e) => {
                    init_failed.push(entry.meta.name.clone());
                    warnings.push(format!(
                        "plugin '{}' skipped: __init__ failed: {}",
                        entry.meta.name, e
                    ));
                }
            }
        }

        // ── Cascade: recursively remove dependents of failed plugins ──
        if !init_failed.is_empty() {
            let mut cascade = true;
            while cascade {
                cascade = false;
                let mut retained = Vec::with_capacity(init_ok.len());
                for entry in init_ok {
                    let has_failed_dep =
                        entry.meta.requires.iter().any(|r| init_failed.contains(r));
                    if has_failed_dep {
                        cascade = true;
                        init_failed.push(entry.meta.name.clone());
                        warnings.push(format!(
                            "plugin '{}' skipped: depends on failed plugin",
                            entry.meta.name
                        ));
                    } else {
                        retained.push(entry);
                    }
                }
                init_ok = retained;
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

        // Build namespace registry from plugin metadata
        let mut ns_registry = NamespaceRegistry::new();
        for (idx, entry) in init_ok.iter().enumerate() {
            if let Some(ref ns) = entry.meta.namespace {
                if let Err(e) = ns_registry.register(ns, idx) {
                    warnings.push(format!(
                        "plugin '{}' namespace conflict: {}",
                        entry.meta.name, e
                    ));
                }
            }
        }

        self.plugins = init_ok;
        self.fn_index = fn_index;
        self.auto_ctx_fns = auto_ctx_fns;
        self.namespace_registry = ns_registry;
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
        self.plugins
            .iter()
            .find(|p| p.meta.name == name)
            .map(|p| &p.meta)
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

    /// Set the default namespace for unqualified function resolution.
    pub fn set_default_namespace(&mut self, namespace: &str) {
        self.namespace_registry.set_default(namespace);
    }

    /// Clear the default namespace.
    pub fn clear_default_namespace(&mut self) {
        self.namespace_registry.clear_default();
    }
}

impl PluginCapability for PluginRegistry {
    fn capability_name(&self) -> &'static str {
        "function_dispatch"
    }
}

impl FunctionDispatcher for PluginRegistry {
    fn dispatch(&mut self, name: &str, args: &[String]) -> AwkResult<Option<String>> {
        // Handle qualified names: "namespace.func" -> route via NamespaceRegistry
        if let Some(dot_pos) = name.find('.') {
            let ns = &name[..dot_pos];
            let func = &name[dot_pos + 1..];
            if let Some(idx) = self.namespace_registry.resolve_qualified(ns, func) {
                if let Some(result) = (self.plugins[idx].dispatch)(func, args)? {
                    return Ok(Some(result));
                }
            }
            return Ok(None);
        }

        // O(1) dispatch via function index
        if let Some(&idx) = self.fn_index.get(name) {
            if let Some(result) = (self.plugins[idx].dispatch)(name, args)? {
                return Ok(Some(result));
            }
            // Plugin returned Ok(None), fall through to namespace resolution
        }

        // Try default namespace resolution
        if let Some((_, idx)) = self.namespace_registry.resolve(name) {
            if let Some(result) = (self.plugins[idx].dispatch)(name, args)? {
                return Ok(Some(result));
            }
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

    /// Explicit namespace-aware qualified dispatch.
    /// Routes through NamespaceRegistry to find the correct plugin, then
    /// dispatches using the unqualified function name.
    fn dispatch_qualified(
        &mut self,
        namespace: &str,
        function: &str,
        args: &[String],
    ) -> AwkResult<Option<String>> {
        // Step 1: Resolve namespace to plugin index via NamespaceRegistry
        if let Some(idx) = self.namespace_registry.resolve_qualified(namespace, function) {
            // Step 2: Dispatch to the resolved plugin with the unqualified function name
            if let Some(result) = (self.plugins[idx].dispatch)(function, args)? {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Check if a namespace is registered in the NamespaceRegistry.
    fn has_namespace(&self, ns: &str) -> bool {
        self.namespace_registry.has_namespace(ns)
    }

    /// Set the default namespace for unqualified function resolution.
    fn set_default_namespace(&mut self, ns: &str) {
        self.namespace_registry.set_default(ns);
    }

    /// Clear the default namespace.
    fn clear_default_namespace(&mut self) {
        self.namespace_registry.clear_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_meta(name: &str, functions: Vec<&str>) -> PluginMeta {
        PluginMeta {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            namespace: None,
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

    fn make_meta_with_deps(name: &str, functions: Vec<&str>, deps: Vec<&str>) -> PluginMeta {
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
                return Err(crate::error::AwkError::RuntimeError(format!(
                    "{}: init failed",
                    p
                )));
            }
            Ok(None)
        })
    }

    #[test]
    fn test_empty_loader() {
        let mut loader = PluginRegistry::new();
        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 0);
        assert!(loader.is_empty());
    }

    #[test]
    fn test_single_plugin_dispatch() {
        let mut loader = PluginRegistry::new();
        let meta = make_meta("test-plugin", vec!["hello", "world"]);
        loader.register(meta, echo_dispatch("test"));
        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 1);

        let result = loader.dispatch("hello", &["arg1".to_string()]).unwrap();
        assert_eq!(result, Some("test:hello(arg1)".to_string()));

        let result = loader.dispatch("unknown", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_multi_plugin_dispatch() {
        let mut loader = PluginRegistry::new();

        let meta_a = make_meta("plugin-a", vec!["fn_a1", "fn_a2"]);
        loader.register(meta_a, echo_dispatch("A"));

        let meta_b = make_meta("plugin-b", vec!["fn_b1"]);
        loader.register(meta_b, echo_dispatch("B"));

        loader.finalize();

        let result = loader.dispatch("fn_a1", &[]).unwrap();
        assert_eq!(result, Some("A:fn_a1".to_string()));

        let result = loader.dispatch("fn_b1", &[]).unwrap();
        assert_eq!(result, Some("B:fn_b1".to_string()));

        let result = loader.dispatch("fn_c1", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_dependency_ordering() {
        let mut loader = PluginRegistry::new();

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
        let mut loader = PluginRegistry::new();

        let meta = make_meta_with_deps("lonely", vec!["fn_x"], vec!["nonexistent"]);
        loader.register(meta, noop_dispatch());

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("lonely"));
        assert_eq!(loader.len(), 0);
    }

    #[test]
    fn test_auto_context_aggregation() {
        let mut loader = PluginRegistry::new();

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
        let mut loader = PluginRegistry::new();

        let meta = make_meta("open-plugin", vec![]);
        loader.register(meta, echo_dispatch("open"));

        loader.finalize();

        let result = loader.dispatch("anything", &["x".to_string()]).unwrap();
        assert_eq!(result, Some("open:anything(x)".to_string()));
    }

    #[test]
    fn test_capability_search() {
        let mut loader = PluginRegistry::new();

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
        let mut loader = PluginRegistry::new();
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
        let mut loader = PluginRegistry::new();
        loader.register(make_meta("p1", vec!["f1"]), noop_dispatch());
        loader.finalize();
        loader.finalize();
    }

    #[test]
    fn test_dispatch_after_finalize() {
        let mut loader = PluginRegistry::new();
        let meta = make_meta("post-fin", vec!["compute"]);
        loader.register(meta, echo_dispatch("pf"));
        loader.finalize();

        let result = loader.dispatch("compute", &["x".to_string()]).unwrap();
        assert_eq!(result, Some("pf:compute(x)".to_string()));

        let r2 = loader.dispatch("compute", &[]).unwrap();
        assert_eq!(r2, Some("pf:compute".to_string()));
    }

    #[test]
    fn test_dispatch_unknown_function() {
        let mut loader = PluginRegistry::new();
        let meta = make_meta("strict", vec!["known_fn"]);
        loader.register(meta, echo_dispatch("s"));
        loader.finalize();

        let result = loader
            .dispatch("totally_unknown", &["a".to_string()])
            .unwrap();
        assert_eq!(result, None);

        let result = loader.dispatch("", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_empty_loader_dispatch() {
        let mut loader = PluginRegistry::new();
        loader.finalize();

        let result = loader.dispatch("anything", &["arg".to_string()]).unwrap();
        assert_eq!(result, None);

        let result = loader.dispatch("", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_auto_context_functions_empty() {
        let mut loader = PluginRegistry::new();
        loader.register(make_meta("plain-a", vec!["fn1"]), noop_dispatch());
        loader.register(make_meta("plain-b", vec!["fn2"]), noop_dispatch());
        loader.finalize();

        let ctx = loader.auto_context_functions();
        assert!(
            ctx.is_empty(),
            "expected empty auto_context_functions, got {:?}",
            ctx
        );
    }

    #[test]
    fn test_plugin_count() {
        let mut loader = PluginRegistry::new();
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
        let mut loader = PluginRegistry::new();
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
        let mut loader = PluginRegistry::new();
        loader.register(make_meta("plugin-a", vec!["fn_a"]), init_echo_dispatch("A"));
        loader.register(make_meta("plugin-b", vec!["fn_b"]), init_echo_dispatch("B"));

        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 2);

        let result = loader.dispatch("fn_a", &[]).unwrap();
        assert_eq!(result, Some("A:fn_a".to_string()));
        let result = loader.dispatch("fn_b", &[]).unwrap();
        assert_eq!(result, Some("B:fn_b".to_string()));
    }

    #[test]
    fn test_init_no_init_is_ok() {
        let mut loader = PluginRegistry::new();
        // Plugin without __init__ (dispatch returns Ok(None) for __init__)
        loader.register(make_meta("no-init", vec!["fn_x"]), noop_dispatch());

        let warnings = loader.finalize();
        assert!(warnings.is_empty());
        assert_eq!(loader.len(), 1);

        let result = loader.dispatch("fn_x", &[]).unwrap();
        assert_eq!(result, None); // noop_dispatch returns Ok(None)
    }

    #[test]
    fn test_init_failure_skips_plugin() {
        let mut loader = PluginRegistry::new();
        loader.register(make_meta("good", vec!["fn_g"]), init_echo_dispatch("G"));
        loader.register(make_meta("bad", vec!["fn_b"]), init_fail_dispatch("B"));

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bad"));
        assert!(warnings[0].contains("__init__ failed"));
        assert_eq!(loader.len(), 1);

        let result = loader.dispatch("fn_g", &[]).unwrap();
        assert_eq!(result, Some("G:fn_g".to_string()));

        let result = loader.dispatch("fn_b", &[]).unwrap();
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

        let mut loader = PluginRegistry::new();
        // Register in reverse dependency order
        loader.register(
            make_meta_with_deps("wawk-crypto", vec!["encrypt"], vec!["wawk-lic"]),
            crypto_dispatch,
        );
        loader.register(make_meta("wawk-lic", vec!["activate"]), lic_dispatch);

        let warnings = loader.finalize();
        assert!(warnings.is_empty());

        let active = loader.active_plugins();
        assert_eq!(active[0].name, "wawk-lic");
        assert_eq!(active[1].name, "wawk-crypto");
    }

    #[test]
    fn test_init_failure_with_dependent() {
        let mut loader = PluginRegistry::new();

        loader.register(
            make_meta("wawk-lic", vec!["activate"]),
            init_fail_dispatch("lic"),
        );
        loader.register(
            make_meta_with_deps("wawk-crypto", vec!["encrypt"], vec!["wawk-lic"]),
            noop_dispatch(),
        );

        let warnings = loader.finalize();
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("wawk-lic"));
        assert!(warnings[1].contains("wawk-crypto"));
        // wawk-crypto cascaded: depends on failed wawk-lic
        assert_eq!(loader.len(), 0);
    }

    // ── Namespace-aware dispatch tests ──────────────────────────────

    fn make_meta_with_ns(name: &str, functions: Vec<&str>, ns: &str) -> PluginMeta {
        PluginMeta {
            namespace: Some(ns.to_string()),
            ..make_meta(name, functions)
        }
    }

    #[test]
    fn test_namespace_registry_populated_in_finalize() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "eval"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-crypto", vec!["sha256"], "crypto"),
            echo_dispatch("crypto"),
        );
        loader.finalize();

        let ns_reg = &loader.namespace_registry;
        assert!(ns_reg.has_namespace("formula"));
        assert!(ns_reg.has_namespace("crypto"));
        assert!(!ns_reg.has_namespace("unknown"));
    }

    #[test]
    fn test_qualified_dispatch_via_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "eval"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-crypto", vec!["sha256"], "crypto"),
            echo_dispatch("crypto"),
        );
        loader.finalize();

        // Qualified call: "formula.sum" should route to formula plugin's "sum"
        let result = loader
            .dispatch("formula.sum", &["1".to_string(), "2".to_string()])
            .unwrap();
        assert_eq!(result, Some("formula:sum(1,2)".to_string()));

        // Qualified call: "crypto.sha256" should route to crypto plugin's "sha256"
        let result = loader
            .dispatch("crypto.sha256", &["hello".to_string()])
            .unwrap();
        assert_eq!(result, Some("crypto:sha256(hello)".to_string()));
    }

    #[test]
    fn test_qualified_dispatch_unknown_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        let result = loader.dispatch("unknown.func", &[]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_default_namespace_dispatch() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "eval"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        // Set default namespace
        loader.set_default_namespace("formula");

        // Unqualified call should resolve via default namespace
        // Note: "sum" is in fn_index, so it dispatches directly.
        // The default namespace fallback is for functions NOT in fn_index
        // but that the default namespace plugin can handle via round-robin.
        let result = loader.dispatch("sum", &[]).unwrap();
        assert_eq!(result, Some("formula:sum".to_string()));
    }

    #[test]
    fn test_clear_default_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        loader.set_default_namespace("formula");
        loader.clear_default_namespace();

        let ns_reg = &loader.namespace_registry;
        assert_eq!(ns_reg.default_namespace(), None);
    }

    #[test]
    fn test_namespace_collision_warning() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("plugin-a", vec!["fn_a"], "shared_ns"),
            echo_dispatch("A"),
        );
        loader.register(
            make_meta_with_ns("plugin-b", vec!["fn_b"], "shared_ns"),
            echo_dispatch("B"),
        );

        let warnings = loader.finalize();
        assert!(
            warnings.iter().any(|w| w.contains("namespace conflict")),
            "expected namespace conflict warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_unqualified_dispatch_still_works_with_namespaces() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "eval"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        // Unqualified call should still work via fn_index
        let result = loader.dispatch("sum", &["1".to_string()]).unwrap();
        assert_eq!(result, Some("formula:sum(1)".to_string()));
    }

    // ── T1-T6: Namespace/Plugin Unification Integration Tests ─────────

    /// T1: Two plugins with same function name coexist without collision.
    /// wawk-formula and wawk-cel both export `evaluate()`. They coexist
    /// because each has its own namespace.
    #[test]
    fn test_t1_same_function_name_coexistence() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["evaluate", "sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-cel", vec!["evaluate", "filter"], "cel"),
            echo_dispatch("cel"),
        );
        let warnings = loader.finalize();
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
        assert_eq!(loader.len(), 2);

        // Both plugins are active and have "evaluate" — no collision
        // because they are in different namespaces
        let formula_result = loader.dispatch("formula.evaluate", &["1+1".to_string()]).unwrap();
        assert_eq!(formula_result, Some("formula:evaluate(1+1)".to_string()));

        let cel_result = loader.dispatch("cel.evaluate", &["x > 5".to_string()]).unwrap();
        assert_eq!(cel_result, Some("cel:evaluate(x > 5)".to_string()));
    }

    /// T2: Qualified calls route correctly via NamespaceRegistry.
    /// formula.sum() goes to formula plugin, cel.filter() goes to cel plugin.
    #[test]
    fn test_t2_qualified_calls_route_via_namespace_registry() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "evaluate"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-cel", vec!["filter", "evaluate"], "cel"),
            echo_dispatch("cel"),
        );
        loader.finalize();

        // Qualified calls should route via NamespaceRegistry explicitly
        // (using dispatch_qualified, not string-based dispatch)
        let r1 = loader.dispatch_qualified("formula", "sum", &["1".to_string(), "2".to_string()]).unwrap();
        assert_eq!(r1, Some("formula:sum(1,2)".to_string()));

        let r2 = loader.dispatch_qualified("cel", "filter", &["x>0".to_string()]).unwrap();
        assert_eq!(r2, Some("cel:filter(x>0)".to_string()));

        // Cross-namespace: formula.evaluate vs cel.evaluate
        let r3 = loader.dispatch_qualified("formula", "evaluate", &["A1+B1".to_string()]).unwrap();
        assert_eq!(r3, Some("formula:evaluate(A1+B1)".to_string()));

        let r4 = loader.dispatch_qualified("cel", "evaluate", &["x>5".to_string()]).unwrap();
        assert_eq!(r4, Some("cel:evaluate(x>5)".to_string()));

        // Unknown namespace returns None
        let r5 = loader.dispatch_qualified("unknown", "func", &[]).unwrap();
        assert_eq!(r5, None);
    }

    /// T3: Unqualified calls route to default namespace set by @plugin.
    /// When "formula" is the default namespace, unqualified sum() goes to formula.
    #[test]
    fn test_t3_unqualified_calls_route_to_default_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "evaluate"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-cel", vec!["filter", "evaluate"], "cel"),
            echo_dispatch("cel"),
        );
        loader.finalize();

        // Set default namespace to "formula" (as @plugin "formula" would do)
        loader.set_default_namespace("formula");

        // has_namespace should confirm both are registered
        assert!(loader.has_namespace("formula"));
        assert!(loader.has_namespace("cel"));

        // Unqualified "sum" should route to formula via fn_index
        let r1 = loader.dispatch("sum", &["1".to_string()]).unwrap();
        assert_eq!(r1, Some("formula:sum(1)".to_string()));
    }

    /// T4: Existing @plugin scripts work unchanged.
    /// Functions registered with prefixed names (formula_sum) still dispatch correctly.
    #[test]
    fn test_t4_backward_compatibility_prefixed_functions() {
        let mut loader = PluginRegistry::new();
        // Plugin registers functions with their prefixed names (as the preprocessor produces)
        loader.register(
            make_meta("wawk-formula", vec!["formula_sum", "formula_Date", "formula_evaluate"]),
            echo_dispatch("formula"),
        );
        let warnings = loader.finalize();
        assert!(warnings.is_empty());

        // Prefixed function names should dispatch correctly
        let r1 = loader.dispatch("formula_sum", &["1".to_string(), "2".to_string()]).unwrap();
        assert_eq!(r1, Some("formula:formula_sum(1,2)".to_string()));

        let r2 = loader.dispatch("formula_Date", &["2024".to_string()]).unwrap();
        assert_eq!(r2, Some("formula:formula_Date(2024)".to_string()));
    }

    /// T5: Mixed qualified/unqualified calls in same script with multiple plugins.
    /// Simulates a script that uses both formula.sum() and cel.filter() (qualified)
    /// plus unqualified calls that route to the default namespace.
    #[test]
    fn test_t5_mixed_qualified_and_unqualified_calls() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum", "evaluate"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-cel", vec!["filter", "evaluate"], "cel"),
            echo_dispatch("cel"),
        );
        loader.finalize();

        // Set default namespace (as @plugin "formula" would)
        loader.set_default_namespace("formula");

        // Unqualified call → default namespace (formula)
        let r1 = loader.dispatch("sum", &["1".to_string()]).unwrap();
        assert_eq!(r1, Some("formula:sum(1)".to_string()));

        // Qualified call → explicit namespace
        let r2 = loader.dispatch_qualified("cel", "filter", &["x>0".to_string()]).unwrap();
        assert_eq!(r2, Some("cel:filter(x>0)".to_string()));

        // Qualified call to formula namespace
        let r3 = loader.dispatch_qualified("formula", "evaluate", &["A1".to_string()]).unwrap();
        assert_eq!(r3, Some("formula:evaluate(A1)".to_string()));

        // Another unqualified call → still default namespace
        let r4 = loader.dispatch("evaluate", &["B2".to_string()]).unwrap();
        // "evaluate" is in fn_index for both plugins, but fn_index takes first registered
        // Since formula was registered first, it gets "evaluate"
        assert!(r4.is_some(), "unqualified evaluate should resolve");
    }
    // ── B2: Plugin dispatch chain tests ──────────────────────────────

    /// Helper: create a dispatch function that returns Ok(None) for specific functions
    fn selective_dispatch(prefix: &str, reject: &[&str]) -> DispatchFn {
        let prefix = prefix.to_string();
        let reject: Vec<String> = reject.iter().map(|s| s.to_string()).collect();
        Arc::new(move |name: &str, args: &[String]| {
            if reject.iter().any(|r| r == name) {
                Ok(None) // Simulate plugin that doesn't handle this function
            } else {
                Ok(Some(format!("{}:{}({})", prefix, name, args.join(","))))
            }
        })
    }

    #[test]
    fn test_b2_fn_index_falls_through_on_none() {
        // B2: When fn_index plugin returns Ok(None), fall through to namespace resolution
        let mut loader = PluginRegistry::new();
        
        // Plugin A declares "test_fn" but rejects it at runtime
        loader.register(
            make_meta_with_ns("plugin-a", vec!["test_fn"], "ns_a"),
            selective_dispatch("A", &["test_fn"]),
        );
        
        // Plugin B has namespace "ns_b" and only handles "other_fn", rejects "test_fn"
        loader.register(
            make_meta_with_ns("plugin-b", vec!["other_fn"], "ns_b"),
            selective_dispatch("B", &["test_fn"]),
        );
        
        loader.finalize();
        loader.set_default_namespace("ns_b");
        
        // test_fn is in fn_index (plugin-a), but plugin-a returns Ok(None)
        // Should fall through to namespace resolution (ns_b -> plugin-b)
        // But plugin-b doesn't have test_fn, so should return Ok(None)
        let result = loader.dispatch("test_fn", &["arg".to_string()]).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_b2_namespace_falls_through_to_round_robin() {
        // B2: When namespace resolution returns Ok(None), fall through to round-robin
        let mut loader = PluginRegistry::new();
        
        // Plugin A has namespace but rejects the function
        loader.register(
            make_meta_with_ns("plugin-a", vec!["test_fn"], "ns_a"),
            selective_dispatch("A", &["test_fn"]),
        );
        
        // Plugin B is a dynamic dispatch plugin (empty functions list)
        let meta_b = PluginMeta {
            name: "plugin-b".to_string(),
            namespace: None,
            functions: vec![], // Dynamic dispatch
            ..make_meta("plugin-b", vec![])
        };
        loader.register(meta_b, echo_dispatch("B"));
        
        loader.finalize();
        loader.set_default_namespace("ns_a");
        
        // test_fn is in namespace ns_a (plugin-a), but plugin-a returns Ok(None)
        // Should fall through to round-robin (plugin-b, dynamic dispatch)
        let result = loader.dispatch("test_fn", &["arg".to_string()]).unwrap();
        assert_eq!(result, Some("B:test_fn(arg)".to_string()));
    }

    #[test]
    fn test_b2_round_robin_tries_next_on_none() {
        // B2: When a dynamic dispatch plugin returns Ok(None), try the next one
        let mut loader = PluginRegistry::new();
        
        // Plugin A is dynamic dispatch but rejects "reject_me"
        let meta_a = PluginMeta {
            name: "plugin-a".to_string(),
            namespace: None,
            functions: vec![],
            ..make_meta("plugin-a", vec![])
        };
        loader.register(meta_a, selective_dispatch("A", &["reject_me"]));
        
        // Plugin B is dynamic dispatch and handles everything
        let meta_b = PluginMeta {
            name: "plugin-b".to_string(),
            namespace: None,
            functions: vec![],
            ..make_meta("plugin-b", vec![])
        };
        loader.register(meta_b, echo_dispatch("B"));
        
        loader.finalize();
        
        // reject_me: plugin-a returns Ok(None), should try plugin-b
        let result = loader.dispatch("reject_me", &["arg".to_string()]).unwrap();
        assert_eq!(result, Some("B:reject_me(arg)".to_string()));
        
        // other_fn: plugin-a handles it
        let result = loader.dispatch("other_fn", &["arg".to_string()]).unwrap();
        assert_eq!(result, Some("A:other_fn(arg)".to_string()));
    }


    /// Edge case: Qualified call to unregistered namespace returns clear None.
    #[test]
    fn test_edge_qualified_call_unknown_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        let result = loader.dispatch_qualified("nonexistent", "func", &[]).unwrap();
        assert_eq!(result, None);

        // has_namespace should return false
        assert!(!loader.has_namespace("nonexistent"));
    }

    /// Edge case: Plugin with no namespace metadata does not claim any namespace.
    #[test]
    fn test_edge_plugin_without_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta("no-ns-plugin", vec!["helper"]),
            echo_dispatch("nons"),
        );
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.finalize();

        // no-ns-plugin should not have a namespace
        assert!(!loader.has_namespace("no-ns-plugin"));
        assert!(!loader.has_namespace("nons"));

        // But its functions should still be dispatchable
        let r1 = loader.dispatch("helper", &[]).unwrap();
        assert_eq!(r1, Some("nons:helper".to_string()));

        // formula namespace should still work
        assert!(loader.has_namespace("formula"));
    }

    /// Edge case: @plugin switch mid-script updates default namespace.
    /// Simulates switching from @plugin "formula" to @plugin "cel".
    #[test]
    fn test_edge_plugin_switch_updates_default_namespace() {
        let mut loader = PluginRegistry::new();
        loader.register(
            make_meta_with_ns("wawk-formula", vec!["sum"], "formula"),
            echo_dispatch("formula"),
        );
        loader.register(
            make_meta_with_ns("wawk-cel", vec!["evaluate"], "cel"),
            echo_dispatch("cel"),
        );
        loader.finalize();

        // First: default is "formula"
        loader.set_default_namespace("formula");
        assert_eq!(loader.namespace_registry.default_namespace(), Some("formula"));

        // Switch: now default is "cel" (as @plugin "cel" mid-script would do)
        loader.set_default_namespace("cel");
        assert_eq!(loader.namespace_registry.default_namespace(), Some("cel"));

        // Both namespaces are still available for qualified calls
        assert!(loader.has_namespace("formula"));
        assert!(loader.has_namespace("cel"));
    }

}
