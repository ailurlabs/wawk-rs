//! Integration tests for wawk-codegen.
//!
//! Tests the full pipeline: load manifest → generate WIT + Rust → verify output.

use std::fs;
use std::path::PathBuf;
use wawk_codegen::{
    generate_dispatcher_rs, generate_dispatcher_wit, generate_lib_rs, load_manifest,
    write_dispatcher,
};

fn temp_output_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "wawk-codegen-integration-{}-{}",
        std::process::id(),
        id
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn create_test_manifest(dir: &std::path::Path) -> PathBuf {
    let manifest_path = dir.join("plugin-manifest.json");
    let content = r#"{
  "name": "test-product",
  "version": "1.0.0",
  "description": "Integration test product",
  "plugins": [
    {
      "name": "domain",
      "interface": "domain-functions",
      "format": true,
      "description": "Domain plugin"
    },
    {
      "name": "plugin-1",
      "interface": "plugin-1-functions",
      "format": false,
      "description": "Math plugin"
    }
  ],
  "host_services": {
    "notify": "Notifications",
    "store_set": "Storage set",
    "store_get": "Storage get",
    "log": "Logging"
  }
}"#;
    fs::write(&manifest_path, content).unwrap();
    manifest_path
}

// ---------------------------------------------------------------------------
// End-to-end pipeline tests
// ---------------------------------------------------------------------------

#[test]
fn test_full_pipeline_load_generate_write() {
    let dir = temp_output_dir();
    let manifest_path = create_test_manifest(&dir);

    // Step 1: Load manifest
    let manifest = load_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.name, "test-product");
    assert_eq!(manifest.plugins.len(), 2);

    // Step 2: Generate WIT
    let wit = generate_dispatcher_wit(&manifest);
    assert!(wit.contains("package wawk:test-product;"));
    assert!(wit.contains("world test-product-dispatcher {"));
    assert!(wit.contains("import wawk:plugins/domain-functions;"));
    assert!(wit.contains("import wawk:plugins/plugin-1-functions;"));
    assert!(wit.contains("import wawk:plugins/domain-format;"));
    assert!(!wit.contains("import wawk:plugins/plugin-1-format;"));
    assert!(wit.contains("import wawk:services/host-services;"));
    assert!(wit.contains("export host-functions;"));

    // Step 3: Generate Rust
    let rs = generate_dispatcher_rs(&manifest);
    assert!(rs.contains("pub(crate) struct TestProductDispatcher;"));
    assert!(rs.contains("impl crate::bindings::exports::wawk::test_product::host_functions::Guest"));
    assert!(rs.contains("\"domain\" =>"));
    assert!(rs.contains("\"plugin-1\" =>"));
    assert!(rs.contains("crate::bindings::wawk::plugins::domain_functions::call"));
    assert!(rs.contains("crate::bindings::wawk::plugins::plugin_1_functions::call"));
    // export! is now in lib.rs
    let lib_rs = generate_lib_rs(&manifest);
    assert!(lib_rs.contains("bindings::export!(TestProductDispatcher with_types_in bindings);"));

    // Step 4: Write to disk
    let output_dir = dir.join("output");
    write_dispatcher(&manifest, &output_dir).unwrap();
    assert!(output_dir.join("wit/dispatcher.wit").exists());
    assert!(output_dir.join("src/dispatcher.rs").exists());

    // Step 5: Verify file contents match generated output
    let written_wit = fs::read_to_string(output_dir.join("wit/dispatcher.wit")).unwrap();
    assert_eq!(written_wit, wit);

    let written_rs = fs::read_to_string(output_dir.join("src/dispatcher.rs")).unwrap();
    assert_eq!(written_rs, rs);

    // Cleanup
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_wit_world_structure() {
    let dir = temp_output_dir();
    let manifest_path = create_test_manifest(&dir);
    let manifest = load_manifest(&manifest_path).unwrap();
    let wit = generate_dispatcher_wit(&manifest);

    // Verify world block structure
    assert!(wit.contains("world test-product-dispatcher {"));

    // Verify imports come before exports
    let import_pos = wit.find("import wawk:services/host-services;").unwrap();
    let export_pos = wit.find("export host-functions;").unwrap();
    assert!(import_pos < export_pos);

    // Verify interface definition is after world block
    let world_close = wit.find("}\n\n/// Unified").unwrap();
    let iface_def = wit.find("interface host-functions {").unwrap();
    assert!(world_close < iface_def);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_rs_dispatch_logic_structure() {
    let dir = temp_output_dir();
    let manifest_path = create_test_manifest(&dir);
    let manifest = load_manifest(&manifest_path).unwrap();
    let rs = generate_dispatcher_rs(&manifest);

    // Verify namespace extraction logic
    assert!(rs.contains("name.find('.')"));
    assert!(rs.contains("Some(pos) => (&name[..pos], &name[pos + 1..])"));
    assert!(rs.contains("None => return None"));

    // Verify match structure
    assert!(rs.contains("match namespace {"));

    // Verify each plugin arm has logging and routing
    assert!(rs.contains("[dispatcher] routing"));

    // Verify unknown namespace handling
    assert!(rs.contains("_ => {"));
    assert!(rs.contains("unknown namespace"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_single_plugin_manifest() {
    let dir = temp_output_dir();
    let manifest_path = dir.join("single.json");
    fs::write(
        &manifest_path,
        r#"{
  "name": "solo",
  "version": "0.1.0",
  "plugins": [
    { "name": "solo", "interface": "solo-functions", "format": false }
  ]
}"#,
    )
    .unwrap();

    let manifest = load_manifest(&manifest_path).unwrap();
    let wit = generate_dispatcher_wit(&manifest);
    let rs = generate_dispatcher_rs(&manifest);

    // WIT should have exactly one plugin import
    assert!(wit.contains("import wawk:plugins/solo-functions;"));
    assert!(!wit.contains("format"));

    // Rust should have exactly one match arm
    assert!(rs.contains("\"solo\" =>"));
    assert!(rs.contains("pub(crate) struct SoloDispatcher;"));
    let lib_rs = generate_lib_rs(&manifest);
    assert!(lib_rs.contains("bindings::export!(SoloDispatcher with_types_in bindings);"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_many_plugins_manifest() {
    let dir = temp_output_dir();
    let manifest_path = dir.join("many.json");
    fs::write(
        &manifest_path,
        r#"{
  "name": "mega-product",
  "version": "2.0.0",
  "plugins": [
    { "name": "alpha", "interface": "alpha-functions", "format": false },
    { "name": "beta", "interface": "beta-functions", "format": true },
    { "name": "gamma", "interface": "gamma-functions", "format": false },
    { "name": "delta", "interface": "delta-functions", "format": false },
    { "name": "epsilon", "interface": "epsilon-functions", "format": true }
  ]
}"#,
    )
    .unwrap();

    let manifest = load_manifest(&manifest_path).unwrap();
    let wit = generate_dispatcher_wit(&manifest);
    let rs = generate_dispatcher_rs(&manifest);

    // All 5 plugins imported
    assert!(wit.contains("import wawk:plugins/alpha-functions;"));
    assert!(wit.contains("import wawk:plugins/beta-functions;"));
    assert!(wit.contains("import wawk:plugins/gamma-functions;"));
    assert!(wit.contains("import wawk:plugins/delta-functions;"));
    assert!(wit.contains("import wawk:plugins/epsilon-functions;"));

    // Format imports only for beta and epsilon
    assert!(wit.contains("import wawk:plugins/beta-format;"));
    assert!(wit.contains("import wawk:plugins/epsilon-format;"));
    assert!(!wit.contains("import wawk:plugins/alpha-format;"));

    // All 5 match arms in Rust
    assert!(rs.contains("\"alpha\" =>"));
    assert!(rs.contains("\"beta\" =>"));
    assert!(rs.contains("\"gamma\" =>"));
    assert!(rs.contains("\"delta\" =>"));
    assert!(rs.contains("\"epsilon\" =>"));

    // PascalCase struct name
    assert!(rs.contains("pub(crate) struct MegaProductDispatcher;"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_generated_wit_has_no_syntax_errors() {
    let dir = temp_output_dir();
    let manifest_path = create_test_manifest(&dir);
    let manifest = load_manifest(&manifest_path).unwrap();
    let wit = generate_dispatcher_wit(&manifest);

    // Count braces — they should be balanced
    let open_braces = wit.chars().filter(|&c| c == '{').count();
    let close_braces = wit.chars().filter(|&c| c == '}').count();
    assert_eq!(
        open_braces, close_braces,
        "Unbalanced braces in generated WIT: {} open vs {} close",
        open_braces, close_braces
    );

    // Every `import` line should end with `;`
    for line in wit.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("import ") {
            assert!(
                trimmed.ends_with(';'),
                "Import line missing semicolon: {}",
                trimmed
            );
        }
        if trimmed.starts_with("export ") {
            assert!(
                trimmed.ends_with(';'),
                "Export line missing semicolon: {}",
                trimmed
            );
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_generated_rs_has_balanced_braces() {
    let dir = temp_output_dir();
    let manifest_path = create_test_manifest(&dir);
    let manifest = load_manifest(&manifest_path).unwrap();
    let rs = generate_dispatcher_rs(&manifest);

    let open_braces = rs.chars().filter(|&c| c == '{').count();
    let close_braces = rs.chars().filter(|&c| c == '}').count();
    assert_eq!(
        open_braces, close_braces,
        "Unbalanced braces in generated Rust: {} open vs {} close",
        open_braces, close_braces
    );

    let _ = fs::remove_dir_all(&dir);
}
