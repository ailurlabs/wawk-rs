//! wawk-codegen CLI — generate dispatcher project from a extension manifest.
//!
//! Usage:
//!   wawk-codegen <MANIFEST_PATH> <OUTPUT_DIR>

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use wawk_core::dispatcher::{
    generate_cargo_toml, generate_dispatcher_rs, generate_dispatcher_wit, generate_lib_rs,
    load_manifest, write_dispatcher,
};

#[derive(Parser, Debug)]
#[command(
    name = "wawk-codegen",
    about = "Generate dispatcher project (WIT + Rust + Cargo.toml) from a extension-manifest.json",
    version
)]
struct Cli {
    /// Path to extension-manifest.json
    #[arg(value_name = "MANIFEST_PATH")]
    manifest: PathBuf,

    /// Output directory for generated files
    #[arg(value_name = "OUTPUT_DIR")]
    output: PathBuf,

    /// Only generate WIT (skip Rust and Cargo.toml)
    #[arg(long)]
    wit_only: bool,

    /// Only generate Rust source (skip WIT and Cargo.toml)
    #[arg(long)]
    rs_only: bool,

    /// Print generated output to stdout instead of writing files
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let manifest = load_manifest(&cli.manifest)?;
    eprintln!(
        "Loaded manifest: {} v{} ({} extensions)",
        manifest.name,
        manifest.version,
        manifest.extensions.len()
    );

    if cli.dry_run {
        if !cli.rs_only {
            let wit = generate_dispatcher_wit(&manifest);
            println!("=== dispatcher.wit ===\n{}", wit);
        }
        if !cli.wit_only {
            let rs = generate_dispatcher_rs(&manifest);
            println!("=== dispatcher.rs ===\n{}", rs);
            let cargo = generate_cargo_toml(&manifest);
            println!("=== Cargo.toml ===\n{}", cargo);
            let lib = generate_lib_rs(&manifest);
            println!("=== lib.rs ===\n{}", lib);
        }
        return Ok(());
    }

    if cli.wit_only {
        let wit = generate_dispatcher_wit(&manifest);
        let wit_dir = cli.output.join("wit");
        std::fs::create_dir_all(&wit_dir)?;
        let wit_path = wit_dir.join("dispatcher.wit");
        std::fs::write(&wit_path, &wit)
            .with_context(|| format!("failed to write {}", wit_path.display()))?;
        eprintln!("Generated: {}", wit_path.display());
    } else if cli.rs_only {
        let rs = generate_dispatcher_rs(&manifest);
        let src_dir = cli.output.join("src");
        std::fs::create_dir_all(&src_dir)?;
        let rs_path = src_dir.join("dispatcher.rs");
        std::fs::write(&rs_path, &rs)
            .with_context(|| format!("failed to write {}", rs_path.display()))?;
        eprintln!("Generated: {}", rs_path.display());
    } else {
        write_dispatcher(&manifest, &cli.output)?;
        eprintln!(
            "Generated dispatcher project in {}",
            cli.output.display()
        );
    }

    Ok(())
}
