use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// Reject local trait-ID literals and predicates in production Rust.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/.."))]
    root: PathBuf,
}

fn main() -> Result<ExitCode> {
    let errors = isomer_tools::trait_ids::check_tree(&Args::parse().root)?;
    for (path, error) in &errors {
        println!(
            "{}:{}: {}: {:?}",
            path.display(),
            error.line,
            error.reason,
            error.value
        );
    }
    if errors.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{} violation(s): local trait IDs are not stable; use hierarchy boundaries.",
            errors.len()
        );
        Ok(ExitCode::FAILURE)
    }
}
