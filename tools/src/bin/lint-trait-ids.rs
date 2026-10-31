use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// Reject local trait-ID literals and predicates in production Rust.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/.."))]
    root: PathBuf,
    /// Traits tree the hierarchies production code names must exist in.
    /// Defaults to a `traits-dev` checkout beside the repository.
    #[arg(long, env = "CLEAVE_TRAITS_DIR")]
    traits: Option<PathBuf>,
}

fn main() -> Result<ExitCode> {
    let args = Args::parse();
    let traits = args
        .traits
        .filter(|t| !t.as_os_str().is_empty())
        .unwrap_or_else(|| args.root.join("../traits-dev"));
    let traits = traits.is_dir().then_some(traits);
    if traits.is_none() {
        eprintln!("lint-trait-ids: no traits tree; hierarchy existence not checked");
    }
    let errors = isomer_tools::trait_ids::check_tree(&args.root, traits.as_deref())?;
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
            "{} violation(s): depend on hierarchies, not local trait IDs, and only on hierarchies the traits tree has.",
            errors.len()
        );
        Ok(ExitCode::FAILURE)
    }
}
