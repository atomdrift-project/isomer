//! Inspect the exact scan model evidence used by Isomer, without an LLM or
//! registry fetch. Usage: cargo run --profile quick --example risk-evidence -- FILE...
//! Prints one JSON record per input. Global-importance reasons are diagnostic
//! context, not causal explanations of a change or per-route SHAP values.

use anyhow::{Context, Result, ensure};
use std::path::PathBuf;

fn main() -> Result<()> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(!paths.is_empty(), "provide one or more files to score");
    let model_dir = scan::models_repo::model_dir()?;
    let analyzer = scan::Analyzer::load(&model_dir)?;
    for path in paths {
        let name = path
            .file_name()
            .context("input has no filename")?
            .to_string_lossy();
        let result = analyzer.scan_file(&path, &name)?;
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "sha256": result.sha256,
                "model_dir": model_dir,
                "model_version": result.version,
                "classification": result.classification.to_string(),
                "probability": result.probability,
                "threshold": result.threshold,
                "level": result.level,
                "file_type": result.file_type,
                "routes": result.model_scores,
                "skipped_routes": result.skipped_models,
                "global_importance_reasons": result.reasons,
            })
        );
    }
    Ok(())
}
