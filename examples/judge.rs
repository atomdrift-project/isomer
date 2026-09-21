//! Judge two trees through the library API and print the verdict.
//!
//! What a non-command-line caller does with isomer — postdoc runs this shape
//! against a release and the release before it. Kept as an example rather than
//! a test because it performs a real analysis, and isomer's test suite is
//! deliberately runnable with no trait bundle, model, or network.
//!
//! ```sh
//! cargo run --profile quick --example judge -- OLD NEW
//! ```

use std::path::Path;

use isomer::judgement::judge;
use isomer::options::Options;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [old, new] = args.as_slice() else {
        eprintln!("usage: judge OLD NEW");
        std::process::exit(2);
    };

    // Everything off that would reach the network, so the example is
    // reproducible: no registry metadata, no dependency fetch, no interpreter.
    let opts = Options {
        offline: true,
        ..Options::default()
    };

    let judgement = judge(Path::new(old), Path::new(new), &opts)?;

    println!("severity      {}", judgement.severity.as_str());
    println!("deterministic {}", judgement.deterministic.as_str());
    println!("new           {}", judgement.new_severity.as_str());
    println!("gated         {}", judgement.gated.as_str());
    println!("clean         {}", judgement.clean);
    println!("band          {}", judgement.severity.band());
    match &judgement.interpretation {
        Some(i) => println!("interpreter   {} ({})", i.verdict, i.nature),
        None => println!("interpreter   not run"),
    }
    println!("envelope      {} bytes", judgement.report.get().len());

    // The envelope is carried pre-serialized; a consumer that wants to read
    // inside it parses once, here.
    let parsed: serde_json::Value = serde_json::from_str(judgement.report.get())?;
    println!("schema        v{}", parsed["v"].as_str().unwrap_or("?"));
    println!(
        "verdict.severity {}",
        parsed["verdict"]["severity"].as_str().unwrap_or("?")
    );

    // The exit code contract the binary implements, for reference.
    if judgement.gated.fails(opts.fail_on) {
        std::process::exit(1);
    }
    Ok(())
}
