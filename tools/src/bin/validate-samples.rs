use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    match isomer_tools::audit::execute(
        &isomer_tools::audit::Args::parse(),
        &mut std::io::stdout().lock(),
    ) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("validate-samples: {error:#}");
            ExitCode::from(2)
        }
    }
}
