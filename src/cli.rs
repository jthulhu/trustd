use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Cli {
    #[arg(short = 'c', long = "config")]
    pub config: PathBuf,
}
