//!
//! zkEVM assembly reader arguments.
//!

use std::path::PathBuf;
use structopt::StructOpt;

///
/// zkEVM assembly reader arguments.
///
#[derive(Debug, StructOpt)]
#[structopt(name = "zkEVM assembly reader")]
pub struct Arguments {
    /// Input file path.
    #[structopt(parse(from_os_str))]
    pub input: PathBuf,

    /// Output file, stdout if not present
    #[structopt(parse(from_os_str))]
    pub output: Option<PathBuf>,
}

impl Arguments {
    ///
    /// A shortcut constructor.
    ///
    pub fn new() -> Self {
        Self::from_args()
    }
}

impl Default for Arguments {
    fn default() -> Self {
        Self::new()
    }
}
