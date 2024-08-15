//!
//! zkEVM assembly reader binary.
//!

pub mod arguments;

use zkevm_opcode_defs::decoding::EncodingModeProduction;

use self::arguments::Arguments;
use std::{convert::TryFrom, io::Write};

///
/// The application entry point.
///
fn main() {
    env_logger::init();

    let args = Arguments::new();

    let mut assembly =
        zkevm_assembly::Assembly::try_from(args.input).expect("Assembly file reading");

    let serialized = assembly
        .compile_to_bytecode_for_mode::<8, EncodingModeProduction>()
        .expect("Must compile the bytecode");

    let mut pretty_bytecode = String::with_capacity((64 + 2) * serialized.len() + 100);
    for el in serialized.into_iter() {
        std::fmt::write(&mut pretty_bytecode, format_args!("{}", hex::encode(el)))
            .expect("Error occurred while trying to write in String");
    }

    if let Some(path) = args.output {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .expect("can not open an output file");
        file.write_all(pretty_bytecode.as_bytes())
            .expect("can not write to file");
    } else {
        std::io::stdout()
            .write_all(pretty_bytecode.as_bytes())
            .expect("can not write to stdout");
    }
}
