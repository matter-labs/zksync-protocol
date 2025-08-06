#[derive(Clone, Copy, Debug)]
pub enum OpcodeDecodingError {
    UnknownOpcode,
    EncodingIsTooLong,
}

impl core::fmt::Display for OpcodeDecodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl core::error::Error for OpcodeDecodingError {}
