#![allow(clippy::bool_comparison)]

pub mod geometry_config;
pub mod proof;
pub mod sort_storage_access;

// IMPORTANT! This constant should never be just changed, since it's used in multiple versions
// of MultiVM, e.g. for old protocol versions too.
// If you are to change it, introduce a new constant instead.
pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

// We're redefining the constants from `zkevm_circuits::eip_4844::input`, because `zkevm_circuits`
// crate requires nightly compiler, while this crate is supposed to be used with stable compiler.
// We have a test to ensure that the values are the same below (having `zkevm_circuits` as a dev
// dependency is OK).
pub const BLOB_CHUNK_SIZE: usize = 31;
pub const ELEMENTS_PER_4844_BLOCK: usize = 4096;
pub const ENCODABLE_BYTES_PER_BLOB: usize = BLOB_CHUNK_SIZE * ELEMENTS_PER_4844_BLOCK;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_monotonic_cycle_counter() {
        // Ensure that constants are in sync with `zkevm_circuits`.
        const _: () = assert!(BLOB_CHUNK_SIZE == zkevm_circuits::eip_4844::input::BLOB_CHUNK_SIZE);
        const _: () = assert!(
            ELEMENTS_PER_4844_BLOCK == zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK
        );
        const _: () = assert!(
            ENCODABLE_BYTES_PER_BLOB == zkevm_circuits::eip_4844::input::ENCODABLE_BYTES_PER_BLOB
        );
    }
}
