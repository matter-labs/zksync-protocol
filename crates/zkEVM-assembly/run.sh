#!/usr/bin/env bash

set -Cx

# Logging level: 'error' | 'warn' | 'info' | 'debug' | 'trace'
case "${1}" in
    info)
        export CARGO_LOG_LEVEL="--verbose"
        ;;
    debug)
        export RUST_BACKTRACE=1
        export CARGO_LOG_LEVEL="--verbose"
        ;;
    trace)
        export RUST_BACKTRACE="full"
        export CARGO_LOG_LEVEL="--verbose"
        ;;
esac

# Target build: 'debug' | 'release'
case "${2}" in
    debug)
        export TARGET_DIRECTORY="debug"
        ;;
    release)
        export RELEASE_FLAG="--release"
        export TARGET_DIRECTORY="release"
        ;;
    *)
        export TARGET_DIRECTORY="debug"
        ;;
esac

cargo fmt --all
cargo clippy
cargo test
for file in examples/*.sasm; do
    cargo run ${CARGO_LOG_LEVEL} ${RELEASE_FLAG} --bin 'reader' -- "${file}"
done
