#![no_main]

use airbender::guest::read;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
#[cfg(not(feature = "legacy-unproven-gaps"))]
use zksync_airbender_verifier::Verify;

// Catch a calibration verifier linked into a guest that did NOT ask for one:
// `guest` is a workspace member, so one cargo invocation that also selects a
// `cycle-markers` package unifies that feature into the linked verifier while
// this crate's own feature list still reads empty. Without this the leak
// surfaces only at the CSR scan, and only because markers and the wire change
// happen to share a feature. Deliberately absent when this crate asks for
// `cycle-markers` itself — that is the intentional bench guest.
#[cfg(not(feature = "cycle-markers"))]
const _: () = assert!(
    !zksync_airbender_verifier::CALIBRATION_FLAVOUR,
    "the linked verifier is the cycle-markers calibration build, which trusts \
     the operator's protocol version and must never be proved with; build the \
     guest as the only selected package"
);

#[airbender::main]
fn main() -> [u32; 8] {
    let input: AirbenderVerifierInput = read().expect("failed to read AirbenderVerifierInput");
    #[cfg(not(feature = "legacy-unproven-gaps"))]
    let result = input.verify().unwrap();
    #[cfg(feature = "legacy-unproven-gaps")]
    let result = zksync_airbender_verifier::verify_legacy_unproven_gaps(input).unwrap();
    result.proof_public_input
}
