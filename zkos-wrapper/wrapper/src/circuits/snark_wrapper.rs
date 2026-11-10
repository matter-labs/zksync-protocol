use bellman::plonk::better_better_cs::cs::ConstraintSystem as SnarkConstraintSystem;
use snark_wrapper::traits::circuit::ErasedBuilderForWrapperVerifier;
use snark_wrapper::traits::circuit::ProofWrapperFunction;
use snark_wrapper::verifier::WrapperCircuit;

use crate::*;

pub type SnarkWrapperCircuit = WrapperCircuit<
    Bn256,
    CompressionTreeHasher,
    CircuitCompressionTreeHasher,
    CircuitCompressionTranscript,
    SnarkWrapperFunction,
>;

#[derive(Debug, Clone)]
pub struct SnarkWrapperFunction;

impl ProofWrapperFunction<Bn256> for SnarkWrapperFunction {
    fn builder_for_wrapper<CS: SnarkConstraintSystem<Bn256> + 'static>(
        &self,
    ) -> Box<dyn ErasedBuilderForWrapperVerifier<Bn256, CS>> {
        Box::new(CompressionCircuitBuilder::default())
    }

    fn proof_config_for_compression_step(&self) -> ProofConfig {
        CompressionCircuit::get_proof_config()
    }
}
