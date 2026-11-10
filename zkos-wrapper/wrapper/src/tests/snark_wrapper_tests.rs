use super::*;

#[cfg(not(feature = "gpu"))]
use bellman::kate_commitment::{Crs, CrsForMonomialForm};

#[cfg(feature = "gpu")]
const DEFAULT_TRUSTED_SETUP_FILE: &str = "../crs/setup_gpu.key";

#[cfg(feature = "gpu")]
fn trusted_setup_file() -> String {
    std::env::var("TRUSTED_SETUP_FILE").unwrap_or_else(|_| DEFAULT_TRUSTED_SETUP_FILE.to_string())
}

#[test]
pub(crate) fn snark_wrapper_full_test() {
    let compression_proof = deserialize_from_bin_file(COMPRESSION_PROOF_PATH).unwrap();
    let compression_vk: crate::CompressionVK =
        deserialize_from_bin_file(COMPRESSION_VK_PATH).unwrap();

    #[cfg(not(feature = "gpu"))]
    let (snark_wrapper_vk, snark_wrapper_proof) = {
        let worker = crate::BellmanWorker::new();
        let crs_mons = Crs::<crate::Bn256, CrsForMonomialForm>::crs_42(
            1 << crate::L1_VERIFIER_DOMAIN_SIZE_LOG,
            &worker,
        );

        let (snark_setup, snark_wrapper_vk) =
            crate::get_snark_wrapper_setup(compression_vk.clone(), &crs_mons, &worker);

        let snark_wrapper_proof = crate::prove_snark_wrapper(
            compression_proof,
            compression_vk,
            &snark_setup,
            &crs_mons,
            &worker,
            true,
        );

        (snark_wrapper_vk, snark_wrapper_proof)
    };

    #[cfg(feature = "gpu")]
    let (snark_wrapper_vk, snark_wrapper_proof) = {
        let crs_file = trusted_setup_file();

        let (gpu_setup, gpu_vk) =
            crate::gpu::snark::gpu_create_snark_setup_data(&compression_vk, &crs_file, None);

        let snark_wrapper_proof = crate::gpu::snark::gpu_snark_prove(
            &gpu_setup,
            &gpu_vk,
            compression_proof,
            compression_vk,
            &crs_file,
            true,
        );

        (gpu_vk, snark_wrapper_proof)
    };

    let is_valid = crate::verify_snark_wrapper_proof(&snark_wrapper_proof, &snark_wrapper_vk);
    assert!(is_valid);

    let mut invalid_proof = snark_wrapper_proof.clone();
    use bellman::Field;
    invalid_proof.inputs[0].add_assign(&crate::Fr::one());
    assert!(!crate::verify_snark_wrapper_proof(
        &invalid_proof,
        &snark_wrapper_vk
    ));

    serialize_to_bin_file(&snark_wrapper_proof, SNARK_WRAPPER_PROOF_PATH).unwrap();
    serialize_to_bin_file(&snark_wrapper_vk, SNARK_WRAPPER_VK_PATH).unwrap();
}

#[test]
pub(crate) fn snark_wrapper_setup_test() {
    let compression_vk: crate::CompressionVK =
        deserialize_from_bin_file(COMPRESSION_VK_PATH).unwrap();

    #[cfg(not(feature = "gpu"))]
    let snark_wrapper_vk = {
        let worker = crate::BellmanWorker::new();
        let crs_mons = Crs::<crate::Bn256, CrsForMonomialForm>::crs_42(
            1 << crate::L1_VERIFIER_DOMAIN_SIZE_LOG,
            &worker,
        );

        let (_snark_wrapper_setup, snark_wrapper_vk) =
            crate::get_snark_wrapper_setup(compression_vk, &crs_mons, &worker);

        snark_wrapper_vk
    };

    #[cfg(feature = "gpu")]
    let snark_wrapper_vk = {
        let crs_file = trusted_setup_file();
        let (_gpu_setup, gpu_vk) =
            crate::gpu::snark::gpu_create_snark_setup_data(&compression_vk, &crs_file, None);
        gpu_vk
    };

    serialize_to_bin_file(&snark_wrapper_vk, SNARK_WRAPPER_VK_PATH).unwrap();
}
