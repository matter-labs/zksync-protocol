use super::*;

#[test]
pub(crate) fn compression_full_test() {
    let worker = boojum::worker::Worker::new();

    let risc_wrapper_proof = deserialize_from_bin_file(RISC_WRAPPER_PROOF_PATH).unwrap();
    let risc_wrapper_vk: crate::RiscWrapperVK =
        deserialize_from_bin_file(RISC_WRAPPER_VK_PATH).unwrap();

    #[cfg(not(feature = "gpu"))]
    let (compression_proof, compression_vk) = {
        let (
            finalization_hint,
            setup_base,
            setup,
            compression_vk,
            setup_tree,
            vars_hint,
            witness_hints,
        ) = crate::get_compression_setup(risc_wrapper_vk.clone(), &worker);

        let compression_proof = crate::prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            &finalization_hint,
            &setup_base,
            &setup,
            &compression_vk,
            &setup_tree,
            &vars_hint,
            &witness_hints,
            &worker,
        );

        let is_valid = crate::verify_compression_proof(&compression_proof, &compression_vk);
        assert!(is_valid);

        (compression_proof, compression_vk)
    };

    #[cfg(feature = "gpu")]
    let (compression_proof, compression_vk) = {
        use shivini::{ProverContext, ProverContextConfig};
        let config = ProverContextConfig::default().with_smallest_supported_domain_size(1 << 15);
        let _prover_context = ProverContext::create_with_config(config).unwrap();

        let (_, _, _, cpu_vk, _, _, _) =
            crate::get_compression_setup(risc_wrapper_vk.clone(), &worker);
        let (gpu_setup, gpu_vk, finalization_hint) =
            crate::gpu::compression::get_compression_setup(&worker, risc_wrapper_vk.clone());

        assert_eq!(
            bincode::serde::encode_to_vec(&cpu_vk, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&gpu_vk, bincode::config::standard()).unwrap(),
            "CPU/GPU compression VK mismatch"
        );

        let compression_proof = crate::gpu::compression::prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            &finalization_hint,
            &gpu_setup,
            &gpu_vk,
            &worker,
        );

        let is_valid = crate::verify_compression_proof(&compression_proof, &gpu_vk);
        assert!(is_valid);

        (compression_proof, gpu_vk)
    };

    let mut invalid_proof = compression_proof.clone();
    invalid_proof.public_inputs[0].0 ^= 1;
    assert!(!crate::verify_compression_proof(
        &invalid_proof,
        &compression_vk
    ));

    serialize_to_bin_file(&compression_proof, COMPRESSION_PROOF_PATH).unwrap();
    serialize_to_bin_file(&compression_vk, COMPRESSION_VK_PATH).unwrap();
}

#[test]
pub(crate) fn compression_setup_test() {
    let worker = boojum::worker::Worker::new();

    let risc_wrapper_vk = deserialize_from_bin_file(RISC_WRAPPER_VK_PATH).unwrap();

    let (
        finalization_hint,
        _setup_base,
        _setup,
        compression_vk,
        _setup_tree,
        _vars_hint,
        _witness_hints,
    ) = crate::get_compression_setup(risc_wrapper_vk, &worker);

    dbg!(finalization_hint);

    serialize_to_bin_file(&compression_vk, COMPRESSION_VK_PATH).unwrap();
}
