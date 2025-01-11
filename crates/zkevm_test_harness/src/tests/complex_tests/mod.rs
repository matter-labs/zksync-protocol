pub mod utils;

pub mod invididual_debugs;
#[cfg(test)]
mod test_synthesis;

#[cfg(test)]
pub mod testing_wrapper;
#[cfg(test)]
mod wrapper_negative_tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::sync_channel;
use std::thread;

use super::*;
use crate::boojum::cs::implementations::pow::NoPow;
use crate::boojum::cs::implementations::prover::ProofConfig;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::field::U64Representable;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::compute_setups::*;
use crate::entry_point::create_out_of_circuit_global_context;
use crate::ethereum_types::*;
use crate::helper::artifact_utils::TestArtifact;
use crate::proof_wrapper_utils::{WrapperConfig, DEFAULT_WRAPPER_CONFIG};
use crate::prover_utils::*;
use crate::tests::complex_tests::utils::empty_node_proof;
use crate::toolset::{create_tools, GeometryConfig};
use crate::witness::oracle::create_artifacts_from_tracer;
use crate::witness::tree::{BinarySparseStorageTree, ZKSyncTestingTree};
use crate::witness::utils::*;
use crate::zk_evm::abstractions::*;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::*;
use crate::zk_evm::testing::storage::InMemoryStorage;
use crate::zk_evm::utils::{bytecode_to_code_hash, contract_bytecode_to_words};
use crate::zk_evm::witness_trace::VmWitnessTracer;
use crate::zk_evm::GenericNoopTracer;
use crate::zkevm_circuits::eip_4844::input::*;
use crate::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;
use crate::zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::circuit_definitions::aux_layer::compression::{
    self, CompressionMode1Circuit,
};
use circuit_definitions::circuit_definitions::aux_layer::wrapper::*;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::ZkSyncLeafLayerRecursiveCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::scheduler::SchedulerCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::zkevm_circuits::scheduler::aux::NUM_CIRCUIT_TYPES_TO_SCHEDULE;
use circuit_definitions::{
    base_layer_proof_config, recursion_layer_proof_config, BASE_LAYER_CAP_SIZE,
    BASE_LAYER_FRI_LDE_FACTOR, RECURSION_LAYER_CAP_SIZE, RECURSION_LAYER_FRI_LDE_FACTOR,
};
use circuit_definitions::{Field, RoundFunction};
use utils::read_basic_test_artifact;

use witness::oracle::WitnessGenerationArtifact;
use zkevm_assembly::Assembly;
use zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;

#[ignore = "Too slow"]
#[test]
fn basic_test() {
    let test_artifact = read_basic_test_artifact();
    let blobs = std::array::from_fn(|i| {
        if i == 0 {
            Some(vec![0xff; ENCODABLE_BYTES_PER_BLOB])
        } else {
            None
        }
    });
    let options = Options {
        use_production_geometry: true,
        ..Default::default()
    };
    run_and_try_create_witness_inner(test_artifact, 40000, blobs, &options);
    // run_and_try_create_witness_inner(test_artifact, 16);
}

#[ignore = "Too slow, requires CRS"]
#[test]
fn test_single_compression() {
    let config = testing_wrapper::get_testing_wrapper_config();

    testing_wrapper::test_compression_for_compression_num(config);
}

#[ignore = "Too slow, requires CRS"]
#[test]
fn test_compression_all_modes() {
    for compression in 1..=WrapperConfig::MAX_COMPRESSION_LAYERS {
        println!("Testing wrapper for mode {}", compression);
        let config = WrapperConfig::new(compression as u8);
        testing_wrapper::test_compression_for_compression_num(config);
    }
}

use crate::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::*;
use circuit_definitions::circuit_definitions::aux_layer::*;
use circuit_definitions::circuit_definitions::aux_layer::compression::ProofCompressionFunction;
use circuit_definitions::circuit_definitions::aux_layer::ZkSyncCompressionLayerVerificationKey;
use crate::data_source::{local_file_data_source::LocalFileDataSource, SetupDataSource, BlockDataSource};
use circuit_definitions::circuit_definitions::aux_layer::compression::*;
use snark_wrapper::verifier_structs::allocated_vk::AllocatedVerificationKey;
use snark_wrapper::franklin_crypto::plonk::circuit::bigint_new::BITWISE_LOGICAL_OPS_TABLE_NAME;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::*;
use snark_wrapper::franklin_crypto::bellman::plonk::commitments::transcript::{
    keccak_transcript::RollingKeccakTranscript,
    Prng
};
use snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use snark_wrapper::franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use snark_wrapper::verifier::WrapperCircuit;
use rescue_poseidon::poseidon2::Poseidon2Sponge;
use rescue_poseidon::poseidon2::transcript::Poseidon2Transcript;
use snark_wrapper::implementations::poseidon2::tree_hasher::AbsorptionModeReplacement;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::gates
    ::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::data_source::in_memory_data_source::InMemoryDataSource;
use crate::witness::artifacts::*;

/// Lover memory requirements
/// Used only for base layer debugging
fn get_testing_geometry_config() -> GeometryConfig {
    GeometryConfig {
        // cycles_per_vm_snapshot: 1,
        cycles_per_vm_snapshot: 1024,
        cycles_per_ram_permutation: 1024,
        cycles_per_code_decommitter: 256,
        cycles_per_storage_application: 4,
        cycles_per_keccak256_circuit: 7,
        cycles_per_sha256_circuit: 7,
        cycles_per_ecrecover_circuit: 2,
        // cycles_code_decommitter_sorter: 512,
        cycles_code_decommitter_sorter: 3,
        cycles_per_log_demuxer: 16,
        cycles_per_storage_sorter: 16,
        cycles_per_events_or_l1_messages_sorter: 4,
        cycles_per_secp256r1_verify_circuit: 2,
        cycles_per_transient_storage_sorter: 16,
        cycles_per_modexp_circuit: 10,
        cycles_per_ecadd_circuit: 10,
        cycles_per_ecmul_circuit: 10,
        cycles_per_ecpairing_circuit: 10,

        limit_for_l1_messages_pudata_hasher: 32,
    }
}

pub(crate) fn generate_base_layer(
    mut test_artifact: TestArtifact,
    cycle_limit: usize,
    geometry: GeometryConfig,
    blobs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
) -> (
    Vec<ZkSyncBaseLayerCircuit>,
    Vec<(
        u64,
        RecursionQueueSimulator<Field>,
        Vec<ZkSyncBaseLayerClosedFormInput<Field>>,
    )>,
    SchedulerCircuitInstanceWitness<
        GoldilocksField,
        CircuitGoldilocksPoseidon2Sponge,
        GoldilocksExt2,
    >,
) {
    use crate::zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    use crate::external_calls::run;
    use crate::toolset::GeometryConfig;

    let mut storage_impl = InMemoryStorage::new();
    let mut tree = ZKSyncTestingTree::empty();

    test_artifact.entry_point_address =
        *zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

    let predeployed_contracts = test_artifact
        .predeployed_contracts
        .clone()
        .into_iter()
        .chain(Some((
            test_artifact.entry_point_address,
            test_artifact.entry_point_code.clone(),
        )))
        .collect::<HashMap<_, _>>();
    save_predeployed_contracts(&mut storage_impl, &mut tree, &predeployed_contracts);

    let used_bytecodes = HashMap::from_iter(
        test_artifact
            .predeployed_contracts
            .iter()
            .map(|(_, bytecode)| {
                (
                    bytecode_to_code_hash(&bytecode).unwrap().into(),
                    bytecode.clone(),
                )
            })
            .chain(
                Some(test_artifact.default_account_code.clone()).map(|bytecode| {
                    (
                        bytecode_to_code_hash(&bytecode).unwrap().into(),
                        bytecode.clone(),
                    )
                }),
            ),
    );
    for (k, _) in used_bytecodes.iter() {
        println!("Have bytecode hash 0x{:x}", k);
    }
    use sha3::{Digest, Keccak256};

    let previous_enumeration_index = tree.next_enumeration_index();
    let previous_root = tree.root();
    // simualate content hash

    let mut hasher = Keccak256::new();
    hasher.update(&previous_enumeration_index.to_be_bytes());
    hasher.update(&previous_root);
    hasher.update(&0u64.to_be_bytes()); // porter shard
    hasher.update(&[0u8; 32]); // porter shard

    let mut previous_data_hash = [0u8; 32];
    (&mut previous_data_hash[..]).copy_from_slice(&hasher.finalize().as_slice());

    let previous_aux_hash = [0u8; 32];
    let previous_meta_hash = [0u8; 32];

    // simulate block header

    let mut hasher = Keccak256::new();
    hasher.update(&previous_data_hash);
    hasher.update(&previous_meta_hash);
    hasher.update(&previous_aux_hash);

    let mut previous_content_hash = [0u8; 32];
    (&mut previous_content_hash[..]).copy_from_slice(&hasher.finalize().as_slice());

    let default_account_codehash =
        bytecode_to_code_hash(&test_artifact.default_account_code).unwrap();
    let default_account_codehash = U256::from_big_endian(&default_account_codehash);

    let evm_simulator_code_hash = bytecode_to_code_hash(&test_artifact.evm_simulator_code).unwrap();
    let evm_simulator_code_hash = U256::from_big_endian(&evm_simulator_code_hash);

    println!("Default AA code hash 0x{:x}", default_account_codehash);
    println!("EVM simulator code hash 0x{:x}", evm_simulator_code_hash);

    let mut basic_block_circuits = vec![];
    let mut recursion_queues = vec![];

    let (sender, receiver) = sync_channel(1);

    let artifacts_receiver_handle = thread::spawn(move || {
        while let Ok(artifact) = receiver.recv() {
            match artifact {
                WitnessGenerationArtifact::BaseLayerCircuit(circuit) => {
                    basic_block_circuits.push(circuit)
                }
                WitnessGenerationArtifact::RecursionQueue((a, b, c)) => recursion_queues.push((
                    a,
                    b,
                    c.into_iter()
                        .map(|x| ZkSyncBaseLayerStorage::from_inner(a as u8, x))
                        .collect(),
                )),
                _ => {}
            }
        }

        (basic_block_circuits, recursion_queues)
    });

    let (scheduler_partial_input, _aux_data) = run(
        Address::zero(),
        test_artifact.entry_point_address,
        test_artifact.entry_point_code,
        vec![],
        false,
        default_account_codehash,
        evm_simulator_code_hash,
        used_bytecodes,
        vec![],
        cycle_limit,
        geometry,
        storage_impl,
        tree,
        "../kzg/src/trusted_setup.json".to_owned(),
        blobs,
        sender,
    );

    let (basic_block_circuits, recursion_queues) = artifacts_receiver_handle.join().unwrap();

    (
        basic_block_circuits,
        recursion_queues,
        scheduler_partial_input,
    )
}

/// Test that does the basic circuit verification - but only one circuit from each kind
/// and it uses test geometry to run faster (as it has smaller circuits).
#[test]
fn basic_layer_test_one_per_kind() {
    let test_artifact = read_basic_test_artifact();
    let blobs = std::array::from_fn(|i| {
        if i == 0 {
            Some(vec![0xff; ENCODABLE_BYTES_PER_BLOB])
        } else {
            None
        }
    });

    // Using smaller geometry to speed things up.
    let geometry = get_testing_geometry_config();

    let (basic_block_circuits, _, _) = generate_base_layer(test_artifact, 40000, geometry, blobs);

    let mut checked = HashSet::new();

    for el in basic_block_circuits.into_iter() {
        if checked.contains(&el.numeric_circuit_type()) {
            continue;
        } else {
            checked.insert(el.numeric_circuit_type());

            let descr = el.short_description();
            println!("Checking circuit type {}", descr);

            base_test_circuit(el);
        }
    }
}

struct Options {
    // Additional tests over the basic circuits.
    test_base_circuits: bool,
    // If true, will use production geometry (less circuits, but more memory).
    // If false, will use 'testing' geometry (more circuits, but smaller and less memory).
    use_production_geometry: bool,

    /// If true, then the test will try to reuse existing artifacts (like proofs etc).
    /// This allows test to not repeat things that it already did.
    /// If false, everything will be computed from scratch.
    try_reuse_artifacts: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            test_base_circuits: false,
            use_production_geometry: false,
            try_reuse_artifacts: true,
        }
    }
}

/// Running the end-to-end tests, using the bytecodes from test_artifact and blobs.
/// Please see the Options to adjust the testing behavior.
#[allow(dead_code)]
fn run_and_try_create_witness_inner(
    test_artifact: TestArtifact,
    cycle_limit: usize,
    blobs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    options: &Options,
) {
    use crate::external_calls::run;
    use crate::toolset::GeometryConfig;

    let geometry = if options.use_production_geometry {
        crate::geometry_config::ProtocolGeometry::latest().config()
    } else {
        get_testing_geometry_config()
    };

    let (basic_block_circuits, mut recursion_queues, scheduler_partial_input) =
        generate_base_layer(test_artifact, cycle_limit, geometry, blobs.clone());

    // It is important that recursion queries are in sorted order - as we later match them with respective proofs.
    recursion_queues.sort_by_key(|(circuit, _, _)| circuit.clone());

    if options.test_base_circuits {
        for (idx, el) in basic_block_circuits.clone().into_iter().enumerate() {
            let descr = el.short_description();
            println!("Doing {}: {}", idx, descr);

            // if idx < 398  {
            //     continue;
            // }

            // match &el {
            //     ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            //         dbg!(&*inner.config);
            //         // let witness = inner.clone_witness().unwrap();
            //         // dbg!(&witness.closed_form_input);
            //         // dbg!(witness.closed_form_input.start_flag);
            //         // dbg!(witness.closed_form_input.completion_flag);
            //     }
            //     _ => {
            //         continue;
            //     }
            // }

            base_test_circuit(el);
        }
    }

    let worker = Worker::new_with_num_threads(8);

    let mut previous_circuit_type = 0;

    let mut instance_idx = 0;

    let mut setup_data = None;

    let mut source = LocalFileDataSource::default();
    source.create_folders_for_storing_data();

    use crate::data_source::*;

    let circuits_len = basic_block_circuits.len();

    for (idx, el) in basic_block_circuits.clone().into_iter().enumerate() {
        let descr = el.short_description();
        println!("Doing {} / {}: {}", idx, circuits_len, descr);

        if el.numeric_circuit_type() != previous_circuit_type {
            instance_idx = 0;
        }

        if options.try_reuse_artifacts {
            if let Ok(_) = source.get_base_layer_proof(el.numeric_circuit_type(), instance_idx) {
                instance_idx += 1;
                previous_circuit_type = el.numeric_circuit_type();
                continue;
            }
        }

        if el.numeric_circuit_type() != previous_circuit_type || setup_data.is_none() {
            println!(
                "Regenerating setup data for {} from {}",
                el.numeric_circuit_type(),
                previous_circuit_type,
            );
            let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
                create_base_layer_setup_data(
                    el.clone(),
                    &worker,
                    BASE_LAYER_FRI_LDE_FACTOR,
                    BASE_LAYER_CAP_SIZE,
                );

            source
                .set_base_layer_vk(ZkSyncBaseLayerVerificationKey::from_inner(
                    el.numeric_circuit_type(),
                    vk.clone(),
                ))
                .unwrap();
            source
                .set_base_layer_finalization_hint(ZkSyncBaseLayerFinalizationHint::from_inner(
                    el.numeric_circuit_type(),
                    finalization_hint.clone(),
                ))
                .unwrap();

            setup_data = Some((
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                wits_hint,
                finalization_hint,
            ));

            previous_circuit_type = el.numeric_circuit_type();
        }

        println!("Proving!");
        let now = std::time::Instant::now();

        let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
            setup_data.as_ref().unwrap();

        let proof = prove_base_layer_circuit::<NoPow>(
            el.clone(),
            &worker,
            base_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_base_layer_proof::<NoPow>(&el, &proof, &vk);

        assert!(is_valid);

        source
            .set_base_layer_proof(
                instance_idx,
                ZkSyncBaseLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
            )
            .unwrap();

        instance_idx += 1;
    }

    println!("Assembling keys");

    let mut proofs = vec![];
    let mut verification_keys = vec![];

    for (circuit_id, queue_simulator, inputs) in recursion_queues.iter() {
        let circuit_type = *circuit_id as u8;
        let mut proofs_for_circuit_type = vec![];
        for idx in 0..inputs.len() {
            println!("Reading base layer proof: {:?} {:?}", circuit_type, idx);

            match source.get_base_layer_proof(circuit_type, idx) {
                Ok(proof) => {
                    proofs_for_circuit_type.push(proof);
                }
                Err(_) => {
                    if idx == 0 && queue_simulator.num_items == 0 {
                        println!("Skipping - assuming that there were no circuits")
                    } else {
                        panic!("Missing for - {} {}", circuit_type, idx);
                    }
                }
            }
        }

        let vk = source.get_base_layer_vk(circuit_type).unwrap();
        verification_keys.push(vk);

        proofs.push(proofs_for_circuit_type);
    }

    println!("Computing leaf vks");

    for base_circuit_type in ((BaseLayerCircuitType::VM as u8)
        ..=(BaseLayerCircuitType::ECPairingPrecompile as u8))
        .chain(std::iter::once(BaseLayerCircuitType::EIP4844Repack as u8))
    {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(base_circuit_type),
        );

        if !options.try_reuse_artifacts
            || source
                .get_recursion_layer_vk(recursive_circuit_type as u8)
                .is_err()
        {
            println!(
                "Computing leaf layer VK for type {:?}",
                recursive_circuit_type
            );
            use crate::zkevm_circuits::recursion::leaf_layer::input::*;
            let input = RecursionLeafInput::placeholder_witness();
            let vk = source.get_base_layer_vk(base_circuit_type).unwrap();

            use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
            let witness = RecursionLeafInstanceWitness {
                input,
                vk_witness: vk.clone().into_inner(),
                queue_witness: FullStateCircuitQueueRawWitness {
                    elements: VecDeque::new(),
                },
                proof_witnesses: VecDeque::new(),
            };

            use crate::zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
            let config = LeafLayerRecursionConfig {
                proof_config: recursion_layer_proof_config(),
                vk_fixed_parameters: vk.into_inner().fixed_parameters,
                capacity: RECURSION_ARITY,
                _marker: std::marker::PhantomData,
            };
            let circuit = ZkSyncLeafLayerRecursiveCircuit {
                base_layer_circuit_type: BaseLayerCircuitType::from_numeric_value(
                    base_circuit_type,
                ),
                witness: witness,
                config: config,
                transcript_params: (),
                _marker: std::marker::PhantomData,
            };

            let circuit = ZkSyncRecursiveLayerCircuit::leaf_circuit_from_base_type(
                BaseLayerCircuitType::from_numeric_value(base_circuit_type),
                circuit,
            );

            let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
                create_recursive_layer_setup_data(
                    circuit,
                    &worker,
                    RECURSION_LAYER_FRI_LDE_FACTOR,
                    RECURSION_LAYER_CAP_SIZE,
                );

            let finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(
                recursive_circuit_type as u8,
                finalization_hint,
            );
            source
                .set_recursion_layer_finalization_hint(finalization_hint)
                .unwrap();
            let vk =
                ZkSyncRecursionLayerVerificationKey::from_inner(recursive_circuit_type as u8, vk);
            source.set_recursion_layer_vk(vk).unwrap();
        }
    }

    println!("Computing leaf params");
    use crate::compute_setups::compute_leaf_params;
    use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
    let leaf_vk_commits = compute_leaf_params(&mut source).unwrap();

    let mut all_leaf_aggregations = vec![];
    use crate::witness::recursive_aggregation::create_leaf_witnesses;

    println!("Creating leaf aggregation circuits");

    let mut all_closed_form_inputs_for_scheduler = vec![];

    assert_eq!(recursion_queues.len(), proofs.len());
    assert_eq!(recursion_queues.len(), verification_keys.len());

    for ((subset, proofs), vk) in recursion_queues
        .clone()
        .into_iter()
        .zip(proofs.into_iter())
        .zip(verification_keys.iter().cloned())
    {
        let param = leaf_vk_commits
            .iter()
            .find(|el| el.0 == subset.0 as u8)
            .cloned()
            .unwrap();

        let (aggregations, recursive_circuits, _closed_form_inputs) =
            create_leaf_witnesses(subset, proofs, vk, param);
        all_leaf_aggregations.push((aggregations, recursive_circuits));
        all_closed_form_inputs_for_scheduler.extend(_closed_form_inputs);
    }

    println!("Proving leaf aggregation circuits");

    let mut previous_circuit_type = 0;

    use circuit_definitions::circuit_definitions::recursion_layer::*;

    for (aggregations_for_circuit_type, recursive_circuits) in all_leaf_aggregations.iter() {
        if aggregations_for_circuit_type.is_empty() {
            continue;
        }

        let mut instance_idx = 0;
        let mut setup_data = None;
        for (idx, el) in recursive_circuits.iter().enumerate() {
            let descr = el.short_description();
            println!("Doing {}: {}", idx, descr);

            // test_recursive_circuit(el.clone());
            // println!("Circuit is satisfied");

            if options.try_reuse_artifacts {
                if let Ok(_proof) =
                    source.get_leaf_layer_proof(el.numeric_circuit_type(), instance_idx)
                {
                    instance_idx += 1;
                    continue;
                }
            }

            if el.numeric_circuit_type() != previous_circuit_type || setup_data.is_none() {
                let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
                    create_recursive_layer_setup_data(
                        el.clone(),
                        &worker,
                        RECURSION_LAYER_FRI_LDE_FACTOR,
                        RECURSION_LAYER_CAP_SIZE,
                    );

                // let other_vk = source
                //     .get_recursion_layer_vk(el.numeric_circuit_type())
                //     .unwrap()
                //     .into_inner();

                // assert_eq!(&other_vk, &vk);

                // let other_finalization_hint = source
                //     .get_recursion_layer_finalization_hint(el.numeric_circuit_type())
                //     .unwrap()
                //     .into_inner();

                // assert_eq!(&other_finalization_hint, &finalization_hint);

                source
                    .set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::from_inner(
                        el.numeric_circuit_type(),
                        vk.clone(),
                    ))
                    .unwrap();
                source
                    .set_recursion_layer_finalization_hint(
                        ZkSyncRecursionLayerFinalizationHint::from_inner(
                            el.numeric_circuit_type(),
                            finalization_hint.clone(),
                        ),
                    )
                    .unwrap();

                setup_data = Some((
                    setup_base,
                    setup,
                    vk,
                    setup_tree,
                    vars_hint,
                    wits_hint,
                    finalization_hint,
                ));

                previous_circuit_type = el.numeric_circuit_type();
            }

            println!("Proving!");
            let now = std::time::Instant::now();

            let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
                setup_data.as_ref().unwrap();

            let proof = prove_recursion_layer_circuit::<NoPow>(
                el.clone(),
                &worker,
                recursion_layer_proof_config(),
                &setup_base,
                &setup,
                &setup_tree,
                &vk,
                &vars_hint,
                &wits_hint,
                &finalization_hint,
            );

            println!("Proving is DONE, taken {:?}", now.elapsed());

            let is_valid = verify_recursion_layer_proof::<NoPow>(&el, &proof, &vk);

            assert!(is_valid);

            source
                .set_leaf_layer_proof(
                    instance_idx,
                    ZkSyncRecursionLayerProof::from_inner(el.numeric_circuit_type(), proof.clone()),
                )
                .unwrap();

            instance_idx += 1;
        }
    }

    // do that once in setup-mode only

    if source.get_recursion_layer_node_vk().is_err() {
        use crate::zkevm_circuits::recursion::node_layer::input::*;
        let input = RecursionNodeInput::placeholder_witness();

        let input_vk = source
            .get_recursion_layer_vk(
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8,
            )
            .unwrap();
        let witness = RecursionNodeInstanceWitness {
            input,
            vk_witness: input_vk.clone().into_inner(),
            split_points: VecDeque::new(),
            proof_witnesses: VecDeque::new(),
        };

        use crate::zkevm_circuits::recursion::node_layer::NodeLayerRecursionConfig;
        use circuit_definitions::circuit_definitions::recursion_layer::node_layer::ZkSyncNodeLayerRecursiveCircuit;
        let config = NodeLayerRecursionConfig {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: input_vk.clone().into_inner().fixed_parameters,
            leaf_layer_capacity: RECURSION_ARITY,
            node_layer_capacity: RECURSION_ARITY,
            _marker: std::marker::PhantomData,
        };
        let circuit = ZkSyncNodeLayerRecursiveCircuit {
            witness: witness,
            config: config,
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit);

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let finalization_hint =
            ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint);
        source
            .set_recursion_layer_node_finalization_hint(finalization_hint.clone())
            .unwrap();
        let vk = ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk);
        source.set_recursion_layer_node_vk(vk.clone()).unwrap();

        let input = RecursionNodeInput::placeholder_witness();
        let input_vk2 = source
            .get_recursion_layer_vk(
                ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter as u8,
            )
            .unwrap();
        let witness = RecursionNodeInstanceWitness {
            input,
            vk_witness: input_vk2.clone().into_inner(),
            split_points: VecDeque::new(),
            proof_witnesses: VecDeque::new(),
        };

        let config = NodeLayerRecursionConfig {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: input_vk2.clone().into_inner().fixed_parameters,
            leaf_layer_capacity: RECURSION_ARITY,
            node_layer_capacity: RECURSION_ARITY,
            _marker: std::marker::PhantomData,
        };
        let circuit = ZkSyncNodeLayerRecursiveCircuit {
            witness: witness,
            config: config,
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        assert_eq!(
            input_vk.clone().into_inner().fixed_parameters,
            input_vk2.clone().into_inner().fixed_parameters
        );

        let circuit = ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit);

        let (
            _setup_base_2,
            _setup_2,
            vk_2,
            _setup_tree_2,
            _vars_hint_2,
            _wits_hint_2,
            finalization_hint_2,
        ) = create_recursive_layer_setup_data(
            circuit,
            &worker,
            RECURSION_LAYER_FRI_LDE_FACTOR,
            RECURSION_LAYER_CAP_SIZE,
        );

        assert_eq!(_vars_hint, _vars_hint_2);
        assert_eq!(_wits_hint, _wits_hint_2);
        assert_eq!(finalization_hint.into_inner(), finalization_hint_2);

        for (idx, (a, b)) in _setup_base
            .constant_columns
            .iter()
            .zip(_setup_base_2.constant_columns.iter())
            .enumerate()
        {
            assert_eq!(a, b, "failed at index {}", idx);
        }
        for (idx, (a, b)) in _setup_base
            .copy_permutation_polys
            .iter()
            .zip(_setup_base_2.copy_permutation_polys.iter())
            .enumerate()
        {
            assert_eq!(a, b, "failed at index {}", idx);
        }
        for (idx, (a, b)) in _setup_base
            .lookup_tables_columns
            .iter()
            .zip(_setup_base_2.lookup_tables_columns.iter())
            .enumerate()
        {
            assert_eq!(a, b, "failed at index {}", idx);
        }
        assert_eq!(_setup_base, _setup_base_2);
        assert_eq!(_setup, _setup_2);
        assert_eq!(_setup_tree, _setup_tree_2);

        assert_eq!(vk.into_inner(), vk_2);
    }

    let node_vk = source.get_recursion_layer_node_vk().unwrap();
    use crate::witness::recursive_aggregation::compute_node_vk_commitment;
    let node_vk_commitment = compute_node_vk_commitment(node_vk);

    println!("Continuing into nodes leaf aggregation circuits");
    for (per_circuit_subtree, _) in all_leaf_aggregations.into_iter() {
        let mut depth = 0;
        let mut next_aggregations = per_circuit_subtree;

        if next_aggregations.len() == 0 {
            // There are no leaf circuits of this type.
            continue;
        }

        let base_circuit_type = next_aggregations[0].0 as u8;
        let circuit_type_enum = BaseLayerCircuitType::from_numeric_value(base_circuit_type);
        println!(
            "Continuing into node aggregation for circuit type {:?}",
            circuit_type_enum
        );

        let recursive_circuit_type =
            base_circuit_type_into_recursive_leaf_circuit_type(circuit_type_enum);

        use crate::witness::recursive_aggregation::create_node_witnesses;
        let vk = if depth == 0 {
            source
                .get_recursion_layer_vk(recursive_circuit_type as u8)
                .unwrap()
        } else {
            source.get_recursion_layer_node_vk().unwrap()
        };

        let mut setup_data = None;

        loop {
            println!("Working on depth {}", depth);
            let mut proofs = vec![];
            for idx in 0..next_aggregations.len() {
                let proof = if depth == 0 {
                    source
                        .get_leaf_layer_proof(recursive_circuit_type as u8, idx)
                        .unwrap()
                } else {
                    source
                        .get_node_layer_proof(recursive_circuit_type as u8, depth, idx)
                        .unwrap()
                };

                proofs.push(proof);
            }
            let (new_aggregations, recursive_circuits) = create_node_witnesses(
                next_aggregations,
                proofs,
                vk.clone(),
                node_vk_commitment,
                &leaf_vk_commits,
            );
            next_aggregations = new_aggregations;

            for (idx, el) in recursive_circuits.iter().enumerate() {
                // test_recursive_circuit(el.clone());
                // println!("Circuit is satisfied");

                if let Ok(_proof) =
                    source.get_node_layer_proof(recursive_circuit_type as u8, depth, idx)
                {
                    continue;
                }

                if setup_data.is_none() {
                    let (
                        setup_base,
                        setup,
                        vk,
                        setup_tree,
                        vars_hint,
                        wits_hint,
                        finalization_hint,
                    ) = create_recursive_layer_setup_data(
                        el.clone(),
                        &worker,
                        RECURSION_LAYER_FRI_LDE_FACTOR,
                        RECURSION_LAYER_CAP_SIZE,
                    );

                    let other_vk = source.get_recursion_layer_node_vk().unwrap().into_inner();

                    assert_eq!(&other_vk, &vk);

                    let other_finalization_hint = source
                        .get_recursion_layer_node_finalization_hint()
                        .unwrap()
                        .into_inner();

                    assert_eq!(&other_finalization_hint, &finalization_hint);

                    // // we did it above
                    // source.set_recursion_layer_node_vk(ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk)).unwrap();
                    // source.set_recursion_layer_node_finalization_hint(ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint)).unwrap();

                    setup_data = Some((
                        setup_base,
                        setup,
                        vk,
                        setup_tree,
                        vars_hint,
                        wits_hint,
                        finalization_hint,
                    ));
                }

                // prove
                println!("Proving!");
                let now = std::time::Instant::now();

                let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
                    setup_data.as_ref().unwrap();

                let proof = prove_recursion_layer_circuit::<NoPow>(
                    el.clone(),
                    &worker,
                    recursion_layer_proof_config(),
                    &setup_base,
                    &setup,
                    &setup_tree,
                    &vk,
                    &vars_hint,
                    &wits_hint,
                    &finalization_hint,
                );

                println!("Proving is DONE, taken {:?}", now.elapsed());

                let is_valid = verify_recursion_layer_proof::<NoPow>(&el, &proof, &vk);

                assert!(is_valid);

                source
                    .set_node_layer_proof(
                        recursive_circuit_type as u8,
                        depth,
                        idx,
                        ZkSyncRecursionLayerProof::NodeLayerCircuit(proof.clone()),
                    )
                    .unwrap();
            }

            if next_aggregations.len() == 1 {
                // end

                // let proof = source
                //     .get_node_layer_proof(recursive_circuit_type as u8, depth, 0)
                //     .unwrap();

                break;
            }

            depth += 1;
        }
    }

    // do everything for recursion tip
    // if source.get_recursion_tip_vk().is_err() {
    //     use crate::zkevm_circuits::recursion::recursion_tip::input::*;
    //     // replicate compute_setups::*
    //     todo!();
    // }

    // collect for recursion tip. We know that is this test depth is 0
    let mut recursion_tip_proofs = vec![];
    for recursive_circuit_type in (ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8)
        ..=(ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECPairing as u8)
    {
        match source.get_node_layer_proof(recursive_circuit_type, 0, 0) {
            Ok(proof) => recursion_tip_proofs.push(proof.into_inner()),
            Err(_) => {
                println!(
                    "Missing node proof for {} - using empty one instead",
                    recursive_circuit_type
                );
                recursion_tip_proofs.push(empty_node_proof().into_inner());
            }
        };
    }

    assert_eq!(recursion_tip_proofs.len(), NUM_CIRCUIT_TYPES_TO_SCHEDULE);

    // node VK
    let node_vk = source.get_recursion_layer_node_vk().unwrap();
    // leaf params
    use crate::zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
    let leaf_layer_params: [RecursionLeafParametersWitness<GoldilocksField>; 20] = leaf_vk_commits
        .iter()
        .map(|el| el.1.clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // compute single(for now) recursion tip proof

    let tip_proof = if source.get_recursive_tip_proof().is_err() || !options.try_reuse_artifacts {
        let node_layer_vk_commitment = compute_node_vk_commitment(node_vk.clone());
        use crate::boojum::gadgets::queue::*;
        use crate::zkevm_circuits::recursion::recursion_tip::input::*;
        use circuit_definitions::boojum::field::Field;
        let mut branch_circuit_type_set = [GoldilocksField::ZERO; RECURSION_TIP_ARITY];
        assert!(branch_circuit_type_set.len() >= recursion_queues.len());
        let mut queue_sets: [_; RECURSION_TIP_ARITY] =
            std::array::from_fn(|_| QueueState::placeholder_witness());

        for ((circuit_type, queue_state), (src_type, src_queue, _)) in branch_circuit_type_set
            .iter_mut()
            .zip(queue_sets.iter_mut())
            .zip(recursion_queues.iter())
        {
            *circuit_type = GoldilocksField::from_u64_unchecked(*src_type);
            *queue_state = take_sponge_like_queue_state_from_simulator(src_queue);
            println!(
                "Circuit: {:?} num items:{:?}",
                circuit_type, src_queue.num_items
            );
        }

        let input = RecursionTipInputWitness {
            leaf_layer_parameters: leaf_layer_params.clone(),
            node_layer_vk_commitment: node_layer_vk_commitment,
            branch_circuit_type_set: branch_circuit_type_set,
            queue_set: queue_sets,
        };

        dbg!(&input);

        let witness = RecursionTipInstanceWitness {
            input,
            vk_witness: node_vk.clone().into_inner(),
            proof_witnesses: recursion_tip_proofs.into(),
        };

        use crate::zkevm_circuits::recursion::recursion_tip::*;
        use circuit_definitions::circuit_definitions::recursion_layer::recursion_tip::*;

        let config = RecursionTipConfig {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: node_vk.clone().into_inner().fixed_parameters,
            _marker: std::marker::PhantomData,
        };

        let circuit = RecursionTipCircuit {
            witness,
            config,
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(circuit);
        // prove it

        // test_recursive_circuit(circuit.clone());

        println!("Creating setup data for recursion tip");

        let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit.clone(),
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        // assert_eq!(source.get_recursion_tip_vk().unwrap().into_inner(), vk);
        source
            .set_recursion_tip_vk(ZkSyncRecursionLayerStorage::RecursionTipCircuit(vk.clone()))
            .unwrap();

        println!("Proving recursion tip");

        let proof = prove_recursion_layer_circuit::<NoPow>(
            circuit.clone(),
            &worker,
            recursion_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Verifying recursion tip");

        let is_valid = verify_recursion_layer_proof::<NoPow>(&circuit, &proof, &vk);

        assert!(is_valid);

        source
            .set_recursive_tip_proof(ZkSyncRecursionLayerProof::RecursionTipCircuit(
                proof.clone(),
            ))
            .unwrap();

        ZkSyncRecursionLayerProof::RecursionTipCircuit(proof)
    } else {
        source.get_recursive_tip_proof().unwrap()
    };

    let recursion_tip_vk = source.get_recursion_tip_vk().unwrap().into_inner();

    // ideally we need to fill previous block meta and aux hashes, but here we are fine

    use crate::zkevm_circuits::scheduler::SchedulerConfig;

    let config = SchedulerConfig {
        proof_config: recursion_layer_proof_config(),
        leaf_layer_parameters: leaf_layer_params.clone(),
        node_layer_vk: node_vk.into_inner(),
        recursion_tip_vk: recursion_tip_vk.clone(),
        vk_fixed_parameters: recursion_tip_vk.fixed_parameters,
        capacity: SCHEDULER_CAPACITY,
        _marker: std::marker::PhantomData,
    };

    let mut scheduler_witness = scheduler_partial_input;
    // we need to reassign block specific data, and proofs

    // proofs
    let recursion_tip_proof = tip_proof.into_inner();
    scheduler_witness.proof_witnesses = vec![recursion_tip_proof].into();

    // blobs
    let eip4844_witnesses: [_; MAX_4844_BLOBS_PER_BLOCK] = blobs.map(|blob| {
        blob.map(|blob| {
            let (_blob_arr, linear_hash, _versioned_hash, output_hash) =
                generate_eip4844_witness::<GoldilocksField>(&blob, "../kzg/src/trusted_setup.json");
            use crate::zkevm_circuits::eip_4844::input::BlobChunkWitness;
            use crate::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
            use crate::zkevm_circuits::eip_4844::input::EIP4844InputOutputWitness;
            use crate::zkevm_circuits::eip_4844::input::EIP4844OutputDataWitness;
            use circuit_definitions::circuit_definitions::base_layer::EIP4844Circuit;
            use crossbeam::atomic::AtomicCell;
            use std::collections::VecDeque;
            use std::sync::Arc;

            let witness = EIP4844OutputDataWitness {
                linear_hash,
                output_hash,
            };

            witness
        })
    });
    scheduler_witness.eip4844_witnesses = eip4844_witnesses;

    let scheduler_circuit = SchedulerCircuit {
        witness: scheduler_witness.clone(),
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    println!("Computing scheduler proof");

    let scheduler_circuit = ZkSyncRecursiveLayerCircuit::SchedulerCircuit(scheduler_circuit);

    if source.get_scheduler_proof().is_err() || !options.try_reuse_artifacts {
        test_recursive_circuit(scheduler_circuit.clone());
        println!("Circuit is satisfied");

        let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                scheduler_circuit.clone(),
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        // we did it above
        source
            .set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::SchedulerCircuit(
                vk.clone(),
            ))
            .unwrap();
        source
            .set_recursion_layer_finalization_hint(
                ZkSyncRecursionLayerFinalizationHint::SchedulerCircuit(finalization_hint.clone()),
            )
            .unwrap();

        // prove
        println!("Proving!");
        let now = std::time::Instant::now();

        let proof = prove_recursion_layer_circuit::<NoPow>(
            scheduler_circuit.clone(),
            &worker,
            recursion_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_recursion_layer_proof::<NoPow>(&scheduler_circuit, &proof, &vk);

        assert!(is_valid);

        source
            .set_scheduler_proof(ZkSyncRecursionLayerProof::SchedulerCircuit(proof))
            .unwrap();
    }

    println!("DONE");
}

#[ignore = "broken test"]
#[test]
fn run_single() {
    use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
    use crate::boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
    use crate::data_source::*;
    use circuit_definitions::circuit_definitions::recursion_layer::verifier_builder::dyn_verifier_builder_for_recursive_circuit_type;

    type TR = GoldilocksPoisedon2Transcript;
    type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

    let f = std::fs::File::open("tmp.json").unwrap();
    let circuit: ZkSyncRecursiveLayerCircuit = serde_json::from_reader(f).unwrap();
    let ZkSyncRecursiveLayerCircuit::SchedulerCircuit(inner) = &circuit else {
        panic!()
    };

    assert_eq!(
        inner.witness.proof_witnesses.len(),
        NUM_CIRCUIT_TYPES_TO_SCHEDULE
    );

    let verifier_builder = dyn_verifier_builder_for_recursive_circuit_type(
        ZkSyncRecursionLayerStorageType::NodeLayerCircuit,
    );
    let verifier = verifier_builder.create_verifier();

    let source = LocalFileDataSource::default();
    source.create_folders_for_storing_data();
    let vk = source.get_recursion_layer_node_vk().unwrap().into_inner();

    for (idx, proof) in inner.witness.proof_witnesses.iter().enumerate() {
        let is_valid = verifier.verify::<H, TR, NoPow>((), &vk, &proof);
        assert!(is_valid, "failed at step {}", idx);
    }

    for circuit_type in (ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8)
        ..=(ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher as u8)
    {
        let proof = source
            .get_node_layer_proof(circuit_type, 0, 0)
            .unwrap()
            .into_inner();
        let is_valid = verifier.verify::<H, TR, NoPow>((), &vk, &proof);
        assert!(is_valid, "failed for circuit type {}", circuit_type);
    }

    test_recursive_circuit(circuit);
}
