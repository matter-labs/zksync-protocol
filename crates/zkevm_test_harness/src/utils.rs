use crate::boojum::field::SmallField;
use crate::kzg::KzgSettings;
use crate::witness::tree::BinaryHasher;

use circuit_definitions::encodings::BytesSerializable;
use circuit_encodings::zk_evm::reference_impls::memory::SimpleMemory;
use zkevm_assembly::zkevm_opcode_defs::FatPointer;

pub fn u64_as_u32_le(value: u64) -> [u32; 2] {
    [value as u32, (value >> 32) as u32]
}

pub fn u128_as_u32_le(value: u128) -> [u32; 4] {
    [
        value as u32,
        (value >> 32) as u32,
        (value >> 64) as u32,
        (value >> 96) as u32,
    ]
}

pub fn bytes_to_u32_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u32; M] {
    assert!(M > 0);
    assert!(M * 4 == N);

    let mut result = [0u32; M];

    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

pub fn bytes_to_u128_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u128; M] {
    assert!(M > 0);
    assert!(M * 16 == N);

    let mut result = [0u128; M];

    for (idx, chunk) in bytes.chunks_exact(16).enumerate() {
        let word = u128::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

pub fn binary_merklize_set<
    'a,
    const N: usize,
    T: BytesSerializable<N> + 'a,
    H: BinaryHasher<32>,
    I: Iterator<Item = &'a T> + ExactSizeIterator,
>(
    input: I,
    tree_size: usize,
) -> [u8; 32] {
    let input_len = input.len();
    assert!(tree_size >= input_len);
    assert!(tree_size.is_power_of_two());
    let mut leaf_hashes = Vec::with_capacity(tree_size);

    for el in input {
        let encoding = el.serialize();
        let leaf_hash = H::leaf_hash(&encoding);
        leaf_hashes.push(leaf_hash);
    }

    let trivial_leaf_hash = H::leaf_hash(&[0u8; N]);
    leaf_hashes.resize(tree_size, trivial_leaf_hash);

    let mut previous_layer_hashes = leaf_hashes;
    let mut node_hashes = vec![];

    let num_layers = tree_size.trailing_zeros();

    for level in 0..num_layers {
        for pair in previous_layer_hashes.chunks(2) {
            let new_node_hash = H::node_hash(level as usize, &pair[0], &pair[1]);
            node_hashes.push(new_node_hash);
        }

        let p = std::mem::replace(&mut node_hashes, vec![]);
        previous_layer_hashes = p;
    }

    assert_eq!(previous_layer_hashes.len(), 1);
    let root = previous_layer_hashes[0];

    root
}

use crate::boojum::pairing::bls12_381::fr::{Fr, FrRepr};
use crate::sha2::Digest;
use crate::sha3::Keccak256;
use crate::snark_wrapper::franklin_crypto::bellman::Field;
use crate::snark_wrapper::franklin_crypto::bellman::PrimeField;
use crate::zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK;

/// Generates eip4844 witness for a given blob and using a trusted setup from a given json path.
/// Returns blob array, linear hash, versioned hash and output hash.
/// Blob must have exact length of 31 * 4096
// Example trusted setup path is in "src/kzg/trusted_setup.json".
pub fn generate_eip4844_witness<F: SmallField>(
    blob: &[u8],
    trusted_setup_path: &str,
) -> (
    [[u8; 31]; ELEMENTS_PER_4844_BLOCK],
    [u8; 32],
    [u8; 32],
    [u8; 32],
) {
    // create blob array from vec
    assert!(blob.len() == 31 * 4096);
    let mut blob_arr = [[0u8; 31]; ELEMENTS_PER_4844_BLOCK];
    blob.chunks(31).enumerate().for_each(|(i, chunk)| {
        if chunk.len() == 31 {
            blob_arr[i].copy_from_slice(chunk);
        } else {
            blob_arr[i][..chunk.len()].copy_from_slice(chunk);
        }
    });

    // There chunks are representation of the monomial form
    let mut poly = crate::zkevm_circuits::eip_4844::zksync_pubdata_into_monomial_form_poly(&blob);
    // so FFT then
    crate::zkevm_circuits::eip_4844::fft(&mut poly);
    // and bitreverse
    crate::zkevm_circuits::eip_4844::bitreverse(&mut poly);
    // now they can be an input to KZG commitment

    use crate::kzg::compute_commitment;
    use circuit_definitions::boojum::pairing::CurveAffine;

    let settings = KzgSettings::new(trusted_setup_path);

    let commitment = compute_commitment(&settings, &poly);
    use crate::sha2::Sha256;
    let mut versioned_hash: [u8; 32] = Sha256::digest(&commitment.into_compressed())
        .try_into()
        .expect("should be able to create an array from a keccak digest");
    versioned_hash[0] = 1;

    // compute linear hash
    let linear_hash: [u8; 32] =
        Keccak256::digest(&blob_arr.clone().into_iter().flatten().collect::<Vec<u8>>())
            .try_into()
            .expect("should be able to create an array from a keccak digest");

    // follow circuit logic to produce FS challenge to later open poly
    // at this point either from KZG in L1 or compute directly from monomial form in the circuit
    let evaluation_point = &Keccak256::digest(
        &linear_hash
            .iter()
            .chain(&versioned_hash)
            .map(|x| *x)
            .collect::<Vec<u8>>(),
    )[16..];
    let evaluation_repr =
        u128::from_be_bytes(evaluation_point.try_into().expect("should have 16 bytes"));
    let evaluation_point_fe = Fr::from_repr(FrRepr([
        evaluation_repr as u64,
        (evaluation_repr >> 64) as u64,
        0u64,
        0u64,
    ]))
    .expect("should have a valid field element from 16 bytes");
    let opening_value = blob_arr
        .iter()
        .enumerate()
        .fold(Fr::zero(), |mut acc, (i, x)| {
            let repr = x
                .chunks(8)
                .map(|bytes| {
                    let mut arr = [0u8; 8];
                    for (i, b) in bytes.iter().enumerate() {
                        arr[i] = *b;
                    }
                    u64::from_le_bytes(arr)
                })
                .collect::<Vec<u64>>();
            let el = Fr::from_repr(FrRepr([repr[0], repr[1], repr[2], repr[3]]))
                .expect("31 bytes should create valid field element");
            acc.add_assign(&el);
            if i != ELEMENTS_PER_4844_BLOCK - 1 {
                acc.mul_assign(&evaluation_point_fe);
            }
            acc
        });
    let opening_value_bytes = opening_value
        .into_repr()
        .0
        .iter()
        .rev()
        .flat_map(|el| el.to_be_bytes())
        .collect::<Vec<u8>>();

    let output_hash: [u8; 32] = Keccak256::digest(
        versioned_hash
            .iter()
            .chain(evaluation_point.iter())
            .chain(opening_value_bytes.iter())
            .map(|x| *x)
            .collect::<Vec<u8>>(),
    )
    .try_into()
    .expect("should be able to convert genericarray to array");

    (blob_arr, linear_hash, versioned_hash, output_hash)
}

pub use circuit_encodings::utils::calldata_to_aligned_data;
pub use circuit_encodings::utils::finalize_queue_state;
pub use circuit_encodings::utils::finalized_queue_state_as_bytes;

/// Reads the memory slice represented by the fat pointer.
/// Note, that the fat pointer must point to the accessible memory (i.e. not cleared up yet).
pub(crate) fn read_fatpointer_from_simple_memory(
    memory: &SimpleMemory,
    pointer: FatPointer,
) -> Vec<u8> {
    let FatPointer {
        offset,
        length,
        start,
        memory_page,
    } = pointer;

    // The actual bounds of the returndata ptr is [start+offset..start+length]
    let mem_region_start = start + offset;
    let mem_region_length = length - offset;

    read_unaligned_bytes_from_simple_memory(
        memory,
        memory_page as usize,
        mem_region_start as usize,
        mem_region_length as usize,
    )
}

// This method should be used with relatively small lengths, since
// we don't heavily optimize here for cases with long lengths
pub fn read_unaligned_bytes_from_simple_memory(
    memory: &SimpleMemory,
    page: usize,
    start: usize,
    length: usize,
) -> Vec<u8> {
    if length == 0 {
        return vec![];
    }

    let end = start + length - 1;

    let mut current_word = start / 32;
    let mut result = vec![];
    while current_word * 32 <= end {
        let word_value = memory.read_slot(page, current_word).value;
        let word_value = {
            let mut bytes: Vec<u8> = vec![0u8; 32];
            word_value.to_big_endian(&mut bytes);
            bytes
        };

        result.extend(extract_needed_bytes_from_word(
            word_value,
            current_word,
            start,
            end,
        ));

        current_word += 1;
    }

    assert_eq!(result.len(), length);

    result
}

// It is expected that there is some intersection between `[word_number*32..word_number*32+31]` and `[start, end]`
fn extract_needed_bytes_from_word(
    word_value: Vec<u8>,
    word_number: usize,
    start: usize,
    end: usize,
) -> Vec<u8> {
    let word_start = word_number * 32;
    let word_end = word_start + 31; // Note, that at `word_start + 32` a new word already starts

    let intersection_left = std::cmp::max(word_start, start);
    let intersection_right = std::cmp::min(word_end, end);

    if intersection_right < intersection_left {
        vec![]
    } else {
        let start_bytes = intersection_left - word_start;
        let to_take = intersection_right - intersection_left + 1;

        word_value
            .into_iter()
            .skip(start_bytes)
            .take(to_take)
            .collect()
    }
}
