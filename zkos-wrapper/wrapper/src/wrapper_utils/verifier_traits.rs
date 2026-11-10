use boojum::gadgets::traits::witnessable::WitnessHookable;

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct PlaceholderSource;

impl NonDeterminismSource for PlaceholderSource {
    #[inline(always)]
    fn read_word() -> u32 {
        0u32
    }
    #[inline(always)]
    fn read_reduced_field_element(_modulus: u32) -> u32 {
        0u32
    }
}

// wrapping NonDeterminismSource functions:
pub fn read_word<F: SmallField, CS: ConstraintSystem<F>, I: NonDeterminismSource>(
    cs: &mut CS,
) -> UInt32<F> {
    UInt32::allocate_checked(cs, I::read_word())
}

pub fn read_mersenne_element<F: SmallField, CS: ConstraintSystem<F>, I: NonDeterminismSource>(
    cs: &mut CS,
) -> MersenneField<F> {
    let modulus = Mersenne31Field::CHARACTERISTICS as u32;
    let witness = Mersenne31Field::from_nonreduced_u32(I::read_reduced_field_element(modulus));
    MersenneField::allocate_checked(cs, witness, false)
}

pub trait CircuitLeafInclusionVerifier<F: SmallField> {
    type OutOfCircuitImpl: LeafInclusionVerifier;

    fn new<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self;

    fn verify_leaf_inclusion<
        CS: ConstraintSystem<F>,
        I: NonDeterminismSource,
        const CAP_SIZE: usize,
        const NUM_COSETS: usize,
    >(
        &mut self,
        cs: &mut CS,
        coset_index: &[Boolean<F>],
        leaf_index: &[Boolean<F>],
        depth: usize,
        leaf_encoding: &[MersenneField<F>],
        merkle_cap: &[WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    );
}

use crate::risc_verifier::blake2s_u32::{
    BLAKE2S_BLOCK_SIZE_U32_WORDS, BLAKE2S_DIGEST_SIZE_U32_WORDS,
};

#[derive(Debug)]
pub struct CircuitBlake2sForEverythingVerifier<F: SmallField> {
    hasher: Blake2sStateGate<F>,
}

impl<F: SmallField> CircuitLeafInclusionVerifier<F> for CircuitBlake2sForEverythingVerifier<F> {
    type OutOfCircuitImpl = Blake2sForEverythingVerifier;

    fn new<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            hasher: Blake2sStateGate::new(cs),
        }
    }

    fn verify_leaf_inclusion<
        CS: ConstraintSystem<F>,
        I: NonDeterminismSource,
        const CAP_SIZE: usize,
        const NUM_COSETS: usize,
    >(
        &mut self,
        cs: &mut CS,
        coset_index: &[Boolean<F>],
        leaf_index: &[Boolean<F>],
        depth: usize,
        leaf_encoding: &[MersenneField<F>],
        merkle_cap: &[WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    ) {
        // our strategy is:
        // - since leaf is used for other purposes, we have to copy it into the buffer, no options here
        // - but when we output the leaf hash, we will put it into the input buffer of our first of `merkle_path_hashers`,
        // and then alternate between them
        self.hasher.reset();

        let input_len_words = leaf_encoding.len();
        let mut num_full_rounds = input_len_words / BLAKE2S_BLOCK_SIZE_U32_WORDS;
        let mut last_round_len = input_len_words % BLAKE2S_BLOCK_SIZE_U32_WORDS;
        if last_round_len == 0 {
            if num_full_rounds > 0 {
                num_full_rounds -= 1;
            }
            last_round_len = BLAKE2S_BLOCK_SIZE_U32_WORDS;
        }

        // full rounds, unrolled
        unsafe {
            let mut src_ptr = leaf_encoding.as_ptr();
            for _ in 0..num_full_rounds {
                let input_slice =
                    core::slice::from_raw_parts(src_ptr, BLAKE2S_BLOCK_SIZE_U32_WORDS);
                self.hasher
                    .input_buffer
                    .iter_mut()
                    .zip(input_slice)
                    .for_each(|(dst, src)| {
                        *dst = Word {
                            inner: src.into_uint32(cs).to_le_bytes(cs),
                        };
                    });

                self.hasher
                    .run_round_function::<CS, USE_REDUCED_BLAKE2_ROUNDS>(
                        cs,
                        BLAKE2S_BLOCK_SIZE_U32_WORDS,
                        false,
                    );
                src_ptr = src_ptr.add(BLAKE2S_BLOCK_SIZE_U32_WORDS);
            }
            // last round unrolled padding
            {
                let input_slice = core::slice::from_raw_parts(src_ptr, last_round_len);
                self.hasher.input_buffer[..last_round_len]
                    .iter_mut()
                    .zip(input_slice)
                    .for_each(|(dst, src)| {
                        *dst = Word {
                            inner: src.into_uint32(cs).to_le_bytes(cs),
                        };
                    });
                self.hasher.input_buffer[last_round_len..]
                    .iter_mut()
                    .for_each(|el| {
                        *el = Word {
                            inner: [UInt8::zero(cs); 4],
                        };
                    });
                self.hasher
                    .run_round_function::<CS, USE_REDUCED_BLAKE2_ROUNDS>(cs, last_round_len, true);
            }
        }

        // now hash output is in state, and we will use it to verify a path below by asking for witness elements
        let absolute_tree_index_bits = leaf_index
            .iter()
            .chain(coset_index.iter())
            .cloned()
            .collect::<Vec<_>>();
        let (head, middle, tail) =
            unsafe { merkle_cap.align_to::<[UInt32<F>; DIGEST_SIZE_U32_WORDS]>() };
        assert!(head.is_empty() && tail.is_empty());
        let merkle_cap_flattened = middle;

        if depth == 0 {
            let cap = binary_parallel_select(cs, merkle_cap_flattened, &absolute_tree_index_bits);
            let output_hash = self.hasher.read_state_for_output();
            for i in 0..DIGEST_SIZE_U32_WORDS {
                let a = cap[i].into_num();
                let b = UInt32::from_le_bytes(cs, output_hash[i].inner).into_num();
                Num::enforce_equal(cs, &a, &b);
            }
            return;
        }

        // every step we:
        // - copy previous from the state into corresponding place of the input buffer
        // - place witness elements into the other part of input buffer
        // - run round function
        for i in 0..depth {
            let current_state = self.hasher.read_state_for_output();
            let witness_dst: [Word<F>; 8] = std::array::from_fn(|_idx| {
                let word = read_word::<F, CS, I>(cs);
                Word {
                    inner: word.to_le_bytes(cs),
                }
            });
            let input_is_right = leaf_index[i];
            self.hasher.input_buffer[..BLAKE2S_DIGEST_SIZE_U32_WORDS]
                .iter_mut()
                .zip(current_state.iter())
                .zip(witness_dst.iter())
                .for_each(|((dst, current), witness)| {
                    (*dst).inner =
                        UInt8::parallel_select(cs, input_is_right, &witness.inner, &current.inner);
                });
            self.hasher.input_buffer[BLAKE2S_DIGEST_SIZE_U32_WORDS..]
                .iter_mut()
                .zip(current_state.iter())
                .zip(witness_dst.iter())
                .for_each(|((dst, current), witness)| {
                    (*dst).inner =
                        UInt8::parallel_select(cs, input_is_right, &current.inner, &witness.inner);
                });

            self.hasher.reset();
            self.hasher
                .run_round_function::<CS, USE_REDUCED_BLAKE2_ROUNDS>(
                    cs,
                    BLAKE2S_BLOCK_SIZE_U32_WORDS,
                    true,
                );
        }

        // here we manually compare, otherwise it's compiled as memcmp that does by byte(!) comparison
        let cap =
            binary_parallel_select(cs, merkle_cap_flattened, &absolute_tree_index_bits[depth..]);
        let output_hash = self.hasher.read_state_for_output();
        for i in 0..DIGEST_SIZE_U32_WORDS {
            let a = cap[i].into_num();
            let b = UInt32::from_le_bytes(cs, output_hash[i].inner).into_num();
            Num::enforce_equal(cs, &a, &b);
        }
    }
}
