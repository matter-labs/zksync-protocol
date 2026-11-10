use super::*;

use boojum::cs::gates::ConstantAllocatableCS;
use boojum::gadgets::blake2s::{
    IV, SIGMAS, mixing_function::Word, mixing_function::mixing_function_g,
    round_function::Blake2sControl,
};
use boojum::gadgets::u8::UInt8;
use std::mem::MaybeUninit;

use crate::risc_verifier::blake2s_u32::{
    BLAKE2S_BLOCK_SIZE_U32_WORDS, BLAKE2S_DIGEST_SIZE_U32_WORDS,
    BLAKE2S_EXTENDED_STATE_WIDTH_IN_U32_WORDS, BLAKE2S_STATE_WIDTH_IN_U32_WORDS, CONFIGURED_IV,
};

const BLAKE2S_REDUCED_ROUNDS: usize = 7;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Blake2sStateGate<F: SmallField> {
    pub preconfigured_state: [Word<F>; BLAKE2S_STATE_WIDTH_IN_U32_WORDS],
    pub extended_state: [Word<F>; BLAKE2S_EXTENDED_STATE_WIDTH_IN_U32_WORDS],
    pub input_buffer: [Word<F>; BLAKE2S_BLOCK_SIZE_U32_WORDS],
    pub t: u32, // we limit ourselves to <4Gb inputs
}

impl<F: SmallField> Blake2sStateGate<F> {
    // pub const SUPPORT_SPEC_SINGLE_ROUND: bool = false;

    pub fn new<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let preconfigured_state: [UInt32<F>; BLAKE2S_STATE_WIDTH_IN_U32_WORDS] =
            std::array::from_fn(|idx| UInt32::allocate_constant(cs, CONFIGURED_IV[idx]));
        let preconfigured_state = preconfigured_state.map(|el| Word {
            inner: el.to_le_bytes(cs),
        });

        let extended_state: [Word<F>; BLAKE2S_EXTENDED_STATE_WIDTH_IN_U32_WORDS] =
            std::array::from_fn(|idx| {
                if idx < BLAKE2S_STATE_WIDTH_IN_U32_WORDS {
                    preconfigured_state[idx]
                } else {
                    Word {
                        inner: [UInt8::zero(cs); 4],
                    }
                }
            });
        let input_buffer: [Word<F>; BLAKE2S_BLOCK_SIZE_U32_WORDS] =
            std::array::from_fn(|_idx| Word {
                inner: [UInt8::zero(cs); 4],
            });
        let t = 0u32;

        Self {
            preconfigured_state,
            extended_state,
            input_buffer,
            t,
        }
    }

    pub fn read_state_for_output(&mut self) -> [Word<F>; BLAKE2S_DIGEST_SIZE_U32_WORDS] {
        // self.extended_state[..BLAKE2S_DIGEST_SIZE_U32_WORDS]
        //     .iter()
        //     .map(|el| UInt32::from_le_bytes(cs,el.inner))
        //     .collect::<Vec<_>>()
        //     .try_into().unwrap()
        self.extended_state[..BLAKE2S_DIGEST_SIZE_U32_WORDS]
            .try_into()
            .unwrap()
    }

    pub fn reset(&mut self) {
        self.t = 0;
        self.extended_state[..BLAKE2S_STATE_WIDTH_IN_U32_WORDS]
            .iter_mut()
            .zip(self.preconfigured_state.iter())
            .for_each(|(dst, src)| {
                dst.inner = src.inner;
            });
    }

    pub fn run_round_function<CS: ConstraintSystem<F>, const REDUCED_ROUNDS: bool>(
        &mut self,
        cs: &mut CS,
        input_size_words: usize,
        last_round: bool,
    ) {
        assert!(REDUCED_ROUNDS, "Only reduced rounds are supported");

        self.t += input_size_words as u32 * core::mem::size_of::<u32>() as u32;
        blake2s_reduced_round_function(
            cs,
            &mut self.extended_state,
            &self.input_buffer,
            Blake2sControl::FixedLength {
                offset: self.t,
                is_last_block: last_round,
            },
        );
    }

    pub fn spec_run_sinlge_round_into_destination<
        CS: ConstraintSystem<F>,
        const REDUCED_ROUNDS: bool,
    >(
        &mut self,
        _cs: &mut CS,
        _block_len: usize,
        _dst: *mut [UInt32<F>; BLAKE2S_DIGEST_SIZE_U32_WORDS],
    ) {
        todo!()
    }
}

pub fn blake2s_reduced_round_function<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    state: &mut [Word<F>; 16],
    message_block: &[Word<F>; 16],
    control: Blake2sControl<F>,
) {
    let mut local_work_vector = [MaybeUninit::<Word<F>>::uninit(); 16];
    // Initialize local work vector v[0..15]
    // v[0..7] := h[0..7]              // First half from state.
    // v[8..15] := IV[0..7]            // Second half from IV.

    for (dst, src) in local_work_vector[..8].iter_mut().zip(state[..8].iter()) {
        dst.write(*src);
    }

    for (idx, dst) in local_work_vector[8..].iter_mut().enumerate() {
        let iv_word = IV[idx];
        let iv_word_bytes = iv_word.to_le_bytes();
        let iv_word_bytes =
            iv_word_bytes.map(|el| cs.allocate_constant(F::from_u64_unchecked(el as u64)));

        let iv_word = unsafe {
            Word {
                inner: iv_word_bytes.map(|el| UInt8::from_variable_unchecked(el)),
            }
        };

        dst.write(iv_word);
    }

    let mut local_work_vector = unsafe { local_work_vector.map(|el| el.assume_init()) };

    // Control flow. Note that we never expect to have too marge input array,
    // so our length (offset) fits into u32 and so v[13] is never XORed

    // v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
    // v[13] := v[13] ^ (t >> w)       // High word.

    // IF f = TRUE THEN                // last block flag?
    //    v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
    // END IF.

    use boojum::gadgets::blake2s::mixing_function::xor_many;

    match control {
        Blake2sControl::FixedLength {
            offset,
            is_last_block,
        } => {
            let offset = offset.to_le_bytes();
            let offset = offset.map(|el| cs.allocate_constant(F::from_u64_unchecked(el as u64)));

            let new_v12 = xor_many(
                cs,
                &local_work_vector[12].inner.map(|el| el.get_variable()),
                &offset,
            );

            let new_v12 = unsafe {
                Word {
                    inner: new_v12.map(|el| UInt8::<F>::from_variable_unchecked(el)),
                }
            };

            local_work_vector[12] = new_v12;

            if is_last_block {
                let max_byte = cs.allocate_constant(F::from_u64_unchecked(0xffu8 as u64));
                let mask = [max_byte; 4];

                let new_v14 = xor_many(
                    cs,
                    &local_work_vector[14].inner.map(|el| el.get_variable()),
                    &mask,
                );

                let new_v14 = unsafe {
                    Word {
                        inner: new_v14.map(|el| UInt8::<F>::from_variable_unchecked(el)),
                    }
                };

                local_work_vector[14] = new_v14;
            }
        }
        _ => unimplemented!(),
    }

    for round_idx in 0..BLAKE2S_REDUCED_ROUNDS {
        let sigma_word = &SIGMAS[round_idx];

        // mix
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [0, 4, 8, 12],
            &message_block[sigma_word[0]],
            &message_block[sigma_word[1]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [1, 5, 9, 13],
            &message_block[sigma_word[2]],
            &message_block[sigma_word[3]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [2, 6, 10, 14],
            &message_block[sigma_word[4]],
            &message_block[sigma_word[5]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [3, 7, 11, 15],
            &message_block[sigma_word[6]],
            &message_block[sigma_word[7]],
        );

        mixing_function_g(
            cs,
            &mut local_work_vector,
            [0, 5, 10, 15],
            &message_block[sigma_word[8]],
            &message_block[sigma_word[9]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [1, 6, 11, 12],
            &message_block[sigma_word[10]],
            &message_block[sigma_word[11]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [2, 7, 8, 13],
            &message_block[sigma_word[12]],
            &message_block[sigma_word[13]],
        );
        mixing_function_g(
            cs,
            &mut local_work_vector,
            [3, 4, 9, 14],
            &message_block[sigma_word[14]],
            &message_block[sigma_word[15]],
        );
    }

    // XOR between halfes
    for ((src0, src1), dst) in local_work_vector[..8]
        .iter()
        .zip(local_work_vector[8..].iter())
        .zip(state[..8].iter_mut())
    {
        let tmp = xor_many(
            cs,
            &src0.inner.map(|el| el.get_variable()),
            &src1.inner.map(|el| el.get_variable()),
        );

        let result = xor_many(cs, &tmp, &dst.inner.map(|el| el.get_variable()));

        let result = unsafe {
            Word {
                inner: result.map(|el| UInt8::<F>::from_variable_unchecked(el)),
            }
        };
        *dst = result;
    }
}
