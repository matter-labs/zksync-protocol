use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::blake2s::mixing_function::Word;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u8::UInt8;
use boojum::gadgets::u32::UInt32;
use circuit_mersenne_field::{MersenneField, MersenneQuartic};

use crate::risc_verifier;
use risc_verifier::field::*;
use risc_verifier::prover::cs::definitions::*;
use risc_verifier::prover::definitions::*;
use risc_verifier::verifier_common::non_determinism_source::NonDeterminismSource;
use risc_verifier::verifier_common::{ProofOutput, ProofPublicInputs};

use crate::transcript::*;

pub mod prover_structs;
pub mod verifier_traits;

use prover_structs::*;

pub fn binary_parallel_select<
    F: SmallField,
    T: Selectable<F>,
    CS: ConstraintSystem<F>,
    const N: usize,
>(
    cs: &mut CS,
    elements: &[[T; N]],
    bits: &[Boolean<F>],
) -> [T; N] {
    assert_eq!(elements.len(), 1 << bits.len());
    assert!(bits.len() > 0);

    let mut input_space = Vec::with_capacity(elements.len() / 2);
    let mut dst_space = Vec::with_capacity(elements.len() / 2);

    for (idx, bit) in bits.iter().enumerate() {
        let src = if idx == 0 { elements } else { &input_space };

        debug_assert_eq!(elements.len() % 2, 0);
        dst_space.clear();

        for src in src.as_chunks::<2>().0.iter() {
            let [a, b] = src;
            // NOTE order here
            let selected = T::parallel_select(cs, *bit, b, a);
            dst_space.push(selected);
        }

        std::mem::swap(&mut dst_space, &mut input_space);
    }

    assert_eq!(input_space.len(), 1);

    input_space.pop().unwrap()
}
