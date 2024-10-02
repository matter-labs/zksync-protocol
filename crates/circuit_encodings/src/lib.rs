use crate::boojum::algebraic_props::round_function::{
    absorb_multiple_rounds, AbsorptionModeOverwrite, AlgebraicRoundFunction,
};
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::QueueStateWitness;
use crate::boojum::gadgets::queue::QueueTailStateWitness;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::boojum::gadgets::traits::round_function::*;
use crate::boojum::gadgets::u160::decompose_address_as_u32x5;
use crate::boojum::gadgets::u256::decompose_u256_as_u32x8;
use derivative::Derivative;
use std::collections::VecDeque;
use zkevm_circuits::base_structures::vm_state::{FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH};

use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;
pub use zk_evm::ethereum_types;

pub type ZkSyncDefaultRoundFunction = Poseidon2Goldilocks;

pub use zk_evm;
pub use zkevm_circuits;
pub use zkevm_circuits::boojum;

// for we need to encode some structures as packed field elements
pub trait OutOfCircuitFixedLengthEncodable<F: SmallField, const N: usize>: Clone {
    fn encoding_witness(&self) -> [F; N];
}

// all encodings must match circuit counterparts
pub mod callstack_entry;
pub mod decommittment_request;
pub mod log_query;
pub mod memory_query;
pub mod recursion_request;
pub mod state_diff_record;

pub use self::log_query::*;

pub(crate) fn make_round_function_pairs<F: SmallField, const N: usize, const ROUNDS: usize>(
    initial: [F; N],
    intermediates: [[F; N]; ROUNDS],
) -> [([F; N], [F; N]); ROUNDS] {
    let mut result = [([F::ZERO; N], [F::ZERO; N]); ROUNDS];
    result[0].0 = initial;
    result[0].1 = intermediates[0];
    for idx in 1..ROUNDS {
        result[idx].0 = result[idx - 1].1;
        result[idx].1 = intermediates[idx];
    }

    result
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct QueueIntermediateStates<F: SmallField, const T: usize, const SW: usize> {
    pub head: [F; T],
    pub tail: [F; T],
    pub previous_head: [F; T],
    pub previous_tail: [F; T],
    pub num_items: u32,
}

impl<F: SmallField, const T: usize, const SW: usize> QueueIntermediateStates<F, T, SW> {
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; T],
            tail: [F::ZERO; T],
            previous_head: [F::ZERO; T],
            previous_tail: [F::ZERO; T],
            num_items: 0,
        }
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(
    Clone(bound = ""),
    Default(bound = "[F; T]: Default, [F; N]: Default"),
    Debug
)]
#[serde(bound = "[F; T]: serde::Serialize + serde::de::DeserializeOwned,
    [F; N]: serde::Serialize + serde::de::DeserializeOwned,
    I: serde::Serialize + serde::de::DeserializeOwned")]
pub struct QueueSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const T: usize,
    const N: usize,
    const ROUNDS: usize,
> {
    pub head: [F; T],
    pub tail: [F; T],
    pub num_items: u32,
    pub witness: VecDeque<([F; N], [F; T], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const T: usize,
        const N: usize,
        const ROUNDS: usize,
    > QueueSimulator<F, I, T, N, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; T],
            tail: [F::ZERO; T],
            num_items: 0,
            witness: VecDeque::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut new = Self::empty();
        new.witness.reserve_exact(capacity);
        new
    }

    pub fn split(mut self, at: u32) -> (Self, Self) {
        if at >= self.num_items {
            let mut artificial_empty = Self::empty();
            artificial_empty.head = self.tail;
            artificial_empty.tail = self.tail;
            return (self, artificial_empty);
        }

        let first_wit: VecDeque<_> = self.witness.drain(..(at as usize)).collect();
        let rest_wit = self.witness;

        let splitting_point = rest_wit.front().unwrap().1;

        let first = Self {
            head: self.head,
            tail: splitting_point,
            num_items: at,
            witness: first_wit,
        };

        let rest = Self {
            head: splitting_point,
            tail: self.tail,
            num_items: self.num_items - at,
            witness: rest_wit,
        };

        (first, rest)
    }

    pub fn merge(first: Self, second: Self) -> Self {
        assert_eq!(first.tail, second.head);

        let mut wit = first.witness;
        wit.extend(second.witness);

        Self {
            head: first.head,
            tail: second.tail,
            num_items: first.num_items + second.num_items,
            witness: wit,
        }
    }

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    fn absorb_element<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        element_encoding: [F; N],
        prev_commitment: [F; T],
        _round_function: &R,
    ) -> (
        [F; T],            // new commitment
        [[F; SW]; ROUNDS], // intermediate states
    ) {
        let mut to_hash = Vec::with_capacity(N + T);
        to_hash.extend_from_slice(&element_encoding);
        to_hash.extend(prev_commitment);

        let mut state = R::initial_state();
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &to_hash,
        );

        let commitment =
            <R as AlgebraicRoundFunction<F, AW, SW, CW>>::state_into_commitment::<T>(&state);

        (commitment, states)
    }

    pub fn make_round_function_pairs<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        round_states: [[F; SW]; ROUNDS],
        _round_function: &R,
    ) -> [([F; SW], [F; SW]); ROUNDS] {
        make_round_function_pairs(R::initial_state(), round_states)
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) -> (
        [[F; SW]; ROUNDS],                 // intermediate round states
        QueueIntermediateStates<F, T, SW>, // new head/tail
    ) {
        let old_tail = self.tail;
        let encoding = element.encoding_witness();

        self.witness.push_back((encoding, old_tail, element));

        let (new_tail, round_states) = self.absorb_element(encoding, old_tail, round_function);

        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            previous_head: self.head, // unchanged
            previous_tail: old_tail,
            num_items: self.num_items,
        };

        (round_states, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        round_function: &R,
    ) -> (I, QueueIntermediateStates<F, T, SW>) {
        let old_head = self.head;
        let (_, _, element) = self.witness.pop_front().unwrap();

        let encoding = element.encoding_witness();

        let (new_head, _states) = self.absorb_element(encoding, old_head, round_function);

        self.num_items -= 1;
        self.head = new_head;

        if self.num_items == 0 {
            assert_eq!(self.head, self.tail);
        }

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: self.tail,
            previous_head: old_head,
            previous_tail: self.tail,
            num_items: self.num_items,
        };

        (element, intermediate_info)
    }

    pub fn split_by<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        mut self,
        chunk_size: usize,
        round_function: &R,
    ) -> Vec<Self> {
        let mut result = vec![];
        if self.num_items == 0 {
            return result;
        } else {
            assert_eq!(self.witness.len(), self.num_items as usize);
        }

        while self.num_items > 0 {
            let mut subqueue = Self::empty();
            subqueue.head = self.head;
            subqueue.tail = self.head;
            for _ in 0..chunk_size {
                if self.num_items == 0 {
                    break;
                }
                let (el, _) = self.pop_and_output_intermediate_data(round_function);
                subqueue.push(el, round_function);
            }

            result.push(subqueue);
        }

        assert_eq!(self.tail, result.last().unwrap().tail);

        result
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct FullWidthQueueIntermediateStates<F: SmallField, const SW: usize> {
    pub head: [F; SW],
    pub tail: [F; SW],
    pub num_items: u32,
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""))]
#[serde(bound = "[F; SW]: serde::Serialize + serde::de::DeserializeOwned,
    [F; N]: serde::Serialize + serde::de::DeserializeOwned,
    I: serde::Serialize + serde::de::DeserializeOwned")]
pub struct FullWidthQueueSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub head: [F; SW],
    pub tail: [F; SW],
    pub num_items: u32,
    pub witness: VecDeque<([F; N], [F; SW], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > Default for FullWidthQueueSimulator<F, I, N, SW, ROUNDS>
{
    fn default() -> Self {
        Self::empty()
    }
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > FullWidthQueueSimulator<F, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; SW],
            tail: [F::ZERO; SW],
            num_items: 0,
            witness: VecDeque::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut new = Self::empty();
        new.witness.reserve_exact(capacity);
        new
    }

    pub fn merge(first: Self, second: Self) -> Self {
        assert_eq!(first.tail, second.head);

        let mut wit = first.witness;
        wit.extend(second.witness);

        Self {
            head: first.head,
            tail: second.tail,
            num_items: first.num_items + second.num_items,
            witness: wit,
        }
    }

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> (
        [F; SW], // old tail
        FullWidthQueueIntermediateStates<F, SW>,
    ) {
        let old_tail = self.tail;
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let mut state = old_tail;
        let _states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_tail = state;

        self.witness.push_back((encoding, new_tail, element));
        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = FullWidthQueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            num_items: self.num_items,
        };

        (old_tail, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        _round_function: &R,
    ) -> (I, FullWidthQueueIntermediateStates<F, SW>) {
        let old_head = self.head;
        assert!(N % AW == 0);
        let (_, _, element) = self.witness.pop_front().unwrap();
        let encoding = element.encoding_witness();

        let mut state = old_head;
        let _states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_head = state;

        self.num_items -= 1;
        self.head = new_head;

        if self.num_items == 0 {
            assert_eq!(self.head, self.tail);
        }

        let intermediate_info = FullWidthQueueIntermediateStates {
            head: self.head,
            tail: self.tail,
            num_items: self.num_items,
        };

        (element, intermediate_info)
    }

    /// Splits the queue into the smaller queues of length `chunk_size`. The last queue might be shorter.
    pub fn split_by<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        mut self,
        chunk_size: usize,
        round_function: &R,
    ) -> Vec<Self> {
        let mut result = vec![];
        if self.num_items == 0 {
            return result;
        } else {
            assert_eq!(self.witness.len(), self.num_items as usize);
        }

        while self.num_items > 0 {
            let mut subqueue = Self::empty();
            subqueue.head = self.head;
            subqueue.tail = self.head;
            for _ in 0..chunk_size {
                if self.num_items == 0 {
                    break;
                }
                let (el, _) = self.pop_and_output_intermediate_data(round_function);
                subqueue.push(el, round_function);
            }

            result.push(subqueue);
        }

        assert_eq!(self.tail, result.last().unwrap().tail);

        result
    }
}

pub trait ContainerForSimulator<T> {
    fn push(&mut self, val: T);
}

use core::marker::PhantomData;
/// Simplified version of FullWidthQueueSimulator
pub struct FullWidthMemoryQueueSimulator<
    F: SmallField,
    I,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> where
    I: OutOfCircuitFixedLengthEncodable<F, N>,
{
    pub head: [F; SW],
    pub tail: [F; SW],
    pub num_items: u32,
    _marker: PhantomData<I>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > FullWidthMemoryQueueSimulator<F, I, N, SW, ROUNDS>
{
    pub fn new() -> Self {
        Self {
            head: [F::ZERO; SW],
            tail: [F::ZERO; SW],
            num_items: 0,
            _marker: Default::default(),
        }
    }

    pub fn take_sponge_like_queue_state(&self) -> QueueStateWitness<F, SW> {
        let result = QueueStateWitness {
            head: self.head,
            tail: QueueTailStateWitness {
                tail: self.tail,
                length: self.num_items,
            },
        };

        result
    }

    pub fn push_and_output_queue_state_witness<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> (
        [F; SW], // old tail
        QueueStateWitness<F, SW>,
    ) {
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let old_tail = self.tail;
        let mut state = old_tail;
        let _ = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        self.tail = state;
        self.num_items += 1;

        let state_witness = QueueStateWitness {
            head: self.head,
            tail: QueueTailStateWitness {
                tail: self.tail,
                length: self.num_items,
            },
        };

        (old_tail, state_witness)
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
#[serde(bound = "")]
pub struct FullWidthStackIntermediateStates<F: SmallField, const SW: usize, const ROUNDS: usize> {
    pub is_push: bool,
    #[serde(with = "crate::boojum::serde_utils::BigArraySerde")]
    pub new_state: [F; SW],
    pub depth: u32,
}

pub struct FullWidthStackSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub state: [F; SW],
    pub num_items: u32,
    pub witness: Vec<([F; SW], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > FullWidthStackSimulator<F, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            state: [F::ZERO; SW],
            num_items: 0,
            witness: vec![],
        }
    }

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> FullWidthStackIntermediateStates<F, SW, ROUNDS> {
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let old_state = self.state;

        let mut state = old_state;
        let _ = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_state = state;

        self.witness.push((self.state, element));
        self.num_items += 1;
        self.state = new_state;

        let intermediate_info = FullWidthStackIntermediateStates {
            is_push: true,
            new_state,
            depth: self.num_items,
        };

        intermediate_info
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        _round_function: &R,
    ) -> (I, FullWidthStackIntermediateStates<F, SW, ROUNDS>) {
        assert!(N % AW == 0);

        let popped = self.witness.pop().unwrap();
        self.num_items -= 1;

        let (previous_state, element) = popped;
        let encoding = element.encoding_witness();

        let mut state = previous_state;
        let _ = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_state = state;
        assert_eq!(new_state, self.state);

        self.state = previous_state;

        let intermediate_info = FullWidthStackIntermediateStates {
            is_push: false,
            new_state: previous_state,
            depth: self.num_items,
        };

        (element, intermediate_info)
    }
}

pub trait CircuitEquivalentReflection<F: SmallField>: Clone {
    type Destination: Clone + CSAllocatable<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness;
}

pub trait BytesSerializable<const N: usize>: Clone {
    fn serialize(&self) -> [u8; N];
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key<const N: usize>(pub [u32; N]);

pub(crate) trait IntoSmallField<F: SmallField>: Sized {
    fn into_field(self) -> F;
}

impl<F: SmallField> IntoSmallField<F> for bool {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u8 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u16 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u32 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

#[inline(always)]
pub(crate) fn scale_and_accumulate<F: SmallField, T: IntoSmallField<F>>(
    dst: &mut F,
    src: T,
    shift: usize,
) {
    let mut tmp = src.into_field();
    tmp.mul_assign(&F::SHIFTS[shift]);
    dst.add_assign(&tmp);
}

#[inline(always)]
pub(crate) fn linear_combination<F: SmallField>(input: &[(F, F)]) -> F {
    let mut result = F::ZERO;
    for (a, b) in input.iter() {
        let mut tmp = *a;
        tmp.mul_assign(&b);
        result.add_assign(&tmp);
    }

    result
}

#[cfg(test)]
mod tests {
    //use franklin_crypto::boojum::field::goldilocks::GoldilocksField;
    use crate::boojum::field::goldilocks::GoldilocksField;

    use crate::ZkSyncDefaultRoundFunction;

    use super::{recursion_request::RecursionRequest, *};

    fn create_recursion_request(x: u64) -> RecursionRequest<GoldilocksField> {
        RecursionRequest {
            circuit_type: GoldilocksField::from_nonreduced_u64(x),
            public_input: [GoldilocksField::from_nonreduced_u64(x); 4],
        }
    }

    /// Basic test to cover push, pop and split.
    #[test]
    fn basic_queue_test() {
        let recursion_request = RecursionRequest {
            circuit_type: GoldilocksField::from_nonreduced_u64(0),
            public_input: [GoldilocksField::from_nonreduced_u64(0); 4],
        };

        let mut queue: FullWidthQueueSimulator<
            GoldilocksField,
            RecursionRequest<GoldilocksField>,
            8,
            12,
            1,
        > = FullWidthQueueSimulator::default();

        let empty_head = queue.head;
        assert_eq!(queue.num_items, 0);

        // First push 1 element, and then remaining 9.
        let round_function = ZkSyncDefaultRoundFunction::default();
        queue.push(recursion_request, &round_function);
        assert_eq!(queue.num_items, 1);
        let tail_after_first = queue.tail;

        for i in 1..10 {
            queue.push(create_recursion_request(i), &round_function)
        }
        assert_eq!(queue.num_items, 10);

        let old_head = queue.head;
        let old_tail = queue.tail;

        // pop one element
        let (element, data) = queue.pop_and_output_intermediate_data(&round_function);
        // it should return the first one that we entered (with circuit 0).
        assert_eq!(element.circuit_type, 0);

        assert_eq!(queue.num_items, 9);
        assert_eq!(data.num_items, 9);

        assert_eq!(data.head, tail_after_first);
        assert_eq!(old_head, empty_head);
        assert_eq!(data.tail, old_tail);

        let mut parts = queue.split_by(3, &round_function);

        assert_eq!(3, parts.len());
        // The queue was cut in 3 pieces, check that head and tails are matching.
        assert_eq!(parts[0].head, tail_after_first);
        assert_eq!(parts[0].tail, parts[1].head);
        assert_eq!(parts[1].tail, parts[2].head);
        assert_eq!(parts[2].tail, data.tail);
        for i in 0..3 {
            assert_eq!(parts[i].num_items, 3);
        }
        let (element, _) = parts[2].pop_and_output_intermediate_data(&round_function);
        assert_eq!(element.circuit_type, 7);
    }
}
