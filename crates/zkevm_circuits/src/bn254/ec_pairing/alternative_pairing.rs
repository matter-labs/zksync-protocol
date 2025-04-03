use super::*;
use bn256::prepare_all_line_functions;
use boojum::config::CSConfig;
use boojum::config::CSWitnessEvaluationConfig;
use boojum::cs::traits::cs::DstBuffer;
use boojum::pairing::CurveAffine;
use boojum::{
    cs::Place,
    gadgets::{non_native_field::traits::NonNativeField, traits::witnessable::CSWitnessable},
    pairing::{
        bn256::{
            Fq, Fq12, Fq2, Fq6, G1Affine, G2Affine, FROBENIUS_COEFF_FQ6_C1, XI_TO_Q_MINUS_1_OVER_2,
        },
        ff::Field,
    },
};
use itertools::izip;
use rand::Rand;
use rand::Rng;
use rand::SeedableRng;
use rand::XorShiftRng;
use std::iter;

pub const NUM_PAIRINGS_IN_MULTIPAIRING: usize = 1;
const NUM_LIMBS: usize = 17;
// multipairing circuit logic is the following:
// by contract design we assume, that input is always padded if necessary on the contract side (by points on infinity),
// and hence the number of pairs (G1, G2) in the input is always equal to NUM_PAIRINGS_IN_MULTIPAIRING
// we are going to have two different version of the precompile ( only naive version is implemented for now):

// Fast and Quick: this circuit assumes that all inputs are valid: i.e. there are regular points or points at infity and that multipairing is always equal to one.
// The circuits proceeds as follows:
// 1) for each individual pair (G1, G2) enforce that input is valid: i.e. each G_i is either regular point or point at infinity
// 2) if either G_i i == 1, 2 is point at infinity we mask both G_i of the tuple by the corresponding group generator
//    and set the flag skip_ith_input = G1_i_is_infty || G2_i_is_infty
// 3) during Miller_loop we either add the corresponding line_evaluation to the total accumulator or not (depending on the pairing_should_be_skipped_flag)
// 4) during Miller_loop we also prepare all the necessary data required for checking if all G2_i are in correct subgroup (subgroup check); enforce it in Miller Loop
//    postprocess routine
// 5) we need to divide result of the Miller by MillerLoop(G1, G2)^i, where i is in range 0..3, depending on the number of trivial pairings
// 6) enforce the Multipairing is equal to one (by providing certificates c and root27_of_unity: note, that this check will be satisfied even if any point is invalid)
// The methods used in this function all have suffix _robust

// Long and Naive - in case there any any exceptions (either points not on the curve, or not in the corresponding subgroups)
// or all is valid but Multipairing is not equal to one
// The methods used in this function all have suffix _naive
// The circuits proceeds as follows:
// 1) for each individual pair we check that both inputs are valid, also set to_skip in case any point is invalid or we point is infinity
// 2) mask both G1 and G2 in the tuple if to_skip flag is set
// 3) proceed almost as in robust case, but this time we have to do explicit final exponentiation and also we should all "enforce" versions we change by "equals"
// 4) at the very end check if there any any exceptions happened - and if it is indeed the case, then mask the final result

/// This trait defines the iterator adapter `identify_first_last()`.
/// The new iterator gives a tuple with an `(element, is_first, is_last)`.
/// `is_first` is true when `element` is the first we are iterating over.
/// `is_last` is true when `element` is the last and no others follow.
pub trait IdentifyFirstLast: Iterator + Sized {
    fn identify_first_last(self) -> Iter<Self>;
}

/// Implement the iterator adapter `identify_first_last()`
impl<I> IdentifyFirstLast for I
where
    I: Iterator,
{
    fn identify_first_last(self) -> Iter<Self> {
        Iter(true, self.peekable())
    }
}

/// A struct to hold the iterator's state
/// Our state is a bool telling if this is the first element.
pub struct Iter<I>(bool, iter::Peekable<I>)
where
    I: Iterator;

impl<I> Iterator for Iter<I>
where
    I: Iterator,
{
    type Item = (bool, bool, I::Item);

    /// At `next()` we copy false to the state variable.
    /// And `peek()` adhead to see if this is the last one.
    fn next(&mut self) -> Option<Self::Item> {
        let first = std::mem::replace(&mut self.0, false);
        self.1.next().map(|e| (first, self.1.peek().is_none(), e))
    }
}

pub(crate) type Fp<F> = BN256BaseNNField<F>;
pub(crate) type Fp2<F> = BN256Fq2NNField<F>;
pub(crate) type Fp6<F> = BN256Fq6NNField<F>;
pub(crate) type Fp12<F> = BN256Fq12NNField<F>;
pub(crate) type RnsParams = BN256BaseNNFieldParams;
pub(crate) type PairingInput<F> = (AffinePoint<F>, TwistedCurvePoint<F>);

// Curve parameter for the BN256 curve
const SIX_U_PLUS_TWO_WNAF: [i8; 65] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0,
    1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0,
    0, 1, 0, 1, 1,
];

const FQ_NUM_LIMBS_FOR_WITNESS_SETTING_IN_ALLOCATION: usize = 16; // top limb is constant 0

const BN254_NUM_ELL_COEFFS: usize = const {
    let mut result = 2;

    let mut i = 0;
    while i < SIX_U_PLUS_TWO_WNAF.len() - 1 {
        result += 1;
        if SIX_U_PLUS_TWO_WNAF[i] != 0 {
            result += 1;
        }

        i += 1;
    }

    result
};

const U_WNAF: [i8; 63] = [
    1, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0,
    0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0,
    1,
];

const X_TERNARY: [i64; 63] = [
    1, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0,
    0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0,
    1,
];

const X_TERNARY_HALF: [i8; 62] = [
    1, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0,
    0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0,
];

// a bunch of useful allocators
pub fn allocate_fq2_constant<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    value: Fq2,
    params: &Arc<BN256BaseNNFieldParams>,
) -> Fp2<F> {
    let c0 = BN256BaseNNField::allocated_constant(cs, value.c0, params);
    let c1 = BN256BaseNNField::allocated_constant(cs, value.c1, params);

    Fp2::new(c0, c1)
}

pub fn allocate_fq6_constant<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    value: Fq6,
    params: &Arc<BN256BaseNNFieldParams>,
) -> Fp6<F> {
    let c0 = allocate_fq2_constant(cs, value.c0, params);
    let c1 = allocate_fq2_constant(cs, value.c1, params);
    let c2 = allocate_fq2_constant(cs, value.c2, params);

    Fp6::new(c0, c1, c2)
}

pub fn allocate_fq12_constant<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    value: Fq12,
    params: &Arc<BN256BaseNNFieldParams>,
) -> Fp12<F> {
    let c0 = allocate_fq6_constant(cs, value.c0, params);
    let c1 = allocate_fq6_constant(cs, value.c1, params);

    Fp12::new(c0, c1)
}

// So far Rust compiler can not take a definition of CSAllocatableExt for Fq2 on top of any non-native field element,
// so we have to use freestanding functions instead

fn fe_to_u16_words<T: crate::ff::PrimeField, const N: usize>(src: &T) -> [u16; N] {
    let mut result = [0u16; N];
    let repr = src.into_repr();
    for (idx, el) in repr.as_ref().iter().enumerate() {
        let mut el = *el;
        let a = (el & (u16::MAX as u64)) as u16;
        el >>= 16;
        let b = (el & (u16::MAX as u64)) as u16;
        el >>= 16;
        let c = (el & (u16::MAX as u64)) as u16;
        el >>= 16;
        let d = (el & (u16::MAX as u64)) as u16;

        if 4 * idx < N {
            result[4 * idx] = a;
        } else {
            debug_assert_eq!(a, 0);
        }
        if 4 * idx + 1 < N {
            result[4 * idx + 1] = b;
        } else {
            debug_assert_eq!(b, 0);
        }
        if 4 * idx + 2 < N {
            result[4 * idx + 2] = c;
        } else {
            debug_assert_eq!(c, 0);
        }
        if 4 * idx + 3 < N {
            result[4 * idx + 3] = d;
        } else {
            debug_assert_eq!(d, 0);
        }
    }

    result
}

fn fp_dump_internal_variables_for_witness_setting<F: SmallField>(
    element: &Fp<F>,
) -> [Variable; FQ_NUM_LIMBS_FOR_WITNESS_SETTING_IN_ALLOCATION] {
    element.limbs[..FQ_NUM_LIMBS_FOR_WITNESS_SETTING_IN_ALLOCATION]
        .try_into()
        .unwrap()
}

fn fp_set_internal_variable_values<F: SmallField>(
    witness: Fq,
    params: &BN256BaseNNFieldParams,
    dst: &mut DstBuffer<'_, '_, F>,
) {
    let limbs = fe_to_u16_words::<_, NUM_LIMBS>(&witness);
    for (idx, el) in limbs.into_iter().enumerate() {
        if idx < params.modulus_limbs {
            dst.push(F::from_u64_unchecked(el as u64));
        } else {
            assert_eq!(el, 0);
        }
    }
}

fn fp2_set_internal_variable_values<F: SmallField>(
    witness: Fq2,
    params: &BN256BaseNNFieldParams,
    dst: &mut DstBuffer<'_, '_, F>,
) {
    fp_set_internal_variable_values(witness.c0, params, dst);
    fp_set_internal_variable_values(witness.c1, params, dst);
}

// Both original Bn256 curve and it's twist are of the form:
// y_p^2 = x_p^3 + b
// points at infinity by spec are encoded with both coordinates equal to zero
struct CurveCheckFlags<F: SmallField> {
    is_point_at_infty: Boolean<F>,
    is_valid_point: Boolean<F>,
    is_invalid_point: Boolean<F>,
}

#[derive(Debug, Clone)]
pub(crate) struct AffinePoint<F: SmallField> {
    x: Fp<F>,
    y: Fp<F>,
    is_in_eval_form: bool,
}

impl<F: SmallField> AffinePoint<F> {
    fn allocate<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: G1Affine,
        params: &Arc<RnsParams>,
    ) -> Self {
        let (x_wit, y_wit) = witness.into_xy_unchecked();
        let x = Fp::<F>::allocate_checked(cs, x_wit, params);
        let y = Fp::<F>::allocate_checked(cs, y_wit, params);

        AffinePoint {
            x,
            y,
            is_in_eval_form: false,
        }
    }
    pub fn from_xy_unchecked(x: Fp<F>, y: Fp<F>) -> Self {
        AffinePoint {
            x,
            y,
            is_in_eval_form: false,
        }
    }

    fn is_point_at_infty<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Boolean<F> {
        let x_is_zero = self.x.is_zero(cs);
        let y_is_zero = self.y.is_zero(cs);
        x_is_zero.and(cs, y_is_zero)
    }

    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        first: &Self,
        second: &Self,
    ) -> Self {
        let x =
            <Fp<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.x, &second.x);
        let y =
            <Fp<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.y, &second.y);

        AffinePoint {
            x,
            y,
            is_in_eval_form: false,
        }
    }

    fn constant<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        wit: G1Affine,
        rns_params: &Arc<RnsParams>,
    ) -> Self {
        let (x_wit, y_wit) = wit.into_xy_unchecked();
        let x = Fp::allocated_constant(cs, x_wit, rns_params);
        let y = Fp::allocated_constant(cs, y_wit, rns_params);
        let point = AffinePoint {
            x,
            y,
            is_in_eval_form: false,
        };
        point
    }

    fn generator<CS: ConstraintSystem<F>>(cs: &mut CS, rns_params: &Arc<RnsParams>) -> Self {
        Self::constant(cs, G1Affine::one(), rns_params)
    }

    fn is_on_curve<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> Boolean<F> {
        let mut b = Fp::allocated_constant(cs, G1Affine::b_coeff(), rns_params);
        let mut lhs = self.y.square(cs);
        let mut x_squared = self.x.square(cs);
        let mut x_cubed = x_squared.mul(cs, &mut self.x);
        let mut rhs = x_cubed.add(cs, &mut b);

        lhs.equals(cs, &mut rhs)
    }

    // we check that this point either represent point at infty or correctly encoded point
    fn validate_point_robust<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> Boolean<F> {
        let is_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let is_regular_point = is_infty.negated(cs);
        is_on_curve.conditionally_enforce_true(cs, is_regular_point);

        is_infty
    }

    fn validate_point_naive<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> CurveCheckFlags<F> {
        let is_point_at_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let point_is_valid = is_point_at_infty.or(cs, is_on_curve);
        let is_invalid_point = point_is_valid.negated(cs);
        CurveCheckFlags {
            is_point_at_infty,
            is_valid_point: point_is_valid,
            is_invalid_point,
        }
    }

    fn mask<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        should_skip: Boolean<F>,
        rns_params: &Arc<RnsParams>,
    ) {
        let default_choice = Self::generator(cs, rns_params);
        *self = Self::conditionally_select(cs, should_skip, &default_choice, &self);
    }

    fn convert_for_line_eval_form<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) {
        // precompute x' = - p.x / p.y; y' = -1 /p.y
        let mut y_inv = self.y.inverse_unchecked(cs);
        let mut y_prime = y_inv.negated(cs);
        let x_prime = self.x.mul(cs, &mut y_prime);
        self.x = x_prime;
        self.y = y_prime;
        self.is_in_eval_form = true;
        self.x.normalize(cs);
        self.y.normalize(cs);
    }

    fn as_variables_set(&self) -> impl Iterator<Item = Variable> {
        let vars_for_x = self.x.as_variables_set();
        let vars_for_y = self.y.as_variables_set();
        vars_for_x.into_iter().chain(vars_for_y.into_iter())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TwistedCurvePoint<F: SmallField> {
    pub x: Fp2<F>,
    pub y: Fp2<F>,
}

impl<F: SmallField> TwistedCurvePoint<F> {
    fn allocate<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: G2Affine,
        params: &Arc<RnsParams>,
    ) -> Self {
        let (x_wit, y_wit) = witness.into_xy_unchecked();
        let x = Fp2::<F>::allocate_from_witness(cs, x_wit, params);
        let y = Fp2::<F>::allocate_from_witness(cs, y_wit, params);

        TwistedCurvePoint { x, y }
    }

    fn is_point_at_infty<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Boolean<F> {
        let x_is_zero = self.x.is_zero(cs);
        let y_is_zero = self.y.is_zero(cs);
        x_is_zero.and(cs, y_is_zero)
    }

    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        flag: Boolean<F>,
        first: &Self,
        second: &Self,
    ) -> Self {
        let x =
            <Fp2<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.x, &second.x);
        let y =
            <Fp2<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.y, &second.y);

        TwistedCurvePoint { x, y }
    }

    fn constant<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        wit: G2Affine,
        rns_params: &Arc<RnsParams>,
    ) -> Self {
        let (x_wit, y_wit) = wit.into_xy_unchecked();
        let x = Fp2::constant(cs, x_wit, rns_params);
        let y = Fp2::constant(cs, y_wit, rns_params);
        let point = TwistedCurvePoint { x, y };
        point
    }

    fn generator<CS: ConstraintSystem<F>>(cs: &mut CS, rns_params: &Arc<RnsParams>) -> Self {
        Self::constant(cs, G2Affine::one(), rns_params)
    }

    fn is_on_curve<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> Boolean<F> {
        let mut b = Fp2::constant(cs, G2Affine::b_coeff(), rns_params);

        let mut lhs = self.y.square(cs);
        let mut x_squared = self.x.square(cs);
        let mut x_cubed = x_squared.mul(cs, &mut self.x);
        let mut rhs = x_cubed.add(cs, &mut b);

        lhs.equals(cs, &mut rhs)
    }

    // we check that this point either represent point at infty or correctly encoded point
    fn validate_point_robust<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> Boolean<F> {
        let is_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let is_regular_point = is_infty.negated(cs);
        is_on_curve.conditionally_enforce_true(cs, is_regular_point);

        is_infty
    }

    fn validate_point_naive<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        rns_params: &Arc<RnsParams>,
    ) -> CurveCheckFlags<F> {
        let is_point_at_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let point_is_valid = is_point_at_infty.or(cs, is_on_curve);
        let is_invalid_point = point_is_valid.negated(cs);

        CurveCheckFlags {
            is_point_at_infty,
            is_valid_point: point_is_valid,
            is_invalid_point,
        }
    }

    fn mask<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        should_skip: Boolean<F>,
        rns_params: &Arc<RnsParams>,
    ) {
        // TODO: check that reallocationg constant default choice doesnt't generate any constraints
        let default_choice = Self::generator(cs, rns_params);
        *self = Self::conditionally_select(cs, should_skip, &default_choice, &self);
    }

    fn negate<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Self {
        let new_y = self.y.negated(cs);
        TwistedCurvePoint {
            x: self.x.clone(),
            y: new_y,
        }
    }

    // TODO: use line object here?
    fn double<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Self {
        let mut x_squared = self.x.square(cs);
        // compute 3 * x_squared
        let mut x_squared_3 = x_squared.double(cs);
        x_squared_3 = x_squared_3.add(cs, &mut x_squared);

        let mut two_y = self.y.double(cs);
        let mut lambda = x_squared_3.div(cs, &mut two_y);

        let mut lambda_squared = lambda.square(cs);
        let mut two_x = self.x.double(cs);
        let mut new_x = lambda_squared.sub(cs, &mut two_x);

        let mut x_minus_new_x = self.x.sub(cs, &mut new_x);
        let mut new_y = x_minus_new_x.mul(cs, &mut lambda);
        new_y = new_y.sub(cs, &mut self.y);

        TwistedCurvePoint { x: new_x, y: new_y }
    }

    // TODO: use line object here?
    fn double_and_add<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, other: &mut Self) -> Self {
        let mut other_x_minus_this_x = other.x.sub(cs, &mut self.x);
        let mut other_y_minus_this_y = other.y.sub(cs, &mut self.y);
        let mut lambda = other_y_minus_this_y.div(cs, &mut other_x_minus_this_x);

        // lambda^2 + (-x' - x)
        let mut lambda_squared = lambda.square(cs);
        let mut other_x_plus_this_x = other.x.add(cs, &mut self.x);
        let mut new_x = lambda_squared.sub(cs, &mut other_x_plus_this_x);

        let mut new_x_minus_this_x = new_x.sub(cs, &mut self.x);
        let mut two_y = self.y.double(cs);
        let mut t0 = two_y.div(cs, &mut new_x_minus_this_x);
        let mut t1 = lambda.add(cs, &mut t0);

        let mut new_x_plus_this_x = new_x.add(cs, &mut self.x);
        let mut new_x = t1.square(cs);
        new_x = new_x.sub(cs, &mut new_x_plus_this_x);

        let mut new_x_minus_x = new_x.sub(cs, &mut self.x);
        let mut new_y = t1.mul(cs, &mut new_x_minus_x);
        new_y = new_y.sub(cs, &mut self.y);

        TwistedCurvePoint { x: new_x, y: new_y }
    }

    // TODO: use line object here?
    fn add<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, other: &mut Self) -> Self {
        let mut other_x_minus_this_x = other.x.sub(cs, &mut self.x);
        let mut other_y_minus_this_y = other.y.sub(cs, &mut self.y);
        let mut lambda = other_y_minus_this_y.div(cs, &mut other_x_minus_this_x);

        // lambda^2 + (-x' - x)
        let mut lambda_squared = lambda.square(cs);
        let mut other_x_plus_this_x = other.x.add(cs, &mut self.x);
        let mut new_x = lambda_squared.sub(cs, &mut other_x_plus_this_x);

        // lambda * (x - new_x) + (- y)
        let mut this_x_minus_new_x = self.x.sub(cs, &mut new_x);
        let mut new_y = lambda.mul(cs, &mut this_x_minus_new_x);
        new_y = new_y.sub(cs, &mut self.y);

        TwistedCurvePoint { x: new_x, y: new_y }
    }

    // TODO: use line object here?
    fn sub<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, other: &mut Self) -> Self {
        let mut other_x_minus_this_x = other.x.sub(cs, &mut self.x);
        let mut other_y_plus_this_y = other.y.add(cs, &mut self.y);
        let mut lambda = other_y_plus_this_y.div(cs, &mut other_x_minus_this_x);

        // lambda^2 + (-x' - x)
        let mut lambda_squared = lambda.square(cs);
        let mut other_x_plus_this_x = other.x.add(cs, &mut self.x);
        let mut new_x = lambda_squared.sub(cs, &mut other_x_plus_this_x);

        // lambda * -(x - new_x) + (- y)
        let mut new_x_minus_this_x = new_x.sub(cs, &mut self.x);
        let mut new_y = lambda.mul(cs, &mut new_x_minus_this_x);
        new_y = new_y.sub(cs, &mut self.y);

        TwistedCurvePoint { x: new_x, y: new_y }
    }

    fn equals<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        left: &mut Self,
        right: &mut Self,
    ) -> Boolean<F> {
        let x_eq = left.x.equals(cs, &mut right.x);
        let y_eq = left.y.equals(cs, &mut right.y);
        x_eq.and(cs, y_eq)
    }

    fn enforce_equal<CS: ConstraintSystem<F>>(cs: &mut CS, left: &mut Self, right: &mut Self) {
        Fp2::enforce_equal(cs, &mut left.x, &mut right.x);
        Fp2::enforce_equal(cs, &mut left.y, &mut right.y);
    }

    fn as_variables_set(&self) -> impl Iterator<Item = Variable> {
        let vars_for_x_c0 = self.x.c0.as_variables_set();
        let vars_for_x_c1 = self.x.c1.as_variables_set();
        let vars_for_y_c0 = self.y.c0.as_variables_set();
        let vars_for_y_c1 = self.y.c1.as_variables_set();
        vars_for_x_c0
            .into_iter()
            .chain(vars_for_x_c1.into_iter())
            .chain(vars_for_y_c0.into_iter())
            .chain(vars_for_y_c1.into_iter())
    }
    fn normalize<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) {
        self.x.normalize(cs);
        self.y.normalize(cs);
    }
}

// Bn Used Mtwist
pub struct LineFunctionEvaluation<F: SmallField> {
    // c0 = 1 always
    c3: Fp2<F>,
    c4: Fp2<F>,
}

impl<F: SmallField> LineFunctionEvaluation<F> {
    fn convert_into_fp12<CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Fp12<F> {
        let params = self.c3.c0.get_params();
        let zero_fp2 = Fp2::zero(cs, params);
        let zero_fp6 = Fp6::zero(cs, params);
        let LineFunctionEvaluation { c3, c4 } = self;

        let fp6_y = Fp6::new(c3, c4, zero_fp2);
        Fp12::new(zero_fp6, fp6_y)
    }

    // this function masks the line function, so that the following multiplication of Miller loop accumulate by this line function will be just multiplication
    // by one -> it requires 4 Fp selects instead of 12 Fp selects, if we deal with masking AFTER multiplication by Fp12
    fn trivialize<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, should_skip: Boolean<F>) {
        self.c3 = self.c3.mask_negated(cs, should_skip);
        self.c4 = self.c4.mask_negated(cs, should_skip)
    }

    fn mul_into_fp12<CS: ConstraintSystem<F>>(self, cs: &mut CS, fp12: &mut Fp12<F>) {
        let LineFunctionEvaluation { mut c3, mut c4 } = self;
        let mut one = Fp::allocated_constant(cs, Fq::one(), &c3.c0.params);

        let mut c3_inc = c3.clone();
        c3_inc.c0 = c3.c0.add(cs, &mut one);

        let mut t0 = fp12.c0.clone();
        // t1 <- a1*b1
        let mut t1 = fp12.c1.mul_by_c0c1(cs, &mut c3, &mut c4);
        // c0 <- t0 + t1*gamma
        let mut t1_gamma = t1.mul_by_nonresidue(cs);
        let new_c0 = t0.add(cs, &mut t1_gamma);
        // t2 <- (b0+b10)v + b11*v + 0*v^2
        let mut t2_c0 = c3_inc;
        let mut t2_c1 = c4.clone();
        // c1 <- (a0 + a1) * t2
        let mut new_c1 = fp12.c0.add(cs, &mut fp12.c1);
        let mut new_c1 = new_c1.mul_by_c0c1(cs, &mut t2_c0, &mut t2_c1);
        // c1 <- c1 - t0 - t1
        let mut new_c1 = new_c1.sub(cs, &mut t0);
        let new_c1 = new_c1.sub(cs, &mut t1);

        fp12.c0 = new_c0;
        fp12.c1 = new_c1;

        // NonNativeField::normalize(fp12, cs);
    }

    fn conditionally_mul_into_fp12<CS: ConstraintSystem<F>>(
        mut self,
        cs: &mut CS,
        skip_flag: Boolean<F>,
        fp12: &mut Fp12<F>,
    ) {
        self.trivialize(cs, skip_flag);
        self.mul_into_fp12(cs, fp12);
    }
}

// Fp2 is generated by u => every element of Fp2 is of the form c0 + c1 * u, c_i in Fp
// Fp6 is generated from Fp2 by cubic_non_residue t => every element of Fp6 is of the form: a0 + a1 * t + a2 * t^2, a_i in Fp^2
// 27th_root_of_unity (see below) is either 1, or a1 * t or a2 * t^2 (actually it belongs to Fp^3, that's the reason it has such compact representation)
// we hence represent element of Fp^3 as a /in Fp^2 and two Boolean flags, the first is set if it is of the form a1 * t; a2 * t - if second if set;
// these flags can't be both set simultaneously - and it is checked!
// if neither of them is set than we assume that our element is just element of Fp2
struct Root27OfUnity<F: SmallField> {
    a: Fp2<F>,
    first_flag: Boolean<F>,
    second_flag: Boolean<F>,
}

impl<F: SmallField> Root27OfUnity<F> {
    fn mul_into_fp6<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, acc: &mut Fp6<F>) {
        // acc = c0 + c1 * t + c2 * t^2; t^3 = w
        // if first_flag is set then root27 of unity is of the form: a * t:
        // acc * root27 = (c0 * a) * t + (c1 * a) * t^2 + (c2 * a * w)
        // if second_flag is set then root27 of unity is of the form: a * t^2:
        // acc * root27 = (c0 * a) * t^2 + (c1 * a * w) + (c2 * a * w) * t
        // if neither flag is set, then the result is just (c0 * a) + (c1 * a) * t + (c2 * a) * t^2

        // so, our strategy is the following:
        // compute all of c0 * a, c1 * a, c2 * a, c1 * a * w, c2 * a * w
        // and then do the select:

        let c0_mul_a = acc.c0.mul(cs, &mut self.a);
        let mut c1_mul_a = acc.c1.mul(cs, &mut self.a);
        let mut c2_mul_a = acc.c2.mul(cs, &mut self.a);
        let c1_mul_a_mul_w = c1_mul_a.mul_by_nonresidue(cs);
        let c2_mul_a_mul_w = c2_mul_a.mul_by_nonresidue(cs);

        // TODO: I didn't found any implementation of "multiselect" or "orthogonal" select in Boojum
        // the closest thing I have found is dot_product, which I'm not sure how to use correctly,
        // so I will just usual select several times in a row
        let res_if_first_flag = Fp6::new(c2_mul_a_mul_w.clone(), c0_mul_a.clone(), c1_mul_a);
        let res_if_second_flag = Fp6::new(c1_mul_a_mul_w, c2_mul_a_mul_w, c0_mul_a);

        *acc = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(
            cs,
            self.first_flag,
            &res_if_first_flag,
            acc,
        );
        *acc = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(
            cs,
            self.second_flag,
            &res_if_second_flag,
            acc,
        );
    }
}

struct WitnessParser<'a, F: SmallField> {
    witness: &'a [F],
    offset: usize,
}

impl<'a, F: SmallField> WitnessParser<'a, F> {
    fn new(witness: &'a [F]) -> Self {
        Self { witness, offset: 0 }
    }

    fn finalize(&self) {
        assert_eq!(self.offset, self.witness.len())
    }

    fn parse_fq(&mut self) -> Fq {
        let values = std::array::from_fn(|i| self.witness[self.offset + i]);
        self.offset += NUM_LIMBS;
        Fp::<F>::witness_from_set_of_values(values).get()
    }

    fn parse_g1_affine(&mut self) -> (G1Affine, bool) {
        let x = self.parse_fq();
        let y = self.parse_fq();

        match G1Affine::from_xy_checked(x, y) {
            Ok(pt) => (pt, true),
            Err(_) => (G1Affine::one(), false),
        }
    }

    fn parse_fq2(&mut self) -> Fq2 {
        let c0 = self.parse_fq();
        let c1 = self.parse_fq();
        Fq2 { c0, c1 }
    }

    fn parse_g2_affine(&mut self) -> (G2Affine, bool) {
        let x = self.parse_fq2();
        let y = self.parse_fq2();
        match G2Affine::from_xy_checked(x, y) {
            Ok(pt) => (pt, true),
            Err(_) => (G2Affine::one(), false),
        }
    }
}

struct Oracle<F: SmallField> {
    line_functions: [[(Fp2<F>, Fp2<F>); BN254_NUM_ELL_COEFFS]; NUM_PAIRINGS_IN_MULTIPAIRING],
    line_function_idx: usize,
    // cert_c_inv: Option<Fq12>,
    // cert_root_of_unity_power: usize,
}

impl<F: SmallField> Oracle<F> {
    fn allocate<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        params: Arc<BN256BaseNNFieldParams>,
        pairing_input: &[PairingInput<F>; NUM_PAIRINGS_IN_MULTIPAIRING],
        should_compute_certificate: bool,
    ) -> Self {
        assert!(should_compute_certificate == false, "not yet supported");

        // always allocate, then create a value function

        // NOTE: internally it allocated with all the range checks
        let line_objects: [[(Fp2<F>, Fp2<F>); BN254_NUM_ELL_COEFFS]; NUM_PAIRINGS_IN_MULTIPAIRING] =
            std::array::from_fn(|_| {
                std::array::from_fn(|_| {
                    let x = Fp2::<F>::allocate_without_value(cs);
                    let y = Fp2::<F>::allocate_without_value(cs);

                    (x, y)
                })
            });

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS == true {
            // dump it as flat array of variables to set as output
            let mut outputs = vec![];
            let params = params.clone();
            for per_pairing_work in line_objects.iter() {
                for (x, y) in per_pairing_work.iter() {
                    outputs.extend(
                        fp_dump_internal_variables_for_witness_setting(&x.c0)
                            .map(|el| Place::from_variable(el)),
                    );
                    outputs.extend(
                        fp_dump_internal_variables_for_witness_setting(&x.c1)
                            .map(|el| Place::from_variable(el)),
                    );
                    outputs.extend(
                        fp_dump_internal_variables_for_witness_setting(&y.c0)
                            .map(|el| Place::from_variable(el)),
                    );
                    outputs.extend(
                        fp_dump_internal_variables_for_witness_setting(&y.c1)
                            .map(|el| Place::from_variable(el)),
                    );
                }
            }
            assert_eq!(
                outputs.len(),
                NUM_PAIRINGS_IN_MULTIPAIRING
                    * BN254_NUM_ELL_COEFFS
                    * 4
                    * FQ_NUM_LIMBS_FOR_WITNESS_SETTING_IN_ALLOCATION
            );

            // populate witness inputs
            let mut inputs = Vec::<Place>::new();
            for (p, q) in pairing_input.iter() {
                let p_vars_iter = p.as_variables_set();
                let q_vars_iter = q.as_variables_set();
                inputs.extend(
                    p_vars_iter
                        .chain(q_vars_iter)
                        .map(|variable| Place::from_variable(variable)),
                );
            }

            let value_fn = move |input: &[F], dst: &mut DstBuffer<'_, '_, F>| {
                let params = params;
                let mut parser = WitnessParser::new(input);

                // default line functions of the pair of generators used in the case we have to mask points at infinity or invalid points
                let g2_generator = G2Affine::one();
                let masking_line_functions = prepare_all_line_functions(g2_generator);

                assert_eq!(masking_line_functions.len(), BN254_NUM_ELL_COEFFS);

                for _ in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
                    let (g1, g1_is_on_curve) = parser.parse_g1_affine();
                    let (g2, g2_is_on_curve) = parser.parse_g2_affine();

                    let should_skip =
                        g1.is_zero() || g2.is_zero() || !g1_is_on_curve || !g2_is_on_curve;

                    if should_skip == false {
                        // normal flow
                        let line_functions = prepare_all_line_functions(g2);
                        assert_eq!(line_functions.len(), BN254_NUM_ELL_COEFFS);

                        for (x, y) in line_functions.into_iter() {
                            fp2_set_internal_variable_values(x, &params, dst);
                            fp2_set_internal_variable_values(y, &params, dst);
                        }
                    } else {
                        // use making ones
                        for (x, y) in masking_line_functions.iter() {
                            fp2_set_internal_variable_values(*x, &params, dst);
                            fp2_set_internal_variable_values(*y, &params, dst);
                        }
                    }
                }
            };

            cs.set_values_with_dependencies_vararg(&inputs, &outputs, value_fn);
        }

        Self {
            line_functions: line_objects,
            line_function_idx: 0,
        }
    }

    fn next_line_object(&mut self) -> LineObject<F> {
        let major = self.line_function_idx / BN254_NUM_ELL_COEFFS;
        let minor = self.line_function_idx % BN254_NUM_ELL_COEFFS;

        let (lambda, mu) = self.line_functions[major][minor].clone();
        self.line_function_idx += 1;

        LineObject { lambda, mu }
    }
}

// y = /lambda * x + /mu
struct LineObject<F: SmallField> {
    lambda: Fp2<F>,
    mu: Fp2<F>,
}

impl<F: SmallField> LineObject<F> {
    fn enforce_pass_through_point<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
    ) {
        // q is on the line: y_q = lambda * x_q + mu
        let mut res = self.lambda.mul(cs, &mut q.x);
        res = res.add(cs, &mut self.mu);
        Fp2::enforce_equal(cs, &mut res, &mut q.y);
    }

    fn enforce_is_tangent<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
    ) {
        // q is on the line: y_q = lambda * x_q + mu
        // line is tangent:  2 * λ * y_q = 3 * x_q^2
        self.enforce_pass_through_point(cs, q);
        let mut lhs = self.lambda.double(cs);
        lhs = lhs.mul(cs, &mut q.y);

        //let mut three = Fp::allocated_constant(cs, Fq::from_str("3").unwrap(), q.x.get_params());
        // let mut rhs = q.x.mul_c0(cs, &mut three);
        let mut x_squared = q.x.square(cs);
        let mut rhs = x_squared.double(cs);
        rhs = rhs.add(cs, &mut x_squared);

        Fp2::enforce_equal(cs, &mut lhs, &mut rhs);
    }

    // enforce that line passes through both t and q
    fn enforce_is_line_through<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
        t: &mut TwistedCurvePoint<F>,
    ) {
        self.enforce_pass_through_point(cs, q);
        self.enforce_pass_through_point(cs, t);
    }

    fn evaluate<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        p: &mut AffinePoint<F>,
    ) -> LineFunctionEvaluation<F> {
        // previously we had: c0 = p.y; c3 = - lambda * p.x; c4 = -mu;
        // however, using optimiziation from Arahna, we may scale ny element of Fp, to get c0 = 1, and have the line:
        // with c0 = 1; c3 = lambda * (- p.x / p.y); c4 = mu * (-1 / p.y);
        // and we can precompute x' = - p.x / p.y; y' = -1 /p.y
        // c3 = lambda * x; c4 = mu * y

        assert!(p.is_in_eval_form);
        let c3 = self.lambda.mul_c0(cs, &mut p.x);
        let c4 = self.mu.mul_c0(cs, &mut p.y);

        LineFunctionEvaluation { c3, c4 }
    }

    fn compute_point_from_x_coordinate<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        mut x: Fp2<F>,
    ) -> TwistedCurvePoint<F> {
        // y = −µ − λ * x
        x.normalize(cs);
        let mut y = self.lambda.mul(cs, &mut x);
        y = y.add(cs, &mut self.mu);
        y = y.negated(cs);

        TwistedCurvePoint { x, y }
    }

    fn double<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
    ) -> TwistedCurvePoint<F> {
        //  x = λ^2 −2 * q.x and y = −µ − λ * x
        let mut lambda_squared = self.lambda.square(cs);
        let mut q_x_doubled = q.x.double(cs);
        let x = lambda_squared.sub(cs, &mut q_x_doubled);
        self.compute_point_from_x_coordinate(cs, x)
    }

    fn add<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
        t: &mut TwistedCurvePoint<F>,
    ) -> TwistedCurvePoint<F> {
        // x3 = λ^2 − x1 − x2 and y3 = −µ − λ * x3
        let mut lambda_squared = self.lambda.square(cs);
        let mut x = lambda_squared.sub(cs, &mut q.x);
        x = x.sub(cs, &mut t.x);
        self.compute_point_from_x_coordinate(cs, x)
    }

    // aggregator functions that do several steps simultaneously:
    fn double_and_eval<CS: ConstraintSystem<F>>(
        mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
        p: &mut AffinePoint<F>,
    ) -> LineFunctionEvaluation<F> {
        self.enforce_is_tangent(cs, q);
        *q = self.double(cs, q);
        self.evaluate(cs, p)
    }

    fn add_and_eval<CS: ConstraintSystem<F>>(
        mut self,
        cs: &mut CS,
        q: &mut TwistedCurvePoint<F>,
        t: &mut TwistedCurvePoint<F>,
        p: &mut AffinePoint<F>,
    ) -> LineFunctionEvaluation<F> {
        self.enforce_is_line_through(cs, q, t);
        *q = self.add(cs, q, t);
        self.evaluate(cs, p)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Ops {
    // first output, then inputs
    ExpByX(usize, usize),
    Mul(usize, usize, usize),
    Square(usize, usize),
    Conj(usize, usize),
    Frob(usize, usize, usize), // the last parameter is power
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Bn256HardPartMethod {
    Devegili,
    FuentesCastaneda,
    Naive,
}

impl Bn256HardPartMethod {
    fn get_optinal() -> Self {
        Bn256HardPartMethod::Devegili
        // Bn256HardPartMethod::Naive
        // Bn256HardPartMethod::FuentesCastaneda
    }

    fn get_ops_chain(self) -> (Vec<Ops>, usize) {
        match self {
            Bn256HardPartMethod::Devegili => Self::devegili_method(),
            Bn256HardPartMethod::FuentesCastaneda => Self::fuentes_castaneda_method(),
            Bn256HardPartMethod::Naive => Self::naive_method(),
        }
    }
    fn get_x_ternary_decomposition() -> &'static [i64] {
        &X_TERNARY
    }

    fn get_half_x_ternary_decomposition() -> &'static [i8] {
        &X_TERNARY_HALF
    }

    fn random_fq12<R: Rng>(rng: &mut R) -> Fq12 {
        let c0 = Fq6::rand(rng);
        let c1 = Fq6::rand(rng);
        Fq12 { c0, c1 }
    }

    fn get_hard_part_generator() -> Fq12 {
        let mut rng = XorShiftRng::from_seed([42, 0, 0, 0]);

        let chains = [
            Bn256HardPartMethod::devegili_method(),
            Bn256HardPartMethod::fuentes_castaneda_method(),
            Bn256HardPartMethod::naive_method(),
        ];

        let x = 4965661367192848881;

        loop {
            let cand = Bn256HardPartMethod::random_fq12(&mut rng);

            if cand == Fq12::one() {
                continue;
            }

            for (ops_chain, num_of_variables) in chains.iter() {
                let mut scratchpad = vec![Fq12::zero(); *num_of_variables];
                scratchpad[0] = cand;

                for op in ops_chain {
                    let out_idx = match op {
                        Ops::ExpByX(out_idx, in_idx) => {
                            let mut tmp = scratchpad[*in_idx];
                            tmp = tmp.pow([x]);
                            scratchpad[*out_idx] = tmp;
                            out_idx
                        }
                        Ops::Mul(out_idx, left_idx, right_idx) => {
                            let mut tmp = scratchpad[*left_idx];
                            tmp.mul_assign(&scratchpad[*right_idx]);
                            scratchpad[*out_idx] = tmp;
                            out_idx
                        }
                        Ops::Square(out_idx, in_idx) => {
                            let mut tmp = scratchpad[*in_idx];
                            tmp.square();
                            scratchpad[*out_idx] = tmp;
                            out_idx
                        }
                        Ops::Conj(out_idx, in_idx) => {
                            let mut tmp = scratchpad[*in_idx];
                            tmp.conjugate();
                            scratchpad[*out_idx] = tmp;
                            out_idx
                        }
                        Ops::Frob(out_idx, in_idx, power) => {
                            let mut tmp = scratchpad[*in_idx];
                            tmp.frobenius_map(*power);
                            scratchpad[*out_idx] = tmp;
                            out_idx
                        }
                    };

                    if scratchpad[*out_idx] == Fq12::one() {
                        continue;
                    }
                }
            }

            return cand;
        }
    }

    /// Computes the easy part of the final exponentiation for BN256 pairings:
    /// result = f^{(q^6 - 1)*(q^2 + 1)}. Using a known decomposition,
    /// it reduces to computing (-m0/m1)^{p^2+1} from the Miller loop result m = m0 + w*m1.
    /// The final returned value is in compressed toru form
    pub fn final_exp_easy_part<F: SmallField, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        elem: &Fp12<F>,
        params: &Arc<BN256BaseNNFieldParams>,
        is_safe_version: bool,
    ) -> (BN256TorusWrapper<F>, Boolean<F>) {
        let (mut elem, is_exception) = if is_safe_version {
            let mut elem_clone = elem.c1.clone();
            let is_exceptional = elem_clone.is_zero(cs);
            let one_fp6 = Fp6::<F>::one(cs, &params);
            let new_c1 = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(
                cs,
                is_exceptional,
                &one_fp6,
                &elem.c1,
            );
            let elem = Fp12::<F>::new(elem.c0.clone(), new_c1);
            (elem, is_exceptional)
        } else {
            (elem.clone(), Boolean::allocated_constant(cs, false))
        };
        // -m0/m1;
        elem.normalize(cs);
        let mut encoding = elem.c0.div(cs, &mut elem.c1);
        encoding = encoding.negated(cs);

        let mut x = BN256TorusWrapper::new(encoding);

        // x^{p^2}:
        let mut y = x.frobenius_map(cs, 2);
        let mut candidate = y.mul_optimal(cs, &mut x, is_safe_version);

        let (res, enc_is_zero) =
            candidate.replace_by_constant_if_trivial(cs, Self::get_hard_part_generator());

        let is_trivial = is_exception.or(cs, enc_is_zero);

        (res, is_trivial)
    }
    pub fn final_exp_hard_part<F: SmallField, CS: ConstraintSystem<F>>(
        self,
        cs: &mut CS,
        elem: &BN256TorusWrapper<F>,
        is_safe_version: bool,
        params: &Arc<BN256BaseNNFieldParams>,
    ) -> BN256TorusWrapper<F> {
        let (ops_chain, num_of_variables) = self.get_ops_chain();
        let x_decomposition = Self::get_x_ternary_decomposition();

        let zero = BN256TorusWrapper::<F>::zero(cs, &params);

        let mut scratchpad = vec![zero; num_of_variables];
        scratchpad[0] = elem.clone();
        for (_is_first, is_last, op) in ops_chain.into_iter().identify_first_last() {
            let may_cause_exp = is_safe_version && is_last;

            match op {
                Ops::ExpByX(out_idx, in_idx) => {
                    scratchpad[out_idx] = scratchpad[in_idx].pow_naf_decomposition(
                        cs,
                        &x_decomposition,
                        may_cause_exp,
                    );
                }
                Ops::Mul(out_idx, left_idx, right_idx) => {
                    let mut left_val = scratchpad[left_idx].clone();
                    let mut right_val = scratchpad[right_idx].clone();
                    left_val.normalize(cs);
                    right_val.normalize(cs);
                    scratchpad[out_idx] = left_val.mul_optimal(cs, &mut right_val, may_cause_exp);
                }
                Ops::Square(out_idx, in_idx) => {
                    let mut tmp = scratchpad[in_idx].clone();
                    tmp.normalize(cs);
                    scratchpad[out_idx] = tmp.square_optimal(cs, may_cause_exp);
                }
                Ops::Conj(out_idx, in_idx) => {
                    let mut tmp = scratchpad[in_idx].clone();
                    tmp.normalize(cs);
                    scratchpad[out_idx] = tmp.conjugate(cs);
                }
                Ops::Frob(out_idx, in_idx, power) => {
                    scratchpad[out_idx] = scratchpad[in_idx].frobenius_map(cs, power);
                }
            }
        }

        scratchpad[0].clone()
    }

    // let x be parameter parametrizing particular curve in Bn256 family of curves
    // there are two competing algorithms for computing hard part of final exponentiation fot Bn256 family of curves
    // the first one is Devegili method which takes 3exp by x, 11 squaring, 14 muls
    // the second one is Fuentes-Castaneda methid which takes 3exp by x, 4 square, 10 muls and 3 Frobenius powers

    // Devegili method:
    // 1) a = f^x         7) a = conj(a)       13) t1 = t1^9       19) t0 = frob(f, 2)     25) t0 = t0^x
    // 2) b = a^2         8) b = frob(a)       14) a = t1 * a      20) b = b * t0          26) t0 = t0 * b
    // 3) a = b * f^2     9) b = a * b         15) t1 = f^4        21) t0 = b^x            27) a = t0 * a
    // 4) a = a^2         10) a = a * b        16) a = a * t1      22) t1 = t0^2           28) t0 = frob(f, 3)
    // 5) a = a * b       11) t0 = frob(f)     17) t0 = t0^2       23) t0 = t1^2           29) f = t0 * a
    // 6) a = a * f       12) t1 = t0 * f      18) b = b * t0      24) t0 = t0 * t1
    fn devegili_method() -> (Vec<Ops>, usize) {
        let (f, f2, a, b, tmp, t0, t1) = (0, 1, 2, 3, 4, 5, 6);
        let ops_chain = vec![
            /*1*/ Ops::ExpByX(a, f),
            /*2*/ Ops::Square(b, a),
            /*3*/ Ops::Square(f2, f),
            Ops::Mul(a, b, f2),
            /*4*/ Ops::Square(a, a),
            /*5*/ Ops::Mul(a, a, b),
            /*6*/ Ops::Mul(a, a, f),
            /*7*/ Ops::Conj(a, a),
            /*8*/ Ops::Frob(b, a, 1),
            /*9*/ Ops::Mul(b, a, b),
            /*10*/ Ops::Mul(a, a, b),
            /*11*/ Ops::Frob(t0, f, 1),
            /*12*/ Ops::Mul(t1, t0, f),
            /*13*/ Ops::Square(tmp, t1),
            Ops::Square(tmp, tmp),
            Ops::Square(tmp, tmp),
            Ops::Mul(t1, tmp, t1),
            /*14*/ Ops::Mul(a, t1, a),
            /*15*/ Ops::Square(t1, f2),
            /*16*/ Ops::Mul(a, a, t1),
            /*17*/ Ops::Square(t0, t0),
            /*18*/ Ops::Mul(b, b, t0),
            /*19*/ Ops::Frob(t0, f, 2),
            /*20*/ Ops::Mul(b, b, t0),
            /*21*/ Ops::ExpByX(t0, b),
            /*22*/ Ops::Square(t1, t0),
            /*23*/ Ops::Square(t0, t1),
            /*24*/ Ops::Mul(t0, t0, t1),
            /*25*/ Ops::ExpByX(t0, t0),
            /*26*/ Ops::Mul(t0, t0, b),
            /*27*/ Ops::Mul(a, t0, a),
            /*28*/ Ops::Frob(t0, f, 3),
            /*29*/ Ops::Mul(f, t0, a),
        ];
        (ops_chain, 7)
    }

    // This is Fuentes-Castaneda method:
    // 1) a = f^x          5) t = b^x                        9) t = t^2                 13) f = f * frob(t, 3)
    // 2) a = a^2          6) f = f * frob(conj(f), 3)       10) t = t^x                14) f = f * frob(t)
    // 3) b = a^2          7) f = f * t                      11) b = b * t              15) f = f * b
    // 4) b = a * b        8) b = b * t                      12) t = b * conj(a)        16) f = f * frob(b, 2)
    fn fuentes_castaneda_method() -> (Vec<Ops>, usize) {
        let (f, a, b, tmp, t) = (0, 1, 2, 3, 4);
        let ops_chain = vec![
            /*1*/ Ops::ExpByX(a, f),
            /*2*/ Ops::Square(a, a),
            /*3*/ Ops::Square(b, a),
            /*4*/ Ops::Mul(b, a, b),
            /*5*/ Ops::ExpByX(t, b),
            /*6*/ Ops::Conj(tmp, f),
            Ops::Frob(tmp, tmp, 3),
            Ops::Mul(f, f, tmp),
            /*7*/ Ops::Mul(f, f, t),
            /*8*/ Ops::Mul(b, b, t),
            /*9*/ Ops::Square(t, t),
            /*10*/ Ops::ExpByX(t, t),
            /*11*/ Ops::Mul(b, b, t),
            /*12*/ Ops::Conj(tmp, a),
            Ops::Mul(t, b, tmp),
            /*13*/ Ops::Frob(tmp, t, 3),
            Ops::Mul(f, f, tmp),
            /*14*/ Ops::Frob(tmp, t, 1),
            Ops::Mul(f, f, tmp),
            /*15*/ Ops::Mul(f, f, b),
            /*16*/ Ops::Frob(tmp, b, 2),
            Ops::Mul(f, f, tmp),
        ];
        (ops_chain, 5)
    }

    // this is algorithm implemented in pairing crate
    // 1) fp = frob(f, 1)         8) fu2p = fu2^p               15) y6 = conj(fu3 * fu3p)       22) t0 = t1 * y1
    // 2) fp2 = frob(f, 2)        9) fu3p = fu3^p               16) y6 = y6^2 * y4 * y5         23) t1 = t1 * y0
    // 3) fp3 = frob(fp2, 1)     10) y2 = frob(fu2, 2)          17) t1 = y3 * y5 * y6           24) t0 = t0^2
    // 4) fu = f^x               11) y0 = fp * fp2 * fp3        18) y6 = y6 * y2                25) f = t0 * t1
    // 5) fu2 = fu^x             12) y1 = conj(f)               19) t1 = t1^2
    // 6) fu3 = fu2^x            13) y5 = conj(fu2)             20) t1 = t1 * y6
    // 7) y3 = conj(fu^p)        14) y4 = conj(fu * fu2p)       21) t1 = t1^2
    fn naive_method() -> (Vec<Ops>, usize) {
        let (f, fp, tmp, fp2, fp3, fu, fu2, fu3, y3, fu2p, fu3p, y2, y0, y1, y4, y5, y6, t0, t1) = (
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        );
        let ops_chain = vec![
            /*1*/ Ops::Frob(fp, f, 1),
            /*2*/ Ops::Frob(fp2, f, 2),
            /*3*/ Ops::Frob(fp3, fp2, 1),
            /*4*/ Ops::ExpByX(fu, f),
            /*5*/ Ops::ExpByX(fu2, fu),
            /*6*/ Ops::ExpByX(fu3, fu2),
            /*7*/ Ops::Frob(tmp, fu, 1),
            Ops::Conj(y3, tmp),
            /*8*/ Ops::Frob(fu2p, fu2, 1),
            /*9*/ Ops::Frob(fu3p, fu3, 1),
            /*10*/ Ops::Frob(y2, fu2, 2),
            /*11*/ Ops::Mul(tmp, fp, fp2),
            Ops::Mul(y0, tmp, fp3),
            /*12*/ Ops::Conj(y1, f),
            /*13*/ Ops::Conj(y5, fu2),
            /*14*/ Ops::Mul(tmp, fu, fu2p),
            Ops::Conj(y4, tmp),
            /*15*/ Ops::Mul(tmp, fu3, fu3p),
            Ops::Conj(y6, tmp),
            /*16*/ Ops::Square(tmp, y6),
            Ops::Mul(tmp, tmp, y4),
            Ops::Mul(y6, tmp, y5),
            /*17*/ Ops::Mul(tmp, y3, y5),
            Ops::Mul(t1, tmp, y6),
            /*18*/ Ops::Mul(y6, y2, y6),
            /*19*/ Ops::Square(t1, t1),
            /*20*/ Ops::Mul(t1, t1, y6),
            /*21*/ Ops::Square(t1, t1),
            /*22*/ Ops::Mul(t0, t1, y1),
            /*23*/ Ops::Mul(t1, t1, y0),
            /*24*/ Ops::Square(t0, t0),
            /*25*/ Ops::Mul(f, t0, t1),
        ];
        (ops_chain, 19)
    }
}

pub(crate) fn multipairing_naive<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    inputs: &mut [PairingInput<F>],
) -> (Fp12<F>, Fp12<F>, Boolean<F>) {
    assert_eq!(inputs.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let params = Arc::new(RnsParams::create());
    let mut skip_pairings = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    let mut validity_checks = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING * 3);
    let mut if_infinity = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING * 2);

    let mut inputs = inputs.to_vec().try_into().unwrap();

    let mut oracle = Oracle::<F>::allocate(cs, params.clone(), &inputs, false);

    for (p, q) in inputs.iter_mut() {
        let p_check_flags = p.validate_point_naive(cs, &params);
        let q_check_flags = q.validate_point_naive(cs, &params);

        let should_skip = Boolean::multi_or(
            cs,
            &[
                p_check_flags.is_point_at_infty,
                p_check_flags.is_invalid_point,
                q_check_flags.is_point_at_infty,
                q_check_flags.is_invalid_point,
            ],
        );

        p.mask(cs, should_skip, &params);
        q.mask(cs, should_skip, &params);
        skip_pairings.push(should_skip);

        validity_checks.push(p_check_flags.is_valid_point);
        validity_checks.push(q_check_flags.is_valid_point);
        if_infinity.push(p_check_flags.is_point_at_infty);
        if_infinity.push(q_check_flags.is_point_at_infty);

        p.convert_for_line_eval_form(cs);
    }

    let mut q_doubled_array: [_; NUM_PAIRINGS_IN_MULTIPAIRING] =
        std::array::from_fn(|i| inputs[i].1.clone());
    let mut q_negated_array: [_; NUM_PAIRINGS_IN_MULTIPAIRING] =
        std::array::from_fn(|i| inputs[i].1.negate(cs));
    let mut t_array: [_; NUM_PAIRINGS_IN_MULTIPAIRING] =
        std::array::from_fn(|i| inputs[i].1.clone());

    let mut f: Fp12<F> = Fp12::one(cs, &params);

    // main cycle of Miller loop:
    let iter = SIX_U_PLUS_TWO_WNAF
        .into_iter()
        .rev()
        .skip(1)
        .identify_first_last();
    for (is_first, _is_last, bit) in iter {
        if !is_first {
            f = f.square(cs);
        }

        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let line_object = oracle.next_line_object();
            let mut t = t_array[i].clone();
            let mut p = inputs[i].0.clone();

            let line_func_eval = line_object.double_and_eval(cs, &mut t, &mut p);
            if is_first {
                q_doubled_array[i] = t.clone();
            }

            line_func_eval.mul_into_fp12(cs, &mut f);
            let to_add: &mut TwistedCurvePoint<F> = if bit == -1 {
                &mut q_negated_array[i]
            } else {
                &mut inputs[i].1
            };

            if bit == 1 || bit == -1 {
                let line_object = oracle.next_line_object();
                let line_func_eval = line_object.add_and_eval(cs, &mut t, to_add, &mut p);
                line_func_eval.mul_into_fp12(cs, &mut f);
            }

            t_array[i] = t;
            inputs[i].0 = p;
        }

        f.normalize(cs);
    }

    // Miller loop postprocess:
    // The twist isomorphism is (x', y') -> (xω², yω³). If we consider just
    // x for a moment, then after applying the Frobenius, we have x̄ω^(2p)
    // where x̄ is the conjugate of x. If we are going to apply the inverse
    // isomorphism we need a value with a single coefficient of ω² so we
    // rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
    // p, 2p-2 is a multiple of six. Therefore we can rewrite as
    // x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the ω².
    // A similar argument can be made for the y value.
    let mut q1_mul_factor = allocate_fq2_constant(cs, FROBENIUS_COEFF_FQ6_C1[1], &params);
    let mut q2_mul_factor = allocate_fq2_constant(cs, FROBENIUS_COEFF_FQ6_C1[2], &params);
    let mut xi = allocate_fq2_constant(cs, XI_TO_Q_MINUS_1_OVER_2, &params);

    for ((p, q), t, q_doubled) in izip!(
        inputs.iter_mut(),
        t_array.iter_mut(),
        q_doubled_array.iter_mut()
    ) {
        let mut q_frob = q.clone();
        q_frob.x.c1 = q_frob.x.c1.negated(cs);
        q_frob.x = q_frob.x.mul(cs, &mut q1_mul_factor);
        q_frob.y.c1 = q_frob.y.c1.negated(cs);
        q_frob.y = q_frob.y.mul(cs, &mut xi);

        let mut q2 = q.clone();
        q2.x = q2.x.mul(cs, &mut q2_mul_factor);

        let mut r_pt = t.clone();

        let line_object = oracle.next_line_object();
        let line_eval_1 = line_object.add_and_eval(cs, t, &mut q_frob, p);

        let line_object = oracle.next_line_object();
        let line_eval_2 = line_object.add_and_eval(cs, t, &mut q2, p);

        line_eval_1.mul_into_fp12(cs, &mut f);
        line_eval_2.mul_into_fp12(cs, &mut f);

        // subgroup check for BN256 curve is of the form: twisted_frob(Q) = [6*u^2]*Q
        r_pt = r_pt.sub(cs, q_doubled);
        let mut r_pt_negated = r_pt.negate(cs);
        let mut acc = r_pt.clone();

        for bit in U_WNAF.into_iter().skip(1) {
            if bit == 0 {
                acc = acc.double(cs);
            } else {
                let to_add = if bit == 1 {
                    &mut r_pt
                } else {
                    &mut r_pt_negated
                };
                acc = acc.double_and_add(cs, to_add);
            }

            acc.x.normalize(cs);
            acc.y.normalize(cs);
        }
        let g2_subgroup_check = TwistedCurvePoint::equals(cs, &mut acc, &mut q_frob);
        validity_checks.push(g2_subgroup_check);
    }

    assert_eq!(
        oracle.line_function_idx,
        NUM_PAIRINGS_IN_MULTIPAIRING * BN254_NUM_ELL_COEFFS
    );

    let input: Vec<_> = skip_pairings
        .iter()
        .map(|el| (el.get_variable(), F::ONE))
        .collect();
    let num_of_skipped_tuples = Num::linear_combination(cs, &input);

    let mut equality_flags = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    for idx in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
        let cur_fr = Num::allocated_constant(cs, F::from_raw_u64_unchecked(idx as u64 + 1));
        let flag = Num::equals(cs, &num_of_skipped_tuples, &cur_fr);
        equality_flags.push(flag);
    }

    let miller_loop_res = f.clone();

    let (wrapped_f, is_trivial) = Bn256HardPartMethod::final_exp_easy_part(cs, &f, &params, true);
    let chain = Bn256HardPartMethod::get_optinal();
    let candidate = chain.final_exp_hard_part(cs, &wrapped_f, true, &params);
    let final_res = candidate.decompress(cs);
    let fp12_one = Fp12::<F>::one(cs, &params);

    let no_exception = is_trivial.negated(cs);
    validity_checks.push(no_exception);

    let success = Boolean::multi_and(cs, &validity_checks);

    let infinity_flag = Boolean::multi_or(cs, &if_infinity);
    let result = <BN256Fq12NNField<F> as NonNativeField<F, _>>::conditionally_select(
        cs,
        infinity_flag,
        &fp12_one,
        &final_res,
    );
    (result, miller_loop_res, success)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::bn256::miller_loop_with_prepared_lines;
    use super::bn256::prepare_all_line_functions;
    use super::bn256::prepare_g1_point;
    use super::bn256::Bn256;
    use boojum::config::CSConfig;
    use boojum::pairing::ff::ScalarEngine;
    use boojum::pairing::Engine;
    use boojum::pairing::{CurveAffine, CurveProjective};
    use boojum::{
        gadgets::non_native_field::traits::NonNativeField,
        pairing::{
            bn256::{Fq12, G1Affine, G2Affine, G1, G2},
            ff::Field,
        },
    };

    use crate::boojum::field::goldilocks::GoldilocksField;
    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder::*;
    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::cs::gates::*;
    use boojum::cs::traits::gate::GatePlacementStrategy;
    use boojum::dag::CircuitResolverOpts;
    use boojum::gadgets::tables::create_range_check_16_bits_table;
    use boojum::gadgets::tables::RangeCheck16BitsTable;
    use boojum::worker::Worker;
    use std::alloc::Global;

    type F = GoldilocksField;
    type P = GoldilocksField;

    type Fr = <Bn256 as ScalarEngine>::Fr;

    use boojum::cs::implementations::reference_cs::CSReferenceImplementation;
    use boojum::cs::{CSGeometry, GateConfigurationHolder, LookupParameters, StaticToolboxHolder};
    fn cs_geometry() -> CSReferenceImplementation<
        F,
        P,
        DevCSConfig,
        impl GateConfigurationHolder<F>,
        impl StaticToolboxHolder,
    > {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: 120,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        };

        type RCfg = <DevCSConfig as CSConfig>::ResolverConfig;
        let builder_impl =
            CsReferenceImplementationBuilder::<F, F, DevCSConfig>::new(geometry, 1 << 20);
        let builder = new_builder::<_, F>(builder_impl);

        let builder = builder.allow_lookup(
            LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                width: 1,
                num_repetitions: 10,
                share_table_id: true,
            },
        );

        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<F, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = DotProductGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<16>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );

        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 26));

        // add tables
        let table = create_range_check_16_bits_table();
        owned_cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);
        owned_cs
    }

    #[test]
    fn test_multipairing_naive() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;

        let params = RnsParams::create();
        let params = std::sync::Arc::new(params);

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        // let mut rng = rand::thread_rng();
        let mut pairs = Vec::new();
        let mut q1_s_for_wit = Vec::new();
        let mut prep_lines = Vec::new();
        for _ in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let p = G1::rand(&mut rng);
            let q = G2::rand(&mut rng);

            let p_affine = p.into_affine();
            let p_prep = prepare_g1_point(p_affine);

            let q_affine = q.into_affine();
            let lines = prepare_all_line_functions(q_affine);

            let g1 = AffinePoint::allocate(cs, p.into_affine(), &params);
            let g2 = TwistedCurvePoint::allocate(cs, q.into_affine(), &params);
            pairs.push((g1, g2));
            q1_s_for_wit.push(p_prep);
            prep_lines.push(lines);
        }
        let miller_loop_wit = miller_loop_with_prepared_lines(&q1_s_for_wit, &prep_lines);
        let actual_miller_loop = Fp12::<F>::allocate_from_witness(cs, miller_loop_wit, &params);
        let fin_exp_res = Bn256::final_exponentiation(&miller_loop_wit).unwrap();
        let mut actual_res = Fp12::<F>::allocate_from_witness(cs, fin_exp_res, &params);
        actual_res.normalize(cs);

        let (res, miller_loop, success) = multipairing_naive(cs, &mut pairs);
        println!("miller_loop check");
        Fp12::<F>::enforce_equal(cs, &actual_miller_loop, &miller_loop);
        println!("final check");
        Fp12::<F>::enforce_equal(cs, &res, &actual_res);
        let one = Boolean::<F>::allocated_constant(cs, true);
        Boolean::<F>::enforce_equal(cs, &success, &one);

        let worker = Worker::new();
        owned_cs.pad_and_shrink();
        let mut owned_cs = owned_cs.into_assembly::<std::alloc::Global>();
        assert!(
            owned_cs.check_if_satisfied(&worker),
            "Constraints are not satisfied"
        );
        owned_cs.print_gate_stats();
    }

    #[test]
    fn test_multipairing_naive_g1_infinity() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;
        let params = Arc::new(RnsParams::create());
        let mut rng = rand::thread_rng();

        let p_infty = G1Affine::zero();
        let q = G2::rand(&mut rng);
        let q_affine = q.into_affine();

        let g1 = AffinePoint::allocate(cs, p_infty, &params);
        let g2 = TwistedCurvePoint::allocate(cs, q_affine, &params);
        let mut pairing_inputs = vec![(g1, g2)];
        let (final_res, _miller_loop_res, success) = multipairing_naive(cs, &mut pairing_inputs);
        let one = Fp12::one(cs, &params);
        Fp12::<F>::enforce_equal(cs, &final_res, &one);
        let one = Boolean::allocated_constant(cs, true);
        Boolean::enforce_equal(cs, &success, &one);
    }
    #[test]
    fn test_multipairing_naive_g2_infinity() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;
        let params = Arc::new(RnsParams::create());
        let mut rng = rand::thread_rng();

        let p = G1::rand(&mut rng);
        let p_affine = p.into_affine();
        let q_infty = G2Affine::zero();

        let g1 = AffinePoint::allocate(cs, p_affine, &params);
        let g2 = TwistedCurvePoint::allocate(cs, q_infty, &params);
        let mut pairing_inputs = vec![(g1, g2)];

        let (final_res, _miller_loop_res, success) = multipairing_naive(cs, &mut pairing_inputs);

        let one = Fp12::one(cs, &params);
        Fp12::<F>::enforce_equal(cs, &final_res, &one);
        let one = Boolean::allocated_constant(cs, true);
        Boolean::enforce_equal(cs, &success, &one);
    }
    #[test]
    fn test_multipairing_naive_invalid_points() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;
        let params = Arc::new(RnsParams::create());

        let invalid_g1 = G1Affine::from_xy_unchecked(bn256::Fq::one(), bn256::Fq::one());

        let invalid_g2 = G2Affine::from_xy_unchecked(bn256::Fq2::one(), bn256::Fq2::one());

        let g1 = AffinePoint::allocate(cs, invalid_g1, &params);
        let g2 = TwistedCurvePoint::allocate(cs, invalid_g2, &params);
        let mut pairing_inputs = vec![(g1, g2)];

        let (_final_res, _miller_loop_res, success) = multipairing_naive(cs, &mut pairing_inputs);

        let one = Boolean::allocated_constant(cs, false);
        Boolean::enforce_equal(cs, &success, &one);
    }
    #[test]
    fn test_final_exponentiation_comparison() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;

        let params = RnsParams::create();
        let params = std::sync::Arc::new(params);

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p = G1::rand(&mut rng);
        let q = G2::rand(&mut rng);
        let p_affine = p.into_affine();
        let q_affine = q.into_affine();

        let p_prepared = prepare_g1_point(p_affine);
        let q_lines = prepare_all_line_functions(q_affine);
        let miller_loop_wit = miller_loop_with_prepared_lines(&[p_prepared], &[q_lines]);
        let _miller = Bn256::miller_loop(
            [(&(p.into_affine().prepare()), &(q.into_affine().prepare()))].iter(),
        );

        //let expected_final_exp = Bn256::final_exponentiation(&miller).unwrap();

        let miller_loop_alloc = Fp12::<F>::allocate_from_witness(cs, miller_loop_wit, &params);

        let (wrapped_torus, _is_trivial) =
            Bn256HardPartMethod::final_exp_easy_part(cs, &miller_loop_alloc, &params, true);

        let chain = Bn256HardPartMethod::get_optinal();
        let candidate = chain.final_exp_hard_part(cs, &wrapped_torus, true, &params);
        let mut candidate_final_exp = candidate.decompress(cs);
        candidate_final_exp.normalize(cs);

        // let mut expected_fp12 = Fp12::allocate_from_witness(cs, expected_final_exp, &params);
        // expected_fp12.normalize(cs);

        // Fp12::enforce_equal(cs, &candidate_final_exp, &expected_fp12);

        let worker = Worker::new_with_num_threads(8);
        drop(cs);
        owned_cs.pad_and_shrink();
        let mut owned_cs = owned_cs.into_assembly::<Global>();
        assert!(
            owned_cs.check_if_satisfied(&worker),
            "Constraints are not satisfied"
        );

        owned_cs.print_gate_stats();
    }

    #[test]
    fn test_easy_part() {
        let mut owned_cs = cs_geometry();
        let cs = &mut owned_cs;

        let params = std::sync::Arc::new(RnsParams::create());

        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p = G1::rand(&mut rng);
        let q = G2::rand(&mut rng);

        let p_affine = p.into_affine();
        let q_affine = q.into_affine();

        let p_prepared = prepare_g1_point(p_affine);
        let q_lines = prepare_all_line_functions(q_affine);

        let miller_loop_native = miller_loop_with_prepared_lines(&[p_prepared], &[q_lines]);

        // naive easy part
        pub fn easy_part_of_final_exp(f: &Fq12) -> Fq12 {
            let mut f_q6_minus_1 = *f;
            f_q6_minus_1.conjugate();

            let inv_f = match f.inverse() {
                Some(inv) => inv,
                None => {
                    return Fq12::zero();
                }
            };

            f_q6_minus_1.mul_assign(&inv_f); // f^(q^6 - 1)

            let mut f_q6_minus_1_q2 = f_q6_minus_1;
            f_q6_minus_1_q2.frobenius_map(2);
            f_q6_minus_1_q2.mul_assign(&f_q6_minus_1);

            f_q6_minus_1_q2
        }

        let mut allocated_miller_loop =
            Fp12::<F>::allocate_from_witness(cs, miller_loop_native, &params);
        let expected_native = easy_part_of_final_exp(&miller_loop_native);
        let allocated_expected = Fp12::<F>::allocate_from_witness(cs, expected_native, &params);
        let (wrapped_torus, _is_trivial) =
            Bn256HardPartMethod::final_exp_easy_part(cs, &allocated_miller_loop, &params, true);

        let mut decompres = wrapped_torus.decompress(cs);
        decompres.normalize(cs);

        Fp12::enforce_equal(cs, &decompres, &allocated_expected);

        let worker = Worker::new_with_num_threads(8);
        owned_cs.pad_and_shrink();
        let mut owned_cs = owned_cs.into_assembly::<std::alloc::Global>();
        assert!(
            owned_cs.check_if_satisfied(&worker),
            "Constraints are not satisfied"
        );

        owned_cs.print_gate_stats();
    }
}
