// use crate::ecrecover::secp256k1::PointAffine;

use super::*;
use bn256::{fq::ROOT_27_OF_UNITY, Certificate, G1Prepared, G2Prepared, Bn256};
use bn256::prepare_all_line_functions;
use bn256::prepare_g1_point;
use bn256::miller_loop_with_prepared_lines;
use boojum::pairing::ff::ScalarEngine;
use boojum::{
    cs::{Place, Witness}, gadgets::{non_native_field::traits::NonNativeField, traits::witnessable::CSWitnessable}, 
    pairing::{bn256::{Fq, Fq12, Fq2, Fq6, G1Affine, G2Affine, G1, G2, FROBENIUS_COEFF_FQ6_C1, XI_TO_Q_MINUS_1_OVER_2}, ff::{Field, PrimeField}}
};
use itertools::izip;
use rand::Rng;
use serde::Serialize;
use std::iter;
use boojum::config::CSConfig;
use boojum::config::CSWitnessEvaluationConfig;
use boojum::cs::traits::cs::DstBuffer;
use boojum::pairing::{CurveAffine, CurveProjective};
use boojum::pairing::Engine;


const NUM_PAIRINGS_IN_MULTIPAIRING: usize = 3;
const NUM_LIMBS: usize = 17;
// multipairing circuit logic is the following:
// by contract design we assume, that input is always padded if necessary on the contract side (by points on infinity), 
// and hence the number of pairs (G1, G2) in the input is always equal to NUM_PAIRINGS_IN_MULTIPAIRING
// we are going to have two different version of the precompile:

// Fast and Quick: this circuit assumes that all inputs are valid: i.e. there are regualr points or points at inifity and that multipairing is always equal to one.
// The circuits proceeds as follows:
// 1) for each individual pair (G1, G2) enforce that input is valid: i.e. each G_i is either regular point or point at inifinity
// 2) if either G_i i == 1, 2 is point at inifinity we mask both G_i of the tuple by the corresponding group generator 
//    and set the flag skip_ith_input = G1_i_is_infty || G2_i_is_infty
// 3) during Miller_loop we either add the corresponding line_evaluation to the total accumulator or not (depending on the pairing_should_be_skipped_flag)
// 4) during Miller_loop we also prepare all the necessary data required for checking if all G2_i are in correct subgroup (subgroup check); enforce it in Miller Loop
//    postprocess routine
// 5) we need to divide result of the Miller by MillerLoop(G1, G2)^i, where i is in range 0..3, depending on the number of trivial pairings
// 6) enforce the Multipairing is equal to one (by providing certificates c and root27_of_unity: note, that this check will be satisfied even if any point is invalid)
// The methods used in this function all have suffix _robust
     
// Long and Naive - in case there any any exceptions (either points not on the curve, or not in the corresponding subgroups)
// or all is valid but Multipairing is not equal to one
// Olena - it's your shinig time!
// The methods used in this function all have suffix _naive
// The circuits proceeds as follows:
// 1) for each individual pair we check that both inputs are valid, also set to_skip in case any point is invalid or we point is infinity
// 2) mask both G1 and G2 in the tuple if to_skip flag is set
// 3) procced almost as in robust case, but this time we have to do explicit final exponentiation and also we should all "enforce" versions we change by "equals"
// 4) at the very end check if there any any exceptions happened - and if it is indeed the case, then mask the final result


/// This trait defines the iterator adapter `identify_first_last()`.
/// The new iterator gives a tuple with an `(element, is_first, is_last)`.
/// `is_first` is true when `element` is the first we are iterating over.
/// `is_last` is true when `element` is the last and no others follow.
pub trait IdentifyFirstLast: Iterator + Sized {
    fn identify_first_last(self) -> Iter<Self>;
}
    
/// Implement the iterator adapter `identify_first_last()`
impl<I> IdentifyFirstLast for I where I: Iterator {
    fn identify_first_last(self) -> Iter<Self> {
        Iter(true, self.peekable())
    }
}

/// A struct to hold the iterator's state
/// Our state is a bool telling if this is the first element.
pub struct Iter<I>(bool, iter::Peekable<I>) where I: Iterator;

impl<I> Iterator for Iter<I> where I: Iterator {
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
type PairingInput<F> = (AffinePoint<F>, TwistedCurvePoint<F>);

// Curve parameter for the BN256 curve
const SIX_U_PLUS_TWO_WNAF: [i8; 65] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0,
    1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0,
    0, 1, 0, 1, 1,
];

const U_WNAF : [i8; 63] =  [
    1, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 
    1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 1
];

const X_TERNARY : [i8; 64] =  [
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

const X_TERNARY_HALF : [i8; 63] =  [
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
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
    let c2 = allocate_fq2_constant(cs, value.c1, params);

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


// Both original Bn256 curve and it's twist are of the form:
// y_p^2 = x_p^3 + b
// points at infinity by spec are encoded with both coordinates equal to zero
struct CurveCheckFlags<F: SmallField> {
    is_point_at_infty: Boolean<F>,
    is_valid_point: Boolean<F>,
    is_invalid_point: Boolean<F>
}


#[derive(Debug, Clone)]
struct AffinePoint<F: SmallField> {
    x: Fp<F>,
    y: Fp<F>,
    is_in_eval_form: bool
}

impl<F: SmallField> AffinePoint<F> {
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: G1Affine, params: &Arc<RnsParams>) -> Self {
        let (x_wit, y_wit) = witness.into_xy_unchecked();
        let x = Fp::<F>::allocate_checked(cs, x_wit, params);
        let y = Fp::<F>::allocate_checked(cs, y_wit, params);

        AffinePoint { x, y, is_in_eval_form: false }
    }

    fn is_point_at_infty<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Boolean<F> {
        let x_is_zero = self.x.is_zero(cs);
        let y_is_zero = self.y.is_zero(cs);
        x_is_zero.and(cs, y_is_zero)
    }

    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: &mut CS, flag: Boolean<F>, first: &Self, second: &Self
    ) -> Self {
        let x = <Fp<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.x, &second.x);
        let y = <Fp<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.y, &second.y);

        AffinePoint { x, y, is_in_eval_form: false }
    }

    fn constant<CS: ConstraintSystem<F>>(cs: &mut CS, wit: G1Affine, rns_params: &Arc<RnsParams>) -> Self {
        let (x_wit, y_wit) = wit.into_xy_unchecked();
        let x = Fp::allocated_constant(cs, x_wit, rns_params);
        let y = Fp::allocated_constant(cs, y_wit, rns_params);
        let point = AffinePoint { x, y , is_in_eval_form: false };
        point
    } 

    fn generator<CS: ConstraintSystem<F>>(cs: &mut CS, rns_params: &Arc<RnsParams>) -> Self {
        Self::constant(cs, G1Affine::one(), rns_params)
    }

    fn is_on_curve<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> Boolean<F> {
        let mut b = Fp::allocated_constant(cs, G1Affine::b_coeff(), rns_params);
        let mut lhs = self.y.square(cs);
        let mut x_squared = self.x.square(cs);
        let mut x_cubed = x_squared.mul(cs, &mut self.x);
        let mut rhs = x_cubed.add(cs, &mut b);
        
        lhs.equals(cs, &mut rhs)
    }

    // we check that this point either represent point at infty or correctly encoded point
    fn validate_point_robust<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> Boolean<F> {
        let is_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let is_regular_point = is_infty.negated(cs);
        is_on_curve.conditionally_enforce_true(cs, is_regular_point);

        is_infty
    }

    fn validate_point_naive<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> CurveCheckFlags<F> {
        let is_point_at_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let point_is_valid = is_point_at_infty.or(cs, is_on_curve);
        let is_invalid_point = point_is_valid.negated(cs);
        
        CurveCheckFlags {
            is_point_at_infty, is_valid_point: point_is_valid, is_invalid_point
        }
    }

    fn mask<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, should_skip: Boolean<F>, rns_params: &Arc<RnsParams>) {
        // TODO: check that reallocationg constant default choice doesnt't generate any constraints
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
struct TwistedCurvePoint<F: SmallField> {
    pub x: Fp2<F>,
    pub y: Fp2<F>
}

impl<F: SmallField> TwistedCurvePoint<F> {
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: G2Affine, params: &Arc<RnsParams>) -> Self {
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
        cs: &mut CS, flag: Boolean<F>, first: &Self, second: &Self
    ) -> Self {
        let x = <Fp2<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.x, &second.x);
        let y = <Fp2<F> as NonNativeField<F, _>>::conditionally_select(cs, flag, &first.y, &second.y);

        TwistedCurvePoint { x, y }
    }

    fn constant<CS: ConstraintSystem<F>>(cs: &mut CS, wit: G2Affine, rns_params: &Arc<RnsParams>) -> Self {
        let (x_wit, y_wit) = wit.into_xy_unchecked();
        let x = Fp2::constant(cs, x_wit, rns_params);
        let y = Fp2::constant(cs, y_wit, rns_params);
        let point = TwistedCurvePoint { x, y };
        point
    } 

    fn generator<CS: ConstraintSystem<F>>(cs: &mut CS, rns_params: &Arc<RnsParams>) -> Self {
        Self::constant(cs, G2Affine::one(), rns_params)
    }

    fn is_on_curve<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> Boolean<F> {
        let mut b = Fp2::constant(cs, G2Affine::b_coeff(), rns_params);

        let mut lhs = self.y.square(cs);
        let mut x_squared = self.x.square(cs);
        let mut x_cubed = x_squared.mul(cs, &mut self.x);
        let mut rhs = x_cubed.add(cs, &mut b);
        
        lhs.equals(cs, &mut rhs)
    }

    // we check that this point either represent point at infty or correctly encoded point
    fn validate_point_robust<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> Boolean<F> {
        let is_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let is_regular_point = is_infty.negated(cs);
        is_on_curve.conditionally_enforce_true(cs, is_regular_point);

        is_infty
    }

    fn validate_point_naive<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, rns_params: &Arc<RnsParams>) -> CurveCheckFlags<F> {
        let is_point_at_infty = self.is_point_at_infty(cs);
        let is_on_curve = self.is_on_curve(cs, rns_params);
        let point_is_valid = is_point_at_infty.or(cs, is_on_curve);
        let is_invalid_point = point_is_valid.negated(cs);
        
        CurveCheckFlags {
            is_point_at_infty, is_valid_point: point_is_valid, is_invalid_point
        }
    }

    fn mask<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, should_skip: Boolean<F>, rns_params: &Arc<RnsParams>) {
        // TODO: check that reallocationg constant default choice doesnt't generate any constraints
        let default_choice = Self::generator(cs, rns_params);
        *self = Self::conditionally_select(cs, should_skip, &default_choice, &self);
    }

    fn negate<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Self {
        let new_y = self.y.negated(cs);
        TwistedCurvePoint { x: self.x.clone(), y: new_y }
    }

    // TODO: use line object here?
    fn double<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Self 
    {
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
        
        TwistedCurvePoint {x: new_x, y: new_y }
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

    fn equals<CS: ConstraintSystem<F>>(cs: &mut CS, left: &mut Self, right: &mut Self) -> Boolean<F> {
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
        vars_for_x_c0.into_iter().chain(vars_for_x_c1.into_iter()).chain(vars_for_y_c0.into_iter()).chain(vars_for_y_c1.into_iter())
    }
    fn normalize<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS){
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
        let zerp_fp6 = Fp6::zero(cs, params);
        let LineFunctionEvaluation { c3, c4 } = self;

        let fp6_y = Fp6::new(c3, c4, zero_fp2);
        Fp12::new(zerp_fp6, fp6_y)
    }

    // this function masks the line function, so that the following multiplication of Miller loop accumular by this line fuction will be just multiplication 
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

    fn conditionally_mul_into_fp12<CS: ConstraintSystem<F>>(mut self, cs: &mut CS, skip_flag: Boolean<F>, fp12: &mut Fp12<F>) {
        self.trivialize(cs, skip_flag);
        self.mul_into_fp12(cs, fp12);
    }
}


// Fp2 is generated by u => every element of Fp2 is of the form c0 + c1 * u, c_i in Fp
// Fp6 is generated from Fp2 by cubic_non_residue t => every element of Fp6 is of the form: a0 + a1 * t + a2 * t^2, a_i in Fp^2
// 27th_root_of_unity (see below) is either 1, or a1 * t or a2 * t^2 (acutally it belongs to Fp^3, that's the reason it has such compact representation)
// we hence represent element of Fp^3 as a /in Fp^2 and two Boolean flags, the first is set if it is of the form a1 * t; a2 * t - if second if set;
// these flags can't be both set simultaneously - and it is checked!
// if neither of them is set than we assume that our element is just element of Fp2
struct Root27OfUnity<F: SmallField> {
    a: Fp2<F>,
    first_flag: Boolean<F>,
    second_flag: Boolean<F>
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

        *acc = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(cs, self.first_flag, &res_if_first_flag, acc);
        *acc = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(cs, self.second_flag, &res_if_second_flag, acc);
    }
}


struct WitnessParser<'a, F: SmallField> {
    witness: &'a [F],
    offset: usize
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

    fn parse_g1_affine(&mut self) -> G1Affine {
        let x = self.parse_fq();
        let y = self.parse_fq();
        println!("x: {}, y: {}", x, y);
        G1Affine::from_xy_checked(x, y).unwrap()
    }

    fn parse_fq2(&mut self) -> Fq2 {
        let c0 = self.parse_fq();
        let c1 = self.parse_fq();
        Fq2 { c0, c1 }
    }

    fn parse_g2_affine(&mut self) -> G2Affine {
        let x = self.parse_fq2();
        let y = self.parse_fq2();
        G2Affine::from_xy_checked(x, y).unwrap()
    }
}

// we are going to use the following hack for Witness Oracle:
// we create an aritifical variable - tag, which is used to overcome graph of dependecies within cs.set_values_with_dependencies
struct Oracle {
    tag: Place,
    line_functions: Vec<(Fq2, Fq2)>,
    line_function_idx: usize,
    cert_c_inv: Option<Fq12>,
    cert_root_of_unity_power: usize
}

impl Drop for Oracle {
    fn drop(&mut self) {
        assert_eq!(self.line_function_idx, self.line_functions.len())
    }
}

impl Oracle {
    fn allocate_boolean<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, witness: bool) -> Boolean<F> {
        let var = cs.alloc_variable_without_value();
        let result = Boolean::from_variable_checked(cs, var);

        // temporal variable
        let c_wit = self.cert_c_inv.as_ref().map_or(Fq12::one(), |cert| *cert);

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS == true {
            let value_fn = move |_inputs: &[F], output_buffer: &mut DstBuffer<'_, '_, F>| {
                let witness_as_fr = if witness { F::ONE } else { F::ZERO };
                let _tmp = c_wit;
                output_buffer.push(witness_as_fr);
            };

            cs.set_values_with_dependencies_vararg(&[self.tag], &[Place::from_variable(var)], value_fn);
        }

        result   
    }

    fn allocate_fq<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, witness: Fq, params: &Arc<BN256BaseNNFieldParams>) -> Fp<F> {
        BN256BaseNNField::allocate_checked_with_tag(cs, witness, params, self.tag)
    }

    fn allocate_fq2<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, witness: Fq2, params: &Arc<BN256BaseNNFieldParams>) -> Fp2<F> {
        let c0 = self.allocate_fq(cs, witness.c0, params);
        let c1 = self.allocate_fq(cs, witness.c1, params);

        Fp2::new(c0, c1)
    }

    fn allocate_fq6<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, witness: Fq6, params: &Arc<BN256BaseNNFieldParams>) -> Fp6<F> {
        let c0 = self.allocate_fq2(cs, witness.c0, params);
        let c1 = self.allocate_fq2(cs, witness.c1, params);
        let c2 = self.allocate_fq2(cs, witness.c2, params);

        Fp6::new(c0, c1, c2)
    }

    fn allocate_fq12<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, witness: Fq12, params: &Arc<BN256BaseNNFieldParams>) -> Fp12<F> {
        let c0 = self.allocate_fq6(cs, witness.c0, params);
        let c1 = self.allocate_fq6(cs, witness.c1, params);
        
        Fp12::new(c0, c1)
    }

    fn allocate_c_inv<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, params: &Arc<RnsParams>) -> Fp12<F> {
        let c_wit = self.cert_c_inv.as_ref().map_or(Fq12::one(), |cert| *cert);
        self.allocate_fq12(cs, c_wit, params)
    }

    fn allocate_next_line_object<F: SmallField, CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, params: &Arc<RnsParams>) -> LineObject<F> {
        let (lambda_wit, mu_wit) = self.line_functions[self.line_function_idx];
        self.line_function_idx += 1;

        let lambda = self.allocate_fq2(cs, lambda_wit, params);
        let mu = self.allocate_fq2(cs, mu_wit, params);
        LineObject { lambda, mu }
    } 

    fn allocate_root_of_unity<F: SmallField, CS: ConstraintSystem<F>>(&self, cs: &mut CS, params: &Arc<RnsParams>) -> Root27OfUnity<F> {
        let root_of_unity_power = self.cert_root_of_unity_power;

        // 27th_root_of_unity is either 1, or a1 * t or a2 * t^2 (acutally it belongs to Fp^3, that's the reason it has such compact representation)
        // we hence represent element of Fp^3 as a /in Fp^2 and two Boolean flags, the first is set if it is of the form a1 * t; a2 * t - if second if set;
        // these flags can't be both set simultaneously - and it is checked!
        let (a_witness, first_flag_witness, second_flag_witness) = match root_of_unity_power {
            0 => {
                // this is just 1
                (Fq2::one(), false, false)
            },
            1 => {
                // root of unity is of the form a * t^2
                (ROOT_27_OF_UNITY.c2, false, true)
            },
            2 => {
                let mut root27_of_unity_squared = ROOT_27_OF_UNITY;
                root27_of_unity_squared.square();
                assert!(root27_of_unity_squared.c0.is_zero());
                assert!(root27_of_unity_squared.c2.is_zero());

                (root27_of_unity_squared.c1, true, false)
            },
            _ => unreachable!()
        };

        let a = self.allocate_fq2(cs, a_witness, params);
        let first_flag = self.allocate_boolean(cs, first_flag_witness);
        let second_flag = self.allocate_boolean(cs, second_flag_witness);
        let validity_check = first_flag.and(cs, second_flag);
        ConstantsAllocatorGate::new_to_enforce(validity_check.get_variable(), F::ZERO);

        Root27OfUnity { a, first_flag, second_flag }
    }

    const fn new_uninitialized() -> Self {
        Oracle {
            tag: Place::placeholder(), line_functions: vec![], line_function_idx: 0, 
            cert_c_inv: None, cert_root_of_unity_power: 0
        }
    }

    pub fn populate<F: SmallField, CS: ConstraintSystem<F>>(
        &'static mut self, cs: &mut CS, pairing_input: &[PairingInput<F>], should_compute_certificate: bool
    ) {
        let Oracle { tag, line_functions, cert_root_of_unity_power, cert_c_inv, line_function_idx } = self;
        *line_function_idx = 0;

        let tag_variable = cs.alloc_variable_without_value();
        let actual_tag = Place::from_variable(tag_variable);
        *tag = actual_tag;

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS == true {
            // populate witness inputs
            let mut inputs = Vec::<Place>::new();
            for (p, q) in pairing_input.iter() {
                let p_vars_iter = p.as_variables_set();
                let q_vars_iter = q.as_variables_set();
                inputs.extend(p_vars_iter.chain(q_vars_iter).map(|variable| Place::from_variable(variable)));
            }
            let num_of_tuples = pairing_input.len();

            let value_fn = move |input: &[F], dst: &mut DstBuffer<'_, '_, F>| {
                let mut parser = WitnessParser::new(input);
                let mut g1_arr = Vec::<G1Affine>::with_capacity(num_of_tuples);
                let mut line_functions_unflattened = Vec::with_capacity(num_of_tuples);
                let mut num_of_line_functions_per_tuple : usize = 0;

                for idx in 0..num_of_tuples {
                    let g1 = prepare_g1_point(parser.parse_g1_affine());
                    let g2 = parser.parse_g2_affine();
                    
                    let line_functions = prepare_all_line_functions(g2);
                    if idx == 0 {
                        num_of_line_functions_per_tuple = line_functions.len();
                    } else {
                        assert_eq!(line_functions.len(), num_of_line_functions_per_tuple);
                    }

                    line_functions_unflattened.push(line_functions);
                    g1_arr.push(g1);
                }

                let f = miller_loop_with_prepared_lines(&g1_arr, &line_functions_unflattened);
                let final_exp = Bn256::final_exponentiation(&f).unwrap();
                let certificate = bn256::construct_certificate(f);

                if final_exp == Fq12::one() {
                    assert!(bn256::validate_ceritificate(&f, &certificate));
                } else {
                    assert!(!bn256::validate_ceritificate(&f, &certificate));
                }

                // prepare certificate (if required)
                if should_compute_certificate {
                    assert_eq!(final_exp, Fq12::one());
        
                    let Certificate { c, root_27_of_unity_power } = certificate;
                    let c_inv = c.inverse().unwrap();

                    *cert_c_inv = Some(c_inv);
                    *cert_root_of_unity_power = root_27_of_unity_power;

                    println!("cert power: {}", cert_root_of_unity_power);
                }

                let mut row_idx = 0;
                for bit in SIX_U_PLUS_TWO_WNAF.into_iter().rev().skip(1) {
                    if bit == 0 {
                        line_functions.extend(line_functions_unflattened.iter().map(|arr| arr[row_idx]));
                        row_idx += 1;
                    } else {
                        line_functions.extend(line_functions_unflattened.iter().flat_map(|arr| {
                            std::iter::once(arr[row_idx]).chain(std::iter::once(arr[row_idx + 1]))
                        }));
                        row_idx += 2;
                    }
                }
                line_functions.extend(line_functions_unflattened.iter().flat_map(|arr| {
                    std::iter::once(arr[row_idx]).chain(std::iter::once(arr[row_idx + 1]))
                }));
                row_idx += 2;
                assert_eq!(row_idx, num_of_line_functions_per_tuple);
               
                dst.push(F::ZERO);  
            };

            cs.set_values_with_dependencies_vararg(&inputs, &[*tag], value_fn);
        }      
    }
}


// y = /lambda * x + /mu
struct LineObject<F: SmallField> {
    lambda: Fp2<F>,
    mu: Fp2<F>,
}

impl<F: SmallField> LineObject<F> {
    fn enforce_pass_through_point<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>) {
        // q is on the line: y_q = lambda * x_q + mu
        let mut res = self.lambda.mul(cs, &mut q.x);
        res = res.add(cs, &mut self.mu);
        Fp2::enforce_equal(cs, &mut res, &mut q.y);
    }

    fn enforce_is_tangent<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>) {
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

    // enforce that line passes throught both t and q
    fn enforce_is_line_through<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>, t: &mut TwistedCurvePoint<F>) {
        self.enforce_pass_through_point(cs, q);
        self.enforce_pass_through_point(cs, t);
    }

    fn evaluate<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, p: &mut AffinePoint<F>) -> LineFunctionEvaluation<F> {
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

    fn compute_point_from_x_coordinate<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, mut x: Fp2<F>) -> TwistedCurvePoint<F> {
        // y = −µ − λ * x
        x.normalize(cs);
        let mut y = self.lambda.mul(cs, &mut x);
        y = y.add(cs, &mut self.mu);
        y = y.negated(cs);

        TwistedCurvePoint { x, y }
    }

    fn double<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>) -> TwistedCurvePoint<F> {
        //  x = λ^2 −2 * q.x and y = −µ − λ * x
        let mut lambda_squared = self.lambda.square(cs);
        let mut q_x_doubled = q.x.double(cs);
        let x = lambda_squared.sub(cs, &mut q_x_doubled);
        self.compute_point_from_x_coordinate(cs, x)
    }

    fn add<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>, t: &mut TwistedCurvePoint<F>) -> TwistedCurvePoint<F> {
        // x3 = λ^2 − x1 − x2 and y3 = −µ − λ * x3
        let mut lambda_squared = self.lambda.square(cs);
        let mut x = lambda_squared.sub(cs, &mut q.x);
        x = x.sub(cs, &mut t.x);
        self.compute_point_from_x_coordinate(cs, x)
    }

    // aggregator functions that do several steps simultaneously:
    fn double_and_eval<CS: ConstraintSystem<F>>(mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>, p: &mut AffinePoint<F>) -> LineFunctionEvaluation<F> {
        self.enforce_is_tangent(cs, q);
        *q = self.double(cs, q);
        self.evaluate(cs, p)
    }

    fn add_and_eval<CS: ConstraintSystem<F>>(
        mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>, t: &mut TwistedCurvePoint<F>, p: &mut AffinePoint<F>
    ) -> LineFunctionEvaluation<F> {
        self.enforce_is_line_through(cs, q, t);
        *q = self.add(cs, q, t);
        self.evaluate(cs, p)
    }
}


unsafe fn multipairing_robust<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    inputs: &mut [PairingInput<F>],
) {
    assert_eq!(inputs.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let params = Arc::new(RnsParams::create());
    let mut skip_pairings = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);

    static mut oracle : Oracle = Oracle::new_uninitialized();
    oracle.populate(cs, inputs, true);

    for (p, q) in inputs.iter_mut() {
        let p_is_infty = p.validate_point_robust(cs, &params);
        let q_is_infty = q.validate_point_robust(cs, &params);
        let should_skip = p_is_infty.or(cs, q_is_infty);

        p.mask(cs, should_skip, &params);
        q.mask(cs, should_skip, &params);
        skip_pairings.push(should_skip);

        p.convert_for_line_eval_form(cs);
    }

    // λ = (6u + 2) + q − q^2 +q^3
    // let f be the final result of Miller loop, certificate of the pairing to be equal to 1 looks like:
    // f = c^λ * u, where u is in Fq^3 (actually it is 27-th root of unity)
    // not that the first term of lambda is the same number as used in Miller Loop, 
    // hence if we start with f_acc = c_inv, than all doubles will be essentially for free! 
    let mut c_inv = oracle.allocate_c_inv(cs, &params);
    let mut c = c_inv.inverse(cs);
    c.normalize(cs);
    let mut root_27_of_unity = oracle.allocate_root_of_unity(cs, &params);
    
    let mut q_doubled_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());
    let mut q_negated_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.negate(cs));
    let mut t_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());

    let mut f : Fp12<F> = c_inv.clone();

    // main cycle of Miller loop:
    let iter = SIX_U_PLUS_TWO_WNAF.into_iter().rev().skip(1).identify_first_last();
    for (is_first, _is_last, bit) in iter {
        f = f.square(cs);
        
        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let line_object = oracle.allocate_next_line_object(cs, &params);
            let mut t = t_array[i].clone();
            let mut p = inputs[i].0.clone();

            let line_func_eval = line_object.double_and_eval(cs, &mut t, &mut p);
            if is_first {
                q_doubled_array[i] = t.clone();
            }
            line_func_eval.mul_into_fp12(cs, &mut f);
       
            let to_add : &mut TwistedCurvePoint<F> = if bit == -1 { &mut q_negated_array[i] } else { &mut inputs[i].1 };
            if bit == 1 || bit == -1 {
                let line_object = oracle.allocate_next_line_object(cs, &params);
                let line_func_eval = line_object.add_and_eval(cs, &mut t, to_add, &mut p);
                line_func_eval.mul_into_fp12(cs, &mut f);
            }

            t_array[i] = t;
            inputs[i].0 = p;
        }

        if bit == 1 || bit == -1 {
            let c_to_mul = if bit == 1 { &mut c_inv } else { &mut c };
            f = f.mul(cs, c_to_mul);
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

    for ((p, q), t, q_doubled) in izip!(inputs.iter_mut(), t_array.iter_mut(), q_doubled_array.iter_mut()) {
        let mut q_frob = q.clone();
        q_frob.x.c1 = q_frob.x.c1.negated(cs);
        q_frob.x = q_frob.x.mul(cs, &mut q1_mul_factor);
        q_frob.y.c1 = q_frob.y.c1.negated(cs);
        q_frob.y = q_frob.y.mul(cs, &mut xi);
        
        let mut q2 = q.clone();
        q2.x = q2.x.mul(cs, &mut q2_mul_factor);

        let mut r_pt = t.clone();

        let line_object = oracle.allocate_next_line_object(cs, &params);
        let line_eval_1 = line_object.add_and_eval(cs, t, &mut q_frob, p);
        
        let line_object = oracle.allocate_next_line_object(cs, &params);
        let line_eval_2 = line_object.add_and_eval(cs, t, &mut q2, p);
        
        line_eval_1.mul_into_fp12(cs, &mut f);
        line_eval_2.mul_into_fp12(cs, &mut f);
    
        // subgroup check for BN256 curve is of the form: twisted_frob(Q) = [6*u^2]*Q
        r_pt = r_pt.sub(cs, q_doubled);
        // r_pt.x.normalize(cs);
        // r_pt.y.normalize(cs);
        
        let mut r_pt_negated = r_pt.negate(cs);
        // r_pt_negated.x.normalize(cs);
        // r_pt_negated.y.normalize(cs);

        let mut acc = r_pt.clone();
        for bit in U_WNAF.into_iter().skip(1) {
            if bit == 0 {
                acc = acc.double(cs);
            } else {
                let to_add = if bit == 1 { &mut r_pt } else { &mut r_pt_negated };
                acc = acc.double_and_add(cs, to_add);  
            }
            acc.x.normalize(cs);
            acc.y.normalize(cs);
        } 
        TwistedCurvePoint::enforce_equal(cs, &mut acc, &mut q_frob);
    }

    // compute c^{q − q^2 + q^3} * root_27_of_unity; c^{−q^2} is just inversion
    let mut c_inv_frob_q = c_inv.frobenius_map(cs, 1);
    let mut c_inv_frob_q3 = c_inv.frobenius_map(cs, 3);
    
    f = f.mul(cs, &mut c_inv_frob_q);
    f = f.mul(cs, &mut c_inv_frob_q3);

    // on RHS would be c^{-q^2} = c_inv^{q^2}
    let mut rhs = c_inv.frobenius_map(cs, 2);
    root_27_of_unity.mul_into_fp6(cs, &mut f.c0);
    root_27_of_unity.mul_into_fp6(cs, &mut f.c1);

    // also lhs is probably multiplied by some power of Miller Loop of (G1 x G2) - we need to do the same for rhs

    // compute the total number of tuples skipped and convert this number into multiselect:
    // the most efficient way to do this is via table invocations, however the costs anyway are comparatevly small to Miller loop anyway,
    // so we just do multiselect
    let input: Vec<_> = skip_pairings.iter().map(|el| (el.get_variable(), F::ONE)).collect();
    let num_of_skipped_tuples = Num::linear_combination(cs, &input);

    let mut equality_flags = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    for idx in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
        let cur_fr = Num::allocated_constant(cs, F::from_raw_u64_unchecked(idx as u64 + 1));
        let flag = Num::equals(cs, &num_of_skipped_tuples, &cur_fr);
        equality_flags.push(flag);
    }
    
    // here we compute witness
    let g1 = prepare_g1_point(G1Affine::one());
    let g2 = G2Affine::one();
    let line_functions = prepare_all_line_functions(g2);
    let g1_mul_g2 = miller_loop_with_prepared_lines(&[g1], &[line_functions]);
   
    let mut cur_acc_witness = Fq12::one();
    let mut multiplier = allocate_fq12_constant(cs, cur_acc_witness, &params);
    for bit in equality_flags.into_iter() {
        cur_acc_witness.mul_assign(&g1_mul_g2);
        let choice = allocate_fq12_constant(cs, cur_acc_witness, &params);
        multiplier = <Fp12<F> as NonNativeField<F, _>>::conditionally_select(cs, bit, &choice, &multiplier);
    }
    rhs = rhs.mul(cs, &mut multiplier);

    Fp12::enforce_equal(cs, &mut f, &mut rhs);
}


#[derive(Clone, Copy, Debug)]
pub enum Ops {
    // first output, then inputs
    ExpByX(usize, usize), 
    Mul(usize, usize, usize),
    Square(usize, usize),
    Conj(usize, usize),
    Frob(usize, usize, usize) // the last parameter is power
}


#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Bn256HardPartMethod {
    Devegili,
    FuentesCastaneda,
    Naive
}

impl Bn256HardPartMethod {
    fn get_optinal() -> Self {
        Bn256HardPartMethod::Devegili
    }

    fn get_ops_chain(self) -> (Vec<Ops>, usize) {
        match self {
            Bn256HardPartMethod::Devegili => Self::devegili_method(),
            Bn256HardPartMethod::FuentesCastaneda => Self::fuentes_castaneda_method(),
            Bn256HardPartMethod::Naive => Self::naive_method()
        }
    }
    fn get_x_ternary_decomposition() -> &'static [i8] {
        &X_TERNARY
    }
    
    fn get_half_x_ternary_decomposition() -> &'static [i8]{
        &X_TERNARY_HALF
    }
    /// Computes the easy part of the final exponentiation for BN256 pairings:
    /// result = f^{(q^6 - 1)*(q^2 + 1)}. Using a known decomposition,
    /// it reduces to computing (-m0/m1)^{p^2+1} from the Miller loop result m = m0 + w*m1.
    /// The final returned value is in compressed toru form
    pub fn final_exp_easy_part<F: SmallField, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        mut elem: &Fp12<F>, 
        params: &Arc<BN256BaseNNFieldParams>,
        is_safe_version: bool
    ) -> (BN256TorusWrapper<F>, Boolean<F>) {

        // Need to be sure if it is technically possible to get m1 = 0
        let mut elem_clone = elem.c1.clone();
        let c1_is_zero = elem_clone.is_zero(cs);
        let one_fp6 = Fp6::<F>::one(cs, &params);
        let new_c1 = <Fp6<F> as NonNativeField<F, _>>::conditionally_select(
            cs,
            c1_is_zero,
            &one_fp6,
            &elem.c1
        );
        let elem = Fp12::<F>::new(elem.c0.clone(), new_c1);

        // -m0/m1;
        let mut tmp = elem.c1;
        tmp.normalize(cs);
        let mut m1 = tmp.inverse(cs);
        let mut encoding = elem.c0;
        encoding = encoding.mul(cs, &mut m1);
        encoding = encoding.negated(cs);

        let mut x = BN256TorusWrapper::new(encoding); 

        // x^{p^2}:
        let mut y = x.frobenius_map(cs, 2);
        let mut candidate = y.mul_optimal(cs, &mut x, true);

        let candidate_is_one = candidate.encoding.is_zero(cs);
        let candidate_is_one = candidate_is_one.negated(cs);

        let is_trivial = c1_is_zero.or(cs,  candidate_is_one);
        // If candidate is trivial or we had an exception, we should replace candidate by the hard part generator.
        // need to check is really mask from Torus return generator
        // let mut hard_part_generator = Fq6::one(); 
        // let hard_part_generator = allocate_fq6_constant(cs, hard_part_generator, &params);
        candidate = candidate.mask(cs, is_trivial);


        (candidate, is_trivial)
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
    
        // should be zero but dl zksync-crypto have a mistake so let have temporary one 
        let zero = BN256TorusWrapper::<F>::one(cs, &params);
    
        let mut scratchpad = vec![zero; num_of_variables];
        scratchpad[0] = elem.clone();
    
        for (i, (_is_first, is_last, op)) in ops_chain.into_iter().identify_first_last().enumerate() {
            let may_cause_exp = is_safe_version && is_last;
            
            match op {
                Ops::ExpByX(out_idx, in_idx) => {
                    scratchpad[out_idx] = scratchpad[in_idx].pow_naf_decomposition(cs, &x_decomposition, may_cause_exp);
                },
                Ops::Mul(out_idx, left_idx, right_idx) => {
                    // So ugly 
                    let mut left_val = scratchpad[left_idx].clone();
                    let mut right_val = scratchpad[right_idx].clone();
                    scratchpad[out_idx] = left_val.mul_optimal(cs, &mut right_val, may_cause_exp);
                },
                Ops::Square(out_idx, in_idx) => {
                    scratchpad[out_idx] = scratchpad[in_idx].square_optimal(cs, may_cause_exp);
                },
                Ops::Conj(out_idx, in_idx) => {
                    scratchpad[out_idx] = scratchpad[in_idx].conjugate(cs);
                },
                Ops::Frob(out_idx, in_idx, power) => {
                    scratchpad[out_idx] = scratchpad[in_idx].frobenius_map(cs, power);
                }
            }
        }
    
        scratchpad[0].clone()
    }

    // let x be parameter parametrizing particular curve in Bn256 family of curves
    // there are two competing agorithms for computing hard part of final exponentiation fot Bn256 family of curves
    // the first one is Devegili method which takes 3exp by x, 11 squaring, 14 muls
    // the second one is Fuentes-Castaneda methid which takes 3exp by x, 4 square, 10 muls and 3 Frobenius powers
    // we implement both of them and will select the most efficient later

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
            /*1*/ Ops::ExpByX(a, f), /*2*/ Ops::Square(b, a), /*3*/ Ops::Square(f2, f), Ops::Mul(a, b, f2), 
            /*4*/ Ops::Square(a, a), /*5*/ Ops::Mul(a, a, b),  /*6*/ Ops::Mul(a, a, f), /*7*/ Ops::Conj(a, a),
            /*8*/ Ops::Frob(b, a, 1), /*9*/ Ops::Mul(b, a, b), /*10*/ Ops::Mul(a, a, b), /*11*/ Ops::Frob(t0, f, 1),
            /*12*/ Ops::Mul(t1, t0, f), /*13*/ Ops::Square(tmp, t1), Ops::Square(tmp, tmp), Ops::Square(tmp, tmp),
            Ops::Mul(t1, tmp, t1), /*14*/ Ops::Mul(a, t1, a), /*15*/ Ops::Square(t1, f2),
            /*16*/ Ops::Mul(a, a, t1), /*17*/ Ops::Square(t0, t0), /*18*/ Ops::Mul(b, b, t0), /*19*/ Ops::Frob(t0, f, 2),
            /*20*/ Ops::Mul(b, b, t0), /*21*/ Ops::ExpByX(t0, b), /*22*/ Ops::Square(t1, t0), /*23*/ Ops::Square(t0, t1),
            /*24*/ Ops::Mul(t0, t0, t1), /*25*/ Ops::ExpByX(t0, t0), /*26*/ Ops::Mul(t0, t0, b), /*27*/ Ops::Mul(a, t0, a),
            /*28*/ Ops::Frob(t0, f, 3), /*29*/ Ops::Mul(f, t0, a)
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
            /*1*/ Ops::ExpByX(a, f), /*2*/ Ops::Square(a, a), /*3*/ Ops::Square(b, a), /*4*/ Ops::Mul(b, a, b),
            /*5*/ Ops::ExpByX(t, b), /*6*/ Ops::Conj(tmp, f), Ops::Frob(tmp, tmp, 3), Ops::Mul(f, f, tmp),
            /*7*/ Ops::Mul(f, f, t), /*8*/ Ops::Mul(b, b, t), /*9*/ Ops::Square(t, t), /*10*/ Ops::ExpByX(t, t),
            /*11*/ Ops::Mul(b, b, t), /*12*/ Ops::Conj(tmp, a), Ops::Mul(t, b, tmp), /*13*/ Ops::Frob(tmp, t, 3),
            Ops::Mul(f, f, tmp), /*14*/ Ops::Frob(tmp, t, 1),  Ops::Mul(f, f, tmp), /*15*/ Ops::Mul(f, f, b),
            /*16*/  Ops::Frob(tmp, b, 2), Ops::Mul(f, f, tmp)
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
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18);
        let ops_chain = vec![
            /*1*/ Ops::Frob(fp, f, 1), /*2*/ Ops::Frob(fp2, f, 2), /*3*/ Ops::Frob(fp3, fp2, 1), 
            /*4*/ Ops::ExpByX(fu, f), /*5*/ Ops::ExpByX(fu2, fu), /*6*/ Ops::ExpByX(fu3, fu2), 
            /*7*/ Ops::Frob(tmp, fu, 1), Ops::Conj(y3, tmp), /*8*/ Ops::Frob(fu2p, fu2, 1), 
            /*9*/ Ops::Frob(fu3p, fu3, 1), /*10*/ Ops::Frob(y2, fu2, 2), /*11*/ Ops::Mul(tmp, fp, fp2), 
            Ops::Mul(y0, tmp, fp3), /*12*/ Ops::Conj(y1, f), /*13*/ Ops::Conj(y5, fu2), /*14*/ Ops::Mul(tmp, fu, fu2p),
            Ops::Conj(y4, tmp), /*15*/ Ops::Mul(tmp, fu3, fu3p), Ops::Conj(y6, tmp), /*16*/ Ops::Square(tmp, y6), 
            Ops::Mul(tmp, tmp, y4), Ops::Mul(y6, tmp, y5), /*17*/ Ops::Mul(tmp, y3, y5), Ops::Mul(t1, tmp, y6), 
            /*18*/ Ops::Mul(y6, y2, y6), /*19*/ Ops::Square(t1, t1), /*20*/ Ops::Mul(t1, t1, y6), 
            /*21*/ Ops::Square(t1, t1), /*22*/ Ops::Mul(t0, t1, y1), /*23*/ Ops::Mul(t1, t1, y0), 
            /*24*/ Ops::Square(t0, t0), /*25*/ Ops::Mul(f, t0, t1)
        ];
        (ops_chain, 19)
    }
}


unsafe fn multipairing_naive<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    inputs: &mut [PairingInput<F>],
) -> Boolean<F> {
    assert_eq!(inputs.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let params = Arc::new(RnsParams::create());
    let mut skip_pairings = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    let mut validity_checks = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING * 3);
    
    static mut oracle : Oracle = Oracle::new_uninitialized();
    oracle.populate(cs, inputs, false);

    for (p, q) in inputs.iter_mut() {
        let p_check_flags = p.validate_point_naive(cs, &params);
        let q_check_flags = q.validate_point_naive(cs, &params);
        let should_skip = Boolean::multi_or(cs, &
            [p_check_flags.is_point_at_infty, p_check_flags.is_invalid_point, q_check_flags.is_point_at_infty, q_check_flags.is_invalid_point]
        );

        p.mask(cs, should_skip, &params);
        q.mask(cs, should_skip, &params);
        skip_pairings.push(should_skip);

        validity_checks.push(p_check_flags.is_valid_point);
        validity_checks.push(q_check_flags.is_valid_point);

        p.convert_for_line_eval_form(cs);
    }

    let mut q_doubled_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());
    let mut q_negated_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.negate(cs));
    let mut t_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());

    // do I pay constraints for zero allocation here?
    // I think, I do, but the whole codebase is awful and doesn't support it, so not my problem
    let mut f : Fp12<F> = Fp12::one(cs, &params);

    // main cycle of Miller loop:
    let iter = SIX_U_PLUS_TWO_WNAF.into_iter().rev().skip(1).identify_first_last();
    for (is_first, _is_last, bit) in iter {
        if !is_first {
            f = f.square(cs);
        }
        
        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let line_object = oracle.allocate_next_line_object(cs, &params);
            let mut t = t_array[i].clone();
            let mut p = inputs[i].0.clone();

            let line_func_eval = line_object.double_and_eval(cs, &mut t, &mut p);

            if is_first {
                q_doubled_array[i] = t.clone();
            }

            if is_first && i == 0 {
                f = line_func_eval.convert_into_fp12(cs);
            } else {
                line_func_eval.mul_into_fp12(cs, &mut f);
            }
       
            let to_add : &mut TwistedCurvePoint<F> = if bit == -1 { &mut q_negated_array[i] } else { &mut inputs[i].1 };
       
            if bit == 1 || bit == -1 {
                let line_object = oracle.allocate_next_line_object(cs, &params);
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

    for ((p, q), t, q_doubled) in izip!(inputs.iter_mut(), t_array.iter_mut(), q_doubled_array.iter_mut()) {
        let mut q_frob = q.clone();
        q_frob.x.c1 = q_frob.x.c1.negated(cs);
        q_frob.x = q_frob.x.mul(cs, &mut q1_mul_factor);
        q_frob.y.c1 = q_frob.y.c1.negated(cs);
        q_frob.y = q_frob.y.mul(cs, &mut xi);
        
        let mut q2 = q.clone();
        q2.x = q2.x.mul(cs, &mut q2_mul_factor);

        let mut r_pt = t.clone();

        let line_object = oracle.allocate_next_line_object(cs, &params);
        let line_eval_1 = line_object.add_and_eval(cs, t, &mut q_frob, p);
        
        let line_object = oracle.allocate_next_line_object(cs, &params);
        let line_eval_2 = line_object.add_and_eval(cs, t, &mut q2, p);
    
        line_eval_1.mul_into_fp12(cs, &mut f);
        line_eval_2.mul_into_fp12(cs, &mut f);
    
        // subgroup check for BN256 curve is of the form: twisted_frob(Q) = [6*u^2]*Q
        r_pt = r_pt.sub(cs, q_doubled);
        let mut r_pt_negated = r_pt.negate(cs);
        let mut acc = r_pt.clone();
        for bit in U_WNAF.into_iter().rev().skip(1) {
            if bit == 0 {
                acc = acc.double(cs);
            } else {
                let to_add = if bit == 1 { &mut r_pt } else { &mut r_pt_negated };
                acc = acc.double_and_add(cs, to_add);  
            }

            acc.x.normalize(cs);
            acc.y.normalize(cs);
        } 
        
        let g2_subgroup_check = TwistedCurvePoint::equals(cs, &mut acc, &mut q_frob);
        validity_checks.push(g2_subgroup_check);
    }

    let input: Vec<_> = skip_pairings.iter().map(|el| (el.get_variable(), F::ONE)).collect();
    let num_of_skipped_tuples = Num::linear_combination(cs, &input);

    let mut equality_flags = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    for idx in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
        let cur_fr = Num::allocated_constant(cs, F::from_raw_u64_unchecked(idx as u64 + 1));
        let flag = Num::equals(cs, &num_of_skipped_tuples, &cur_fr);
        equality_flags.push(flag);
    }
    
    // here we compute witness
    let g1 = prepare_g1_point(G1Affine::one());
    let g2 = G2Affine::one();
    let line_functions = prepare_all_line_functions(g2);
    let g1_mul_g2 = miller_loop_with_prepared_lines(&[g1], &[line_functions]).inverse().unwrap();
   
    let mut cur_acc_witness = Fq12::one();
    let mut multiplier = allocate_fq12_constant(cs, cur_acc_witness, &params);
    for bit in equality_flags.into_iter() {
        cur_acc_witness.mul_assign(&g1_mul_g2);
        let choice = allocate_fq12_constant(cs, cur_acc_witness, &params);
        multiplier = <Fp12<F> as NonNativeField<F, _>>::conditionally_select(cs, bit, &choice, &multiplier);
    }
    f = f.mul(cs, &mut multiplier);

    // here comes the final exponentiation
    // Olena, paste your code here, no need to change anything else! - f right now is the final unmasked result of Miller loop

    let (wrapped_f, is_trivial) = Bn256HardPartMethod::final_exp_easy_part(cs, &f, &params, true);
    let chain = Bn256HardPartMethod::get_optinal(); 
    let candidate = chain.final_exp_hard_part(cs, &wrapped_f, true, &params);
    
    let no_exception = Boolean::multi_and(cs, &validity_checks);
    let mut fp12_one = allocate_fq12_constant(cs, Fq12::one(), &params);
    let pairing_is_one = f.equals(cs, &mut fp12_one);
    
    // let result = pairing_is_one.and(cs, no_exception);

    // should be deleted later
    ConstantsAllocatorGate::new_to_enforce(no_exception.get_variable(), F::ONE);

    no_exception
}


use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::cs::*;
use boojum::cs::cs_builder::*;
use boojum::cs::gates::*;
use boojum::config::DevCSConfig;
use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use boojum::cs::traits::gate::GatePlacementStrategy;
use boojum::dag::CircuitResolverOpts;
use boojum::gadgets::tables::create_range_check_16_bits_table;
use boojum::gadgets::tables::RangeCheck16BitsTable;
use rand::*;
use std::alloc::Global;
use boojum::worker::Worker;
use std::env;

type F = GoldilocksField;
type P = GoldilocksField;

type Fr = <Bn256 as ScalarEngine>::Fr;

/// Creates a test constraint system for testing purposes that includes the
/// majority (even possibly unneeded) of the gates and tables.
#[test]
fn test_alternative_circuit(
) {
    //env::set_var("RUST_MIN_STACK", "100000000");
    use tests::utils::cs::create_test_cs;
    
    // let geometry = CSGeometry {
    //     num_columns_under_copy_permutation: 30,
    //     num_witness_columns: 0,
    //     num_constant_columns: 4,
    //     max_allowed_constraint_degree: 4,
    // };

    // type RCfg = <DevCSConfig as CSConfig>::ResolverConfig;
    // let builder_impl =
    //     CsReferenceImplementationBuilder::<F, F, DevCSConfig>::new(geometry, 1 << 22);
    // let builder = new_builder::<_, F>(builder_impl);

    // let builder = builder.allow_lookup(
    //     LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
    //         width: 1,
    //         num_repetitions: 10,
    //         share_table_id: true,
    //     },
    // );

    // let builder = ConstantsAllocatorGate::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = ReductionGate::<F, 4>::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = DotProductGate::<4>::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = UIntXAddGate::<16>::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = SelectionGate::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    // );
    // let builder = ZeroCheckGate::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    //     false
    // );

    // let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    // let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 26));

    // add tables
    // let table = create_range_check_16_bits_table();
    // owned_cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);
    // let cs = &mut owned_cs;

    let mut owned_cs = create_test_cs(1 << 20);
    let cs = &mut owned_cs;

    let params = RnsParams::create();
    let params = std::sync::Arc::new(params);

    //let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let g1_generator = G1::one();
    let g2_generator = G2::one();
    let mut cs_point_tuples = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    let mut rng = rand::thread_rng();

    let mut dlog_relation = Fr::zero();
    for (_is_first, is_last, _) in (0..NUM_PAIRINGS_IN_MULTIPAIRING - 1).identify_first_last() {
        let points_tuple = if !is_last {
            let mut g1_scalar = Fr::rand(&mut rng);
            let g2_scalar = Fr::rand(&mut rng);

            let mut p = g1_generator.clone();
            let mut q = g2_generator.clone();

            p.mul_assign(g1_scalar.into_repr());
            q.mul_assign(g2_scalar.into_repr());

            g1_scalar.mul_assign(&g2_scalar);
            dlog_relation.add_assign(&g1_scalar);

            let g1 = AffinePoint::allocate(cs, p.into_affine(), &params);
            let g2 = TwistedCurvePoint::allocate(cs, q.into_affine(), &params);
            (g1, g2)
        } else {
            let mut g1_scalar = Fr::rand(&mut rng);
            // g1 * g2 = -dlog_rel
            dlog_relation.negate();
            dlog_relation.mul_assign(&g1_scalar.inverse().unwrap());

            let mut p = g1_generator.clone();
            let mut q = g2_generator.clone();
            
            p.mul_assign(g1_scalar.into_repr());
            q.mul_assign(dlog_relation.into_repr());

            let g1 = AffinePoint::allocate(cs, p.into_affine(), &params);
            let g2 = TwistedCurvePoint::allocate(cs, q.into_affine(), &params);
            (g1, g2)
        };

        cs_point_tuples.push(points_tuple);
    }

    let p_point_at_infty = G1Affine::zero();
    let (x, y) = p_point_at_infty.into_xy_unchecked();
    println!("init x: {}, y: {}", x, y);
    let q = G2Affine::rand(&mut rng);

    let g1 = AffinePoint::allocate(cs, p_point_at_infty, &params);
    let g2 = TwistedCurvePoint::allocate(cs, q, &params);
    cs_point_tuples.push((g1, g2));

    unsafe {
        multipairing_robust(cs, &mut cs_point_tuples)
    };
    // let candidate_witness = candidate_acc.witness_hook(cs);

    let worker = Worker::new_with_num_threads(8);

    drop(cs);
    owned_cs.pad_and_shrink();
    let mut owned_cs = owned_cs.into_assembly::<Global>();
    assert!(owned_cs.check_if_satisfied(&worker));
    owned_cs.print_gate_stats();

    // let lines = prepare_all_line_functions(q);
    // let p_prepared = prepare_g1_point(p);
    // let actual_miller_loop_f = miller_loop_with_prepared_lines(&[p_prepared], &[lines]);

    // // unwrap candidate witness
    // let candidate_witness_wrapper = candidate_witness().unwrap();
    // let candidate_miller_loop_f = Fq12 {
    //     c0: Fq6 {
    //         c0: Fq2 { c0: candidate_witness_wrapper.0.0.0.get(), c1: candidate_witness_wrapper.0.0.1.get() },
    //         c1: Fq2 { c0: candidate_witness_wrapper.0.1.0.get(), c1: candidate_witness_wrapper.0.1.1.get() },
    //         c2: Fq2 { c0: candidate_witness_wrapper.0.2.0.get(), c1: candidate_witness_wrapper.0.2.1.get() },
    //     },
    //     c1: Fq6 {
    //         c0: Fq2 { c0: candidate_witness_wrapper.1.0.0.get(), c1: candidate_witness_wrapper.1.0.1.get() },
    //         c1: Fq2 { c0: candidate_witness_wrapper.1.1.0.get(), c1: candidate_witness_wrapper.1.1.1.get() },
    //         c2: Fq2 { c0: candidate_witness_wrapper.1.2.0.get(), c1: candidate_witness_wrapper.1.2.1.get() },
    //     },
    // };

    // assert_eq!(actual_miller_loop_f, candidate_miller_loop_f);
}

#[test]
fn test_naive_circuit(
) {
    
    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 30,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };

    type RCfg = <DevCSConfig as CSConfig>::ResolverConfig;
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, DevCSConfig>::new(geometry, 1 << 23);
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
        false
    );

    let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 26));

    // add tables
    let table = create_range_check_16_bits_table();
    owned_cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);
    let cs = &mut owned_cs;

    let params = RnsParams::create();
    let params = std::sync::Arc::new(params);

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let p = G1Affine::rand(&mut rng);
    let q = G2Affine::rand(&mut rng);
    let mut p_negated = p.clone();
    p_negated.negate();

    let g1 = AffinePoint::allocate(cs, p, &params);
    let g2 = TwistedCurvePoint::allocate(cs, q, &params);
    let g1_negated = AffinePoint::allocate(cs, p_negated, &params);

     unsafe {
        multipairing_naive(cs, &mut [(g1.clone(), g2.clone()), (g1_negated, g2.clone()), (g1, g2.clone())])
        // multipairing_naive(cs, &mut [(g1, g2.clone())])
    };


    let worker = Worker::new_with_num_threads(8);

    drop(cs);
    owned_cs.pad_and_shrink();
    let mut owned_cs = owned_cs.into_assembly::<Global>();
    assert!(owned_cs.check_if_satisfied(&worker));


}


