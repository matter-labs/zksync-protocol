use super::*;
use boojum::{
    gadgets::non_native_field::traits::NonNativeField,
    pairing::{bn256::{Fq, Fq2, Fq6, Fq12, G1Affine, G2Affine, FROBENIUS_COEFF_FQ6_C1, XI_TO_Q_MINUS_1_OVER_2}, ff::Field, GenericCurveAffine},
};
use itertools::izip;
use std::iter;


const NUM_PAIRINGS_IN_MULTIPAIRING: usize = 3;
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
    

type Fp<F> = BN256BaseNNField<F>;
type Fp2<F> = BN256Fq2NNField<F>;
type Fp6<F> = BN256Fq6NNField<F>;
type Fp12<F> = BN256Fq12NNField<F>;
type RnsParams = BN256BaseNNFieldParams;
type PairingInput<F> = (AffinePoint<F>, TwistedCurvePoint<F>);

// Curve parameter for the BN256 curve
const SIX_U_PLUS_TWO_WNAF: [i8; 65] = [
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0,
    1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0,
    0, 1, 0, 1, 1,
];

const U_WNAF : [i8; 64] =  [
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];


// todo: substitute correct value later: it is just the result of the Miller Loop of G1 x G2
// const GEMERATORS_MILLER_LOOP_RESULT : Fq12 = Fq12 {
//     c0: Fq6 { 
//         c0: Fq2 {
//             c0: Fq(FqRepr([0x974bc177a0000006, 0xf13771b2da58a367, 0x51e1a2470908122e, 0x2259d6b14729c0fa])),
//             c1: Fq(FqRepr([0x974bc177a0000006, 0xf13771b2da58a367, 0x51e1a2470908122e, 0x2259d6b14729c0fa])),
//         }, c1: (), c2: () },
//     c1: todo!(),
// }


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
    }
}


#[derive(Debug, Clone)]
struct TwistedCurvePoint<F: SmallField> {
    pub x: Fp2<F>,
    pub y: Fp2<F>
}

impl<F: SmallField> TwistedCurvePoint<F> {
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
    fn allocate<CS: ConstraintSystem<F>, O: WitnessOracle>(cs: &mut CS, oracle: &mut O, params: &Arc<RnsParams>) -> Self {
        let a = Fp2::allocate_from_witness(cs, oracle.get_fp2_witness(), params);
        let first_flag = Boolean::allocate(cs, oracle.get_bool_witness());
        let second_flag = Boolean::allocate(cs, oracle.get_bool_witness());
        let validity_check = first_flag.and(cs, second_flag);
        let zero = Boolean::allocate_constant(cs, false);
        Boolean::enforce_equal(cs, &validity_check, &zero);

        Root27OfUnity { a, first_flag, second_flag }
    }

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


trait WitnessOracle {
    fn get_fp2_witness(&mut self) -> Fq2;
    fn get_bool_witness(&mut self) -> bool;
    fn get_fp12_witness(&mut self) -> Fq12;
}

// y = /lambda * x + /mu
struct LineObject<F: SmallField> {
    lambda: Fp2<F>,
    mu: Fp2<F>,
}

impl<F: SmallField> LineObject<F> {
    fn allocate<CS: ConstraintSystem<F>, O: WitnessOracle>(cs: &mut CS, oracle: &mut O, params: &Arc<RnsParams>) -> Self {
        let lambda = Fp2::allocate_from_witness(cs, oracle.get_fp2_witness(), params);
        let mu = Fp2::allocate_from_witness(cs, oracle.get_fp2_witness(), params);
        LineObject { lambda, mu }
    } 

    fn enforce_pass_through_point<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>) {
        // q is on the line: y_q = lambda * x_q + mu
        let mut res = self.lambda.mul(cs, &mut q.x);
        res = res.add(cs, &mut self.mu);
        Fp2::enforce_equal(cs, &mut res, &mut q.y);
    }

    fn enforce_is_tangent<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS, q: &mut TwistedCurvePoint<F>) {
        // q is on the line: y_q = lambda * x_q + mu
        // line is tangent:  2 * λ * y_q = 3 * x_q
        self.enforce_pass_through_point(cs, q);
        let mut lhs = self.lambda.double(cs);
        lhs = lhs.mul(cs, &mut q.y);

        //let mut three = Fp::allocated_constant(cs, Fq::from_str("3").unwrap(), q.x.get_params());
        // let mut rhs = q.x.mul_c0(cs, &mut three);
        let mut rhs = q.x.double(cs);
        rhs = rhs.add(cs, &mut q.x);

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


fn multipairing_robust<F: SmallField, CS: ConstraintSystem<F>, O: WitnessOracle>(
    cs: &mut CS,
    inputs: &mut [PairingInput<F>],
    oracle: &mut O,
) {
    assert_eq!(inputs.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let params = Arc::new(RnsParams::create());
    let mut skip_pairings = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);

    for (p, q) in inputs.iter_mut() {
        let p_is_infty = p.validate_point_robust(cs, &params);
        let q_is_infty = q.validate_point_robust(cs, &params);
        let should_skip = p_is_infty.or(cs, q_is_infty);

        p.mask(cs, should_skip, &params);
        q.mask(cs, should_skip, &params);
        skip_pairings.push(should_skip);
    }

    // λ = (6u + 2) + q − q^2 +q^3
    // let f be the final result of Miller loop, certificate of the pairing to be equal to 1 looks like:
    // f = c^λ * u, where u is in Fq^3 (actually it is 27-th root of unity)
    // not that the first term of lambda is the same number as used in Miller Loop, 
    // hence if we start with f_acc = c_inv, than all doubles will be essentially for free! 
    let mut c = Fp12::allocate_from_witness(cs, oracle.get_fp12_witness(), &params);
    let mut c_inv = c.inverse(cs);
    let mut root_27_of_unity = Root27OfUnity::allocate(cs, oracle, &params);
    
    let mut q_doubled_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());
    let mut q_negated_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.negate(cs));
    let mut t_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());

    let mut f : Fp12<F> = c_inv.clone();

    // main cycle of Miller loop:
    let iter = SIX_U_PLUS_TWO_WNAF.into_iter().rev().skip(1).identify_first_last();
    for (is_first, _is_last, bit) in iter {
        f = f.square(cs);
        
        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let line_object = LineObject::allocate(cs, oracle, &params);
            let mut t = t_array[i].clone();
            let mut p = inputs[i].0.clone();

            let line_func_eval = line_object.double_and_eval(cs, &mut t, &mut p);

            if is_first {
                q_doubled_array[i] = t.clone();
            }
            line_func_eval.mul_into_fp12(cs, &mut f);
       
            let to_add : &mut TwistedCurvePoint<F> = if bit == -1 { &mut q_negated_array[i] } else { &mut inputs[i].1 };
            let c_to_mul = if bit == 1 { &mut c_inv } else { &mut c };
       
            if bit == 1 || bit == -1 {
                let line_object = LineObject::allocate(cs, oracle, &params);
                let line_func_eval = line_object.add_and_eval(cs, &mut t, to_add, &mut p);
                line_func_eval.mul_into_fp12(cs, &mut f);
                f = f.mul(cs, c_to_mul); 
            }

            t_array[i] = t;
            inputs[i].0 = p;
        }
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

        let line_object = LineObject::allocate(cs, oracle, &params);
        let line_eval_1 = line_object.add_and_eval(cs, t, &mut q_frob, p);
        
        let line_object = LineObject::allocate(cs, oracle, &params);
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
        } 
        TwistedCurvePoint::enforce_equal(cs, &mut acc, &mut q_frob);
    }

    // compute c^{q − q^2 + q^3} * root_27_of_unity; c^{−q^2} is just inversion
    let mut c_frob_q = c.frobenius_map(cs, 1);
    let mut c_frob_q3 = c.frobenius_map(cs, 3);

    let mut rhs = c_frob_q.mul(cs, &mut c_inv);
    rhs = rhs.mul(cs, &mut c_frob_q3);
    root_27_of_unity.mul_into_fp6(cs, &mut rhs.c0);
    root_27_of_unity.mul_into_fp6(cs, &mut rhs.c1);

    // compute the total number of tuples skipped and convert this number into multiselect:
    // the most efficient way to do this is via table invocations, however the costs anyway are comparatevly small to Miller loop anyway,
    // so we just do multiselect
    let input: Vec<_> = skip_pairings.iter().map(|el| (el.get_variable(), F::ONE)).collect();
    let num_of_skipped_tuples = Num::linear_combination(cs, &input);
    let bitmask = num_of_skipped_tuples.spread_into_bits::<_, NUM_PAIRINGS_IN_MULTIPAIRING>(cs);

    // TODO: substite correct constant witness here - which is just the Miller Loop of the product of generators of corresponding subgroups
    let g1_mul_g2 = Fq12::one();
    let mut cur_acc_witness = Fq12::one();
    let mut multiplier = allocate_fq12_constant(cs, cur_acc_witness, &params);
    for bit in bitmask.into_iter() {
        cur_acc_witness.mul_assign(&g1_mul_g2);
        let choice = allocate_fq12_constant(cs, cur_acc_witness, &params);
        multiplier = <Fp12<F> as NonNativeField<F, _>>::conditionally_select(cs, bit, &choice, &multiplier);
    }
    rhs = rhs.mul(cs, &mut multiplier);

    Fp12::enforce_equal(cs, &mut f, &mut rhs);
}


fn multipairing_naive<F: SmallField, CS: ConstraintSystem<F>, O: WitnessOracle>(
    cs: &mut CS,
    inputs: &mut [PairingInput<F>],
    oracle: &mut O,
) -> Boolean<F> {
    assert_eq!(inputs.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let params = Arc::new(RnsParams::create());
    let mut skip_pairings = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    let mut validity_checks = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING * 3);

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
    }

    let mut q_doubled_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());
    let mut q_negated_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.negate(cs));
    let mut t_array : [_; NUM_PAIRINGS_IN_MULTIPAIRING] = std::array::from_fn(|i| inputs[i].1.clone());

    // do I pay constraints for zero allocation here?
    let mut f = Fp12::<F>::zero(cs, &params);

    // main cycle of Miller loop:
    let iter = SIX_U_PLUS_TWO_WNAF.into_iter().rev().skip(1).identify_first_last();
    for (is_first, _is_last, bit) in iter {
        f = f.square(cs);
        
        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let line_object = LineObject::allocate(cs, oracle, &params);
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
                let line_object = LineObject::allocate(cs, oracle, &params);
                let line_func_eval = line_object.add_and_eval(cs, &mut t, to_add, &mut p);
                line_func_eval.mul_into_fp12(cs, &mut f);
            }

            t_array[i] = t;
            inputs[i].0 = p;
        }
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

        let line_object = LineObject::allocate(cs, oracle, &params);
        let line_eval_1 = line_object.add_and_eval(cs, t, &mut q_frob, p);
        
        let line_object = LineObject::allocate(cs, oracle, &params);
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
        } 
        
        let g2_subgroup_check = TwistedCurvePoint::equals(cs, &mut acc, &mut q_frob);
        validity_checks.push(g2_subgroup_check);
    }

    let input: Vec<_> = skip_pairings.iter().map(|el| (el.get_variable(), F::ONE)).collect();
    let num_of_skipped_tuples = Num::linear_combination(cs, &input);
    let bitmask = num_of_skipped_tuples.spread_into_bits::<_, NUM_PAIRINGS_IN_MULTIPAIRING>(cs);

    // TODO: substite correct constant witness here - which is just the Miller Loop of the product of generators of corresponding subgroups
    let g1_mul_g2 = Fq12::one();
    let mut cur_acc_witness = Fq12::one();
    let mut multiplier = allocate_fq12_constant(cs, cur_acc_witness, &params);
    for bit in bitmask.into_iter() {
        cur_acc_witness.mul_assign(&g1_mul_g2);
        let choice = allocate_fq12_constant(cs, cur_acc_witness, &params);
        multiplier = <Fp12<F> as NonNativeField<F, _>>::conditionally_select(cs, bit, &choice, &multiplier);
    }
    f = f.mul(cs, &mut multiplier);

    // here comes the finalu exponentiation
    
    let no_exception = Boolean::multi_and(cs, &validity_checks);
    let mut fp12_one = allocate_fq12_constant(cs, Fq12::one(), &params);
    let pairing_is_one = f.equals(cs, &mut fp12_one);
    
    let result = pairing_is_one.and(cs, no_exception);
    result
}




    


// // computation of the witness cerificate from the result of Miller Loop:
// fn get_certificate_witnesses(miller_loop_f: Fq12) {
//     miller_loop_f.pow(exp)
// }





//(9783115122450100638512690547982431507792126166079612669952755732980124836560*u + 11338001438479956798774934917208773767173747287567736129812394786879783479299)*y
// this is our 27_root_of_unity



// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
// base_field = GF(q)

// R.<x> = PolynomialRing(base_field)
// ext2 = base_field.extension(x^2 + 1, 'u')

// # BN256 (v^3 - ξ) where ξ = u + 9
// epsilon = ext2(x + 9)
// R.<y> = PolynomialRing(ext2)
// ext6 = ext2.extension(y^3 - epsilon, 't')

// root_of_unity = ext6(
//     (ext2(9783115122450100638512690547982431507792126166079612669952755732980124836560*x) + 
//      ext2(11338001438479956798774934917208773767173747287567736129812394786879783479299))* y
// )

// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// embedded_degree = 12


// def checked_div(nominator, denom):
//     assert(nominator % denom == 0)
//     return int(nominator / denom)

    

// h = checked_div(q^embedded_degree - 1, r)
// l = checked_div(temp, 27)
// x = 4965661367192848881
// lmbd = 6 * x + 2 + q - q^2 + q^3
// m = checked_div(lmbd, r)
// d = gcd(m, h)
// assert(d == 3)
// m_prime = checked_div(m, 3)

// r_prime = inverse_mod(r, h)
// m_prime2 = inverse_mod(m_prime, q^embedded_degree - 1)

// print(m_prime2)


// print("success")