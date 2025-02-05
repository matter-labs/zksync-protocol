use boojum::gadgets::curves::sw_projective::extended::ExtendedSWProjectivePoint;
use boojum::gadgets::curves::sw_projective::SWProjectivePoint;
use boojum::gadgets::non_native_field::implementations::{
    NonNativeFieldOverU16, NonNativeFieldOverU16Params,
};
use boojum::gadgets::tower_extension::algebraic_torus::TorusWrapper;
use boojum::gadgets::tower_extension::params::bn256::{
    BN256Extension12Params, BN256Extension2Params, BN256Extension6Params,
};
use boojum::gadgets::tower_extension::{
    fq12::Fq12 as NonNativeFq12, fq2::Fq2 as NonNativeFq2, fq6::Fq6 as NonNativeFq6,
};

// Characteristic of the base field for bn256 curve
pub use boojum::pairing::bn256::fq::Fq as BN256Fq;
// Order of group of points for bn256 curve
pub use boojum::pairing::bn256::fr::Fr as BN256Fr;

// Affine point for bn256 curve
pub use boojum::pairing::bn256::G1Affine as BN256Affine;
pub use boojum::pairing::bn256::G2Affine as BN256AffineTwisted;

// Modules for different operations on bn256 curve
pub mod ec_add;
pub mod ec_mul;
pub mod ec_pairing;
pub mod fixed_base_mul_table;
pub mod utils;
#[cfg(test)]
pub mod tests;
mod validation;

// --- Base and scalar field params for BN256 curve ---
/// Params of BN256 base field
pub type BN256BaseNNFieldParams = NonNativeFieldOverU16Params<BN256Fq, 17>;
/// Params of BN256 scalar field
pub type BN256ScalarNNFieldParams = NonNativeFieldOverU16Params<BN256Fr, 17>;
/// Non-native field over u16 for BN256 base field
pub type BN256BaseNNField<F> = NonNativeFieldOverU16<F, BN256Fq, 17>;
/// Non-native field over u16 for BN256 scalar field
pub type BN256ScalarNNField<F> = NonNativeFieldOverU16<F, BN256Fr, 17>;

// P.S. we used 17 bits since 17 bits * 16 bits in u16 = 272 bits > 254 bits
// used in BN254 (so we have some extra space to deal with)

// --- Field extensions for BN256 curve ---
/// Non-native field extension Fq2 for BN256 curve
pub type BN256Fq2NNField<F> = NonNativeFq2<F, BN256Fq, BN256BaseNNField<F>, BN256Extension2Params>;
/// Non-native field extension Fq6 for BN256 curve
pub type BN256Fq6NNField<F> = NonNativeFq6<F, BN256Fq, BN256BaseNNField<F>, BN256Extension6Params>;
/// Non-native field extension Fq12 for BN256 curve
pub type BN256Fq12NNField<F> =
    NonNativeFq12<F, BN256Fq, BN256BaseNNField<F>, BN256Extension12Params>;

// --- Torus compression types for BN256 curve ---
pub type BN256TorusWrapper<F> =
    TorusWrapper<F, BN256Fq, BN256BaseNNField<F>, BN256Extension12Params>;

// --- SW Projective points for BN256 curves: regular and twisted ---
/// SW Projective point for BN256 curve over non-extended base field
pub type BN256SWProjectivePoint<F> = SWProjectivePoint<F, BN256Affine, BN256BaseNNField<F>>;
/// SW Projective point for twisted BN256 curve over extended base field `Fp2`
pub type BN256SWProjectivePointTwisted<F> =
    ExtendedSWProjectivePoint<F, BN256Fq, BN256AffineTwisted, BN256Fq2NNField<F>>;

// --- Parameters creation functions ---
/// Returns BN254 base field parameters
pub fn bn254_base_field_params() -> BN256BaseNNFieldParams {
    NonNativeFieldOverU16Params::create()
}

/// Returns BN254 scalar field parameters
pub fn bn254_scalar_field_params() -> BN256ScalarNNFieldParams {
    NonNativeFieldOverU16Params::create()
}
