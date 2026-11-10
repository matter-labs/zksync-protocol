#![feature(unboxed_closures)]
#![feature(fn_traits)]
// allocator_api is only exercised by the test modules (std::alloc::Global);
// gating it keeps the non-test build free of the unused-feature warning.
#![cfg_attr(test, feature(allocator_api))]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use boojum::config::CSConfig;
use boojum::config::CSSetupConfig;
use boojum::config::CSWitnessEvaluationConfig;
use boojum::cs::gates::ConstantAllocatableCS;
use boojum::cs::gates::FmaGateInBaseFieldWithoutConstant;
use boojum::cs::gates::FmaGateInBaseWithoutConstantParams;
use boojum::cs::gates::ReductionGate;
use boojum::cs::gates::ReductionGateParams;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::cs::Place;
use boojum::cs::Variable;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::CSWitnessable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u32::UInt32;

use mersenne_field::field::{Field, PrimeField};
use mersenne_field::Mersenne31Field;

use boojum::gadgets::u8::UInt8;

pub mod extension_trait;
pub mod field;
pub mod fourth_ext;
pub mod second_ext;

pub use field::MersenneField;
pub use fourth_ext::MersenneQuartic;
pub use second_ext::MersenneComplex;

pub const M31_MODULUS: u64 = Mersenne31Field::CHARACTERISTICS; // 2^31 - 1
