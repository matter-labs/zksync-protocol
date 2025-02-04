
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::gadgets::num::Num;
use boojum::gadgets::queue::QueueState;
use boojum::pairing::bn256;
use cs_derive::*;
use derivative::Derivative;

use super::*;
use crate::base_structures::log_query::*;
use crate::base_structures::memory_query::*;
use crate::ethereum_types::U256;
use crate::fsm_input_output::*;
use boojum::cs::Variable;


pub mod final_exp;
pub mod implementation;
pub mod alternative_pairing;
pub mod alternative_precompile_naive;
pub mod input_alternative;

