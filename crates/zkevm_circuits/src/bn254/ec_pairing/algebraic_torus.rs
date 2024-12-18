// use boojum::gadgets::non_native_field::implementations::NonNativeFieldOverU16;
// use boojum::gadgets::tower_extension::params::{TorusExtension12Params, Extension12Params};
// use boojum::{field::SmallField, gadgets::non_native_field::traits::NonNativeField};
// // use super::alternative_pairing::{Fp, Fp2, Fp6, Fp12, RnsParams};
// use std::sync::Arc;
// use boojum::cs::traits::cs::ConstraintSystem;
// use boojum::gadgets::boolean::Boolean;
// use boojum::pairing::ff::Field;
// use boojum::pairing::{ff::PrimeField, BitIterator};
// use super::alternative_pairing::{Fp6, RnsParams};
// use boojum::gadgets::tower_extension::fq6::Fq6;
// use boojum::gadgets::tower_extension::fq12::Fq12;

// pub use boojum::pairing::bn256::fq::Fq as BN256Fq;
// pub use boojum::pairing::bn256::fq12::Fq12 as BN256Fq12;
// pub use boojum::pairing::bn256::fq6::Fq6 as BN256Fq6;

// // Let k be positve number (usually taken to be the embedding degree of the curve), 
// // p - odd prime number, and q = p^(k/2), F_q^2 = F_q[w] / (w^2 - \gamma), N - is norm function of F_q^2 over F_q
// // Let G_q,2 = {m \in F_q^2 : m^{q+1} = 1} = {m = m_0 + \gamma * m_1 \in F_q^2: N(m) = m_0^2 - \gamma * m_1^2} 
// // there is a map of G_q,2 / {+1} -> algebraic Torus T_2 defined by:

// // compress: 
// // m -> (1 + m_0) / m1 if m != {+1, -1}
// // -1 -> 0

// // decompress:
// // g -> (g + w)/(g - w)

// // arithmetic in comressed form:
// // multiply(g1, g2) = (g1 * g2 + \gamma) / (g1 + g2) (not defined for m = -1 i.e. g = 0)
// // inverse(g) = -g (not defined for m = -1 i.e. g = 0)
// // square(g) = 1/2 (g + \gamma / g) (not defined for m = -1 i.e. g = 0)
// // Frob_power_map(g, i) = g^{p^i} / \gamma^({p^i-1}/2) 

// // this module implements exception-free wrapper for G_6,2 which could handle all the values including {-1, +1}
// // TODO: probably better to make it more generic and work for any field in the towes and not only for Fp12
// #[derive(Clone, Debug, Copy)]
// pub struct TorusWrapper<F, T, NN, P>
// where
//     F: SmallField,
//     T: PrimeField,
//     NN: NonNativeField<F, T>,
//     P: TorusExtension12Params<T>,
// {
//     pub encoding: Fq6<F, T, NN, P::Ex6>,
// }

// impl<F, T, P, const N: usize> TorusWrapper<F, T, NonNativeFieldOverU16<F, T, N>, P>
// where
//     F: SmallField,
//     T: PrimeField,
//     P: TorusExtension12Params<T>,
//     [(); N + 1]:,
// { 
//     pub fn get_params(
//         &self,
//     ) -> &Arc<<NonNativeFieldOverU16<F, T, N> as NonNativeField<F, T>>::Params> {
//         self.encoding.get_params()
//     }

//     pub fn mask<CS: ConstraintSystem<F>>(&self, cs: &mut CS, flag: Boolean<F>) -> Self {
//         let params = self.get_params();
//         let new_encoding = self.encoding.mask(cs, flag);
      
//         let res = Self { encoding: new_encoding };
//         res
//     }
//     // if encoding is zero replace it by some other el
//     pub fn replace_by_constant_if_trivial<CS: ConstraintSystem<F>>(
//         &mut self, cs: &mut CS, cnst: BN256Fq12
//     ) -> (Self, Boolean<F>) {
//         let params = self.get_params();
//         let is_trivial = self.encoding.is_zero(cs);
      
//         let compressed_cnst = {
//             //let mut res = c1.inverse().unwrap();
//             let mut res = cnst.c1;
//             res.mul_assign(&cnst.c0);
//             res.negate();
//             res
//         };
//         let allocated_cnst: Fq6<F, T, NonNativeFieldOverU16<F, T, N>, P::Ex6>  = Fq6::constant(cs, compressed_cnst, params);
//         let new_encoding = Fq6::conditionally_select(
//             cs, is_trivial, &allocated_cnst, &self.encoding
//         );

//         let res = Self { encoding: new_encoding };
//         (res, is_trivial)
//     }

//     pub fn new(encoding: Fq6<F, T, NonNativeFieldOverU16<F, T, N>, P::Ex6>) -> Self {
//         let res = Self { encoding };
//         res
//     }

//     pub fn compress<CS: ConstraintSystem<F>>(
//         cs: &mut CS, elem: &mut Fp12<F>, is_safe_version: bool
//     ) -> Self {
//         let params = elem.get_params();
//         let res = if is_safe_version {
//             // conversion is a bit expensive, but we are okay to pay this one-time-cost
//             let is_exceptional = Fp6::is_zero(&mut elem.c1, cs);
//             let one = Fq6::one(cs, params);
//             let c0_is_one = Fp6::equals(cs, &mut elem.c1, );
//             let c0_is_one_as_fp6 = Fp6::from_boolean(&c0_is_one, params);

//             // m -> (1 + c0 - 2 * c0_is_one) / (c1 + is_exceptional) works for all values including {+1, -1}
//             let mut num = Fp6Chain::new();
//             num.add_pos_term(&Fp6::one(params)).add_pos_term(&elem.c0).add_neg_term(&c0_is_one_as_fp6.double(cs));
//             let denom = elem.c1.add(cs, &Fp6::from_boolean(&is_exceptional, params))?;
//             let encoding = Fp6::div_with_chain(cs, num, &denom);

//             Self { encoding, value: elem.get_value() }
//         } else {
//             // m -> (1 + m_0) / m1 = g is constrained as g * m1 = 1 + m0;
//             // if m = -1, then m1 = 0, 1 + m0 = 0 and hence g would be unconstrained variable: g * 0 = 0
//             // we want to exclude this case ad hence we explicitely prove that there is no exception, i.e. m1 != 0
//             Fp6::enforce_not_equal(cs, &mut elem.c1, &mut Fp6::zero(params));
//             let tmp = elem.c0.add(cs, &Fp6::one(params));
//             let encoding = Fp6::div(cs, &tmp, &elem.c0);
//             Self { encoding, value: elem.get_value() }
//         };

//         res.debug_check_value_coherency();
//         Ok(res)
//     }

//     pub fn decompress<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Fp12 
//     {
//         let params = self.encoding.get_params();
//         let fp_6_one = Fp6::one(params);
//         let fp_6_minus_one = fp_6_one.negate(cs)?;
//         // g -> (g + w)/(g - w)
//         let mut numerator = Fp12::from_coordinates(self.encoding.clone(), fp_6_one);
//         let mut denomerator = Fp12::from_coordinates(self.encoding.clone(), fp_6_minus_one);
//         let candidate = Fp12::div(cs, &mut numerator, &mut denomerator)?;
//         Ok(candidate)
//     }

//     pub fn inverse<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Self, SynthesisError> {
//         Ok(Self { 
//             encoding: self.encoding.negate(cs)?, 
//             value: self.value.map(|x| x.inverse().unwrap())
//         })
//     }

//     pub fn conjugation<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Self, SynthesisError> {
//         // NOte: for elements on T2 conjugation coincides with inversion
//         self.inverse(cs)
//     }

//     fn compute_gamma() -> <T::Ex6 as Extension6Params<F>>::Witness {
//         let fp2_zero = <<T::Ex6 as Extension6Params<F>>::Ex2 as Extension2Params<F>>::Witness::zero();
//         let fp2_one = <<T::Ex6 as Extension6Params<F>>::Ex2 as Extension2Params<F>>::Witness::one();
//         T::Ex6::convert_to_structured_witness(fp2_zero, fp2_one, fp2_zero)
//     }

//     fn compute_w() -> T::Witness {
//         let fp6_zero = <T::Ex6 as Extension6Params<F>>::Witness::zero();
//         let fp6_one = <T::Ex6 as Extension6Params<F>>::Witness::one();
//         T::convert_to_structured_witness(fp6_zero, fp6_one)
//     }

//     pub fn mul<CS: ConstraintSystem<E>>(
//         cs: &mut CS, left: &Self, right: &Self, is_safe_version: bool
//     ) -> Result<Self, SynthesisError> {
//         let params = left.encoding.get_params();
//         let gamma = Self::compute_gamma();
//         let value = left.value.mul(&right.value);
//         let res = if is_safe_version {
//             // exceptions in case g2 = - g1
//             // modified formula looks like (here flag = exception_flag):
//             // x = g1 * g2 + \gamma
//             // g = (x - flag * x) / (g1 + g2 + flag)
//             let mut lhs = left.encoding.clone();
//             let mut rhs = Fp6::negate(&right.encoding, cs)?;
//             let exc_flag = Fp6::equals(cs, &mut lhs, &mut rhs)?;
//             let flag_as_fe = Fp6::from_boolean(&exc_flag, params);
           
//             let mut chain = Fp6Chain::new();
//             chain.add_pos_term(&Fp6::constant(gamma, params));
//             let x = Fp6::mul_with_chain(cs, &left.encoding, &right.encoding, chain)?;
//             let y = Fp6::conditionally_select(cs, &exc_flag, &x, &Fp6::zero(params))?;
//             let mut num_chain = Fp6Chain::new();
//             num_chain.add_pos_term(&x).add_neg_term(&y);

//             let mut chain = Fp6Chain::new();
//             chain.add_pos_term(&left.encoding).add_pos_term(&right.encoding).add_pos_term(&flag_as_fe);
//             let denominator = Fp6::collapse_chain(cs, chain)?;
//             let encoding = Fp6::div_with_chain(cs, num_chain, &denominator)?;
//             Self { encoding, value }
//         }
//         else {
//             // g = (g1 * g2 + \gamma) / (g1 + g2)
//             // assume that are in the exceptional case: g2 = -g1
//             // we are going to enforce relation of the form: g * 0 = g1 * g2 + \gamma
//             // unless g1 * g2 + \gamma == 0 g would be never underconstrained
//             // if g1 * g2 + \gamma = \gamma - g1^2 = 0 and hence g1 is the root of polynomial X^2 - \gamma = 0,
//             // and hence this poly is not irreducible - contradiction with F_q^2 = F_q[w] / (w^2 - \gamma)
//             // This means, we are completely safe here and no additional checks are requierd
//             let mut chain = Fp6Chain::new();
//             chain.add_pos_term(&Fp6::constant(gamma, params));
//             let numerator = Fp6::mul_with_chain(cs, &left.encoding, &right.encoding, chain)?;
//             let denominator = left.encoding.add(cs, &right.encoding)?;
//             let encoding = Fp6::div(cs, &numerator, &denominator)?;
//             Self { encoding, value }
//         };

//         res.debug_check_value_coherency();
//         Ok(res)
//     }

//     pub fn frobenius_power_map<CS>(&self, cs: &mut CS, power: usize) -> Result<Self, SynthesisError>
//     where CS: ConstraintSystem<E> 
//     {
//         // Frob_power_map(g, i) = g^{p^i} / \gamma^({p^i-1}/2)
//         // x = \gamma^({p^i-1}/2) = w^{p^i-1}
//         let params = self.encoding.get_params();
//         let numerator = self.encoding.frobenius_power_map(cs, power)?;
//         let w = Self::compute_w();
//         let cnst = {
//             let mut t = w.clone();
//             t.frobenius_map(power);
//             let w_inv = w.inverse().unwrap();
//             t.mul_assign(&w_inv);
//             let (c0, c1) = T::convert_from_structured_witness(t);
//             assert!(c1.is_zero());
//             c0.inverse().unwrap()
//         };

//         let cnst_circ = Fp6::constant(cnst, params);
//         let new_encoding = Fp6::mul(cs, &numerator, &cnst_circ)?;

//         let mut result : TorusWrapper::<E, F, T> = self.clone();
//         result.encoding = new_encoding;
//         result.value = self.value.map(|x| {
//             let mut tmp = x;
//             tmp.frobenius_map(power);
//             tmp
//         });
        
//         result.debug_check_value_coherency();
//         Ok(result)
//     } 

//     pub fn square<CS>(&mut self, cs: &mut CS, is_safe_version: bool) -> Result<Self, SynthesisError>
//     where CS: ConstraintSystem<E> {
//         let params = self.encoding.get_params();
//         let gamma = Self::compute_gamma();
//         let value = self.value.mul(&self.value);

//         // exception_free formula looks like (here flag := is_exceptional)
//         // res = 1/2 (g + [(\gamma * flag!) / (g + flag)])
//         // unsafe formula is : res = 1/2 (g + \gamma / g);
//         // we are going to do with them simultaneouly, rewriting the formula as: res = 1/2 (g + tmp)
//         // where tmp := (\gamma * flag!) / (g + flag) in the first case and tmp := \gamma / g in the second
//         let tmp = if is_safe_version {
//             let is_exceptional = Fp6::is_zero(&mut self.encoding, cs)?;
//             let denom = self.encoding.add(cs, &Fp6::from_boolean(&is_exceptional, params))?;
//             Fp6::div(cs, &Fp6::conditional_constant(gamma, &is_exceptional.not(), params), &denom)?
//         } else {
//             Fp6::div(cs, &Fp6::constant(gamma, params), &self.encoding)?
//         };

//         let res_wit = self.encoding.get_value().add(&tmp.get_value()).map(|mut x| {
//             let mut inv_2 = <<T::Ex6 as Extension6Params<F>>::Witness as Field>::one();
//             inv_2.double();
//             inv_2 = inv_2.inverse().unwrap();
//             x.mul_assign(&inv_2);
//             x
//         });
//         let encoding = if self.encoding.is_constant() && tmp.is_constant() {
//             Fp6::constant(res_wit.unwrap(), params)
//         } else {
//             let res = Fp6::alloc(cs, res_wit, params)?;
//             let mut chain = Fp6Chain::new();
//             chain.add_pos_term(&self.encoding).add_pos_term(&tmp).add_neg_term(&res.double(cs)?);
//             Fp6::enforce_chain_is_zero(cs, chain)?;
//             res
//         };

//         let res = Self { encoding, value };
//         res.debug_check_value_coherency();
//         Ok(res)
//     }

//     pub fn pow<CS: ConstraintSystem<E>>(
//         &mut self, cs: &mut CS, exp: &BigUint, decomposition: &[i64], is_safe_version: bool
//     ) -> Result<Self,SynthesisError> {
//         assert!(!exp.is_zero());
//         let mut res : TorusWrapper<'a, E, F, T> = self.clone();
//         let mut self_inv = self.conjugation(cs)?;
//         for bit in decomposition.iter().skip(1) {
//             res = res.square(cs, is_safe_version)?;
//             if *bit == 1i64 {
//                 res = Self::mul(cs, &mut res, self, is_safe_version)?;
//             }
//             if *bit == -1i64 {
//                 res = Self::mul(cs, &mut res, &mut self_inv, is_safe_version)?;
//             }
//         }
//         res.value = self.value.map(|x| x.pow(exp.to_u64_digits()));

//         res.debug_check_value_coherency();
//         Ok(res)
//     }
// }