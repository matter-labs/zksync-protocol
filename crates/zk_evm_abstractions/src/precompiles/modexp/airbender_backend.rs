//! Modexp backend that uses the Airbender 256-bit bigint delegation circuit.
//!
//! The legacy implementation performs one 512-by-256-bit long division per
//! squaring/multiplication, which dominates its cost when run inside the
//! RISC-V proving guest. This backend removes all long division from the
//! exponentiation loop:
//!
//! * The modulus is normalized once per call: `M = m << s` so that the top
//!   bit of `M` is set, and all intermediate values are kept in the shifted
//!   domain `v' = v << s`. Since `x·2^s mod M = (x mod m)·2^s`, results
//!   translate back with a single exact right shift at the end.
//! * Each modular multiplication is a Barrett reduction with `k = 256`:
//!   `μ = ⌊2^512 / M⌋` is computed once per call (the only long division),
//!   and every reduction afterwards is two extra 256×256→512 multiplications
//!   done by the delegation circuit.
//! * Power-of-two moduli take a separate path: `mod 2^j` is plain
//!   truncation, so the whole exponentiation runs modulo `2^256` with
//!   `MulLow` delegations only and the result is masked at the end.
//!
//! The result is bit-identical to `modexp_inner`; the differential tests in
//! `tests.rs` enforce this.

use airbender_crypto::{
    bigint_op_delegation_raw, bigint_op_delegation_with_carry_bit_raw, BigIntOps,
};
use zkevm_opcode_defs::ethereum_types::{U256, U512};

/// 256-bit value in the layout the bigint delegation circuit expects:
/// little-endian `u64` limbs at a 32-byte-aligned address.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
struct Limbs([u64; 4]);

impl Limbs {
    const ONE: Self = Self([1, 0, 0, 0]);

    fn from_u256(v: U256) -> Self {
        Self(v.0)
    }

    fn to_u256(self) -> U256 {
        U256(self.0)
    }
}

fn add_assign(a: &mut Limbs, b: &Limbs) -> bool {
    unsafe { bigint_op_delegation_raw(ptr_mut(a), ptr_const(b), BigIntOps::Add) != 0 }
}

fn sub_assign(a: &mut Limbs, b: &Limbs) -> bool {
    unsafe { bigint_op_delegation_raw(ptr_mut(a), ptr_const(b), BigIntOps::Sub) != 0 }
}

fn sub_assign_with_borrow(a: &mut Limbs, b: &Limbs, borrow: bool) -> bool {
    unsafe {
        bigint_op_delegation_with_carry_bit_raw(ptr_mut(a), ptr_const(b), borrow, BigIntOps::Sub)
            != 0
    }
}

/// Low 256 bits of `a * b`.
fn mul_low(a: &Limbs, b: &Limbs) -> Limbs {
    let mut result = *a;
    unsafe {
        bigint_op_delegation_raw(ptr_mut(&mut result), ptr_const(b), BigIntOps::MulLow);
    }
    result
}

/// Full 512-bit product of `a * b` as `(low, high)`.
fn mul_wide(a: &Limbs, b: &Limbs) -> (Limbs, Limbs) {
    let mut low = *a;
    let mut high = *a;
    unsafe {
        bigint_op_delegation_raw(ptr_mut(&mut low), ptr_const(b), BigIntOps::MulLow);
        bigint_op_delegation_raw(ptr_mut(&mut high), ptr_const(b), BigIntOps::MulHigh);
    }
    (low, high)
}

fn ptr_mut(a: &mut Limbs) -> *mut () {
    (a as *mut Limbs).cast()
}

fn ptr_const(a: &Limbs) -> *const () {
    (a as *const Limbs).cast()
}

fn is_geq(a: &Limbs, b: &Limbs) -> bool {
    for i in (0..4).rev() {
        if a.0[i] != b.0[i] {
            return a.0[i] > b.0[i];
        }
    }
    true
}

/// `(low, high) >> s` of a 512-bit value, `0 <= s <= 255`.
fn shr_512(low: &Limbs, high: &Limbs, s: u32) -> (Limbs, Limbs) {
    let src = [
        low.0[0], low.0[1], low.0[2], low.0[3], high.0[0], high.0[1], high.0[2], high.0[3],
    ];
    let word = (s / 64) as usize;
    let bit = s % 64;
    let mut out = [0u64; 8];
    for (i, out_limb) in out.iter_mut().enumerate() {
        let from = i + word;
        if from < 8 {
            let mut v = src[from] >> bit;
            if bit != 0 && from + 1 < 8 {
                v |= src[from + 1] << (64 - bit);
            }
            *out_limb = v;
        }
    }
    (
        Limbs([out[0], out[1], out[2], out[3]]),
        Limbs([out[4], out[5], out[6], out[7]]),
    )
}

/// `v << s` widened to 512 bits as `(low, high)`, `0 <= s <= 255`.
fn shl_to_512(v: &Limbs, s: u32) -> (Limbs, Limbs) {
    let word = (s / 64) as usize;
    let bit = s % 64;
    let mut out = [0u64; 8];
    for i in (0..8).rev() {
        if i < word {
            continue;
        }
        let from = i - word;
        if from < 4 {
            out[i] = v.0[from] << bit;
        }
        if bit != 0 && from >= 1 && from - 1 < 4 {
            out[i] |= v.0[from - 1] >> (64 - bit);
        }
    }
    (
        Limbs([out[0], out[1], out[2], out[3]]),
        Limbs([out[4], out[5], out[6], out[7]]),
    )
}

/// Barrett reduction of a 512-bit value `y` modulo the normalized modulus
/// `m_norm` (top bit set), with `mu0 = ⌊2^512 / m_norm⌋ - 2^256`.
///
/// Requires `y < m_norm * 2^256`, which guarantees `q = ⌊y / m_norm⌋` fits
/// in 256 bits. Returns `y mod m_norm`.
fn barrett_reduce(y_low: Limbs, y_high: Limbs, m_norm: &Limbs, mu0: &Limbs) -> Limbs {
    // q1 = y >> 255 < 2^257; its bit 256 is the top bit of `y_high`.
    let (q1, q1_overflow) = shr_512(&y_low, &y_high, 255);
    let q1_high_bit = q1_overflow.0[0];
    debug_assert!(q1_high_bit <= 1 && q1_overflow.0[1..] == [0; 3]);

    // q2 = q1 * mu, where mu = 2^256 + mu0. Expanding,
    //   q2 = t_low + (t_high + q1 + q1_high_bit * mu0) * 2^256 + q1_high_bit * 2^512,
    // with (t_low, t_high) = q1_low * mu0. We only need floor(q2 / 2^257),
    // so t_low is never computed.
    let (_, t_high) = mul_wide(&q1, mu0);
    let mut mid = t_high;
    let mut high = q1_high_bit;
    high += add_assign(&mut mid, &q1) as u64;
    if q1_high_bit != 0 {
        high += add_assign(&mut mid, mu0) as u64;
    }
    // q1 < 2 * m_norm and mu <= 2^512 / m_norm give q2 < 2^513, so the part
    // of q2 above 2^512 is a single bit.
    debug_assert!(high <= 1);

    // q_hat = floor(q2 / 2^257) = high * 2^255 + (mid >> 1).
    let q_hat = Limbs([
        (mid.0[0] >> 1) | (mid.0[1] << 63),
        (mid.0[1] >> 1) | (mid.0[2] << 63),
        (mid.0[2] >> 1) | (mid.0[3] << 63),
        (mid.0[3] >> 1) | (high << 63),
    ]);

    // r = y - q_hat * m_norm; Barrett guarantees 0 <= r < 3 * m_norm.
    let (qm_low, qm_high) = mul_wide(&q_hat, m_norm);
    let mut r = y_low;
    let borrow = sub_assign(&mut r, &qm_low);
    let mut r_high = y_high;
    let underflow = sub_assign_with_borrow(&mut r_high, &qm_high, borrow);
    debug_assert!(!underflow);
    debug_assert!(r_high.0[0] <= 2 && r_high.0[1..] == [0; 3]);

    // At most two correcting subtractions.
    let mut r_extra = r_high.0[0];
    while r_extra != 0 || is_geq(&r, m_norm) {
        let borrow = sub_assign(&mut r, m_norm);
        if borrow {
            debug_assert!(r_extra > 0);
            r_extra -= 1;
        }
    }
    r
}

/// `(x * y) mod m_norm` for values in the shifted domain: `x = a << s`,
/// `y = b << s` with `a, b < m`. The product is `a·b·2^2s`; shifting right by
/// `s` (exact, the low `s` bits are zero) yields `a·b·2^s < m·m_norm`, which
/// satisfies the `barrett_reduce` precondition.
fn modmul_shifted(x: &Limbs, y: &Limbs, m_norm: &Limbs, mu0: &Limbs, s: u32) -> Limbs {
    let (p_low, p_high) = mul_wide(x, y);
    let (y_low, y_high) = shr_512(&p_low, &p_high, s);
    barrett_reduce(y_low, y_high, m_norm, mu0)
}

/// `b^e mod 2^j` for `m = 2^j`, `j >= 1`. Truncation modulo `2^256` is a ring
/// homomorphism onto `mod 2^j`, so the whole exponentiation runs on plain
/// `MulLow` and the result is masked once at the end.
fn modexp_pow2(b: U256, e: U256, m: U256) -> U256 {
    let mask = m - U256::one();
    let base = Limbs::from_u256(b);
    let mut acc = Limbs::ONE;
    for i in (0..e.bits()).rev() {
        acc = mul_low(&acc, &acc);
        if e.bit(i) {
            acc = mul_low(&acc, &base);
        }
    }
    acc.to_u256() & mask
}

fn modexp_barrett(b: U256, e: U256, m: U256) -> U256 {
    let s = 256 - m.bits() as u32;
    let m_shifted = m << s;
    let m_norm = Limbs::from_u256(m_shifted);

    // mu = ⌊2^512 / M⌋; M is not a power of two here, so ⌊(2^512 - 1) / M⌋
    // is the same value. This is the only long division in the call.
    let mu = U512::MAX / U512::from(m_shifted);
    debug_assert!(mu.0[4] == 1 && mu.0[5..] == [0; 3]);
    let mu0 = Limbs([mu.0[0], mu.0[1], mu.0[2], mu.0[3]]);

    // base' = (b mod m) << s via a Barrett reduction of b << s. The bound
    // holds: b·2^s < 2^256·2^s <= 2^256·M since 2^s <= 2^254 < M.
    let (b_low, b_high) = shl_to_512(&Limbs::from_u256(b), s);
    let base = barrett_reduce(b_low, b_high, &m_norm, &mu0);

    // acc' = 1 << s.
    let mut acc = Limbs::from_u256(U256::one() << s);

    for i in (0..e.bits()).rev() {
        acc = modmul_shifted(&acc, &acc, &m_norm, &mu0, s);
        if e.bit(i) {
            acc = modmul_shifted(&acc, &base, &m_norm, &mu0, s);
        }
    }

    acc.to_u256() >> s
}

/// Drop-in replacement for [`super::modexp_inner`] built on the bigint
/// delegation circuit. Produces bit-identical results.
pub fn modexp_delegated(b: U256, e: U256, m: U256) -> U256 {
    // Edge cases mirror `modexp_inner` exactly; see EIP-198.
    if m.is_zero() {
        return U256::zero();
    }
    if e.is_zero() {
        return if m == U256::one() {
            U256::zero()
        } else {
            U256::one()
        };
    }
    if e == U256::one() {
        return b % m;
    }
    if b.is_zero() {
        return U256::zero();
    }
    if b == U256::one() {
        return if m == U256::one() {
            U256::zero()
        } else {
            U256::one()
        };
    }

    // From here on: m >= 2, e >= 2, b >= 2.
    if (m & (m - U256::one())).is_zero() {
        modexp_pow2(b, e, m)
    } else {
        modexp_barrett(b, e, m)
    }
}
