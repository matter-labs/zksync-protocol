#!/usr/bin/env python3
"""Build the cost table from measurements.

This replaces `fit_cost_model.py`. The difference is not a refactor, it is a change
of kind: that script inferred ~30 per-operation rates by regressing whole batches,
and this one *reads* rates that were measured one operation at a time and fits only
what cannot be isolated.

The reason is that a batch-level fit cannot recover a per-operation rate. In real
traffic every feature moves with every other, so the design matrix is near-singular
and the fit is free to move cost between collinear partners: several axes came out at
exactly zero not because they were free but because a partner absorbed them. It gave
a table that was accurate in total and wrong on every axis an attacker can isolate.

So:

  MEASURED  a rate from an isolated single-axis batch, priced in a unit the cost is
            linear in. Carries the domain it was measured over.
  BOUNDED   a worst-case rate, for an operation whose cost-determining input the
            tracer cannot observe (so no exact rate is deployable) or whose cost
            varies with operands. Over-predicts by construction.
There is no third category. An axis with no measurement is ABSENT from the table and
any batch using it is declined -- see the note on UNMEASURED below. The previous version
had a `Fitted` provenance for axes inferred from organic batches; it is gone, along with
the NNLS solver and every list that tracked it, because a number a regression invented
for an axis it cannot identify is not a weaker measurement, it is a fabrication with a
plausible magnitude. The committed table showed both directions of that: six of the
eleven fitted axes came out at exactly 0 (a collinear partner absorbed the cost) and
`sha256_cycles` at 114,364 cycles per round, implausible by orders of magnitude. Every
one of them predicted the 52-batch corpus well.

The base is measured too: it is what a near-empty batch costs. Nothing here fits
anything -- this script reads literals, derives the base by subtraction, and writes
JSON. It needs no numerical libraries at all.

Usage:
    python scripts/cycle_model/build_cost_table.py \\
        --organic testdata/cycle_model/dataset.json \\
        --out crates/cycle_estimator/model/cost_table.json \\
        --guest-sha256 ... --verifier-commit ... --vm2-rev ... --measured-on 2026-08-21
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measurement import effective_cycles, feature_counts, raw_cycles  # noqa: E402

# ---------------------------------------------------------------------------
# MEASURED rates: cycles per unit, from the isolation corpus (9001xx/9002xx),
# reduced by scripts/cycle_model/derive_rates.py. Every one is a regression
# slope over three or more volume tiers with R^2 >= 0.9896 and an intercept
# reproducing the measured empty-batch baseline.
#
# Where a feature covers several opcodes the rate is the WORST member, because an
# attacker picks the shape: arith_cheap_op takes `sub` 145 over add 137 / bitwise
# 119 / jump 102, and arith_shift_op takes `shift` 376 over shift_m 287 / rotate 262.
# Both classes were confirmed homogeneous first -- a 1.4x internal spread -- which is
# the test a feature has to pass to be one feature.
# ---------------------------------------------------------------------------
MEASURED = {
    # Each rate is a family's regression slope MINUS its co-moving companions at their
    # own rates -- see derive_rates.py for why a raw slope double-charges, and for the
    # attribution asymmetry (prediction takes a cost class's dearest member, attribution
    # its cheapest, because over-subtracting a companion under-prices the target).
    #
    # Arithmetic is split by measured cost class, not opcode taxonomy, and each class
    # takes its WORST member because an attacker picks the shape: arith_cheap_op takes
    # `sub` 145 over add 137 / bitwise 119 / jump 102.
    # CONVEX AXES take their TOP-TIER marginal, not the through-range slope: an average
    # over the range under-prices the top, which is the end an attacker operates at. Inside
    # the domain the base cushions it, so the fixtures still look over-predicted -- which is
    # exactly why a through-range slope looks safe here. `transient_storage_read` and
    # `uma_read` are genuinely flat and keep their slope; convexity is a per-family
    # property, not an assumption.
    "arith_cheap_op": 145,
    "arith_shift_op": 207,
    "arith_mul_op": 852,
    # GROSS slope, not the net 287. A netted rate only transfers if the target's companion
    # mix resembles the family's: the slicing family retires 9 cheap ops per pointer op,
    # contract deployment 4.3. The net under-predicts deploy batch 900204 by 19.9% and a
    # zero rate by 23.5%. Gross >= marginal unconditionally. Batch 900204 is in the
    # adversarial fixture to hold this.
    "arith_ptr_op": 1_680,
    "average_op": 107,
    "far_call": 14_877,
    # Also gross: its net came out at -14, meaning the companions account for the whole
    # slope and attribution cannot resolve it. A near call is additionally counted into
    # `average_op` by design, so it costs 107 + 926 on the committed table.
    "near_call_count": 926,
    "event": 3_788,
    "uma_read": 475,
    "uma_write": 507,
    "transient_storage_read": 414,
    "transient_storage_write": 11_911,
    # Per 64-byte word. TWO producers, different costs: `decommit_opcode` (the DECOMMIT
    # opcode) at 7,066 and `pay_for_decommit` (every far call) at 11,124 -- a 1.56x spread
    # on the marginal.
    #
    # Do NOT naively raise this to the dearer producer; it makes both populations worse.
    # The base is the smallest batch minus its priced ops, so raising the rate lowers the
    # base, and the decommit fixtures lose more from that than they gain. A slope is not a
    # safety criterion on its own -- only the total prediction can be judged.
    #
    # The real fix is to split the feature: the tracer can attribute the stat to the
    # instruction that produced it. Needs a tracer change and a re-measurement.
    #
    # Until then the dearer producer is held by an adversarial fixture rather than by the
    # rate: `bytecode_size_26208b` (batch 900388) reaches the axis through `pay_for_decommit`
    # only, and its point estimate is already 0.4% under with the margin covering it. So a
    # widening spread shows up as a test failure instead of silently. `farcall_flood` does
    # not serve that purpose -- its callees are already decommitted, so it moves the axis by
    # 92 units.
    "decommit_cycles": 7_123,
    # Per ROUND, from sweeps that moved rounds 478x and 1,025x with the call count
    # pinned. That the round count tracks the input is what makes these measured rates
    # rather than bounds -- unlike modexp and ecmul, whose payload is flat 1 per call.
    "keccak256_cycles": 6_153,
    "sha256_cycles": 5_602,
    # Per-CALL overhead, from differencing the two keccak sweeps (sweep A's round count is
    # exactly 1 per call with constant offsets, so the difference is exact). 484 rather than
    # the reducer's 482.6 because the raw target derives 484 and `effective >= raw` must
    # hold per axis; a call dispatch does no delegated work, so their agreeing is expected.
    "precompile_call": 484,
    # Per PAIR, and measured rather than bounded because `CycleStats::EcPairing` carries
    # the pair count exactly (1.0000 per pair across an 8x pair sweep) -- unlike modexp
    # and ecmul, whose payload is a flat 1 per call. Two orthogonal sweeps agree to
    # 0.014%: 12,452,078/pair with the call count pinned at 127, and 12,453,809 with
    # calls moving 127->907, both R^2 = 1.000000. Their difference, 1,732, is the per-call
    # overhead and independently reproduces `precompile_call` above.
    #
    # This axis had NO fixture at all until now, and the previously shipped 12,448,624
    # turns out to have been right to 0.03% -- which was luck, not evidence, and is
    # exactly why it needed a fixture.
    #
    # The degenerate case (G1 = point at infinity) is 19% CHEAPER and still increments
    # the counter, so it is over-charged: the opposite shape from `ecadd`, where the
    # identity case is 12x cheaper AND the cost is charged per call. Miller-loop cost is
    # a fixed iteration count per pair regardless of the points, so there is no dearer
    # input to bound against.
    "ec_pairing_cycles": 12_452_078,
    # Storage. `storage_read` is the pure per-opcode cost, from a WARM family (repeat
    # reads of one slot) where storage_application and merkle_leaf_count stay pinned at
    # baseline -- the only shape that separates them. `storage_application` carries the
    # extra a COLD access costs, including its Merkle witness.
    "storage_read": 4_996,
    "storage_application": 183_168,
    "storage_write": 17_615,
    "state_diff_count": 90_208,
    "pubdata_bytes": 735,
    "transaction_count": 251_376,
}



# ---------------------------------------------------------------------------
# Repeat-decommit cost model, derived rather than asserted so the bound below can be
# re-checked without re-reading this comment.
#
# Measured from the three `dc_*` isolation families (four volume tiers each, R^2 >=
# 0.99994), which give cost per repeat at three bytecode sizes:
#     14,240 B -> 116,918     133,152 B -> 397,119     329,760 B -> 267,322
# The first two share the program-cache path (`World::decommit_code` re-encodes the
# code page) and set the slope; the third takes the raw path and comes out at
# 0.5579/byte, so the cache path is the worst case and the one to bound against.
# These reproduce vm2 PR #130's independent numbers (83,583 + 2.3435/byte) to three
# digits, from a separate harness -- which is also what validates the repeat detector.
REPEAT_FLAT = 83_363
REPEAT_PER_BYTE = 2.3564

# The largest bytecode a repeat can be taken against. NOT the protocol maximum
# (2,097,120 B): a contract has to be deployed before it can be decommitted, and
# publishing 2 MB of bytecode exceeds any single batch's pubdata budget, so no batch
# can ever deploy one -- the limit is what one batch's pubdata can carry, and the
# attacker is free to deploy in batch N and attack in batch N+1.
#
# ⚠️ This is therefore a claim about the pubdata budget, and it moves if that budget
# does (more blobs per batch raises it). 800 KiB is the conservative end of the
# 512-800 KiB range the blob accounting admits; re-derive it before raising the blob
# count, because this is the only input to a safety-critical bound.
# ⚠️ ONE quantity, and it is not pinned: how much pubdata one batch can carry. The blob
# accounting admits somewhere in 512-800 KiB depending on blobs per batch, and this file
# used to carry both ends as if they were different quantities (819,232 for the repeat
# bound, 500,000 for the domain caps), which is how a contradiction hides.
#
# Until it is sourced from the actual blob config, each site uses the end that is
# CONSERVATIVE for it: the upper end where a larger value makes a bound safer, the lower
# end where a smaller value keeps a domain from admitting more than it should.
PUBDATA_CAP_LOW = 500_000
PUBDATA_CAP_HIGH = 819_200

# The largest bytecode a repeat can be taken against -- upper end, because under-stating it
# would under-state the bound. 25,601 words: bytecode is an odd number of 32-byte words.
# Derived, not repeated: bytecode is an odd number of 32-byte words, so round the
# upper cap up to the next odd word count. Revising PUBDATA_CAP_HIGH now moves this.
MAX_DEPLOYABLE_BYTECODE = ((PUBDATA_CAP_HIGH // 32) | 1) * 32

# ---------------------------------------------------------------------------
# BOUNDED rates: the cost-determining input is not observable through the tracer, so
# no exact rate can be deployed at any level of modelling effort. Each is the worst
# case over the inputs an attacker can choose.
#
# ⚠️ These entries deliberately carry NO domain (see where domains are computed), and that
# has a consequence beyond accuracy: a domain-free entry never extrapolates, so a BOUNDED
# axis is the only kind that can carry a *trusted* estimate up to the consumer's budget.
# Every measured axis trips its domain first -- all of them together at 1.8x domain reach
# 0.61 of the ceiling. So the reject branch is bounded-axis-only, and a bound over-charges
# by however far the true cost sits below it: `arith_div_op` refuses a transaction at
# ~3.17M divisions, which at the cheapest measured shape (1,162/div) truly costs 7.0% of
# the ceiling.
#
# Giving the axis a domain looks like the fix and is not: distrust means IncludeAndSeal in
# the deployed consumer, so the WORST-shape flood -- the one that genuinely exceeds 2^36 --
# would then be admitted and sealed. Refusing an honest transaction costs its sender;
# admitting that one costs the chain a batch it cannot prove. The gap closes only when the
# operand shape becomes observable (price per quotient digit), which needs a vm2 change:
# a `Tracer` cannot see an instruction's operands.
#
# `crates/cycle_estimator/tests/gate_reachability.rs` asserts all of the above, including
# which bounds are reachable at all -- the five crypto ones are gated by
# `precompile_call`'s domain, because their payload is one unit per call.
# ---------------------------------------------------------------------------
BOUNDED = {
    # Operand-dependent, and the operands are gone by the time a count is recorded, so a
    # bound is the only possible form. Five divisor shapes measured from one harness
    # (900390-900404), all R^2 = 1.000000, net of 8 harness cheap-ops per division:
    #
    #     4-limb dividend / 4-limb divisor        5,984   (1 quotient digit)
    #     4 / 3-limb                             10,836
    #     4 / 2-limb, leading limb 1             11,158
    #     4 / 1-limb ("small divisor")           13,103   (4 quotient digits)
    #     4 / 2-limb, leading limb 3, shift 62   14,658   <- worst
    #
    # Cost tracks QUOTIENT DIGITS (dividend limbs - divisor limbs + 1), which is why a
    # small divisor is near the worst rather than the fast path. An earlier table shipped a
    # "fast path" of 1,173 from a family that must also have had a small dividend; against a
    # full-width dividend there is no cheap regime.
    #
    # Takes the worst family's GROSS slope. This is the only axis that alone breaches the
    # proving ceiling, so it takes the provably-upper value: the harness cheap-ops are
    # charged separately, so gross double-counts them, and gross >= marginal always.
    #
    # ⚠️ The previous 7,711 was **1.90x too low** and under-predicted these fixtures by 67%,
    # far outside the margin. It came from `div_worst2`, a second attempt after `div_worst`
    # (900162-165) died: a 256-bit seed made `div(K,v)` return 0 and the divide-by-zero guard
    # short-circuited every later div. This family cannot degenerate -- the divisor is a
    # constant parameter and the dividend is re-seeded from a counter, and the driver aborts
    # if `arith_div_op < n` or the in-loop non-zero count disagrees.
    #
    # Reach: 54 ergs/div in this harness, so 500M ergs buys 9.26M divisions = 1.98x the
    # ceiling at this rate. That is a FLOOR on the reach: 54 includes the harness bookkeeping
    # a real attack would not carry.
    "arith_div_op": 15_474,
    # A REPEAT decommit does O(len) work for refunded ergs and no counter reports the
    # length, so this is a per-call bound at the largest deployable bytecode.
    #
    # It must be >= the true worst case, not merely large: with bound B and true cost T, M
    # repeats predict M*B and cost M*T, so any B < T opens a window ceiling/T < M <
    # ceiling/B in which the gate accepts an unprovable batch.
    #
    # Only the DECOMMIT opcode is affected: the far-call path goes through
    # `World::decommit`, whose repeat case is a program_cache hit plus an Arc clone, O(1),
    # while the opcode path re-encodes the code page. That asymmetry is why `far_call` can
    # stay a flat measured rate. vm2 PR #130 removes the dead work entirely.
    "decommit_repeat": REPEAT_FLAT + REPEAT_PER_BYTE * MAX_DEPLOYABLE_BYTECODE,
    # Precompiles. vm2 reports each through `CycleStats::X(cycles)`, and for MODEXP and
    # ECMUL that value is a flat 1 per call -- so the input that sets the cost never reaches
    # the feature vector, and the erg price is flat too. An attacker buys the expensive
    # input at the cheap input's price, and a bound is the only possible form for those two.
    #
    # Calibrated against an INPUT sweep (9003xx), not just a volume sweep: the previous
    # entries were taken at one arbitrary input each and were bounds in name only --
    # `mod_exp` 9.77x under its worst case, `ec_mul` 2.49x.
    #
    # modexp and ecmul take the measured worst directly (bit length IS the cost axis and
    # 256/254 bits is the maximum either accepts, so the sweep is exhaustive). ecadd,
    # ecrecover and secp256r1 are input-independent within 1.5%, but their input space was
    # SAMPLED rather than exhausted, hence the 1.10x uplift.
    "mod_exp_cycles": 228_241,
    "ec_mul_cycles": 683_591,
    "ec_add_cycles": int(53_560 * 1.10),
    "ec_recover_cycles": int(466_954 * 1.10),
    "secp256r1_verify_cycles": int(738_043 * 1.10),
}


# ---------------------------------------------------------------------------
# Axes that exist in the feature schema and have NO rate.
#
# They are recorded here, and deliberately NOT written into the table: an absent entry
# makes `untrusted_pricing` decline any batch that uses the axis, whereas a placeholder
# number would be silently believed. That is the whole difference, and it is why the
# `Fitted` provenance was removed rather than renamed.
#
# Be clear about what this costs. These eleven carry ~19.6% of a typical batch's
# predicted total (max 25.9%), and every real batch touches several of them, so **while
# this list is non-empty the table declines every batch and there is no usable gate.**
# That is intended pressure, not an oversight: the previous state was a gate that
# accepted batches using numbers like `storage_read = 0`.
#
# Each entry says what closes it. Removing an entry means a rate moved into MEASURED or
# BOUNDED above.
UNMEASURED = {}


# Not priced at all, deliberately -- an absence that is CORRECT, so a batch using one
# is not declined. Distinct from a missing rate, and the distinction is load-bearing.
#
#   decommit           counts fresh and repeat decommits together, and both halves are
#                      already priced (fresh per 64-byte unit by `decommit_cycles`,
#                      repeat per call by `decommit_repeat`). Charging the total too
#                      would double-charge. It stays in the schema because the tracer
#                      emits it and `decommit_repeat` is derived from it.
#   merkle_leaf_count  its witness cost is charged through `storage_application`, which
#                      it never exceeds: a witnessed leaf requires a cold access, so
#                      merkle <= storage_application structurally, and the measured
#                      maximum of the ratio is 0.9997 across 123 batches. Pricing both
#                      would double-charge the witness.
UNPRICED = ["decommit", "merkle_leaf_count"]

# ---------------------------------------------------------------------------
# RAW main-trace cycles per unit -- the same axes against a different target.
#
# `effective` folds in delegation weights with no authoritative source in this tree
# (`native_cost_conversion.md` implies ~40 against the shipped 16/4/4), so `raw` -- what the
# prover reports directly -- is the only prediction an operator can check. The delegation
# share is far from uniform across axes, so a weight revision re-ranks the table rather than
# scaling it; that is why both are carried instead of one derived from the other.
RAW = {
    "arith_cheap_op": 145,
    "arith_div_op": 7_711,
    "arith_mul_op": 852,
    "arith_ptr_op": 1_680,
    "arith_shift_op": 207,
    "average_op": 107,
    "decommit_cycles": 7_123,
    "decommit_repeat": 2_013_801,
    "ec_add_cycles": 51_670,
    "ec_mul_cycles": 542_836,
    "ec_pairing_cycles": 9_921_775,
    "ec_recover_cycles": 303_871,
    "event": 3_788,
    "far_call": 14_877,
    "keccak256_cycles": 3_556,
    "mod_exp_cycles": 201_820,
    "near_call_count": 926,
    "precompile_call": 484,
    "pubdata_bytes": 482,
    "secp256r1_verify_cycles": 470_991,
    "sha256_cycles": 5_599,
    "state_diff_count": 81_495,
    "storage_application": 142_048,
    "storage_read": 4_996,
    "storage_write": 17_612,
    "transaction_count": 70_446,
    "transient_storage_read": 414,
    "transient_storage_write": 11_911,
    "uma_read": 475,
    "uma_write": 507,
}

# Axes exempt from the raw+channels reconstruction check, with why. Each is a confounded
# CHANNEL rate, not a suspect effective rate -- the channel derivation hits the same
# collinearity the rate derivation does, and for these axes it loses.
RECONSTRUCTION_EXCEPTIONS = {
    "precompile_call": "its keccak-channel rate absorbs the rounds it co-moves with in the "
                       "keccak-calls family, so the reconstruction comes out ~6x high",
    "pubdata_bytes": "deliberately the top-tier marginal, not the through-range slope",
    "transaction_count": "channel rates over-attribute; the tx family moves every channel",
    "storage_write": "keccak channel picks up the mapping harness's hashing",
    "state_diff_count": "same as storage_write, milder",
    "decommit_cycles": "the raw target's class max is the FAR-CALL producer (11,124) while "
                       "the shipped effective is the DECOMMIT-opcode one (7,123). Not a "
                       "vintage mismatch -- a deliberate producer choice, see the literal. "
                       "It resolves when the feature is split.",
}

# MEASURED literals that deliberately depart from derive_rates.py's fixed point, with the
# reason. Anything not listed here must reproduce, or the build fails.
# Only entries that are actually live belong here. Four were dead: `arith_ptr_op` and
# `near_call_count` reproduce without an override (the gross fallback in derive_rates.py
# makes the reducer's answer the gross slope), and listing them would have MASKED that
# fallback breaking; `decommit_cycles` and `ec_pairing_cycles` have no family the reducer
# groups, so the check skips them before the override is consulted.
DELIBERATE_OVERRIDES = {
    "pubdata_bytes": "top-tier marginal, not the through-range slope (convex axis)",
    "transient_storage_write": "top-tier marginal (convex axis)",
    "uma_write": "top-tier marginal (convex axis)",
    "arith_div_op": "the worst shape's GROSS slope (15,474) rather than its net (14,658). "
                    "This is the only axis that alone breaches the ceiling, so it takes "
                    "the provably-upper value.",
    "decommit_cycles": "the DECOMMIT-opcode producer (7,123) rather than the far-call one "
                       "(11,124) the reducer now picks as the class max. Raising it makes "
                       "BOTH populations worse via the base -- see the note on the literal. "
                       "The real fix is to split the feature.",
}

# Hard protocol caps, for axes the protocol itself bounds. Where the cost at the cap
# cannot reach the proving ceiling, the axis is provably harmless at ANY reachable count,
# and the calibrated domain should be the cap rather than what the corpus happened to
# contain.
#
# Otherwise the domain check costs liveness for no safety benefit, and the numbers are not
# marginal: `transaction_count` reaches 0.093x of the ceiling at MAX_TXS_IN_BATCH, yet a
# domain derived from 416 observed txs declines anything above 748. Every legitimate batch
# between 748 and 10,000 transactions would be refused -- and since the deployed consumer
# answers distrust with IncludeAndSeal, refused means the gate contributes nothing while
# looking like it works.
#
# Only list an axis here when cost x cap < 2^36. That is checked below, so a rate rising
# enough to make a capped axis dangerous turns into a build failure rather than a silently
# widened domain.
PROTOCOL_CAPS = {
    "transaction_count": (10_000, "MAX_TXS_IN_BATCH"),
    # Lower end here: a cap is only a licence to widen a domain, so understating it is the
    # safe direction.
    "pubdata_bytes": (PUBDATA_CAP_LOW, "batch pubdata cap, conservative end"),
    "state_diff_count": (PUBDATA_CAP_LOW // 37, "pubdata cap / 37 B per state diff"),
}

CEILING = 2**36  # MAX_NUMBER_OF_CYCLES, zksync-airbender cs/src/definitions/constants.rs
# DOMAIN_SLACK in model.rs, where it is now `pub` so the Rust side can stop duplicating it
# too. Still transcribed here -- this script does not link against the crate -- but there is
# one authority for it, and gate_reachability.rs reads that one rather than a copy.
SLACK = 1.8

# ---------------------------------------------------------------------------
# ⚠️ THE BASE IS PROTOCOL-VERSION SPECIFIC. It is the smallest batch in the corpus, which
# is v31, and v31's bootloader does per-batch work v29's does not (interop roots). Being
# per-batch it lands here rather than on any feature: the gap is ~302M cycles, 4.5% of a
# batch, and it is why v29 traffic is over-predicted ~4.5%.
#
# Correct for the deployed gate, which runs on v31. But re-derive the base from a batch of
# the version being gated, never from whichever happens to be smallest -- and note the
# organic error is therefore measured mostly against the wrong version.


def measured_base(rows, rates=None):
    """The base is measured, not fitted: it is what the smallest batch in the corpus
    costs once its own priced operations are subtracted. Fitting an intercept invites
    it to absorb whatever the rates got wrong, which is how a large constant ends up
    flattering an R^2."""
    target = raw_cycles if rates is not None else effective_cycles
    rates = rates if rates is not None else {**MEASURED, **BOUNDED}
    best = min(rows, key=target)
    f = feature_counts(best)
    return target(best) - sum(r * f.get(k, 0) for k, r in rates.items()), best["batch_number"]



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--organic", required=True, help="measured organic dataset.json")
    ap.add_argument("--isolation",
                    help="measured isolation dataset.json. Used ONLY for axes that organic "
                         "traffic never exercises, where there is no real-traffic evidence "
                         "to draw a domain from and the alternative is declining every "
                         "batch that uses the axis. `ec_pairing_cycles` is the case in "
                         "point. It deliberately does NOT widen a domain that organic "
                         "traffic already sets -- see the note where domains are computed.")
    ap.add_argument("--out", required=True)
    # A one-sided tolerance bound on the 40 held-out synthetic batches -- the only
    # population that answers "how wrong is this on a shape it was not calibrated on".
    # Upper-tail fit gives 1.0955 at 99.9% coverage / 95% confidence. The observed maximum
    # (1.0807) is NOT a high-confidence bound: with n=40 it covers the 99th percentile at
    # 33% confidence. 1.30 is the pessimistic symmetric fit, affordable because real batches
    # run at 9.8-13.0% of the ceiling, so any margin below 7.4x refuses nothing.
    #
    # ⚠️ A margin covers model error on a PRICED axis. It cannot cover a rate that is simply
    # wrong, nor guest drift. Full derivation in the README.
    ap.add_argument("--margin", type=float, default=1.30)

    ap.add_argument("--guest-sha256")
    ap.add_argument("--verifier-commit")
    ap.add_argument("--vm2-rev")
    ap.add_argument("--measured-on")
    ap.add_argument("--corpus")
    ap.add_argument("--check-reconstruction", nargs=4, metavar=("RAW", "BLAKE2", "BIGINT", "KECCAK"),
                    help="four derive_rates.py --emit files. Checks per axis that "
                         "effective ~= raw + 16*blake2 + 4*bigint + 4*keccak.")
    ap.add_argument("--check-rates", metavar="JSON",
                    help="a derive_rates.py --emit file. Every MEASURED literal is checked "
                         "against the reducer's own answer and a drift beyond tolerance is "
                         "an error, unless the axis is listed in DELIBERATE_OVERRIDES.")
    args = ap.parse_args()

    overlap = set(MEASURED) & set(BOUNDED)
    if overlap:
        raise SystemExit(f"ERROR: {sorted(overlap)} are both MEASURED and BOUNDED")
    stray = (set(UNMEASURED) | set(UNPRICED)) & (set(MEASURED) | set(BOUNDED))
    if stray:
        raise SystemExit(
            f"ERROR: {sorted(stray)} have a rate but are also listed as unmeasured or "
            f"deliberately unpriced. A closed gap must be removed from those lists, "
            f"otherwise the table claims a rate the estimator will not trust."
        )

    missing_raw = sorted((set(MEASURED) | set(BOUNDED)) - set(RAW))
    if missing_raw:
        raise SystemExit(
            f"ERROR: {missing_raw} have an effective rate but no RAW rate. Both targets "
            f"must be complete: a consumer comparing a partial raw prediction against the "
            f"prover's actual would read the gap as model error."
        )
    # A table with no provenance cannot be checked against the guest it prices, and the
    # runbook claimed this was already refused when it was not.
    stamp = {"guest-sha256": args.guest_sha256, "verifier-commit": args.verifier_commit,
             "vm2-rev": args.vm2_rev, "measured-on": args.measured_on}
    unstamped = sorted(k for k, v in stamp.items() if not v)
    if unstamped:
        raise SystemExit(
            f"ERROR: refusing to write an unstamped table; missing "
            f"{', '.join('--' + k for k in unstamped)}. Without the stamp nothing "
            f"downstream can tell whether this table still describes the guest it gates."
        )

    # `effective = raw + weighted delegations` with every weight positive, so a per-axis
    # raw above effective is arithmetically impossible and means the two literals came
    # from different vintages. `storage_write` shipped that way (16,222 effective against
    # 17,612 raw); the corpus-total test could not see it because the base gap hid it.
    inverted = [k for k in set(MEASURED) | set(BOUNDED)
                if RAW.get(k, 0) > {**MEASURED, **BOUNDED}[k]]
    if inverted:
        raise SystemExit(
            f"ERROR: {sorted(inverted)} have a RAW rate above their effective rate. "
            f"effective = raw + weighted delegations and every weight is positive, so "
            f"this cannot be measured -- the two literals are from different vintages."
        )
    # The literals in MEASURED are meant to be the reducer's output, transcribed so that a
    # rate change is a reviewable diff. Transcription drifts: five of them were from earlier
    # vintages of the fixed point, one (`storage_write`) below its own raw rate. This makes
    # the drift an error instead of a silent divergence, while keeping the literals
    # reviewable. Deliberate departures must be named.
    if args.check_rates:
        derived = json.loads(Path(args.check_rates).read_text())["rates"]
        drift = []
        for k, v in sorted({**MEASURED, **BOUNDED}.items()):
            d = derived.get(k)
            if d is None or k in DELIBERATE_OVERRIDES:
                continue
            if abs(v - d) > max(1.0, 0.005 * d):
                drift.append(f"    {k:<26} literal {v:>14,} vs reducer {d:>14,.1f}")
        if drift:
            raise SystemExit(
                "ERROR: MEASURED literals have drifted from derive_rates.py's own output:\n"
                + "\n".join(drift)
                + "\n  Re-transcribe them, or add the axis to DELIBERATE_OVERRIDES with the "
                  "reason.\n  A literal nobody can reproduce is the thing this pipeline "
                  "exists to prevent."
            )
        gated = sum(1 for k in {**MEASURED, **BOUNDED}
                    if k in derived and k not in DELIBERATE_OVERRIDES)
        print(f"  {gated} of {len(MEASURED) + len(BOUNDED)} rate literals reproduce from "
              f"{args.check_rates}; the rest have no family the reducer groups")

    # `effective = raw + 16*blake2 + 4*bigint + 4*keccak` is an identity, so deriving all
    # four targets independently gives a real cross-check on the two rate dicts: they were
    # transcribed separately and drifted before (`storage_write` shipped an effective rate
    # BELOW its raw one). 17 of the 22 family-derived axes reconstruct within 5%, and
    # `keccak256_cycles` to 0.05% -- which is what makes the disagreements meaningful.
    #
    # It is a check and not a replacement, deliberately. The channel rates inherit the same
    # attribution confounding as any other: in the keccak-calls family `precompile_call` and
    # the keccak rounds move together, so that axis's keccak-channel rate absorbs the rounds
    # and the reconstruction comes out 6x high. Adopting reconstruction wholesale would
    # import those artifacts.
    if args.check_reconstruction:
        raw_f, bl_f, bi_f, kc_f = (json.loads(Path(f).read_text())
                                   for f in args.check_reconstruction)
        off = []
        for k, r in sorted(raw_f["rates"].items()):
            if k in RECONSTRUCTION_EXCEPTIONS or k not in MEASURED:
                continue
            recon = (r + 16 * bl_f["rates"].get(k, 0.0)
                     + 4 * bi_f["rates"].get(k, 0.0) + 4 * kc_f["rates"].get(k, 0.0))
            if recon <= 0:
                continue
            ratio = MEASURED[k] / recon
            if not 0.95 <= ratio <= 1.10:
                off.append(f"    {k:<26} effective {MEASURED[k]:>12,} vs "
                           f"raw+channels {recon:>12,.0f}  ratio {ratio:.3f}")
        if off:
            raise SystemExit(
                "ERROR: these axes do not reconstruct from raw + weighted delegations:\n"
                + "\n".join(off)
                + "\n  effective = raw + 16*blake2 + 4*bigint + 4*keccak is an identity, so "
                  "a\n  disagreement means the two rate dicts are from different vintages, "
                  "or a\n  channel rate is confounded. Add the axis to "
                  "RECONSTRUCTION_EXCEPTIONS with the reason\n  only once you have "
                  "established which."
            )
        print(f"  effective reconstructs from raw + delegation channels on "
              f"{len(raw_f['rates']) - len(RECONSTRUCTION_EXCEPTIONS)} axes")

    rows = json.loads(Path(args.organic).read_text())
    base, base_batch = measured_base(rows)
    raw_base = measured_base(rows, RAW)[0]

    # Domains: the largest count each rate was calibrated over, across BOTH corpora --
    # organic traffic keeps it honest for axes whose isolation family was smaller than
    # real batches, and the isolation corpus supplies the axes real traffic never
    # exercises at all. BOUNDED entries carry no domain: a bound holds outside the range
    # it was taken over, which is the point of it -- and, less obviously, it is what makes
    # a bounded axis the only route to the consumer's budget. That is a deliberate trade
    # with a liveness price on it; the note above BOUNDED has the argument and
    # gate_reachability.rs has the assertions.
    # A domain must describe REAL traffic, not the synthetic floods used to measure
    # rates. Taking the maximum over both corpora looks harmless and is not: the
    # isolation fixtures are deliberately extreme single-axis batches, so widening a
    # domain to include them sets the trip point at the attack shape itself. It measurably
    # broke the guard -- `near_call_count`'s domain went from 174,463 (organic) to 780,292
    # (its own flood fixture), which moved the frame-churn trip point from 314k to 1.40M
    # against the ~1.68M iterations that reach the ceiling: headroom 5.3x -> 1.19x. It also
    # made all 30 adversarial fixtures fall inside their own domains, so the domain half of
    # the safety test could no longer fire at all.
    #
    # So domains come from organic traffic, plus a protocol cap where the cap is provably
    # safe. The one exception is an axis real traffic never exercises: there is no organic
    # evidence to draw on, and the alternative is declining every batch that uses it, so it
    # falls back to the isolation maximum. Those are listed explicitly at the end of the
    # build rather than blended in silently.
    organic_max = {}
    for r in rows:
        for k, v in feature_counts(r).items():
            organic_max[k] = max(organic_max.get(k, 0), v)
    iso_only = {}
    if args.isolation:
        for r in json.loads(Path(args.isolation).read_text()):
            for k, v in feature_counts(r).items():
                if not organic_max.get(k):
                    iso_only[k] = max(iso_only.get(k, 0), v)

    ops = {}
    for k, v in MEASURED.items():
        domain = int(organic_max.get(k, 0)) or int(iso_only.get(k, 0)) or None
        if k in PROTOCOL_CAPS:
            cap, src = PROTOCOL_CAPS[k]
            reach = v * cap / CEILING
            if reach >= 1.0:
                raise SystemExit(
                    f"ERROR: {k} is listed in PROTOCOL_CAPS but reaches {reach:.2f}x the "
                    f"proving ceiling at its cap of {cap:,} ({src}). The cap no longer "
                    f"makes it harmless, so its domain must NOT be widened to the cap -- "
                    f"remove it from PROTOCOL_CAPS."
                )
            domain = max(domain or 0, cap)
        ops[k] = {"cycles_per_unit": float(v), "kind": "measured", "domain_max": domain,
                  "raw_cycles_per_unit": float(RAW[k])}
    for k, v in BOUNDED.items():
        ops[k] = {"cycles_per_unit": float(v), "kind": "bounded",
                  "raw_cycles_per_unit": float(RAW[k])}

    table = {
        # No `kind` here: the base is measured by construction (smallest batch minus its
        # own priced ops) and nothing ever read the field.
        "base": {"cycles": float(base), "raw_cycles": float(raw_base)},
        "ops": {k: ops[k] for k in sorted(ops)},
        # Emitted so the estimator can tell a correct absence from a missing rate
        # without hard-coding the list on the Rust side.
        "unpriced": sorted(UNPRICED),
        "margin": args.margin,
        "provenance": {
            "guest_sha256": args.guest_sha256,
            "verifier_commit": args.verifier_commit,
            "vm2_rev": args.vm2_rev,
            "measured_on": args.measured_on,
            "corpus": args.corpus,
        },
    }
    Path(args.out).write_text(json.dumps(table, indent=2) + "\n")

    print(f"Wrote {args.out}")
    print(f"  base {base:,.0f} measured from batch {base_batch} (smallest in corpus)")
    print(f"  {len(MEASURED)} measured + {len(BOUNDED)} bounded = {len(ops)} priced ops")
    if iso_only:
        print(f"  ⚠️  domains taken from the ISOLATION corpus, for axes organic traffic "
              f"never exercises:")
        for k in sorted(iso_only):
            if k in ops:
                print(f"        {k:<24} domain {iso_only[k]:>10,}  (no organic evidence; "
                      f"the alternative is declining every batch that uses it)")
    for k, (cap, src) in sorted(PROTOCOL_CAPS.items()):
        if k in ops:
            print(f"  domain of {k} widened to its protocol cap {cap:,} ({src}); "
                  f"reaches {MEASURED[k] * cap / CEILING:.3f}x of the ceiling there")

    if UNMEASURED:
        print(f"  ⚠️  {len(UNMEASURED)} axes have NO rate, so every batch using one is "
              f"DECLINED:")
        for k in sorted(UNMEASURED):
            seen = max((feature_counts(r).get(k, 0) for r in rows), default=0)
            print(f"        {k:<24} up to {seen:>12,} per batch")
        print("      Until this list is empty there is no usable gate. That is the "
              "point: the\n      alternative was a gate trusting invented numbers "
              "like storage_read = 0.")
    else:
        print("  every axis in the schema is measured, bounded, or deliberately "
              "unpriced")

    # Accuracy over the corpus. Reported, never asserted here: while UNMEASURED is
    # non-empty this is the error of an INCOMPLETE table, so it says nothing about the
    # rates that ARE present. Note which way it errs -- the missing axes make it
    # under-predict, the unsafe direction, which is why those batches are declined
    # rather than merely flagged.
    errs = []
    for r in rows:
        f = feature_counts(r)
        pred = base + sum(e["cycles_per_unit"] * f.get(k, 0) for k, e in ops.items())
        a = effective_cycles(r)
        errs.append(100 * (pred - a) / a)
    label = "INCOMPLETE table" if UNMEASURED else "organic error"
    print(f"  {label}: MAPE {sum(abs(e) for e in errs)/len(errs):.2f}%  "
          f"min {min(errs):+.2f}%  max {max(errs):+.2f}%  "
          f"under {sum(1 for e in errs if e < 0)}/{len(errs)}")
    if UNMEASURED:
        print("      The shortfall is the unmeasured axes, which carried ~19.6% of the "
              "predicted\n      total in the last fitted table. Do not read this as "
              "accuracy.")

    # What the TRUSTED range admits, per axis. The domain is the largest count seen in
    # real traffic; the slack then trusts 1.8x that, and nothing checked what that costs.
    # An axis whose admitted maximum alone approaches 2^36 is one where the slack, not any
    # measurement, is carrying the safety argument.
    print(f"  admitted maximum per axis (domain x {SLACK}), as a fraction of 2^36:")
    worst = []
    for k, e in sorted(ops.items()):
        dom = e.get("domain_max")
        if not dom:
            continue
        worst.append((e["cycles_per_unit"] * dom * SLACK / CEILING, k, int(dom * SLACK)))
    for frac, k, adm in sorted(worst, reverse=True)[:6]:
        flag = "   <-- the slack is carrying this, not a measurement" if frac > 0.5 else ""
        print(f"    {k:<26} admits {adm:>12,}  = {frac:>6.3f}x of the ceiling{flag}")

    print("  cost of each bound on organic traffic (share of predicted total):")
    for k in sorted(BOUNDED):
        rate = ops[k]["cycles_per_unit"]
        shares = [100 * rate * feature_counts(r).get(k, 0) / effective_cycles(r) for r in rows]
        if max(shares) == 0:
            print(f"    {k:<26} absent from the corpus -- untested against real traffic")
        else:
            print(f"    {k:<26} mean {sum(shares)/len(shares):>6.2f}%  max {max(shares):>6.2f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
