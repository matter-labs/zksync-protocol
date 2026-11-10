# Retired isolation rows

These rows were carried over from the hand-maintained adversarial fixture. Their
batch **inputs were never committed**, so none of them can be re-measured against a
new guest -- which is the whole reason the corpus moved to committed `.bin.gz`
fixtures. They are recorded here rather than deleted, because three of them are
coverage we have LOST and not yet replaced, and a dropped row leaves no trace in a
test that still passes.

| batch | label | resolution |
|---|---|---|
| 1061 | `div_flood_orig` | superseded by 900168 div_fast + 900176 div_worst2, which cover both operand regimes with committed inputs |
| 1078 | `mod_exp_flood` | superseded by the 9003xx input sweep (900301-900306) |
| 1080 | `ec_add_flood` | superseded by the 9003xx input sweep (900312-900314) |
| 1082 | `ec_mul_flood` | superseded by the 9003xx input sweep (900307-900311) |
| 1084 | `ec_pairing_flood` | NO REPLACEMENT — ec_pairing has no committed fixture, so its invariant is currently unasserted |
| 1086 | `secp256r1_flood` | superseded by the 9003xx input sweep (900317-900318) |
| 1092 | `sha256_flood` | NO REPLACEMENT YET — isolation family in flight |
| 1094 | `ec_recover_flood` | superseded by the 9003xx input sweep (900315-900316) |
| 900065 | `storage_reads_140k` | NO REPLACEMENT YET — the LFS object for this fixture is unretrievable, so it cannot be re-measured; isolation family in flight |

## Coverage since restored

All three gaps this file used to list are closed:

- **`ec_pairing`** — fixtures 900372–900380. The payload carries the pair count, so it is
  a measured per-pair rate rather than a bound.
- **`sha256`** — fixtures 900327–900334 (call-count and input-size sweeps).
- **`storage_read`** — fixtures 900335–900340 and 900364–900368, including warm-read
  variants that separate it from `storage_application`.

The rows below stay recorded because their inputs were never committed and so cannot be
re-measured; they are history, not outstanding work.
