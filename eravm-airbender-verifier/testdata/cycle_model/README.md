# Cycle-model corpora

Everything the committed cost table is built from. `python scripts/cycle_model/build_cost_table.py
--organic dataset.json --isolation isolation_dataset.json ...` reproduces
`crates/cycle_estimator/model/cost_table.json` **byte-identically**; that is the property
this directory exists to guarantee, and it is worth re-checking after any change here,
because it was silently false for a while (the committed datasets were a stale vintage of
the ones actually used).

| file | what it is |
|---|---|
| `dataset.json` | 52 organic batches — 3 v31 (84730–84732), 49 v29 mainnet (513601–513649). Supplies the BASE and the domains, and is the out-of-sample accuracy check: no rate is derived from it. |
| `isolation_dataset.json` | 197 synthetic single-axis batches (900101–900405). Every per-operation rate comes from these. |
| `isolation_corpus.csv` | family / tier / intended axis / axis count / ergs for the first campaign. `derive_rates.py` reads it to group tiers. |
| `isolation_input_corpus.csv` | the same for the second campaign (input sweeps, storage, keccak/sha256, pubdata, tx count, pointer, pairing, bytecode volume). |
| `isolation_manifest.json` | which fixtures are adversarial, i.e. land in `tests/fixtures/adversarial.json`. |
| `decommit_corpus.csv` | the decommit families' shapes (contract sizes, repeat counts). |
| `RETIRED_FIXTURES.md` | rows retired because their inputs were never committed and cannot be re-measured. History, not outstanding work. |

The batch inputs themselves are Git LFS objects under
`testdata/era_mainnet_batches/binary/`. A fixture whose `.bin.gz` is unretrievable cannot
be re-measured against a new guest, which is why batch 900065 was dropped from the corpus
rather than kept as an unreproducible row.

## Rebuilding

See `scripts/cycle_model/REFIT-RUNBOOK.md`. Two things that are easy to get wrong:
`--isolation` is not optional (without it `ec_pairing_cycles` gets no domain and the table
declines every pairing batch, tests still green), and the provenance flags are mandatory —
the build refuses to write an unstamped table.
