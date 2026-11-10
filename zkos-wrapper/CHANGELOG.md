# Changelog

## 0.1.0 (2026-08-27)

Baseline release, cut by hand at the vendoring commit so that release-please has
a commit to stop at rather than walking the whole history (see `RELEASE.md`).

This tree is upstream at `19fa580`. Upstream never cut a release, so `0.1.0`
is the version its manifest has carried throughout.

`boojum` and friends resolve through `../crypto/`, and `shivini` and friends
through `../crypto-gpu/`, instead of the branches upstream pins: the FRI
batch degree lift those branches were cut for is on both trunks already, and
`PlonkSnarkWrapperLogN` was ported into `crypto-gpu/` for this. The airbender
crates stay git pins, there being no airbender workspace here.

One thing from the crypto branch did not come along: a 20% FRI query increase in
boojum's `compute_fri_schedule` and the `security_level_calculator` module behind
it. Until that lands in `crypto/`, this workspace proves at the trunk schedule.
