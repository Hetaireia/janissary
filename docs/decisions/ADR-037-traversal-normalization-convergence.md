# ADR-037 -- Path traversal: normalization probe and convergence oracle

**Status:** Proposed (2026-11-25)
**Supersedes:** None.
**Extends:** ADR-003 (pathtraver ceiling), ADR-006 (traversal collapse oracle), ADR-027 (pathtraver recall strategy), ADR-028 (pathtraver signatures and verbose).
**Blocks:** Any published traversal recall claim above 0.323, and the 7.11.5 release.

## Context

Path traversal recall on the Track A corpus is 0.323, the weakest measured number in the project. The README's Known limitations section attributes the remaining false negatives to the response layout: most responses do not leak a file-existence signal, so the existing oracle cannot see them. This ADR adds two oracles that detect traversal from response shape rather than an existence signal, under the same precision contract as every other class.

The traversal commits from 4bbcca1 to de1418e implement the mechanisms and are on main, unreleased. Their messages cite "ADR-036" for this work. ADR-036 in docs/decisions is the request-count provenance decision (D-7), so those citations are stale. No history is rewritten. This ADR is the canonical record for the traversal work.

Evidence base: the commit messages, the phase plan recorded in the project handover, and the README limitation text. The module-level mechanics below must be checked against the code before this ADR is accepted (see the checklist).

## Decision

Two additive oracles and one mandatory guard, all routed through the existing VerificationEngine. None of them emits a finding directly.

D1. Payload-reflection guard (pathtraver_reflection_guard.py). A pure filter. A candidate whose traversal payload is reflected in the response is rejected before emission. Mandatory for D2 and D3.

D2. Normalization probe (pathtraver_normalization_probe.py). Sends self-referential, depth-derived variants of the traversal payload, including off-by-slash forms. A candidate is produced only when the variant response shows the same signal as the original and differs from the baseline, and the guard passes. The exact rule must be copied from the module at acceptance.

D3. Depth-invariant convergence oracle (pathtraver_convergence_oracle.py). Sends the traversal payload at depths N-1, N, N+1 and a canary path that does not exist. Let H be a hash of the normalised response. Emit only when H(N) equals H(N+1), H(N) differs from H(N-1), H(N) differs from H(canary), and the guard passes. Interpretation: the response stops changing at the depth where the filesystem root clamps the traversal, and the clamped response is distinct from a not-found response.

## Precision contract (M89)

Required before any emission from D2 or D3:

P1. Baseline capture strips nonces, CSRF tokens and timestamps before any hash or comparison.
P2. The reflection guard (D1) rejects reflected payloads.
P3. Each candidate is paired with a negative control request to a nonexistent path, janissary_nonexistent_canary_<random>. The candidate response must differ from the control.

## Acceptance gates (measured on recorded runs, not asserted)

G1. The reflection guard removes no true positive from Track A.
G2. The two additive oracles introduce no true-positive regression against the 0.323 baseline. Measured with the three-run aggregation harness, all gates.
G3. M89 negative corpus precision stays at 1.000, with zero false positives.
G4. Recall is reported as a computed number with its run directories. Any change is reported as measured, including zero or negative.

## Status transitions

Proposed becomes Accepted only when G1 to G4 hold on recorded runs. If G2 or G3 fails, the failing oracle is disabled by default or removed, and this ADR gets an addendum. No recall figure appears in documentation before G4.

## Acceptance checklist

1. Read all three modules in full. Record line anchors in an addendum.
2. Confirm the emission path (_emit_oracle_findings and the oracle_mechanism field) matches D1 to D3 and P1 to P3.
3. Establish the M89 negative corpus path. Not established as of 2026-11-25.
4. Nominate the three baseline runs for the 0.323 measurement. Not confirmed.
5. Decide the SARIF rule identifiers for the two new oracles, and whether test_sarif_rules expects them. Open since the wiring commits.

## Consequences

Positive: a route to traversal recall beyond the response-leak limit, under the same precision contract as other classes.

Negative: more requests per parameter (the depth ladder plus canary); more WAF exposure; D3 cannot fire on targets that do not clamp, so its reach is limited to them.

Non-goals: no change to score_dast_aware.py; no new payload families beyond traversal; no change to SSRF or any other class.

## Release relationship

Release 7.11.4 (tag d4cf1e9) does not include these oracles. They ship only in a release after this ADR is Accepted.