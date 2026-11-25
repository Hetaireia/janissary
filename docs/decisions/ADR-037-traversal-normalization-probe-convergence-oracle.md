# ADR-037 -- Path traversal: normalization probe and convergence oracle

**Status:** Proposed (2026-11-25)
**Supersedes:** None.
**Extends:** ADR-003 (pathtraver ceiling), ADR-006 (traversal collapse oracle), ADR-027 (pathtraver recall strategy), ADR-028 (pathtraver signatures and verbose).
**Blocks:** Any published traversal recall claim above 0.323, and the 7.11.5 release.
**Cited by:** traversal commits from this ADR onward cite it. The commits from 4bbcca1 to de1418e cite "ADR-036", which in docs/decisions is the request-count provenance decision (D-7). Their citations are stale. No history is rewritten; this ADR is the canonical record for that work.

## Context

Path traversal recall on the Track A corpus is 0.323, the weakest measured number in the project. The README's Known limitations section attributes the remaining false negatives to the response layout: most responses do not leak a file-existence signal, so the existing oracle cannot see them. This ADR adds two oracles that detect traversal from response shape rather than an existence signal, under the same precision contract as every other class.

The traversal commits from 4bbcca1 to de1418e implement the mechanisms and are on main, unreleased.

Evidence base: the commit messages, the phase plan recorded in the project handover, and the README limitation text. The module-level mechanics below must be checked against the code before this ADR is accepted (see the checklist).

## Decision

Two additive oracles, one mandatory guard and one SARIF identity rule, all routed through the existing VerificationEngine. None of the oracles emits a finding directly.

D1. Payload-reflection guard (pathtraver_reflection_guard.py). A pure filter. A candidate whose traversal payload is reflected in the response is rejected before emission. Mandatory for D2 and D3.

D2. Normalization probe (pathtraver_normalization_probe.py). Sends self-referential, depth-derived variants of the traversal payload, including off-by-slash forms. A candidate is produced only when the variant response shows the same signal as the original and differs from the baseline, and the guard passes. The exact rule must be copied from the module at acceptance.

D3. Depth-invariant convergence oracle (pathtraver_convergence_oracle.py). Sends the traversal payload at depths N-1, N, N+1 and a canary path that does not exist. Let H be a hash of the normalised response. Emit only when H(N) equals H(N+1), H(N) differs from H(N-1), H(N) differs from H(canary), and the guard passes. Interpretation: the response stops changing at the depth where the filesystem root clamps the traversal, and the clamped response is distinct from a not-found response.

D4. SARIF identity. Both oracles emit under the existing path-traversal SARIF rule identifier -- the same rule ADR-006's collapse oracle uses -- and are distinguished per finding by the oracle_mechanism field. No new rule identifiers are introduced, so test_sarif_rules needs no new expectation and acceptance simply verifies it passes unchanged. Rejected alternative A5 records why.

Request cost, stated so it can be priced: D3 sends the depth ladder plus exactly one canary, and that single canary is simultaneously the P3 control for the candidate -- 4 requests per parameter before retries. D2 sends its variant set plus its own separate control. Neither oracle reuses the other's canary.

## Precision contract (M89)

Required before any emission from D2 or D3:

P1. Baseline capture strips nonces, CSRF tokens and timestamps, and also every depth-dependent token that would defeat an H(N) against H(N-1) comparison: the requested path where it is echoed into the body or into error text, absolute server-side paths, and path-length-dependent padding or truncation.
P2. The reflection guard (D1) rejects reflected payloads.
P3. Each candidate is paired with a negative control request to a nonexistent path, janissary_nonexistent_canary_<random>. The candidate response must differ from the control. For a D3 candidate the control is the canary named in D3.

## Alternatives considered

A1. Extend ADR-006's collapse oracle in place instead of adding a module. Rejected: the collapse oracle keys on a single collapse transition, while the depth ladder needs three distinct depths and a canary to separate "root clamped" from "path not found". Folding both into one module would make the existing collapse contract unreadable and its tests ambiguous.

A2. Canary-only rule -- treat any response differing from the not-found canary as traversal. Rejected: a target returning one generic page for every unknown path differs from the canary without having traversed at all, which breaks the M89 precision floor. The guard plus normalization evidence is what makes the difference mean traversal.

A3. Two depths (N, N+1) instead of three. Rejected: equality at N and N+1 alone is satisfied by a response that never varies with depth, so no transition is proven. The N-1 comparison is what establishes that a change occurred.

A4. Reflection guard as the only gate, no canary. Rejected: reflection is necessary but not discriminating. A reflected-but-not-traversed response passes it cleanly.

A5. A new SARIF rule identifier per oracle. Rejected: it splits one class of finding across three rules and puts the burden on every downstream triage and dedup consumer. oracle_mechanism already carries the distinction inside the finding.

## Acceptance gates (measured on recorded runs, not asserted)

G1. The reflection guard removes no true positive from Track A.
G2. The two additive oracles introduce no true-positive regression against the 0.323 baseline. Measured with the three-run aggregation harness, all gates.
G3. M89 negative corpus precision stays at 1.000, with zero false positives.
G4. Recall is reported as a computed number with its run directories, per family and per oracle, not only as a corpus-wide aggregate. Any change is reported as measured, including zero or negative.

Per-oracle reporting in G4 is required because D3 is silent on any target that does not clamp. A small aggregate gain can therefore pass G4 while the real effect is confined to the clamping subset, and an aggregate figure alone would hide that.

## Status transitions

Proposed becomes Accepted only when G1 to G4 hold on recorded runs. If G2 or G3 fails, the failing oracle is disabled by default or removed, and this ADR gets an addendum in the pattern of ADR-027-addendum-2026-11-18.md. No recall figure appears in documentation before G4.

## Acceptance checklist

Verification items, all answerable from the code and the runs:

1. Read all three modules in full. Record line anchors in an addendum.
2. Confirm the emission path (_emit_oracle_findings and the oracle_mechanism field) matches D1 to D4 and P1 to P3.
3. Establish the M89 negative corpus path. Not established as of 2026-11-25.
4. Nominate the three baseline runs for the 0.323 measurement. Not confirmed.
5. Confirm test_sarif_rules passes unchanged under D4, with no new rule identifiers registered.

The SARIF question is no longer open here: D4 decides it, and item 5 only verifies the decision held.

## Consequences

Positive: a route to traversal recall beyond the response-leak limit, under the same precision contract as other classes.

Negative: more requests per parameter -- the D3 depth ladder plus canary quadruples the per-parameter cost of that oracle; more request volume means more WAF exposure; D3 cannot fire on targets that do not clamp, so its reach is limited to them and its recall contribution should be read as conditional rather than general.

Non-goals: no change to score_dast_aware.py; no new payload families beyond traversal; no change to SSRF or any other class; no exhaustiveness claim for the depth ladder beyond N-1, N and N+1.

## Release relationship

Release 7.11.4 (tag d4cf1e9) does not include these oracles. They ship only in a release after this ADR is Accepted.
