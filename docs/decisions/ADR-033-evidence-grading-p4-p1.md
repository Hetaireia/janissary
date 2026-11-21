# ADR-033 — Evidence grading schema (P4 to P1)

**Status:** Accepted (implemented dcb1786, default table 699b98f)
**Date:** 2026-11-19
**Defects:** D-5 (no evidence-grading schema: DNS-only and in-band treated as if they were the same promotion class)
**Related:** D-6 (DNS-vs-HTTP discrimination), D-7 (request-accounting contract, already dual-field in code), D-8 (parse-proven bypass), ADR-012 (SSRF collaborator), ADR-032 (FP floor pattern)

## Context

Register section 5 D-5 and section 8 B-9 require a P4-to-P1 evidence-grading schema. A DNS-only OOB callback is informative-grade evidence; an HTTP collaborator fetch is high-grade evidence. Without a named grade on the finding, consumers cannot tell the two apart except by free-form severity strings, and later modules have no ceiling to enforce.

Shipped code already splits SSRF OOB by protocol at scanner.py:1057-1074: HTTP/HTTPS hits emit severity critical and finding_type collaborator_hit; DNS hits emit severity info and finding_type dns_only_resolution. SARIF rules mirror that (sarif_rules.py:168-181). Unit tests lock it (tests/unit/test_ssrf.py:100-157). What is missing is the schema itself: no evidence_grade field, no matrix, no ceiling that a finding without an in-band marker cannot exceed P4, and no grade recorded in an evidence block.

ScanFinding and VerifiedFinding carry severity and confidence but not a P-grade (scanner.py:276-332, verification/types.py:78-132). VerificationEngine remains the sole emitter of verified findings; grading must not open a second emission path.

## Decision

1. Every VerifiedFinding and ScanFinding gains evidence_grade: one of P1, P2, P3, P4. Empty is invalid on a verified finding after this ADR ships.
2. Grade is orthogonal to severity. Severity stays the existing vocabulary (info/low/medium/high/critical). Grade answers how strong the evidence is; severity answers how bad the class is when proven.
3. Ceiling: a finding with no in-band marker cannot exceed P4. In-band marker means at least one of: (a) HTTP or HTTPS collaborator hit on the same unique id, (b) response-body or header oracle the detector already treats as proof for that class (quoted error, file content, reflected probe with confirmer pass). DNS-only OOB is not an in-band marker.
4. SSRF OOB mapping (codifies current behaviour under the schema): collaborator_hit -> evidence_grade P1; dns_only_resolution -> evidence_grade P4. Severity strings for those two types stay critical and info respectively unless a later ADR changes them.
5. All other verified finding types receive a default grade from a single table in code (module under janissary/verification or engine). First ship: defaults that preserve today severity-to-consumer behaviour and M89 delta 0; the table is revised in place with evidence, not by silent per-call constants.
6. Grading runs at promotion time: VerificationEngine.verify success path or the single _to_scan_finding boundary sets evidence_grade. Discovery/heuristic candidates do not require a grade until verified.
7. Serialisation: JSON/JSONL include evidence_grade on each finding object. SARIF puts evidence_grade under result.properties (same pattern as other Janissary extensions). CLI human summary may show grade beside severity when non-default. approximate_requests and total_requests stay untouched (D-7).
8. Gate before default enablement of any new graded behaviour that can change who appears in verified findings: M89 rescore delta 0 against the current baseline, plus the existing SSRF unit tests extended to assert evidence_grade.

## Matrix (initial)

- P1: in-band proof or HTTP(S) OOB fetch proving server-side request. Example: collaborator_hit.
- P2: strong differential or multi-observation confirmer pass with stable baseline (reserved; not required for first SSRF wiring).
- P3: single-observation confirmer pass with weaker oracle (reserved).
- P4: weak or out-of-band-only evidence. Example: dns_only_resolution. Ceiling for anything without an in-band marker.

Full per-finding_type rows beyond SSRF OOB are filled when each class is touched; inventing a complete matrix without class-by-class evidence is rejected.

## Gate

- tests/unit/test_ssrf.py: HTTP hit evidence_grade P1; DNS-only evidence_grade P4; severities unchanged.
- No verified finding serialises without evidence_grade after the field ships.
- M89 delta 0 on the graded wiring PR (grading metadata must not drop or add verified Track A rows).
- D-6 may later demote DNS-only from verified to candidate; this ADR does not require that demotion. Grade P4 on a verified DNS-only finding is enough for D-5.

## Consequences

- Consumers can filter or rank by evidence strength without parsing detail strings.
- D-6 and D-8 gain a place to hang discrimination and parse-proof requirements without overloading severity.
- Cost: field on two dataclasses, one grading helper, serialisation keys, SSRF test asserts, SARIF property. No change to confirmer chain ownership.
- Register D-5 can move to resolved only after the field ships and gates pass; this ADR alone does not close D-5.

## Alternatives considered

- Overload severity only (info vs critical). Rejected: already done for SSRF and does not generalise; register asked for a schema, not two magic strings.
- Map grade onto confidence float. Rejected: confidence is documented as heuristic metadata, not a calibrated probability (ScanFinding note at scanner.py:307-308).
- Demote DNS-only to candidate in the same change (fold D-6 into D-5). Rejected: D-6 has its own gate (downgrade instead of verify, M89 delta 0). Sequencing keeps D-5 first as metadata, D-6 as emission policy.
- Full lostsec matrix copied verbatim for every class. Rejected: no complete matrix table exists in-repo; inventing grades without per-class evidence violates the no-claim rule.

## Refs

- D-5, docs/MILESTONE-REGISTER-COLLATED.md sections 5, 8, 9 item 3
- src/janissary/engine/scanner.py _ssrf_phase (approx 1040-1110)
- src/janissary/sarif_rules.py SSRF rules
- tests/unit/test_ssrf.py test_scanner_ssrf_hit_http_emits_finding, test_scanner_ssrf_dns_only_emits_info
- ADR-012, ADR-016, ADR-032

## Implementation

- dcb1786: field on CandidateFinding, VerifiedFinding, ScanFinding; `_EVIDENCE_FIELDS` carry; SSRF OOB P1/P4 wiring; JSON/JSONL and SARIF `result.properties`; test asserts.
- 699b98f: `janissary/verification/grading.py` single table (`collaborator_hit` P1, `dns_only_resolution` P4), mechanism fallback P3 confirmed / P4 otherwise, filled at `_promote` and `_candidate_to_scan_finding`, 5 table tests.
- Unit suite 1411 passed, 1 skipped. M89 delta 0 still outstanding.
