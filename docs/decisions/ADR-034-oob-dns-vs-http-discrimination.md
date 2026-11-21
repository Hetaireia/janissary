# ADR-034 — OOB DNS-vs-HTTP discrimination in the SSRF oracle

**Status:** Accepted
**Date:** 2026-11-21
**Defects:** D-6 (SSRF oracle cannot distinguish a DNS callback from an HTTP response, B-10)
**Related:** ADR-033 (evidence grading, P4 ceiling), ADR-012 (SSRF collaborator), ADR-007 (finding identity), D-8, D-9, M89

## Context

Measured from the tree, not assumed:

- SSRF_PAYLOADS carries five entries (integrations/collaborator.py:63-68). ssrf_http and ssrf_https fetch. ssrf_gopher and ssrf_dict target 6379. ssrf_dns_only targets port 9, so it resolves without any HTTP fetch by construction.
- poll() returns every hit with its protocol (collaborator.py:145-179). The parser does not lose the distinction.
- _ssrf_phase classifies per hit: http or https -> collaborator_hit, critical; dns -> dns_only_resolution, info (scanner.py:1061-1084).
- Both classes go through _ENGINE.verify(). dns_only_resolution matches no specialised confirmer, falls through to AnalyzerImplicitConfirmer, and that confirmer confirms unconditionally (confirmers.py:94-113). A DNS packet alone is therefore promoted to verification_status=verified.
- record() applies no verification filter (scanner.py:575-586) and _ssrf_phase never inspects status, unlike the main scan() loop which routes unproven to candidates (scanner.py:1206-1209).
- Once any hit arrives for a uniq, that uniq leaves pending (scanner.py:1052-1119). A later HTTP fetch on the same uniq is never polled, so an early DNS record is final.
- Findings list enforces verified-only and candidates list enforces unproven-only (scanner.py:409-447, 516-542); _DedupedFindingsList inherits the verified guard. The stream split is a hard invariant, not a convention.

Consequence of the above: a fetching backend emits both a critical collaborator_hit from ssrf_http and an info dns_only_resolution from ssrf_dns_only, for the same param. A resolving-only backend emits up to five info findings that each count as verified. This is the mechanism behind the unscoreable SSRF rows in the Track A status line.

## Decision

1. Per-uniq classification is terminal rather than first-hit-wins. A uniq remains pending across all poll delays until an HTTP or HTTPS hit arrives or the delays are exhausted. The strongest protocol observed for a uniq decides the class.
2. Param-level suppression. When any HTTP or HTTPS hit exists for a param, DNS-only hits on that param are not emitted. DNS resolution precedes any OOB fetch, so a DNS record beside an HTTP record carries no extra information.
3. DNS-only with no HTTP or HTTPS hit anywhere on the param emits exactly one finding per param: finding_type dns_only_resolution, severity info, evidence_grade P4.
4. DNS-only findings are unproven. A DnsOnlyOobConfirmer returns unproven with reason oob_dns_only_no_http and is inserted before AnalyzerImplicitConfirmer. Status then flows through the existing contract: verify() -> unproven -> candidates.
5. _ssrf_phase routes by status, mirroring scanner.py:1206-1209: verified to record(), unproven to summary.candidates. The two-stream boundary stays the single definition of what counts as a finding.
6. collaborator_hit stays verified, critical and P1. Payload set, payload templates, poll delays and the rest of the confirmer order are unchanged.
7. finding_count counts verified findings only, so a param that resolves but never fetches lowers finding_count. Intended; consumers of ssrf scans must read candidates too.
8. dns_only_resolution stays in the grade table at P4 and in the sarif_rules and grouping tables. Nothing is renumbered.

## Gate

- tests/unit/test_ssrf.py: DNS-only -> candidates, unproven, reason oob_dns_only_no_http, grade P4, severity info, exactly one per param.
- tests/unit/test_ssrf.py: HTTP hit -> findings, verified, P1, critical; a param carrying both protocols emits the HTTP finding only.
- tests/unit/test_ssrf.py: an HTTP hit arriving after an early DNS hit on the same uniq resolves to collaborator_hit.
- M89 delta 0. SSRF is outside Track A scoring scope, so the expected delta is zero verified Track A rows.
- Full unit suite green, ruff clean, both stream guards still enforced.

## Consequences

- A resolver is no longer reported as a fetcher. The candidate stream shows it without claiming verification.
- SSRF rows per param fall from up to five to at most one.
- Cost: one confirmer class, a strongest-hit map in the poll loop, a status branch, rewritten ssrf tests. No change to payloads or the collaborator contract.
- Risk: a backend that resolves and then fetches beyond the 10 s poll budget is scored as a candidate. Accepted, because candidate is the honest answer and the budget is unchanged by this ADR.

## Alternatives considered

- Leave grading only, as ADR-033 did. Rejected: DNS stays verified and _ssrf_phase keeps bypassing the candidate stream.
- Keep first-hit-wins. Rejected: the class then depends on delivery order rather than on what was observed.
- Drop DNS-only findings entirely. Rejected: a DNS record is real evidence the target resolved the host, and an operator should see it.

## Refs

- scanner.py:990-1119 (_ssrf_phase), 1061-1084 (classification), 1206-1209 (status routing), 575-586 (record), 409-447 and 516-542 (stream guards)
- confirmers.py:94-113 (AnalyzerImplicitConfirmer)
- integrations/collaborator.py:63-68 (payloads), 145-179 (hit parsing)
- ADR-033 decision 3, gate line 4, alternative 3
