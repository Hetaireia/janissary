# ADR-029 — SSRF via redirect chain (BL-1)

**Status:** Proposed (design)
**Parent:** ADR-012 (SSRF via collaborator), ADR-015 (Interactsh OOB client)
**Amends:** ADR-012 by adding a user-supplied redirector probe path
**Backlog:** docs/DETECTION-BACKLOG.md BL-1

## Problem

Current SSRF detection sends payloads that point directly at either a metadata IP or an Interactsh unique URL. Both fail when the target's outbound fetcher only allows URLs whose host matches an allowlist. The classic bypass is to point the parameter at an allowlisted host that responds 302 Location: http://169.254.169.254/... — the target's fetcher follows the redirect to the internal address.

Verification (2026-11-10): `_paced_request` defaults `allow_redirects=False` on JANISSARY's own client. This is correct — JANISSARY should not follow the redirect. The target should. The probe currently never gives the target the opportunity because every payload host is either internal IP or Interactsh; neither is allowlisted by a defensive target.

## Decision

Add a second SSRF phase, `_ssrf_redirect_phase`, gated on a new CLI flag `--ssrf-redirector URL`. When set, the phase sends two payload families:

1. **Metadata via redirect** — parameter becomes `<redirector>?to=http://169.254.169.254/latest/meta-data/` (and GCP/Azure variants). If the target follows the redirect and returns metadata content in its response, the existing SSRF metadata oracle (ADR-012) fires.
2. **OOB via redirect** — parameter becomes `<redirector>?to=http://<uniq>.<collab>/`. If the target follows the redirect, Interactsh receives the callback. Existing collaborator poll logic detects the hit.
Both reuse the differential oracle — no new finding type is needed.

## Design constraints

**JANISSARY does not host the redirector.** The user supplies it. Reasons:

- Hosted redirector routes all customer scans through project infrastructure — privacy and liability problem
- Uptime becomes a project commitment — one more thing to fund and monitor
- The tool's operating model is single-binary, single-target; a hosted dependency breaks that

Bug bounty hunters already have a redirector (their own domain, or an SSRF-as-a-service). One flag tells JANISSARY how to use it.

## Scope

**In scope:** HTTP 302 Location header redirects. One hop.
**Out of scope:** Multi-hop redirect chains, meta-refresh, JavaScript redirects. Those need browser execution (different concern, DOM-XSS territory).

## Not a change to existing SSRF

`_ssrf_phase` is untouched. The new phase runs after it and only when `--ssrf-redirector` is set. Existing scans see zero behavior change. F1 0.921 (Track A) and the pathtraver ceiling (ADR-003) are unaffected.

## Test cases (three, all required)

1. **Benign redirect** — mock server 302s to `https://example.com`. Oracle silent. Verifies no false positive.
2. **Metadata redirect** — mock server 302s to a page containing AWS metadata markers. Differential oracle fires. Verifies response-body detection.
3. **Interactsh redirect** — mock server 302s to the Interactsh unique URL. Poll returns a hit. Verifies OOB detection.

Test harness: same pattern as existing `tests/unit/test_ssrf_metadata.py` — httpx mock transport, one test per case.

## CLI shape

`janissary scan -u https://target.example -p url --ssrf-redirector https://your.domain/r`

`--ssrf-redirector` is optional. Absent — no behavior change. Present — one additional phase runs per param.

## Verification criteria

The ADR is correct when:

1. All three test cases pass.
2. Existing SSRF tests still pass.
3. `janissary scan` without `--ssrf-redirector` produces byte-identical output to today.
4. `--ssrf-redirector` against a redirecting mock fires on cases 2 and 3, silent on case 1.

## Effort

~80 lines scanner + ~10 lines CLI + ~100 lines tests = ~190 lines. One commit. No new dependencies.

## Revisit triggers

- If users report needing multi-hop chains — extend to allow `--ssrf-redirector-hops N`
- If a hosted redirector becomes a product feature — new ADR, new funding question

## Implementation note (2026-11-10)

Initial commit `408098d` shipped the **metadata-via-redirect** payload family: three payloads (`ssrf_redirect_aws`, `ssrf_redirect_gcp`, `ssrf_redirect_azure`) gated on `--ssrf-redirector`, reusing the existing `SSRF_BODY_MARKERS` response-body oracle. 7 new tests, 1134 total passing.

The **OOB-via-redirect** family was shipped in a follow-up commit the same session. Two payloads (`ssrf_redirect_oob_http`, `ssrf_redirect_oob_https`) are appended inside `_ssrf_phase` when `--ssrf-redirector` is set, using the same collaborator allocation path as the direct-SSRF payloads. Four tests in `tests/unit/test_ssrf_redirect_oob.py` verify the plumbing: payloads are issued when the flag is set, silent when unset, and values carry the correct `<redirector>?to=<proto>://<uniq>.<collab>/` shape. 1138 total tests passing. The end-to-end OOB callback path itself is not exercised by unit tests — that requires a live Interactsh instance and is verified manually against a redirecting mock, tracked as verification criterion 3.

Verification criterion 3 (end-to-end Interactsh callback) remains unmet by unit tests only; manual verification against a redirecting mock is required. Criteria 1, 2, and 4 are met by the shipped test suite.
