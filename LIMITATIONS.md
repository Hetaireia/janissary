# Limitations

Last updated: 2026-11-01. Linked from README. Updated every release.

This is the honest inventory of what Janissary can and cannot prove.
Absence of a limitation here does not mean absence of a limitation;
it means the limitation is not yet known. If you find one, file it.

## Supported vulnerability classes

Recall is measured on the OWASP Benchmark DAST-applicable corpus (track_a).
Per-class breakdown for crAPI and Juice Shop is pending Phase 1.1.

| Class | Protocol | Recall | Notes |
|---|---|---|---|
| SQL injection (quote / union) | HTTP | high | See FN-12 for 4xx-baseline exception |
| SQL injection (error-based) | HTTP | high | Requires SQL text in error body |
| SQL injection (blind) | HTTP | medium | Timing-based; requires stable baseline |
| Reflected XSS | HTTP | high | Unescaped echo is the bug |
| Path traversal | HTTP | **0.049-0.308** | Partially supported; see "Known gaps" |
| LDAP injection | HTTP | medium | — |
| LFI | HTTP | medium | — |
| SSRF | HTTP | medium | — |
| XML-RPC | HTTP | medium | — |
| Secure cookie | HTTP | high | — |
| Weak randomness | HTTP | high | — |
| Trust boundary | HTTP | medium | — |
| GraphQL | HTTP | partial | Introspection and depth only; see Phase 2.1 |
| WebSocket | WS | **not supported** | See Phase 2.2 |
| gRPC | gRPC | **not supported** | See Phase 2.3 |

## Known gaps (false negatives)

### FN-12 — SQLi on non-2xx baseline

**Status:** Open. Reclassified to Phase 0.2(b); blocked on Phase 0.1's
data model.

**What it is:** a 401-baseline endpoint with SQL injection in the payload
is not detected. Two layers block it: `_check_status` at
`analyzer.py:688` returns `[]` for 4xx baselines, and even when it
doesn't, `status_change` is dropped at `scanner.py:1048` as a
corroborator unless a detector (`db_error`, `reflection`, `timing`)
also fires.

**What to expect:** scans against endpoints that 4xx on baseline report
zero SQLi findings even when the endpoint is vulnerable. This is a
**known and documented** blind spot, not a silent failure.

**Unblock:** Phase 0.1 (`CandidateFinding` / `VerifiedFinding`) then
Phase 0.2(b) (candidate emission with `verification_reason`).

**Reproducer:** `benchmark/track_c/templates/juice_login.json`. See
session-3 handover for the full diagnosis.

### Path traversal

**Status:** partially supported. Recall 0.049-0.308 on OWASP Benchmark.
Content-signature gates exist but are narrow; parameters that produce
no distinctive traversal content in the response are missed.

**Unblock:** Phase 2 protocol-specific oracle, or a traversal-specific
content-signature expansion.

## Unsupported protocols

- **GraphQL:** introspection and depth checks are partial. Full
  query/mutation argument fuzzing is Phase 2.1.
- **WebSocket:** no support. Phase 2.2.
- **gRPC:** no support. Phase 2.3.

## Candidate-only classes

Currently none — discovery and verification are the same code path.
Phase 3 will introduce candidate-only classes; this section will list
them when it does.

## What this document is not

This is not a vulnerability disclosure policy. If you are reporting a
vulnerability *in* Janissary, use `SECURITY.md`. This document is about
what Janissary *detects*.