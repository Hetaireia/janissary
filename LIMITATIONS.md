# Limitations

Last updated: 2026-11-01. Linked from README. Updated every release.

This is the honest inventory of what Janissary can and cannot prove.
Absence of a limitation here does not mean absence of a limitation;
it means the limitation is not yet known. If you find one, file it.

## Supported vulnerability classes

Recall is measured on the OWASP Benchmark DAST-applicable corpus (track_a).
Per-class breakdown for Juice Shop is published in `BENCHMARK.md`
Amendment 26 (Track C). crAPI breakdown is pending.

| Class | Protocol | Recall | Notes |
|---|---|---|---|
| SQL injection (quote / union) | HTTP | high | See FN-12 for 4xx-baseline exception |
| SQL injection (error-based) | HTTP | high | Requires SQL text in error body |
| SQL injection (blind) | HTTP | medium | Timing-based; requires stable baseline |
| Reflected XSS | HTTP | high | Unescaped HTML echo caught. DOM-based XSS on SPAs is out of scope — see "DOM-based XSS on SPAs" |
| Path traversal | HTTP | **0.049-0.308** | Partially supported; see "Known gaps" |
| LDAP injection | HTTP | medium | — |
| LFI | HTTP | medium | — |
| SSRF | HTTP | medium | — |
| XML-RPC | HTTP | medium | — |
| Secure cookie | HTTP | high | — |
| Weak randomness | HTTP | high | — |
| Trust boundary | HTTP | medium | — |
| GraphQL | HTTP | **integrated** | Full feature coverage (introspection, depth, alias, argument fuzzing) routed through VerificationEngine and BaselineNormalizer. Findings emitted with verification_status='unproven' — recon observations, not vulnerability proofs. See FN-15 (FIXED) |
| WebSocket | WS | **passive recon only** | Plaintext, missing Origin, blind echo, no-auth checks. Learn/probe/verify pipeline not built. See FN-16 |
| gRPC | gRPC | **not supported** | See Phase 2.3 |

## Known gaps (false negatives)

### FN-12 — SQLi on non-2xx baseline (FIXED 2026-11-01)

**Status:** Fixed. Was Phase 0.2(b); unblocked by Phase 0.1 and fixed
in commits `faade6c`, `2707a32`, `ef79e31`.

**What it was:** a 401-baseline endpoint with SQL injection in the
payload was not detected. Live investigation (session 13) found
**three** layers, not the two originally diagnosed:

1. `_check_status` at `analyzer.py:688` returned `[]` for 4xx baselines
2. `status_change` was dropped at `scanner.py` as a corroborator unless
   a detector also fired
3. `benchmark/track_c/templates/juice_login.json` did not opt into sqli
   payloads — json-body injection filters payloads to `["ssrf"]` unless
   the template declares `_categories`. **The reproducer never sent the
   `'` payload.** All three layers had to be fixed together; fixing the
   first two still produced 0 findings.

**How it is fixed:**

- 4xx baselines now reach `_check_status` (only modal_status=0 stays
  blocked)
- A new `CorroboratorConfirmer` marks `status_change` findings
  `unproven` with `verification_reason='corroborator_structural'`
- The scanner suppresses `status_change` only on 2xx/3xx baselines —
  the original `/traversal` misattribution shape is preserved
- The CLI marks unproven findings `[unproven]` at the finding line and
  group header

**What to expect now:** scans against 4xx-baseline endpoints with
injection payloads produce findings with `verification_status='unproven'`
visible in human output. On a live juice-shop `v17.1.1`, the fixed
reproducer emits 8 findings where it previously emitted 0.

**What remains unfixed (by design):** `status_change` on a **2xx/3xx**
baseline is still suppressed. A 200→500 transition on a target that
500s for any unknown input is the `/traversal` misattribution shape;
detecting real bugs there needs content-signature gates (Phase 2).

**JSON / SARIF output (FIXED 2026-11-01, commit `96e0e49`):**
`verification_status` and `verification_reason` are emitted in
`--json`, `--jsonl`, `--export *.json`, and `--export *.sarif`
output. A CI consumer reading machine-readable output sees the
unproven qualifier alongside the finding. Verified against live
juice-shop: JSON emits `"verification_status": "unproven"` and
`"verification_reason": "corroborator_structural"` on all 8
findings; SARIF `properties` block carries the same two fields.

**Reproducer:** `benchmark/track_c/templates/juice_login.json` (with
`_categories: ["sqli"]`).

### DOM-based XSS on SPAs

**Status:** Out of scope for server-side DAST. Documented 2026-11-01
(BENCHMARK.md Amendment 26, which retracted an earlier false filing
as FN-13).

**What it is:** many modern web applications render content client-side
via JavaScript frameworks (Angular, React, Vue). A search query or user
input may reflect into the rendered page *after* JavaScript executes, but
never into the server's HTTP response body. On OWASP Juice Shop's
`/rest/products/search?q=` endpoint, for example, the unauthenticated
response is `{"status":"success","data":[]}` — the payload is not
reflected server-side at all. The search results are rendered by
Angular's client-side router.

**Why it is out of scope:** Janissary is a server-side scanner. It sends
HTTP requests and analyzes HTTP responses. It does not execute
JavaScript, does not build a DOM, and does not simulate browser behavior.
A vulnerability that only manifests inside the browser's DOM is not
observable from the server side, regardless of how the scanner is
architected. This is a limit of the tool class, not a bug.

**What to expect:** scan output against SPA endpoints will not include
DOM-based xss findings even when the client-side application is
vulnerable. HTML-rendering endpoints (traditional server-rendered pages)
are unaffected — reflected-xss detection there remains high-quality.

**What would close it:** a headless browser engine (Playwright,
Puppeteer) driving the scan and executing client-side code, then
inspecting the live DOM for unescaped reflections. That is a different
scanner architecture, not a feature of the current one. No work is
scheduled.

**Prior mis-filing:** this limit was originally filed as FN-13 on
2026-11-01, framed as "JSON-API reflected-XSS detection gap." That
framing was wrong — the endpoint tested returned no reflection
server-side, and the apparent miss was compounded by a benchmark-runner
bug (see Amendment 26). FN-13 is retracted; the limit is recorded here
as scope, not bug.

### Path traversal

**Status:** partially supported. Recall 0.049-0.308 on OWASP Benchmark.
Content-signature gates exist but are narrow; parameters that produce
no distinctive traversal content in the response are missed.

**Unblock:** Phase 2 protocol-specific oracle, or a traversal-specific
content-signature expansion.

## Unsupported protocols

- **GraphQL:** integrated as of 2026-11-01 (`--graphql` flag).
  Full feature coverage (introspection, depth probes, alias probes,
  argument fuzzing, batch detection) routed through `VerificationEngine`
  and `BaselineNormalizer`. Findings emitted with
  `verification_status='unproven'` and
  `verification_reason='graphql_recon'` — recon observations, not
  vulnerability proofs. See FN-15 (FIXED).
- **WebSocket:** passive reconnaissance only — plaintext detection,
  missing-Origin (CSWSH) detection, blind echo detection, no-auth
  handshake check. The full Phase 2.2 learn/probe/verify pipeline
  (traffic sampling, schema fingerprinting, message-sequence oracle)
  is not built. Findings surface from the standalone `janissary ws`
  subcommand, not through `Scanner.scan()` or `VerificationEngine`.
  Tracked as FN-16.
- **gRPC:** no support. Phase 2.3.

## Candidate-only classes

Currently none — discovery and verification are the same code path.
Phase 3 will introduce candidate-only classes; this section will list
them when it does.

## What "no finding" means (and doesn't mean)

A scan that produces no findings is not a claim that the target is clean.
It is a claim that the scanner did not detect anything. In some cases
those are the same thing. In others, "no finding" means the scanner
never actually tested that path.

### Silent false negatives — a real bug class

Two GraphQL detection paths shipped reporting "clean" against every real
server they ever ran against. The cause: probes that hardcoded
assumptions about response shape (`__typename` as a nestable field; a
probe name close enough to trigger a suggestion) that no real server
matches. The scanner had no way to say "I couldn't test this" — it
reported "no finding" identically to a genuine clean result.

Filed as FN-18 and FN-19, fixed 2026-11-01, and live-validated against
a graphql-core fixture server. The general lesson: **a probe that never
fires because of an assumed constant is indistinguishable from a probe
that works and reports "clean."**

These were not caught by the unit test suite. They were caught by
running the scanner against a real GraphQL server and inspecting the
results. Mocks that match the code's assumptions confirm the code's
assumptions; they do not test the code against reality.

### How we're improving this

As of 2026-11-01, protocol detection paths are validated against a live
server, not just mocked unit tests:

- `scripts/graphql_fixture_server.py` — real GraphQL server using
  graphql-core, exercises all 5 GraphQL detection paths (introspection,
  batching, suggestions, depth, alias). Committed at `334b625`, extended
  at `1f4cca5`.
- Future WebSocket and gRPC work (FN-16, FN-17) will follow the same
  pattern: a live fixture server under `scripts/`, positive-control
  tests that prove each detection fires, and a "no finding" result on
  that fixture treated as a claim that requires live verification.

### What to expect today

If a scan reports "no finding," the honest question is: was the path
tested?

- **HTTP classes** (SQLi, XSS, traversal, etc.): yes — positive-control
  tests against known-vulnerable endpoints.
- **GraphQL** (all 5 paths): yes — live-verified 2026-11-01.
- **WebSocket** (FN-16): partial — passive recon only; learn/probe/verify
  pipeline not built. "No finding" there means "not tested" by design.
- **gRPC** (FN-17): no support. "No finding" there means "not tested"
  by design.

## What this document is not

This is not a vulnerability disclosure policy. If you are reporting a
vulnerability *in* Janissary, use `SECURITY.md`. This document is about
what Janissary *detects*.