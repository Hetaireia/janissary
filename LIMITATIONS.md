# Limitations

Last updated: 2026-11-01. Linked from README. Updated every release.

This is the honest inventory of what Janissary can and cannot prove.
Absence of a limitation here does not mean absence of a limitation;
it means the limitation is not yet known. If you find one, file it.

## Supported vulnerability classes

Recall is measured on the OWASP Benchmark DAST-applicable corpus (track_a).
Per-class breakdown for Juice Shop is published in `BENCHMARK.md`
Amendment 25 (Track C). crAPI breakdown is pending.

| Class | Protocol | Recall | Notes |
|---|---|---|---|
| SQL injection (quote / union) | HTTP | high | See FN-12 for 4xx-baseline exception |
| SQL injection (error-based) | HTTP | high | Requires SQL text in error body |
| SQL injection (blind) | HTTP | medium | Timing-based; requires stable baseline |
| Reflected XSS | HTTP | **high (HTML) / low (JSON)** | Unescaped HTML echo caught; JSON body echo not caught — see "Reflected XSS on JSON APIs" |
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

### Reflected XSS on JSON APIs

**Status:** Open. Documented 2026-11-01 by Track C expansion (BENCHMARK.md
Amendment 25). Not yet filed as a formal FN item.

**What it is:** the reflected-xss oracle detects unescaped HTML echo but
does not detect a JSON response that reflects the xss payload in a
string field. On OWASP Juice Shop's `/rest/products/search?q=` endpoint,
xss payloads are reflected in the JSON `data` array, but the scanner
emits no xss finding (it emits a correctly-classed sqli finding on the
same endpoint, because the endpoint *is* SQLi-vulnerable).

This is a genuine detection gap: the payload *is* reflected, the JSON
response *would* be exploitable by a downstream consumer that renders
it in HTML context, but the current reflection gate either cannot see
into JSON or refuses to classify JSON reflection as xss.

**What to expect:** scans against JSON APIs that echo xss payloads in
string fields will produce zero xss findings even when the payload is
present in the response. HTML-rendering endpoints are unaffected.

**Tracked at:** `BENCHMARK.md` Amendment 25, H-C2 falsification.

**Reproducer:** with OWASP Juice Shop running on `127.0.0.1:3000`:

    janissary scan -u "http://127.0.0.1:3000/rest/products/search?q=test" -p q --jsonl --quiet

Expected: xss finding. Actual: no xss finding (sqli finding emitted).

**Unblock:** Phase 2 protocol-specific oracle work — a JSON-aware
reflection confirmer that inspects `data` field values for the payload
under an HTML-rendering assumption. Not yet scheduled.

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