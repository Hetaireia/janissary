# Phase 4 - Detection Gaps & Mode Extensions

**Status:** CLOSED. All FNs resolved in Phase 4 execution.
**Prerequisite:** Phase 3 closed at `725f942` - corpus-wide baseline measured.
**Parent:** `docs/AMENDMENT-24.md` (Phase 3 harness), `docs/PHASE-3-PLAN.md`.

## Baseline state at Phase 3 close (commit `725f942`)

Corpus-wide aggregate from `benchmark/track_c/corpus-score.json`:

| Metric | Value |
|---|---|
| Apps | 6 (dvwa, juice-shop, vampi, gitea, nextcloud, bwapp) |
| tp | 5 |
| fp | 0 |
| fn | 3 |
| tn | 20 |
| precision | 1.0 |
| recall | 0.625 |
| f1 | 0.7692 |

Read: **the scanner never lies.** Every miss was on a known-vulnerable endpoint. Phase 4 was about closing FNs, not cleaning FPs.

## Closeout (Phase 4 execution)

All three FNs closed. Corpus: **tp=8 fp=0 fn=0 tn=21 recall=1.0 f1=1.0**.

| FN | Endpoint | Initial classification | Actual root cause | Commit |
|---|---|---|---|---|
| FN-3 | bwapp `/directory_traversal_1.php` | needs LFI-shape oracle | Confirmed: content-injection oracle needed | `bcb140e` |
| FN-2 | dvwa `/vulnerabilities/fi/` | "oracle too narrow" | **Wrong.** Payload-library depth gap (3-deep vs 5-deep) | `1ee061d` |
| FN-1 | dvwa `/vulnerabilities/sqli_blind/` | "temporal/paired-request" | **Wrong.** Status-code delta, not timing | `502c54a` |

### FN-3 closeout - LFI content oracle

The collapse oracle (`ADR-006`) catches structural removal. It cannot catch
in-page LFI where the file content appears inside a preserved page structure.
Fix: `src/janissary/detection/lfi_oracle.py` - content-signature oracle
(passwd/shadow/hosts/win.ini/group regexes), fires when the signature
appears in the payload response but not in any baseline snapshot.

### FN-2 closeout - payload depth, not oracle

Original analysis: "traversal oracle too narrow - it looks for canary-is-missing,
but LFI returns different valid content."

Empirical probe against DVWA at `low` security showed:
- `page=file1.php` through `file4.php` all return distinct valid content (page param honored)
- Traversal depth 1-4 all return uniform 3244B (not deep enough)
- Traversal depth 5+ (`../../../../../etc/passwd`) and absolute `/etc/passwd` both return 4219B with passwd content

Root cause: DVWA's FI page sits 5 path segments from `/`; the payload library
only shipped 3-deep payloads (tuned for bWAPP, 2 segments). The LFI oracle
was correct - it just never saw passwd content because the payload couldn't
reach the file.

Fix: added `traversal_passwd_deep` (`../../../../../etc/passwd`) and
`traversal_passwd_abs` (`/etc/passwd`) to `DEFAULT_PAYLOADS` in `scanner.py`.
No oracle change.

### FN-1 closeout - status-code delta, not timing

Original analysis: "requires a temporal/paired-request oracle."

Empirical probe against DVWA at `low` security showed:
- `1' AND SLEEP(3)#` returns in 3.01s (MySQL SLEEP blocked from returning data, but the time delay fires - however this is unreliable cross-platform)
- **Status code delta is the reliable signal:** `1' OR '1'='1` -> 200, `1' AND '1'='2` -> 404
- Body length is essentially identical (4561 vs 4567, delta 0.1%) - length alone would not fire
- Numeric pairs (`1 OR 1=1` vs `1 AND 1=2`) do not differentiate (MySQL type coercion)

Fix: `src/janissary/detection/blind_sqli_oracle.py` - paired-request oracle
gated on status code, with length-delta fallback when neither payload is
reflected. Quoted string payloads only (`1' OR '1'='1` vs `1' AND '1'='2`).

## Non-goals (unchanged)

- No new scanner features without a real target.
- No score.py or emitter changes without a measurement need.
- POST-body inject deferred until crAPI is added as a real corpus app.

## Reference

- `benchmark/track_c/corpus-score.json` - the live baseline.
- `docs/PHASE-3-PLAN.md` - prior phase.
- `docs/AMENDMENT-24.md` - the trial model (TP/FP/FN/TN).
- `benchmark/track_c/SCHEMA.md` - case schema.
- `docs/decisions/ADR-006-traversal-collapse-oracle.md` - collapse oracle design.


---

## Status update — 2026-10-30 — v7.7.0 (Session B) closed the ADR-012 D2 SSRF-response-body path

The original Phase 4 plan (and the 7.5.0 release notes for ADR-012) noted
that three SSRF payloads (`metadata_http`, `metadata_v6`, `file`) could
not be detected via collaborator OOB alone and required a "response-body
detection path" that was **"deferred to a follow-up response-body detection
path."**

v7.7.0 implements that follow-up path:

- `src/janissary/detection/ssrf_response_oracle.py` — response-body oracle.
  Detects server-side fetch by matching fetched-service content in the
  response body. Gated by (a) baseline-differential (marker absent from
  baseline), (b) reflection stripping (marker must survive removal of the
  reflected payload — this distinguishes actual fetch from XSS-in-JSON).
- `--inject-in json-body --json-template PATH` — payload injection mode
  that substitutes into a JSON body template's `{{PAYLOAD}}` placeholder.
  Required because crAPI's SSRF endpoint accepts a URL inside a JSON body,
  not a query parameter.
- crAPI added as app 7 to the track-C corpus. Its SSRF endpoint
  (`POST /workshop/api/merchant/contact_mechanic`) is now detected:
  previously documented as `fn=1 aborts=1`, now `tp=1`.

Corpus impact:
- v7.6.0: `tp=8 fn=1 tn=21 aborts=1` (7 apps, crAPI included as gap)
- v7.7.0: `tp=9 fn=0 tn=24 aborts=0` (7 apps, gap closed)
- Precision 1.0 maintained, F1 0.9412 → 1.0

### What is still deferred

`--inject-in path` (Phase 1c) is still deferred. That is a **distinct
concern** from the SSRF response-body path: path-parameter injection is
about URL structure (`/api/users/{id}` vs `/api/users/1`), not SSRF
detection. Not closed by v7.7.0. When a corpus app justifies it, it
remains a Phase 1c candidate.

See also:
- `BENCHMARK.md` Amendment 23 (2026-10-30) — Track C corpus documented,
  hypotheses H-C1/H-C2/H-C3 stated as the falsifiable standard for
  future runs.
- `CHANGELOG.md` v7.7.0 entry — full feature description.
