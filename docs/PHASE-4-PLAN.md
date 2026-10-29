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
