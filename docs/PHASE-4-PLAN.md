# Phase 4 — Detection Gaps & Mode Extensions

**Status:** proposed (design only, no code yet)
**Prerequisite:** Phase 3 closed at `725f942` — corpus-wide baseline measured.
**Parent:** `docs/AMENDMENT-24.md` (Phase 3 harness), `docs/PHASE-3-PLAN.md`.

## Baseline state at Phase 3 close (commit `725f942`)

Corpus-wide aggregate from `benchmark/track_c/corpus-score.json`:

| Metric | Value | Note |
|---|---|---|
| Apps | 6 | dvwa, juice-shop, vampi, gitea, nextcloud, bwapp |
| tp | 5 | dvwa 2, juice-shop 1, bwapp 2 |
| fp | 0 | across all 21 safe trials |
| fn | 3 | dvwa 2, bwapp 1 — all confirmed-vulnerable endpoints |
| tn | 20 | scanner correctly quiet on safe endpoints |
| aborts | 1 | nextcloud `/` (302 redirect) |
| precision | 1.0 | no false positives |
| recall | 0.625 | every miss is a *detection gap*, not a false claim |
| f1 | 0.7692 | |
| fp_rate_safe | 0.0 | |
| unmatched_findings | 0 | no scanner hallucination on un-asked URLs |

Read: **the scanner never lies.** Every miss is on a known-vulnerable endpoint we've confirmed is real. That's the honest interpretation — Phase 4 is about closing FNs, not cleaning FPs.

## The three FNs (all confirmed vulnerable)

### FN-1: dvwa `/vulnerabilities/sqli_blind/?id=` (class `sqli_blind`)
- Endpoint returns distinct responses for TRUE vs FALSE conditions (blind injection is by definition real).
- Current scanner requires either a SQL error string or a response-shape delta the collapse oracle recognizes.
- **Gap:** the collapse oracle's `_aux_tiny_body` threshold (10% × baseline_mean, per handover §5) and the length-delta thresholds are too conservative for blind cases where the delta is small but consistent.
- **Fix shape:** add a blind-SQLi aux oracle — request the endpoint with a TRUE-condition payload and FALSE-condition payload, measure response length delta, require consistency across ≥2 pairs. Unit-testable with synthetic responses.

### FN-2: dvwa `/vulnerabilities/fi/?page=include.php` (class `traversal`)
- Endpoint returns distinct file content for different `page=` values (file inclusion is by definition real).
- Current scanner's traversal oracle compares baseline vs payload body but requires a signature-shaped delta the local-file-inclusion case doesn't produce (it returns different HTML, not an error page).
- **Gap:** traversal oracle too narrow — it looks for "canary is missing" or "error page replaced content," but LFI returns *different valid content*.
- **Fix shape:** add an LFI-shape oracle — request two distinct file paths known to exist on DVWA (e.g. `include.php` vs `include2.php`), verify response bodies differ meaningfully, then inject traversal payloads and require a third distinct body that isn't a 404 page.

### FN-3: bwapp `/directory_traversal_1.php?page=` (class `traversal`)
- Direct probe of `page=../../../etc/passwd` returns `root:x:` in the body (confirmed in cmd-81 §A).
- Same gap as FN-2 — scanner emits nothing because the body-content differential isn't a shape it recognizes.
- **Fix shape:** shares FN-2's new oracle. Would fire on bwapp immediately if FN-2's oracle is generic.

**Combined estimate for FN-1 + FN-2 + FN-3:** one to two sessions. FN-2's oracle is the hardest — it needs a body-content fingerprint that recognizes "different valid content" vs "error page" vs "same content reflected."

## The one known abort

### ABORT-1: `preflight()` returns `"empty body"` on 302-redirecting roots (CLOSED in cmd-91)
- Affected: nextcloud `/` (302 → `/index.php/login`), bwapp `/` (302 → `/portal.php`), likely any login-gated app root.
- Current code: `src/janissary/engine/scanner.py` line 398: `if not (r.text or "").strip(): return False, "empty body"`.
- **Gap:** preflight doesn't follow redirects on the initial probe, so it sees the empty 302 body and aborts before any real scan.
- **Fix shape:** in `preflight()`, either (a) pass `allow_redirects=True` on the probe request, or (b) treat 3xx as preflight-pass (a live app that redirects is a live app). Option (a) is more useful — it gives a real body to work with.
- **Cost:** one line, one test.
- **Justification:** two corpus apps hit this. Not speculative.

## The one mode gap (deferred from Phase 1c)

### POST-BODY-INJECT — structural analogue of Phase 1c (`--inject-in path`)
- Current scanner: query-param inject only. `--inject-in` accepts `query` (default); `path` is unimplemented (deferred 1c).
- Candidate apps needing POST-body inject: **crAPI** (`/workshop/...` form and JSON bodies), **Juice Shop** (`/rest/user/login` JSON body — SQLi in email field, XSS in multiple).
- **Decision recorded in Phase 3 §5:** do not build until a real corpus app justifies it. That justification is now available (Juice Shop is already in the corpus with 1 vuln case; crAPI is not yet added). But Juice Shop's *current* vuln case (search param) already fires — POST-body would only increase depth, not add new coverage unless we add crAPI or expand Juice Shop's case set.
- **Provisional sequencing:** do NOT start POST-body inject until (a) FN-1/2/3 are closed and (b) crAPI is added to the corpus as app 7, at which point POST-body mode has two justifying apps.

## Non-goals

- **No new scanner features without a real target.** Same discipline as Phase 1c / §5.
- **No score.py or emitter changes.** Both were hardened in `725f942`; further changes come from measurement needs, not speculative cleanup.
- **No `src/` tree dedupe.** The tree has two nested git repos (`janissary/.git` outer, `janissary/janissary/.git` inner) plus a 7.5.0 worktree. Which copies are load-bearing for the venv / inner repo hasn't been determined. Requires its own diagnostic (identify what's tracked where) before any rm. Not a Phase 4 concern.

## Suggested sequencing

1. **ABORT-1 first** (root-URL preflight fix). 1 line, 1 test, closes 1 abort in the corpus, demonstrates the "measure → fix → re-measure" loop. Lowest risk, highest clarity.
2. **FN-3 (bwapp traversal) next.** The body-content differential is the simplest case — confirmed by direct probe, single-payload shape.
3. **FN-2 (dvwa LFI) next** — same oracle as FN-3, adds one more app's coverage.
4. **FN-1 (blind SQLi) last of the FNs** — requires a temporal/paired-request oracle, most code.
5. **POST-body inject + crAPI** — only after 1-4 land, as its own design + implementation phase.

## On each phase-4 item, the loop is:

design commit → implementation → trial run → score → commit. If a trial doesn't fire, diagnostic first, minimal fix. Same discipline that closed Phase 3.

## Reference

- `benchmark/track_c/corpus-score.json` — the baseline that Phase 4 improves against.
- `docs/PHASE-3-PLAN.md` — prior phase.
- `docs/AMENDMENT-24.md` — the trial model (TP/FP/FN/TN).
- `benchmark/track_c/SCHEMA.md` — case schema, abort field added in `725f942`.
