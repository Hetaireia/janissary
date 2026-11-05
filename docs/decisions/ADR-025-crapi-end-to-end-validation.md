# ADR-025 -- crAPI end-to-end validation (M43)

**Status:** Accepted (2026-11-05). Phase 2 close.
**Supersedes:** None.
**Amends:** FUTURE-STATE-PLAN.md L157 (tri-session-vs-crAPI deferred to M43.5).
**Extends:** ADR-023 (tri-session), ADR-024 (IDOR), SCHEMA.md v2.1 (multi-container apps).

## Context

Plan L146-158 scopes Phase 2 as "Tri-Session Auth (Months 4-6) -- M41-M43"
with M43 specifically:

- L157: `[ ] Tri-session auth works against crAPI end-to-end`
- L250: `| -- | M43 | crAPI end-to-end validation |`

M41 delivered tri-session rotation (ADR-023). M42 delivered IDOR candidate
detection (ADR-024). M43 is the validation milestone -- proof those features
work against a real target, not just synthetic unit tests.

Probe on 2026-11-05 (post-M42) found crAPI ~80% pre-staged from a prior
session: `apps.json["crapi"]` has all 10 image digests pinned, `cases.csv`
has 5 trial rows (3 safe + SSRF + SQLi blind), both JSON templates exist,
and `runs/20261030T110245Z-crapi/` shows a clean prior run (TP=2, FP=0,
FN=0, TN=3, F1=1.0).

But there is a scope conflict:

- Plan L157 says "tri-session auth works against crAPI"
- `apps.json["crapi"].login` is single-session (one email/password pair)
- `runner.py` does one login per scan; no multi-identity loop

Running tri-session against crAPI would require 2-3 accounts, a runner
extension (multi-login + rotation exercise), and 3-5 new trial rows to
prove rotation happened without abort. That is not what M43's name says.

## Current state (evidence)

Probe 2026-11-05:

1. **Prior crAPI run**: `runs/20261030T110245Z-crapi/score.json` = F1=1.0,
   TP=2, TN=3, zero unmatched, zero aborts, zero stderr. Both vuln trials
   (SSRF, SQLi blind) found; all 3 safe endpoints clean.

2. **`score.py` CLASS_MAP has 5 keys** (sqli, sqli_blind, xss, cmdi,
   traversal) -- no `ssrf`. Scoring works because SCHEMA.md v2.1
   prioritises `expected_finding_class` column; CLASS_MAP is only the v1
   fallback. crAPI rows set `expected_finding_class = ssrf`, so the run
   scored correctly. The CLASS_MAP gap is real but latent -- would only
   trigger on a case missing the column.

3. **`apps/crapi/` documentation directory is absent.** dvwa, juice-shop,
   webgoat each have one; crAPI does not.

4. **No `verify_url`** on `apps.json["crapi"]`. bwapp has one
   (`/portal.php`); the other apps do not. Optional per SCHEMA; adds a
   diagnostic signal for silent login failures.

5. **crAPI containers not currently running.** Prior run made from a
   state whose specific container contents are not preserved.

6. **Plan L157 not annotated** -- currently `[ ]` pending despite a
   passing run existing in the repo.

## Decisions

### D1. M43 = crAPI single-session end-to-end validation

Validate the current crAPI config (single-session login, 5 trial rows)
end-to-end. Produce a fresh run dated 2026-11-05 that reproduces the
2026-10-30 result. This satisfies M43's name without scope expansion.

### D2. Plan L157 (tri-session vs crAPI) explicitly deferred to M43.5

The plan's checkbox "Tri-session auth works against crAPI end-to-end" is
narrower than M43's name. It requires:

- 2-3 crAPI accounts in `apps.json["crapi"].login_alt` (or sessions list)
- `runner.py` extension: run each trial as identity A then identity B,
  verify both succeed without 401 abort
- 2-3 new cases.csv rows: endpoints where A and B both return 200
- Scoring rules: verify no aborts, TPs for both identities

That is a ~2-day milestone. ADR-025 records it as M43.5 scope in
`docs/FUTURE-STATE-PLAN.md`, not M43's.

### D3. Add `ssrf` to `score.py` CLASS_MAP

Defensive coverage. Current scoring works because crAPI rows set
`expected_finding_class`, but the CLASS_MAP fallback would fail if any
future crAPI row (or any other app's SSRF row) omitted it. Adding:

```python
"ssrf": {"ssrf", "ssrf:oob", "ssrf:response", "ssrf:blind", "ssrf:metadata"},
```

Same shape as other entries. No behavior change for existing runs (all
cases have `expected_finding_class` set). Three lines of defensive code.

### D4. Add `apps/crapi/README.md` mirroring webgoat's template

Per `apps/README.md` structure. Content: base URL, image digests summary,
auth flow, trial class, start command, known vulns, prior-run reference.
Serves (a) standalone documentation of crAPI's role in the corpus, (b)
pattern for future multi-container apps.

### D5. Add `verify_url` to `apps.json["crapi"]`

`verify_url: "/identity/api/v2/user/dashboard"` matches bwapp's
`/portal.php` pattern. Used by runner post-login to confirm auth
succeeded before scanning. Optional per SCHEMA; improves diagnostics.

### D6. Fresh run required (2026-11-05)

The 2026-10-30 run is evidence but not validation -- it was made from a
stack whose specific container state we can no longer reproduce exactly.
M43 delivers:

- Tear down any crAPI stack
- `docker compose -f ..\\crapi\\deploy\\docker\\docker-compose.yml up -d`
- Wait for all 10 services healthy (30-120s cold start)
- `python -m benchmark.track_c.runner --app crapi`
- `python -m benchmark.track_c.score --app crapi`
- Verify TP=2, FP=0, FN=0, TN=3, F1=1.0

If the fresh run reproduces the prior result, M43 is complete. If not
(image behavior drift, config drift, stack not healthy), investigate and
fix before marking delivered.

### D7. Both runs preserved in `runs/`

Prior `20261030T110245Z-crapi/` stays. New `2026-11-05T*-crapi/` added.
The `runs/` directory is an evidence trail, not current state. Deletion
would erase the "before" that justifies "after".

### D8. Update `benchmark/track_c/README.md` "Targets" list

Current targets list: DVWA, OWASP Juice Shop, OWASP WebGoat. Add crAPI
between juice-shop and webgoat. Note crAPI's multi-container nature and
prior-passing status.

### D9. `corpus-score.json` inspection deferred to M43-3

Probe showed `corpus-score.json` is 470 lines / ~10.8 KB. If it already
has a `crapi` block with matching numbers (TP=2, etc.), M43 does not
touch it. If absent, M43 adds the block. Deferred because the probe did
not read the file -- M43-3 inspects and acts.

### D10. Update `docs/FUTURE-STATE-PLAN.md` L157

Change `[ ] Tri-session auth works against crAPI end-to-end` to
`[ ] Tri-session auth works against crAPI end-to-end (deferred to M43.5;
M43 ships single-session validation -- see ADR-025)`. Plan stays honest
about what shipped versus what is deferred.

### D11. No new unit tests for M43

M43's deliverable is:

- One code change (CLASS_MAP entry, D3) -- testable but not covered by
  existing tests; adding a test for a dict literal is low-value
- Three documentation changes (README additions)
- One verification artifact (fresh run)

Unit tests validate code behavior; M43 has almost no code. If `score.py`
needs a new branch, the fresh crAPI run itself verifies it. Adding
`test_score_class_map_has_ssrf` would test a constant -- not meaningful.

### D12. Re-run reproduces TP=2/FP=0/FN=0 required before delivery

D6's fresh run must be green. If it is not (e.g. crAPI's startup differs
on the current Docker version, or an image drifted), M43 is not
delivered. Fix the drift, then re-run. Same discipline as M41/M42:
verify-before-commit.

## Consequences

**Positive:**
- crAPI's role in the corpus is documented (apps/crapi/README.md)
- Fresh run produces evidence dated 2026-11-05 that anyone can inspect
- Plan L157's deferral is explicit, not silent
- Multi-container apps get a template for future onboarding
- CLASS_MAP defensive coverage closed
- Milestone closes with an artifact (score.json) not just a claim

**Negative:**
- Plan L157's literal checkbox remains unchecked; M43 "completes" without
  satisfying it. Mitigation: documented in D2 + plan annotation (D10).
- Fresh run depends on crAPI stack health at validation time. Some image
  tags are `latest`; if the registry drops a tag, apps.json pins a
  digest that may become unavailable. Low probability but nonzero.
- One more run in `runs/` (minor).

**Neutral:**
- Scope: ~3 lines code + 1 doc file + 1 verify_url field + 1 live run.
  Much smaller than M41/M42.
- M43.5 becomes the tri-session-vs-crAPI milestone.
- Follow-up path clear: M44 (janissary-crawl) begins; M43.5 in parallel.

## Alternatives rejected

**A: M43 = full Phase 2 close (single-session + tri-session + IDOR).**
Rejected per D2. Scope bloats to 2-3 days. Session discipline argues for
smaller, verifiable milestones. M43 as single-session is enough; tri-
session-vs-crAPI is M43.5.

**B: Delete the 2026-10-30 run and require only fresh.**
Rejected per D7. The prior run is evidence that the config works;
deleting it deprives future sessions of "this config passed on date X".
Preserve both.

**C: Skip ssrf in CLASS_MAP (works today via expected_finding_class).**
Rejected per D3. Latent bugs are worse than fixed ones. Three lines of
defensive code, no behavior change, easy future-proofing.

**D: Skip fresh run, cite 2026-10-30 as evidence.**
Rejected per D6. Prior run was made in a session whose state we cannot
reproduce. Fresh run costs ~5 minutes and produces airtight evidence.

**E: Mark plan L157 as `[x]` anyway.**
Rejected per D10. False checkmarks are the class of drift ADR-022 and
ADR-024 addressed. L157 stays honest.

## References

- `docs/FUTURE-STATE-PLAN.md` L146-158, L250
- `benchmark/track_c/SCHEMA.md` v2.1 -- trial model, multi-container apps
- `benchmark/track_c/BOOTSTRAP.md` -- crAPI start command
- `benchmark/track_c/apps.json` -- crAPI config (10 image digests)
- `benchmark/track_c/cases.csv` -- 5 crAPI trial rows
- `benchmark/track_c/runner.py` -- capture_jwt_from_json path
- `benchmark/track_c/score.py` -- CLASS_MAP location
- `benchmark/track_c/runs/20261030T110245Z-crapi/` -- prior passing run
- `benchmark/track_c/apps/webgoat/README.md` -- template for apps/crapi/
- `docs/decisions/ADR-023-tri-session-auth.md` -- M41 (rotation mechanism
  M43 does not exercise; M43.5 will)
- `docs/decisions/ADR-024-idor-candidate-probe.md` -- M42 (IDOR probe M43
  does not exercise; separate validation path)
- `..\\crapi\\deploy\\docker\\docker-compose.yml` -- crAPI stack definition
