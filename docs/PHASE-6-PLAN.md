# Phase 6 - Scope Decision

Status: **unresolved** (decision required from maintainer)
Entry point: b144be9, v7.10.2, 667/667 tests, corpus tp=11 fp=0 fn=0 tn=24 f1=1.0

## Purpose

Phase 5 closed the locked 7-app regression. Phase 6 has no defined scope.
This document records the three candidates discussed, their known state,
scope estimates, and risks, so the decision is a choice and not a
re-derivation. Nothing below is a commitment. No candidate has been started.

## Candidate A - Integration arms (Nuclei / SARIF)

**What it is.** Connect Janissary to external detection and reporting:
a Nuclei arm (shell out to nuclei, normalize JSONL into the finding model)
and a SARIF arm (emit results.sarif v2.1.0 for CI / code scanning).

**Known state - audit first.** The test tree already contains:
- tests/unit/test_nuclei.py
- tests/integration/test_sarif_output.py
- tests/integration/test_sarif_schema.py
- tests/unit/test_sarif_rules.py

So this candidate may be built, half-built, or scaffolded-then-abandoned.
**First task under this candidate is a 30-minute audit, not a build.**
Read those four files, run them, and report what works end-to-end versus
what is unit-tested against stubs only.

**Scope estimate.** Small if the audit finds working arms (documentation
plus corpus wiring). Medium if it finds stubs (build, wire, negative-check).
Unknown until audited.

**Dependencies.** nuclei binary availability; SARIF schema version pin.

**Risks.**
- Two external moving parts (nuclei version, SARIF schema evolution).
- An arm that only passes mock-based unit tests is a claim, not evidence.
  Same discipline as 4a2d0d1: demonstrate against a live target.

**Done looks like.** Nuclei findings normalized into the finding model for
at least one live corpus app; SARIF emits schema-valid v2.1.0 for the same
run; both wired into a reproducible command.

## Candidate B - New app category

**What it is.** Deploy one additional vulnerable app into benchmark/track_c:
image digest pinned in apps.json, startup documented in BOOTSTRAP.md,
corpus cases added. Primary motivation on the table: no current app has a
confirmed injectable POST+path target, so the v7.9.1 capability is
wire-verified but corpus-untested.

**Scope estimate.** Multi-hour (handover estimate). New deploy, digest pin,
BOOTSTRAP entry, corpus rows, fresh full run.

**Dependencies.** Docker; image digest reproducibility; BOOTSTRAP.md update.

**Risks.**
- An app that does not exercise anything the current 7 do not is padding.
  The concrete gap is POST+path; a candidate must plausibly close it.
- Fresh-volume state issues (gitea note in BOOTSTRAP.md) recur per app.
- crAPI compose already lives outside the repo; another external dependency
  worsens fresh-clone reproducibility.

**Open question.** Which app? WebGoat (broad, older Java stack), Juice Shop
(Node, overlapping surface with DVWA/bwapp), or a custom Flask (control,
maintenance burden). Answer needed before scoping.

**Done looks like.** New app pinned and startable from BOOTSTRAP.md alone;
at least one corpus case exercising a previously-untested capability
(ideally POST+path); fresh full run reproduces, or honestly documents the
delta (4a2d0d1 style).

## Candidate C - Deeper corpus

**What it is.** Expand cases.csv against the existing 7 apps: more trials,
more auth states, more injection points. No new deploys.

**Scope estimate.** Small per case. Diminishing returns after the first few.

**Dependencies.** None new.

**Risks.**
- Self-deception: more green on the same apps does not prove generalization.
  Every added case needs a stated reason it is non-trivial; a case that only
  re-tests what is green inflates the corpus without adding evidence.
- If a new case exposes an FN, that is the valuable outcome. Record it
  (4a2d0d1 style) before fixing.

**Done looks like.** Corpus grows with a written rationale per case; f1
stays 1.0 only if each new case was genuinely hard; any FN found is
recorded as a measurement commit before the fix.

## Recommended pre-decision step (candidate-independent)

Audit Candidate A. Cheap (~30 min), may collapse the decision (if the SARIF
and Nuclei arms already work, the build is small), and costs nothing if you
then choose B or C. Do this before committing to any direction.

## Decision

Direction: _unresolved_

Chosen: ______
Rationale: ______
First concrete task: ______
Exit criteria: ______

## Exit criteria template

Whichever direction is chosen, Phase 6 is done when:
- the capability is demonstrated against a live target, not only unit tests;
- any gap found is recorded in git history before it is fixed;
- full suite green and corpus numbers either reproduce or the delta is documented;
- package version matches newest tag (guard: tests/test_version_tag_consistency.py).
