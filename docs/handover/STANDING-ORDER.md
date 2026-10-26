# JANISSARY - Operator Standing Order

**Issued:** 2026-10-26
**By:** Operator
**Binding on:** All sessions from 2026-10-26 forward
**Supersedes:** Any prior delegation boundary in handover section "Do NOT"

## The order

The assistant holds delegated authority to make decisions advancing JANISSARY
toward the best DAST tool on the current and future markets, with explicit
priority on enterprise readiness. The operator's role is execution and
course-correction; routine scope decisions do not require operator approval.

Solutions must be automated wherever possible. Human-remembered process steps
are a defect class, not a control.

## What this order does NOT authorize

- Force-push, rewrite of published history, or push on red CI.
- Regeneration of the committed benchmark artifact (breaks F1 across history).
- Alteration of ADR-003 traversal ceiling without the Docker evidence gate.
- Addition of AI/LLM features the test suite cannot verify deterministically.
- Bypass of Process Rule 1 (whole-tree pre-commit gate). The rule may be
  automated (pre-commit framework); it may not be shortcut.

## What this order does authorize

- Selection, scheduling, and execution of next-scope work from the roadmap menu
  without per-item operator approval.
- Creation and amendment of ADRs, provided the change is documented in the ADR
  itself and in the session handover.
- Addition of developer-facing tooling (linters, hooks, schema validators,
  fixtures) that hardens the release process.
- Deferral of blocked work (Docker-gated, target-gated) without re-litigation.

## Strategic thesis (recorded for continuity across sessions)

JANISSARY's moat is signal quality and cross-scan stability, not rule coverage.
Competitors (ZAP, Burp, Invicti, Acunetix) will out-cover us for years; chasing
coverage we cannot measure is a losing game (see pathtraver F1 0.049-0.308,
Docker-blocked). "Best on the market" means: highest signal-to-noise, strongest
identity stability, most complete enterprise surface, and a release process
that cannot ship broken code. "Future markets" means AI-agent-orchestrated
scanning - our advantages are deterministic output, stable fingerprints, and
SARIF compliance. Do not add AI features the suite cannot verify.

## Referenced by

Every session handover from 2026-10-26 forward MUST contain a section titled
"Standing order" that quotes the paragraph above and links to this file.