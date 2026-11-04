# ADR-018 -- License framework (defer, define triggers)

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None.
**Extends:** ADR-016 (vocabulary), ADR-017 (emission model).
**Blocks:** M36a completion (ADR series 016-021).

## Context

The uploaded roadmap proposed a licensing transition: shift the
project from Apache-2.0 to GNU Affero General Public License v3
(AGPLv3), add a Contributor License Agreement (CLA), and require
copyright assignment from contributors. The stated purpose was to
prevent SaaS resellers from commercializing the code without
paying.

That instinct is correct. The mechanism is not. This ADR captures
the strategic decision (Decision 1, option D in FUTURE-STATE-PLAN.md)
and specifies the concrete triggers under which the license
question should be revisited. It does NOT execute a license change.

The FUTURE-STATE-PLAN.md analysis (Part 1, "What is risky as
written") documents the specific problems with the AGPL-now
proposal:

- Retroactive relicensing of Apache-2.0 code requires consent from
  every prior contributor. Today that set is empty (clean baseline),
  but the consent requirement means the window closes as soon as
  the first external PR lands.
- AGPL is banned outright by many enterprise legal departments.
  If the target customer is a Fortune 500 security team, AGPL is
  a 6-month procurement blocker before the first line of code is
  read.
- BUSL (Business Source License) is not OSI-approved and has the
  same procurement friction as AGPL, plus "not really open source"
  branding risk.

The hybrid pattern (Decision 1D) is: keep the core Apache-2.0,
build the commercial SaaS layer as separate proprietary code that
talks to the core over a defined interface. This is what Snyk,
GitLab, and HashiCorp (pre-BUSL) all did successfully.

## Decisions

### D1. Current license stays Apache-2.0

The core repository (everything currently under `src/janissary/`)
remains Apache-2.0. No license change is executed by this ADR. No
CLA is introduced. No copyright assignment is required from
contributors.

Contributors who submit PRs sign the standard Apache-2.0 inbound
license terms by the act of submitting (as specified in the
Apache-2.0 license itself, section 5). No additional CLA is needed
until ADR-025 (license decision execution) says otherwise.

### D2. Commercial layer is separate, proprietary, defined by interface

The eventual commercial SaaS layer (dashboard, SSO, RBAC, audit,
multi-tenancy -- see FUTURE-STATE-PLAN.md Part 3 Phase 5) will be
proprietary code in a separate repository or a separate top-level
directory. It communicates with the Apache-2.0 core through a
defined interface (HTTP API or Python package boundary).

This is the "hybrid" pattern from Decision 1, option D. It is
what Snyk, GitLab, and HashiCorp (pre-BUSL) all did successfully.
The core remains freely adoptable. The commercial layer monetizes
the workflow, not the detection logic.

### D3. Revisit triggers (all three must hold)

The license question is revisited (via ADR-025) if and only if
ALL of the following are true:

1. **100+ GitHub stars** on the public repository
2. **5+ external contributors** with merged PRs
3. **At least one named enterprise** expressing interest in
   managed hosting or commercial support

If any of the three is absent, the license stays Apache-2.0. The
bar is deliberately high. The failure mode we are guarding against
is the "went AGPL too early, killed the contributor funnel" pattern
documented in FUTURE-STATE-PLAN.md Part 4 (Failure Pattern 2).

### D4. CLA deferred indefinitely

No Contributor License Agreement is introduced now. If the project
reaches the D3 trigger threshold, a CLA may be introduced as part
of ADR-025. Until then, standard Apache-2.0 inbound contribution
terms apply.

Rationale: A CLA is infrastructure with real friction. It requires
an automated bot (CLA Assistant or similar), legal review, and
onboarding overhead for every contributor. Introducing it before
there are contributors signals "we are not ready for you" more than
"we are enterprise-ready." Wait for the contributors, then decide.

## Consequences

**Positive:**
- Zero legal friction for contributors (standard Apache-2.0 terms)
- Zero procurement friction for enterprise adopters
- Clean baseline: no consent required to revisit later
- Preserves the hybrid commercial pattern that has worked for
  Snyk, GitLab, HashiCorp

**Negative:**
- Apache-2.0 permits SaaS resellers to commercialize the code
  without paying. This is a real business risk -- but smaller than
  the risk of AGPL killing adoption.
- If the project does succeed commercially and a competitor forks
  to build a commercial SaaS on the Apache-2.0 code, we would have
  limited legal recourse.
- The revisit triggers (D3) are project metrics, not legal metrics.
  They measure community traction, not business need.

**Neutral:**
- No code changes ship with this ADR.
- No new files, no CLA bot, no LICENSE.md changes.

## Alternatives rejected

**Option A: Execute AGPLv3 now.**

Rejected. Enterprise procurement blocker, closes the contributor
consent window (small but real), and solves a problem that does
not yet exist (no SaaS resellers). See Decision 1, FUTURE-STATE-PLAN.md.

**Option B: Execute BUSL now.**

Rejected. Not OSI-approved. Same procurement friction as AGPL.
Branding risk ("not really open source").

**Option C: Introduce CLA now (regardless of license).**

Rejected. See D4. CLA infrastructure before contributors
exists is a negative signal.

**Option D: Defer framework with defined triggers.**

Accepted. This ADR.

## References

- `docs/FUTURE-STATE-PLAN.md` Part 2 Decision 1 (hybrid Apache +
  proprietary SaaS wrapper)
- `docs/FUTURE-STATE-PLAN.md` Part 4 Failure Pattern 2 (license
  change alienates contributors)
- ADR-016 -- Verified vs Discovery vocabulary (orthogonal but
  referenced for context)
- `LICENSE` -- current Apache-2.0 license text
- Apache-2.0 section 5 -- inbound contribution terms

