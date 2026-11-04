# ADR-021 -- Crawler placement (defer until enterprise demand)

**Status:** Accepted (2026-11-04). Phase 0 Foundation.
**Supersedes:** None.
**Extends:** ADR-016 (vocabulary), ADR-017 (emission model).
**Blocks:** M36a completion (ADR series 016-021); M44-M45 (crawler implementation).

## Context

The uploaded roadmap proposed a Playwright-based headless crawler
in Phase 3 (Milestones M44-M45). The crawler was to discover
endpoints and parameters on complex Single-Page Applications, then
feed the parameter map into the existing JANISSARY scan engine.
The roadmap also suggested placing this crawler in a separate
proprietary repository, keeping it closed-source while the scan
core remained open.

This ADR captures Decision 2 from FUTURE-STATE-PLAN.md (option C
now, B if the crawler ships) and specifies the concrete trigger
under which the crawler work should begin. It does NOT commit to
building the crawler. M44 and M45 remain in the ASCENSION roadmap
but are marked conditional.

The FUTURE-STATE-PLAN.md analysis (Part 1, "What is risky as
written") documents the specific problems with the closed-source
crawler proposal:

- Legal ambiguity: a Playwright crawler feeding parameter maps
  into an Apache-2.0 scanner may be a derivative work depending on
  how it is wired. Splitting the community by closing the crawler
  compounds this ambiguity.
- The pattern that has worked elsewhere (Snyk, GitLab, HashiCorp)
  is open everything that a user runs locally, and proprietary only
  the multi-tenant workflow layer (dashboard, SSO, RBAC, audit).
  The crawler is local-user-facing, not workflow-layer.
- Scope: a production-grade crawler that handles modern SPAs
  (JS-rendered routes, WebSocket-driven state, auth flows) is
  6-8 weeks of engineering, not one of four quarterly milestones.

## Decisions

### D1. Crawler work is deferred (not cancelled)

M44 (`janissary-crawl` repo) and M45 (crawler-to-scan pipeline)
remain in `tools/ascension_state.json` but are conditional. They
are not part of any committed release. If the trigger in D3 fires,
they become active deliverables. If the trigger never fires, they
stay parked and Phase 3 is skipped.

This is the same pattern as Phase 5 and Phase 6 business milestones
(M21-M30): visible on the dashboard, not committed to a date,
conditional on external evidence.

### D2. When built, the crawler ships open-source

If D3 fires and the crawler work begins, the crawler is open-source
under Apache-2.0, in its own repository (`janissary-crawl`), with
no proprietary components. It emits a parameter-map file that the
existing `janissary scan` can consume via a simple shell pipe or a
future `--params-from` flag.

Rationale:

- The crawler is local-user-facing, not workflow-layer. It runs on
  the user machine, has no multi-tenant state, no shared data, no
  auth boundary with other users. Closing it would split the
  community without monetizing anything -- exactly the failure
  pattern from FUTURE-STATE-PLAN.md Part 1 ("Proprietary headless
  crawler in separate repo" as a risk).
- The proprietary layer (Phase 5 SaaS) is the multi-tenant workflow:
  dashboard, SSO, RBAC, audit. That layer talks to the core via a
  defined interface (ADR-018 D2). The crawler is not that layer.
- Open-sourcing the crawler builds the contributor funnel that
  Phase 5 depends on. Closing it starves the funnel before it can
  form.

### D3. Revisit triggers (any one is sufficient)

The crawler work begins if and only if at least ONE of the following
is true:

1. **A named enterprise** has requested crawler capability as a
   condition for a purchase or trial. This is the strongest signal:
   external demand with a commercial commitment behind it.
2. **Three or more named users** have independently asked for
   "point the scanner at a URL and let it discover endpoints" as
   a feature they would use. Three independent asks is the bar;
   two could be one noisy user, one is anecdote.
3. **A documented workflow gap** in the existing scan is unblockable
   without a crawler. Example: the current CLI requires `-p params`
   on every invocation, and no combination of `--json-template` +
   manual parameter specification covers a real customer use case
   (e.g., a customer with 500 endpoints who cannot manually list
   them).

If none of the three fire by 2027-06-30, M44-M45 are marked
`excluded: true` in `ascension_state.json` and the plan reverts to
Phase 2 (tri-session auth) directly into Phase 4 (local UI). The
crawler may still be built later if demand emerges; it just stops
being on the roadmap.

### D4. Non-goals (explicit)

The crawler, if built, does NOT do the following. These are
explicit scoping decisions to prevent scope creep:

- **Not a general-purpose web crawler.** No page ranking, no
  content indexing, no archiving. Its only job is to enumerate
  endpoints + parameters on a target the user is authorized to
  scan.
- **Not a fuzzer.** Discovery only. It emits parameter maps; it
  does not send payloads. Payload sending stays in the existing
  scan engine.
- **Not a login automator.** It accepts pre-authenticated sessions
  (cookie/bearer, same as `scan`), but does not perform login flows
  itself. Login automation is a separate concern that the scan
  engine already handles via `--cookie` / `--bearer`.
- **Not a WAF bypass tool.** It sends discovery requests at the
  same pace the scan engine sends payloads. No additional stealth
  or evasion beyond what the pacer provides (ADR-012 D1).
- **Not a replacement for `scan -p params`.** The existing
  parameter-list CLI remains. The crawler is additive; users who
  know their parameters keep using `-p`.

## Consequences

**Positive:**
- No 6-8 week engineering commitment for a capability that may
  not be used
- Preserves the option: if demand emerges, the crawler can be
  built on the same architecture without rework
- Keeps the contributor funnel intact: the crawler, when built,
  ships open-source
- Forces demand validation before engineering investment -- the
  same pattern as Gate 1 (heuristic mode), Gate 2 (tri-session),
  and Gate 4 (SaaS)

**Negative:**
- Users who expect "point at URL, get scan" need a two-step
  workflow (run crawl, then scan). This is more friction than a
  fully integrated crawler-scan product.
- If a competitor ships integrated crawl+scan first, JANISSARY
  has no response until the trigger fires. This is a market risk,
  not a technical one.
- The 2027-06-30 review date is a soft deadline. If no trigger
  fires by then, we mark M44-M45 excluded and move on -- which
  also means no crawler ever ships unless a new ADR revives it.

**Neutral:**
- No code changes ship with this ADR.
- M44-M45 remain on the dashboard with no delivery date.

## Alternatives rejected

**Option A: Build open-source crawler now (Phase 3 as scheduled).**

Rejected. 6-8 weeks of engineering against a capability that
nobody outside the project has yet asked for. Violates the
demand-before-code principle that governs Gates 1-4 in
FUTURE-STATE-PLAN.md.

**Option B: Build closed-source crawler now.**

Rejected. Same demand problem as Option A, plus the legal and
community risk documented in Context. This was the uploaded
roadmap's proposal and it is exactly what FUTURE-STATE-PLAN.md
Part 1 rejects.

**Option C: Defer crawler entirely (remove from roadmap).**

Rejected. Removing M44-M45 from the ASCENSION dashboard would
mean the capability is never revisited. Deferring with explicit
triggers (D3) is more honest: the option stays open, but the
commitment is conditional.

**Option D: Defer until named enterprise asks.**

Accepted. This ADR.

## References

- `docs/FUTURE-STATE-PLAN.md` Part 2 Decision 2 (open crawler,
  delay integration -- option C now, B if built)
- `docs/FUTURE-STATE-PLAN.md` Part 1 "What is risky as written"
  (proprietary crawler analysis)
- ADR-018 D2 -- commercial layer defined by interface, not by
  crawler placement
- ADR-012 D1 -- WAF pacing contract (crawler paces at same rate
  as scan)
- `tools/ascension_state.json` M44, M45 -- milestones marked
  conditional by this ADR

