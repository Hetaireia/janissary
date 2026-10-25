# ADR-007 — Finding identity scheme (Phase 0.3)

**Status:** Accepted (2026-10-26)
**Depends on:** ADR-002 (fingerprint pattern), `agent.Finding.dedup_key()` (predecessor)
**Blocks:** 0.3a (this ADR + module), 0.3b (wiring)

## Context

Phase 0.3 is "stable finding fingerprint" per the 1.3b handover. It was
never designed. Three observations reshaped the problem during scope
discovery:

1. **A cross-scan identity primitive already exists** in
   `agent/finding_store.py` — `Finding.dedup_key()`, a SHA-256 truncated
   to 128 bits over `(target, category, finding_type, discriminator)`.
   It is persisted (`load()` / `save()` / `all()`), used by
   `FindingStore.add()` for dedup, and stable across runs.

2. **The existing primitive does not reach scan output.**
   `agent.Finding.dedup_key()` is landlocked in the agent store.
   `engine/scanner.py:ScanFinding`, `engine/grouping.py`,
   `output/emitter.py`, and `cli._write_sarif` all operate on
   `ScanFinding`, a separate dataclass that carries no dedup or
   fingerprint field. SARIF output (`cli.py:944`) emits `ruleId` but has
   no `partialFingerprints`, the field SARIF 2.1.0 defines for
   cross-run identity.

3. **`agent.Finding.dedup_key()` is unstable.** It hashes the raw
   `target`, so `http://EXAMPLE.COM/a` and `http://example.com/a`
   produce different keys for the same endpoint. It does not strip
   volatile query parameters (`?sessionid=...`, `?ts=...`). Cross-scan
   identity in the presence of any of these is broken today.

Scope discovery resolved three candidates:

- **(a) Formalize the existing store primitive** into a versioned
  scheme (fix normalization, add prefix).
- **(b) Add a fingerprint to `ScanFinding`** that reaches emitter,
  SARIF, and any downstream consumer.
- **(c) Both, with (b) derived from (a)'s scheme.**

(c) is the correct scope. 0.3 formalizes the scheme (this document),
ships it as a pure module, and wires it into both `ScanFinding` and
`agent.Finding` so the identity is consistent across every surface
where a finding appears.

## Decisions

### D1. Fingerprint input tuple

Inputs: `(canonical_target, discriminator, category, finding_type)`.

- **canonical_target** — see D2.
- **discriminator** — the injectable parameter name for scanner
  findings, or the resource name for agent/adapter findings.
- **category** — the finding's category, **post-reclassification**.
  Scanner reclassification (`scanner.py:692-700`) mutates `category`
  from probe-family to evidence-grounded class before finding
  construction. The fingerprint consumes the evidence-grounded class,
  which is the correct identity: a DB error triggered by an XSS probe
  is a SQLi, and the fingerprint says SQLi.
- **finding_type** — the finding's type.

**Deliberately excluded from v1:**

- `payload_name` / `payload_value` — varies per probe; not part of
  identity.
- Response body / status / timing / length — evidence-level; can
  change between scans even when the bug is unchanged.
- `severity` — evidence-level; can escalate as more evidence is
  gathered.
- `detail` — evidence-level; can carry rotating tokens.

If payload-level identity is ever needed (e.g. to track one payload
family's behaviour across scans separately from the bug), it becomes
`jfv2` or a sibling `partialFingerprints` key — not an extension of v1.

### D2. Target canonicalization

`canonicalize_target(raw, exclude)` returns:

- `scheme` lowercased.
- `netloc` lowercased.
- `path` preserved verbatim (case-sensitive on most servers).
- `params` (`;k=v`) dropped — unused by all target URLs observed.
- `query`:
  - parsed with `keep_blank_values=True`,
  - pairs whose name is `exclude` dropped (the injected parameter),
  - pairs whose name is in `VOLATILE_PARAMS` dropped,
  - pairs sorted `(k, v)` lexicographic,
  - pairs re-encoded with `urlencode` (stable form).
- `fragment` dropped.
- `?` dropped if no pairs remain.

Non-URL strings (file paths, git repo identifiers, bare hostnames)
fall through to `raw.strip().lower()` — identity preserved without URL
semantics.

**Why exclude the discriminator?** `_request` builds the request URL
with the payload injected into `param`. So `ScanFinding.url` on a
finding is `https://target/?q=' OR '1'='1` — the injected form. Two
findings on the same param with different payloads have different
`url` values but are the same bug. Excluding the discriminator from
the query and using it separately as an explicit tuple element restores
the endpoint identity. For `agent.Finding`, `target` is the base URL
(no injected param); the `exclude` is a no-op unless the base URL
happens to carry the discriminator as a real param.

**Why `VOLATILE_PARAMS` is conservative (11 entries, not 20+).**
Aggressive stripping (`key`, `auth`, `token`, `t`, `sid`) risks
**false merges** — two real bugs on the same endpoint collapsed into
one fingerprint because a legitimate query param was stripped. A false
merge means the analyst never sees the second bug. Under-stripping
risks **false splits** — same bug reported twice because a rotating
session ID wasn't stripped. An analyst can merge a false split in
seconds; a false merge may never be noticed. For enterprise
(SARIF-driven dashboards, Jira sync, SLA tracking), false merges are
strictly worse. So `VOLATILE_PARAMS` keeps only params that are
essentially guaranteed volatile: session IDs (`session`, `sessionid`,
`jsessionid`, `phpsessid`), CSRF nonces (`csrf`, `csrftoken`,
`nonce`), cache-busters/timestamps (`_`, `ts`, `timestamp`), and
query-carried JWTs (`jwt`). Everything else is preserved.

### D3. Output format

`jfv1:<32-hex>`.

- **`jfv1:` prefix** versions the scheme. A future `jfv2:` can
  coexist in the same store without invalidating `jfv1:` entries.
- **32-hex (128 bits)** matches the legacy `dedup_key()` width.
  128 bits is sufficient for the collision domain (per-bug-per-param
  across scans of one target). Birthday bound is not a concern at this
  domain.
- `fp[0:5] == "jfv1:"` is a stable test surface.

### D4. Placement and consumers

Module lands at `src/janissary/finding_identity.py` — top-level, next
to `auth.py`, `scope.py`, `legal.py`. It is a pure primitive imported
by two disjoint packages (`engine` and `agent`); placing it in either
would create an artificial directionality constraint. Top-level
placement signals cross-cutting nature and avoids pulling
`detection/analyzer.py` into the agent import path.

Consumers wired in 0.3b (not this PR):

- `engine/scanner.py:ScanFinding` — new `fingerprint: str = ""` field,
  populated in `__post_init__` if empty. `cli._summary_to_dict` emits
  it in scan JSON output.
- `agent/finding_store.py:Finding` — new `fingerprint: str = ""` field,
  populated in `__post_init__` if empty. `dedup_key()` returns
  `self.fingerprint` unconditionally. `from_dict` backfills via
  `__post_init__` on legacy records.
- `output/emitter.py:_normalize_finding` — new `fingerprint` output
  key; `id` populated from `fingerprint` when no explicit `id` is set.
  `_REQUIRED_FINDING_KEYS` gains `fingerprint`.
- `cli.py:_write_sarif` — emits
  `partialFingerprints: {"finding/v1": f.fingerprint}`.

### D5. Migration

Out of 0.3. No batch rewrite. `Finding.from_dict` runs `__post_init__`,
which computes the fingerprint if absent. Legacy stores are read
correctly and re-saved with fingerprints populated. The committed 19MB
benchmark artifact is not modified — it is scored on fields it already
carries, not on fingerprint.

Note: legacy stores may silently merge entries on next `load()` when
their raw targets differed only in case or volatile params. This is
the intended dedup behavior of D2, and is documented here so it is not
a surprise.

### D6. Benchmark acceptance

Metric-neutral, verified by construction:

- The benchmark gate (`benchmark-gate.yml`) scores the committed
  artifact — not a live scan — against ground-truth vuln IDs, matching
  on `(param, category, finding_type)`. Adding a `fingerprint` field
  to `ScanFinding` cannot change TP/FN/FP on the artifact because the
  artifact is static and does not carry the field.
- No change to `classify_root_cause`, `_ROOT_CAUSE_MAP`,
  `_REFLECTION_TYPES`, or the values of `param`/`category`/
  `finding_type`. Grouping is untouched.

Acceptance gate: `benchmark-gate` CI green on the PR; F1=0.921
unchanged, FP=0. Same gate as ADR-006 D6.

### D7. Stability contract

For any two findings F1, F2 constructed from scans of the same target
with the same bug, `F1.fingerprint == F2.fingerprint`.

Tested by:

- `test_fingerprint_ignores_injected_payload` — different payload
  values on same endpoint/param yield identical fingerprints.
- `test_fingerprint_ignores_volatile_query_params` — session IDs and
  timestamps in URL don't move the fingerprint.
- `test_fingerprint_ignores_host_case` — case variation in host
  doesn't move the fingerprint.
- `test_fingerprint_ignores_query_order` — query order doesn't move
  the fingerprint.
- `test_fingerprint_stable_across_calls` — determinism within a
  process. Cross-process determinism relies on SHA-256 and stdlib
  `urllib.parse`, both specified and implementation-stable.

### D8. 0.3a / 0.3b boundary

**0.3a (this ADR + module + unit tests):**

- `src/janissary/finding_identity.py` — pure functions,
  `canonicalize_target` and `compute_fingerprint`.
- `tests/unit/test_finding_identity.py` — determinism, field
  sensitivity, payload insensitivity, volatile-param stripping,
  format invariants, Unit-Separator field-boundary safety,
  `VOLATILE_PARAMS` conservativeness.
- No wiring. No dataclass changes. Mergeable independently.

**0.3b (wiring + integration):**

- `ScanFinding.fingerprint`, `ScanFinding.__post_init__`.
- `Finding.fingerprint`, `Finding.__post_init__`, `dedup_key()`
  delegation, `from_dict` backfill, `FINDING_KEYS` update.
- `cli._summary_to_dict` — emit `fingerprint`.
- `cli._write_sarif` — `partialFingerprints`.
- `output/emitter._REQUIRED_FINDING_KEYS` — gain `fingerprint`.
- `output/emitter._normalize_finding` — emit `fingerprint`; populate
  `id` from `fingerprint`.
- Integration tests: end-to-end scan -> emitted JSON has fingerprint;
  end-to-end scan -> SARIF has `partialFingerprints`; agent store ->
  save -> reload -> dedup key stable.

## Consequences

**Positive.**

- Cross-scan identity is available on every surface where a finding
  appears (scan summary, emitted JSON, SARIF, agent store).
- Downgrades `id: null` in emitter output to a meaningful value. The
  `_REQUIRED_FINDING_KEYS` contract already required `id`; populating
  it is strictly more useful for SARIF/dashboard consumers.
- Prepares Phase 2.x (dashboard dedup, scheduled rescan reopening) and
  Phase 6 (enterprise integration) with the identity primitive they
  need.
- `agent.Finding.dedup_key()` becomes stable across URL case variation
  and volatile query params. Stores that previously held duplicates of
  the same bug under different raw URLs are silently deduplicated on
  load (behavior change, documented in D5).

**Neutral.**

- 0.3a is purely additive. No existing module touched. No test
  modified. Mergeable with zero risk of behavior change.

**Negative, minor.**

- `Finding.dedup_key()` now returns `jfv1:`-prefixed value rather than
  bare hex. Any external script that parses `dedup_key()` output by
  inspecting the first characters or expecting specific length will
  need updating. Internal consumers (`FindingStore._keys`) are
  unaffected.
- `emitter._normalize_finding` now populates `id` from `fingerprint`.
  Consumers relying on `id == null` as a signal will need updating.
  Consumers using `id` for identity get correct behavior without
  change.

**Deferred.**

- Payload-level identity (per family), evidence accumulation across
  scans, severity-escalation-aware reopening, SLA/SLO tracking, and
  versioned migration of legacy stores are Phase 2.x / 6 concerns.
  Not in 0.3.

## Alternatives considered and rejected

- **Reuse `agent.Finding.dedup_key()` as-is.** Rejected — it is
  unnormalized (raw target), unversioned (no prefix), landlocked
  (does not reach scan output), and lacks field-boundary safety
  (uses `"|"` which can appear in URLs).
- **Include `payload_name` in the fingerprint.** Rejected — payload
  varies per probe. Two payloads finding the same bug are the same
  bug; the fingerprint would split them.
- **Include response body or content fingerprint.** Rejected — body
  carries rotating tokens that break cross-scan stability.
  `detection/analyzer.body_fingerprint` is a per-response primitive;
  using it as a finding-identity input reproduces exactly the
  instability the scheme is designed to eliminate.
- **Use `root_cause` (from `grouping.classify_root_cause`) instead
  of raw `category` + `finding_type`.** Rejected — precision over
  aggregation. Bug-level rollup is a *view* (group finding
  fingerprints by `classify_root_cause`); the primitive must not lose
  granularity. False merge (two bugs -> one ticket) is worse than
  false split (two tickets, analyst merges).
- **Aggressive `VOLATILE_PARAMS` (stripping `key`, `auth`, `token`,
  `t`, `sid`).** Rejected — see D2 rationale. False merges are worse
  than false splits for enterprise.
- **Full 256-bit hex.** Rejected — 128 bits is sufficient for the
  collision domain, matches existing `dedup_key` width, and keeps
  fingerprints short enough to embed in SARIF, ticket descriptions,
  and log lines without truncation pain.
- **Lazy `@property` for fingerprint.** Rejected —
  `dataclasses.asdict` does not serialize properties, and a lazily-
  computed field breaks the invariant that `asdict(finding)`
  roundtrips through `from_dict`. Eager `__post_init__` is the correct
  pattern.
- **Require explicit `fingerprint=...` at every `ScanFinding`
  construction site.** Rejected — nine call sites, easy to miss one,
  and the fields are always available at construction.
  `__post_init__` centralizes.

## References

- ADR-002 — baseline_struct fingerprinting (pattern precedent).
- ADR-006 — traversal collapse oracle (ADR format precedent).
- `agent/finding_store.py` — existing `Finding.dedup_key()`
  (superseded by D3 format).
- `engine/scanner.py:ScanFinding` — consumer of D4 wiring.
- `cli.py:_write_sarif` — SARIF output site, gains `partialFingerprints`.
- `output/emitter.py:_REQUIRED_FINDING_KEYS` — output schema contract.
- SARIF 2.1.0 §3.27.17 — `partialFingerprints` specification.
- handover session-1.3e §11 — scope discovery questions.
- handover session-1.3e §9 — read-order list (three path errors
  corrected during discovery: `detection/fingerprint.py` ->
  `recon/fingerprint.py`; `engine/finding_store.py` ->
  `agent/finding_store.py`; `tests/unit/test_fingerprint.py` is the
  recon fingerprinter, not a finding-identity test).
