# L03 — Framework-Specific SQL Injection: Failure Classification

**Status:** Classification frame (no implementation)
**Parent:** JAN-L03, ADR-027 (structural precedent for classify-before-measure)
**Scope:** Analytical only. No payload, scanner, oracle, or threshold changes. This document establishes the taxonomy and evidence requirements any future L03 implementation must measure against.

## 1. Problem

JAN-L03 records "Not Started": no ORM profiles, no dialect selection, no delivery-path analysis. Before any of those can be built, the project needs to distinguish three outcomes for a SQLi payload that does not produce a finding:

- the payload was **delivered** to a sink and executed, but the response revealed nothing
- the payload was **neutralised** before reaching a sink (parameter binding, escaping, WAF)
- the outcome is **indistinguishable** from the response alone

Without that distinction, "false negative" is one bucket and any recall improvement is unfalsifiable.

## 2. Operational definitions

**Delivered** — the payload reached query construction and executed. Evidence: a channel observes execution (dialect error string, union extraction, reproducible boolean response change, reproducible timing delay) but no finding was emitted because of oracle/threshold/aggregation, not because the query did not run.

**Neutralised** — the payload was prevented from executing. Evidence: a controlled comparison shows the delivery path transformed it (binding visible, escaping observable, WAF block response), or the dialect-specific syntax that would have executed is absent from what the query received.

**Indistinguishable** — neither delivered nor neutralised evidence is available. The response is consistent with either. This is the default, not a classification failure: it is the honest record that the observation cannot resolve the question.

**Critical rule:** absence of the payload from the final response is NOT evidence of neutralisation. It is the most common indistinguishable case. Delivered-but-silent and neutralised-before-sink produce identical observables at the response layer.

## 3. What exists (verified 2026-11-14)

**Dialects recognised for error-based detection:** `detection/analyzer.py:126-175` — `DB_ERROR_PATTERNS` keyed by six dialects: mysql, postgresql, hsqldb, mssql, oracle, sqlite.

**Dialects recognised for union extraction:** `attack/sqli_union.py:49` — `DBMS_SIGNATURES` has **five** keys: mysql, `postgres`, mssql, oracle, sqlite. Two divergences from `DB_ERROR_PATTERNS`: (a) `hsqldb` is absent entirely, not just from `DBMS_SIGNATURES` but from every sibling dict in the module (comment styles, version, database, table payloads); (b) the PostgreSQL key is `postgres` here, `postgresql` there. Neither is a live bug: consumed by disjoint code paths. Both are latent for a shared schema. Resolved in §9.1.

**Payloads:** `engine/scanner.py:73` — `DEFAULT_PAYLOADS`. Two entries are dialect-targeted by name:
- `sql_sleep_mysql` — `' OR SLEEP(5)--`
- `sql_sleep_pg` — `'; SELECT pg_sleep(5)--`

The scanner does not *select* between them by detected dialect; it sends the full set. Both statements are true and distinct: no dialect-keyed selection, but dialect-specific payloads exist in the set. Any classification record must name which payload produced the observation. Note: `analyzer.py:237-249` carries expected-sleep durations for four SQL sleep payloads (`sql_sleep_mysql`, `sql_sleep_mssql`, `sql_sleep_pg`, `sql_sleep_oracle`); only two appear in `DEFAULT_PAYLOADS`. The map is not consumed by the timing trigger (§3 timing row) and the two unmatched entries are orphans. Open item 9.5.

**Observability channels:**

| Channel | Where | Observes |
|---|---|---|
| Error-pattern | `detection/analyzer.py:126-175` (`DB_ERROR_PATTERNS`) | DBMS error string in response body |
| Union extraction | `attack/sqli_union.py` (`UnionExtractor`, `ExtractionStep`) | Extracted data appearing in response body |
| Boolean blind | `detection/blind_sqli_oracle.py:36,42` (`_coherent`, `_coherent_for_length`) | Response coherence / length change on boolean flip |
| Timing | `analyzer.py:~675` — statistical delta vs baseline mean; both `delta >= MIN_TIMING_DELTA` and `z >= MIN_TIMING_Z` required; emits `timing_anomaly` | Response delay beyond baseline noise |

`UnstableTargetError` (`sqli_union.py:200`) is a pre-existing uncertainty signal — reuse, do not parallel.

## 4. Dialect × ORM-framework matrix

Axis 1 (verified): the six dialects in `analyzer.py:126-175`.

Axis 2 (no in-repo grounding — open item 9.4): ORM framework. Candidate frameworks by benchmark target stack:
- Juice Shop — Node/Express, Sequelize (raw query path varies by endpoint)
- crAPI — Java/Spring, JPA/Hibernate
- Generic — Django ORM, ActiveRecord, Entity Framework

Matrix cells record **what was observed** for a payload × dialect × framework, not what is expected. Empty cell = not measured.

## 5. Evidence requirements per class, per channel

| Channel | Delivered evidence | Neutralised evidence | Indistinguishable when |
|---|---|---|---|
| Error-pattern | dialect error string returned for this payload | no error AND delivery path shows binding/escaping | no error, path unobservable |
| Union extraction | extracted data appears in body | no extracted data AND syntax observably stripped | no extracted data, path unobservable |
| Boolean blind | response differs reproducibly on boolean flip | response identical AND binding observable | response identical, path unobservable |
| Timing | elapsed delta >= MIN_TIMING_DELTA and z >= MIN_TIMING_Z vs baseline mean, reproducible across N runs | no `timing_anomaly` AND path shows no execution | no `timing_anomaly`, path unobservable |

**Reproducibility threshold:** a boolean or timing observation must reproduce across N runs (N per M83 phase 2 protocol) before counting as evidence at all. A single flip is not evidence.

## 6. Adjudication

Adopt M83 R2a **strict inconclusive**: when channel evidence is absent or contradictory, the class is `indistinguishable`. Do not adjudicate to `delivered` or `neutralised` on inference alone. Precedent and rationale: `docs/m83_scope.md` §5.

## 7. Evidence / inference / uncertainty separation

Every classification record carries three fields:

- `observed` — raw response evidence (status, body excerpt or length, timing)
- `inferred` — the class (delivered / neutralised / indistinguishable)
- `uncertainty` — what additional observation would change the inference

A record with no `uncertainty` field is rejected. It claims more certainty than any single observation supports.

## 8. Scope constraints

- No payload changes
- No scanner changes
- No oracle changes
- No threshold changes
- Output: this classification document, plus (if useful) a per-case record schema mirroring `docs/m83_scope.md` §3's `case_records.jsonl`

## 9. Open items

**9.1 — DBMS_SIGNATURES reconciliation. RESOLVED 2026-11-14.** Divergence confirmed: `DBMS_SIGNATURES` has 5 keys (mysql, postgres, mssql, oracle, sqlite) vs `DB_ERROR_PATTERNS`' 6. HSQLDB is absent from all of `sqli_union.py`; `postgres` vs `postgresql` name mismatch. Consumers disjoint (`sqli_union.py:247,424` vs `analyzer.py:405,858`) so no live bug. A shared classification record must declare a canonical identifier; `postgresql` (the analyzer' key) is the more general form.

**9.2 — Register L03 evidence correction.** The current line says "payloads are dialect-agnostic." Two payloads are dialect-targeted by name (§3). "No dialect-keyed selection" is true; "dialect-agnostic payloads" is not. Corrected in the same commit as this document.

**9.3 — Timing channel. RESOLVED 2026-11-14.** Channel exists: `analyzer.py:~675` emits `timing_anomaly` (critical if `z>=6 AND delta>=3.0s`, else high) when `delta >= MIN_TIMING_DELTA` AND `z >= MIN_TIMING_Z`. It is a statistical anomaly detector against baseline mean, not an expected-duration comparison. §3 and §5 corrected accordingly.

**9.4 — ORM framework grounding.** Axis 2 has no in-repo citation. Either pin to the two benchmark targets' stacks (§4) or declare frameworks generically. The matrix can be written either way; the choice should be explicit.

**9.5 — Expected-sleep map coverage.** `analyzer.py:237-249` names four SQL sleep payloads; `DEFAULT_PAYLOADS` sends two. The `sql_sleep_mssql` and `sql_sleep_oracle` entries are not consumed by the timing trigger (which uses statistical delta, not expected duration) and are not sent by the scanner. Are they planned, dead, or consumed by a path not found in this pass? Read-only: search `analyzer.py` for `sql_sleep_mssql`, `sql_sleep_oracle`, and any expected-duration constant definition or lookup.

**9.6 — Canonical dialect identifier.** `postgres` and `postgresql` both name the same DBMS in different modules. A shared classification schema (per §11 next steps) must pick one. Recommendation: `postgresql`, matching the analyzer' key and the more general name.

## 10. Acceptance criteria

1. Operational definitions of delivered / neutralised / indistinguishable — §2
2. Dialect × ORM-framework evidence matrix — §4
3. Explicit evidence requirements per class, per channel — §5
4. M83 R2a adjudication — §6
5. Separation of observed evidence, inferred cause, unresolved uncertainty — §7
6. No payload or scanner changes — §8
7. Absence from final response is not neutralisation — §2 critical rule

## 11. Next steps after this document

1. Resolve 9.1 and 9.3 with read-only greps; record findings as amendments to this document.
2. Decide 9.4 (grounded vs generic ORM axis).
3. Only then: per-case record schema, then measurement protocol, then any implementation. The order mirrors M83: taxonomy → schema → measurement → implementation.