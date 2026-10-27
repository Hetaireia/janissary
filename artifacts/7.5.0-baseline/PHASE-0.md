# Phase 0 - Foundations (evidence)

**Exit gate:** Amendment 23 committed.
**Status:** Preparing commit.

## What was produced

| Item | Location |
|---|---|
| Commit record | `artifacts/7.5.0-baseline/commit.txt` |
| Machine-readable metadata | `artifacts/7.5.0-baseline/metadata.json` |
| README claims inventory | `artifacts/7.5.0-baseline/summary/readme-claims.md` |
| Original README (pre-change) | `artifacts/7.5.0-baseline/raw/README.orig.md` |
| Rewritten README draft | `artifacts/7.5.0-baseline/raw/README.draft.md` |
| Amendment 23 (pre-registration) | `docs/AMENDMENT-23.md` |

## What was verified

- Repository: `Hetaireia/janissary` on branch `main`.
- Baseline tag `7.5.0` resolves to commit `e5b484078223f626e32b7ab8552ee947ff71253d`.
- Isolated worktree at tag `7.5.0` created for baseline runs.
- README claim scan: 25 matches in `README.md` (benchmark 15, percentage 15, precision 14, false-positive 8) and 3 matches in `README.new.md`.
- No `superlative` matches in either file - "best-in-class" not present in current text.

## README changes (draft, applied in Phase 0 commit)

- Authorised-use blockquote replaced with a GitHub alert callout.
- Colour-coded callouts added to `## Why JANISSARY`, `## Install`, `## Benchmark`, `## What JANISSARY is not`, `## Known Limitations`, `## Security`.
- Measurement-status callout placed before `## Benchmark`, pointing at this amendment.
- Precision qualifiers added: `Precision (dev splits) | 1.000 (0 FP observed)`.
- `zero-false-positive` claim reworded to `no observed false positives on the dev corpus`.
- Six duplicate limitation bullets removed (path traversal, SSRF payload scope, no IDOR).

## Pending (Phase 1+)

- Phase 1 baseline runs: 3x 7.5.0 on dev splits in the isolated worktree.
- Item 9: external reproducer recruitment.
- Held-out corpora verification (WebGoat, DVWA, bWAPP, Juice Shop, WAVSEP, OWASP BenchmarkPython).
- Real-world negative environment build-out (60+ apps).
- Claim ladder placeholders `X`, `Y`, `N` remain unresolved by design.