# JANISSARY-ASCENSION

**Road to top 20.** Differential DAST for teams who need results they can trust.

- **Created:** 14-OCT-2026 11:53:28
- **Target:** 14-APR-2028 11:53:28 (18 calendar months)
- **Total duration:** 548 days
- **Work complete:** 23.3%

> Countdown, time-elapsed percentage, and days-ahead-of-schedule are computed live in `renders/dashboard-refined.html`. This document is the static source of truth for milestone state.

## Milestones

### Phase 3

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M1 | P1.1 SQLI UNION extractor | 02-OCT-2026 | 26-SEP-2026 |
| M2 | P3.2 Nuclei runner | 05-OCT-2026 | 26-SEP-2026 |
| M3 | P3.3 Agent / FindingStore | 09-OCT-2026 | 26-SEP-2026 |
| M4 | Technical blog post + demo video | 09-OCT-2026 | 26-SEP-2026 |

### Phase 3.5

| ID | Milestone | Proposed | Delivered |
|---|---|---|---|
| M5 | README polish | 11-OCT-2026 | 26-SEP-2026 |
| M6 | README scrub: verify or delete every promise | 12-OCT-2026 | 13-OCT-2026 |
| M7 | demo.gif regenerated from a live scan | 13-OCT-2026 | *pending investigation* |
| M8 | PyPI + Docker + fresh-venv install verify | 16-OCT-2026 | 27-OCT-2026 (mechanism for 7.5.0; see FN-7) |
| M9 | Comparative benchmark (vs ZAP, nuclei) | 18-OCT-2026 | 13-OCT-2026 |

### Phases 4 - 6

All proposed, none delivered. See dashboard for full list (M10-M30).

## Distribution state (verified 2026-11-01)

| Channel | Latest version | Uploaded |
|---|---|---|
| PyPI (`janissary`) | **7.5.0** | 27-OCT-2026 |
| Docker Hub (`oraclemode337/janissary`) | **7.5.0** | 28-OCT-2026 |
| Git tags | **v7.10.2** | 30-OCT-2026 |
| Repo HEAD (`pyproject.toml`) | **7.10.2** | 30-OCT-2026 |
| README pinned install | **7.5.0** | 28-OCT-2026 |

**Gap:** 5 tagged versions (`v7.6.0`-`v7.10.2`) exist in git only. No wheel, no container. Public install paths return a scanner that predates FN-4, FN-5, and every fix between 7.5.0 and 7.10.2.

## Recently shipped (2026-11-01 session)

- **FN-5** (`ebb449b` + doc `d18693f`) - `--nuclei-path` CLI flag on `attack nuclei`, plumbed to `NucleiRunner(nuclei_path=...)`. Negative-checked. Live `--help` shows the flag.
- **FN-4** (`f02d72d` + doc `8ea1669`) - `scan` adapter registered in `default_adapters()`. Live gate: `agent http://127.0.0.1:5000` exits 0 (was 2 at `e8e1b47`). 3 new tests, negative-checked.

Test count: 667 -> 668 (FN-5) -> 671 (FN-4).

## Open items

| ID | Item | Type | Est. |
|---|---|---|---|
| FN-6 | Fallback scan adapter finds 0 on vampi | measurement first | 5 min + 60-120 min fix |
| **FN-7 (new)** | **PyPI / Docker are 5 versions behind repo** | release | 15-30 min |
| - | `--rate-limit` help text (cli.py:1480) | tail | 5 min |
| - | `janissary_findings.json` .gitignore | cleanup | 2 min |
| - | FN-4 evidence run dir | optional | 10 min |
| - | M7 investigation | blocked | 2 min |
| Candidate B | New app category (WebGoat / Juice Shop) | multi-hour | requires app choice |
| Candidate C | Deeper corpus | small per case | needs justification |
| - | Volume scripts untested against live containers | verification | unknown |
| - | Gitea fresh-volume state | automation | unknown |
| - | crAPI compose (external) | vendoring | unknown |
| - | SSRF-FP-1 corpus regression gap | regression | unknown |

## Repo state at time of update

- HEAD: `8ea1669` on `origin/main`
- Working tree: clean
- Tests: 671/671 passing
- Corpus: `tp=11 fp=0 fn=0 tn=24 f1=1.0`
- Package version: 7.10.2 (matching newest tag `v7.10.2`, enforced by `tests/test_version_tag_consistency.py`)

## Sources

- `Session Handover, 2026-11-01.txt`
- Distribution evidence: PyPI JSON API + Docker Hub image inspection, 2026-11-01
- Fresh-venv verification: successful install of 7.5.0, `janissary --version` output captured
