# FN-4 evidence: scan adapter fallback

**Run:** 2026-11-01 06:22 local
**Target:** http://127.0.0.1:5000 (vampi, seeded)
**Command:** janissary agent http://127.0.0.1:5000 --attack-confirm --store agent-findings.json --export agent-export.json
**Agent exit code:** 0

## What this demonstrates

FN-4 registered the scan adapter in default_adapters(), so the agent
orchestrator has a fallback when platform detection yields no plan.
Previously (commit e8e1b47) the same command exited 2 with:

    [!] aborted: no modules to run: no platforms detected and no fallback scan adapter registered

After FN-4, the same command exits 0. The plan falls back to scan, the
scan adapter runs with default parameters, and returns 0 findings because
vampi's injectable endpoints are path-based (/users/v1/{username}), not
query-based.

Zero findings here is CORRECT behavior for the fallback — it's a blind
default-params scan against an app whose SQLi requires path injection.
The fallback's job is to prevent abort, not to find vulns.

## Files

- agent.log — full agent output, including exit code at end
- agent-findings.json — findings store written by --store
- agent-export.json — full run export from --export

## Reproducer (the actual detection path)

    janissary scan -u "http://127.0.0.1:5000/users/v1/{username}" -p username --inject-in path --baseline-value name1

That produces 9 findings (see docs/PHASE-6-PLAN.md FN-6 resolution).
The agent fallback above deliberately uses only default params.

## Acceptance criteria (from handover)

- Agent exits 0
- Plan: scan
- Modules run: scan
- Run dir committed
