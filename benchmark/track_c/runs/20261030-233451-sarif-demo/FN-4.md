# FN-4 measurement - 2026-10-30

Target: vampi (http://127.0.0.1:5000), HTTP 200
Command: janissary agent <url> --attack-confirm --export out.sarif
         --store findings.json --timeout 120 --quiet

## Two facts, not conflated

### 1. SARIF arm is LIVE-PROVEN (GREEN)

out.sarif: 3342 bytes, validates against OASIS SARIF 2.1.0
(tests/fixtures/sarif/sarif-schema-2.1.0.json via jsonschema.validate).
Produced on an aborted-scan invocation - this matches the assertion in
tests/integration/test_sarif_output.py::test_sarif_aborted_scan_invocation.
Closes PHASE-6-PLAN Candidate A task 1 (no code change required).

### 2. Agent orchestrator FN-4 candidate (RED - measurement)

Agent exit: 2
stderr: "[!] aborted: no modules to run: no platforms detected and no
fallback scan adapter registered"

vampi is a locked corpus app with 4 known vulnerability classes in
apps.json (per the corpus schema). "No platforms detected" against it
is either a detector gap or a missing fallback scan adapter - both are
FN-class findings.

This note is written BEFORE any fix. Same discipline as 4a2d0d1.
Fix (if any) is a separate forward commit, not part of task 1.
