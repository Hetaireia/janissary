Track A — 7.11.1 False-Negative Recovery Record

Measurement date: 12 November 2026
Tool version: 7.11.1
Track: A
Status: Recovery investigation complete; preservation recommended

## 1. Purpose

This record documents the 7.11.1 false-negative recovery candidate set, its relationship to the original Track A baseline, and the result of the subsequent recovery run.

The recovery input is:

`benchmark/track_a/_fn_recovery_7_11_1.csv`

It contains 206 cases marked `vulnerable=true`. These are recovery candidates, not the final benchmark false-negative count.

The 206 recovery candidates must not be confused with the benchmark's classified false-negative total of 168. They represent different measurements.

## 2. Original baseline

Run directory:

`benchmark/track_a/runs/20261112T180530Z-janissary-r1`

Manifest details:
- Input: `benchmark/track_a/case_vectors.csv`
- Case count: 2,740
- Tool version: 7.11.1
- Harness commit: `ea7b3e50af0d148d000d50d6c9e7d395bc898532`
- Target version: `20cbf3d`
- Started: `2026-11-12T18:05:30Z`
- Finished: `2026-11-12T19:15:12Z`
- Exit code: 1

The baseline findings contain 1,388 unique benchmark test names.

None of the 206 recovery candidate names appears among those baseline finding names. This is consistent with their selection as vulnerable cases that did not produce baseline findings.

## 3. Recovery pass

Run directory:

`benchmark/track_a/runs/20261112T195341Z-janissary-r1`

The recovery manifest identifies the input as:

`benchmark/track_a/_fn_recovery_7_11_1.csv`

Manifest details:
- Case count: 206
- Tool version: 7.11.1
- Harness commit: `ea7b3e50af0d148d000d50d6c9e7d395bc898532`
- Target version: `20cbf3d`
- Started: `2026-11-12T19:53:41Z`
- Finished: `2026-11-12T19:57:43Z`
- Exit code: 0

The recovery findings file is empty. The timeout file is also empty.

### 3.1 Dispatch and skip qualification

The recovery run recorded 42 skipped cases.

All 42:
- Belong to the 206-case recovery CSV.
- Also appear in the original baseline's skipped records.
- Were therefore not newly introduced skips in the recovery pass.

The skip distribution is:

| Mode | Skipped cases |
|---|---:|
| header_any | 39 |
| out_of_scope_stream | 2 |
| out_of_scope_uri | 1 |
| **Total** | **42** |

The runner source explains these exclusions:
- `header_any` requires header-name-safe payloads and is explicitly unsupported in run 1.
- `out_of_scope_*` and unclassified modes are excluded from dispatch.
- `_dispatch()` returns `None` for these modes.
- `run_janissary()` records those cases in `skipped.jsonl`.

Consequently, 164 candidates were dispatched and produced no findings; 42 were intentionally excluded by the runner's dispatch policy.

This record does not claim that all 206 candidates were tested.

## 4. Merged findings verification

Merged run directory:

`benchmark/track_a/runs/20261112T180530Z-janissary-r1+rec`

The SHA-256 hashes of the original baseline findings file and the merged recovery findings file are identical:

`AE0DA77AFD5CF823920AAD883ACBDC7013C4B40772F113743A457112A22B82A7`

This establishes that the recovery pass added no findings to the merged findings output.

The conclusion is supported by both:
- The empty recovery findings file.
- The byte-identical baseline and merged findings files.

## 5. Result and limitations

The evidence supports the following conclusion:

The 206-case recovery candidate set was processed in a subsequent recovery run. The run emitted zero findings and recorded zero timeouts. Of the 206 candidates, 164 were dispatched and produced no findings; 42 were skipped under the same runner exclusions observed in the original baseline. The merged findings file is byte-identical to the original baseline findings file. No additional findings were recovered.

The 42 skipped cases remain outside the tested recovery coverage for this runner configuration.

This result does not establish that the skipped cases are not vulnerable. Nor does it change the benchmark's separately classified false-negative total of 168.

## 6. Reproducibility and preservation

The recovery CSV is the exact input identified by the recovery run's manifest.

The recovery run directory and its manifest were found to be untracked by Git during this investigation. Therefore, the manifest's reference to the CSV is not currently a dangling reference in tracked repository content.

Preserving the CSV is recommended as a historical benchmark input. The CSV and this record provide a durable account of the candidate set and the qualified recovery outcome.

The original and recovery run directories were used as local evidence during this investigation. Their wholesale inclusion in the repository is not implied by this recommendation.

## 7. Evidence paths

- Candidate input: `benchmark/track_a/_fn_recovery_7_11_1.csv`
- Original baseline manifest: `benchmark/track_a/runs/20261112T180530Z-janissary-r1/manifest.json`
- Original baseline findings: `benchmark/track_a/runs/20261112T180530Z-janissary-r1/findings.jsonl`
- Original baseline skips: `benchmark/track_a/runs/20261112T180530Z-janissary-r1/skipped.jsonl`
- Recovery manifest: `benchmark/track_a/runs/20261112T195341Z-janissary-r1/manifest.json`
- Recovery findings: `benchmark/track_a/runs/20261112T195341Z-janissary-r1/findings.jsonl`
- Recovery skips: `benchmark/track_a/runs/20261112T195341Z-janissary-r1/skipped.jsonl`
- Recovery timeouts: `benchmark/track_a/runs/20261112T195341Z-janissary-r1/timeouts.jsonl`
- Merged findings: `benchmark/track_a/runs/20261112T180530Z-janissary-r1+rec/findings.jsonl`
- Runner dispatch policy: `benchmark/track_a/runner.py`

## 8. Disposition

Preservation of the recovery CSV and this record is recommended.

This record documents the observed evidence and its limitations. It does not claim that the recovery candidate set was fully tested, and it does not authorize any Git staging, commit, or push.
