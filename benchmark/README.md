# JANISSARY Benchmark Harness

See `../BENCHMARK.md` for the pre-registered methodology. This directory
holds the harness that executes that methodology.

## Layout

- `track_a/` — OWASP Benchmark (Java), 2,740 labelled cases, 3 tools x 3 runs
- `track_b/` — OWASP Juice Shop behind Cloudflare free tier, 3 tools x 1 run
- `common/` — shared harness code (subprocess wrappers, JSON helpers)
- `runs/` — raw run artifacts, committed verbatim after each official run
- `analyze.py` — top-level entry: reads runs/, emits metrics + charts

## Do not

- Modify BENCHMARK.md hypotheses after a run has started.
- Delete or re-run a run to improve a number.
- Hand-edit any JSON in `runs/`.

## Reproducing

Every run is reproducible from:

1. The pinned tool versions in `track-*/tools.env`
2. The pinned target images in `track-*/docker-compose.yml`
3. The harness version = the git commit that produced the run

Each `runs/<timestamp>/manifest.json` records all three.