"""ADR-036 phase 6: three-run aggregation harness tests."""

import json

import pytest
from pytest import fixture

from benchmark.track_a import runner_3run_aggregation as agg
from benchmark.track_a import score_dast_aware

ROWS = [
    (
        "BenchmarkTest00001",
        "/pathtraver-00/BenchmarkTest00001",
        "pathtraver-00",
        "true",
    ),
    (
        "BenchmarkTest00002",
        "/pathtraver-00/BenchmarkTest00002",
        "pathtraver-00",
        "true",
    ),
    ("BenchmarkTest00003", "/xss-00/BenchmarkTest00003", "xss-00", "true"),
    ("BenchmarkTest00004", "/xss-00/BenchmarkTest00004", "xss-00", "true"),
    (
        "BenchmarkTest00005",
        "/pathtraver-00/BenchmarkTest00005",
        "pathtraver-00",
        "false",
    ),
    ("BenchmarkTest00006", "/xss-00/BenchmarkTest00006", "xss-00", "false"),
]

HITS = [
    ("/pathtraver-00/BenchmarkTest00001", "traversal"),
    ("/pathtraver-00/BenchmarkTest00002", "traversal"),
    ("/xss-00/BenchmarkTest00003", "xss"),
    ("/xss-00/BenchmarkTest00004", "xss"),
]


@fixture(autouse=True)
def no_exclusions(monkeypatch, tmp_path):
    monkeypatch.setattr(score_dast_aware, "EXCLUDE_FILE", tmp_path / "none.txt")
    monkeypatch.setattr(
        score_dast_aware, "SUPPORTED_EXCLUDE_FILE", tmp_path / "none2.txt"
    )


def _cases(tmp_path, rows, name="cases.csv"):
    path = tmp_path / name
    lines = ["testname,urlpath,category,vulnerable"]
    lines += [f"{n},{u},{c},{v}" for (n, u, c, v) in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_run(root, label, number, findings, tool="janissary"):
    d = root / label
    d.mkdir()
    manifest = {"tool": tool, "run_number": number, "tool_version": "9.9.9"}
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    lines = [
        json.dumps({"url": "http://h:8080/benchmark" + p, "class": c})
        for (p, c) in findings
    ]
    body = "\n".join(lines) + ("\n" if lines else "")
    (d / "findings.jsonl").write_text(body, encoding="utf-8")
    return d


def _argv(runs, cases, extra=()):
    argv = []
    for r in runs:
        argv += ["--run", str(r)]
    argv += ["--cases-csv", str(cases)]
    return argv + [str(x) for x in extra]


def test_three_clean_runs_pass_all_gates(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--floor", "0.3308", "--baseline-runs"]
    extra += [str(r) for r in runs]
    assert agg.main(_argv(runs, cases, extra)) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["aggregate"]["mean"]["recall"] == 1.0
    assert data["aggregate"]["mean"]["target_recall"] == 1.0
    assert data["aggregate"]["stdev"]["recall"] == 0.0
    assert data["aggregate"]["stdev"]["target_recall"] == 0.0
    assert data["runs"][0]["confusion"] == {"tp": 4, "fp": 0, "fn": 0, "tn": 2}
    assert data["runs"][0]["target_tp"] == 2
    gate = data["gates"]["baseline"]
    assert gate["baseline_true_positives"] == 4
    assert gate["held"] == 4
    assert gate["regressed"] == []
    assert data["gates"]["floor"]["passed"] is True
    assert data["failed"] is False


def test_missing_baseline_true_positive_fails_gate(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    base = [_write_run(root, f"base{i}", i, HITS) for i in (1, 2, 3)]
    short = [f for f in HITS if f[0] != "/pathtraver-00/BenchmarkTest00002"]
    cur = [_write_run(root, f"cur{i}", i, short) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--baseline-runs"] + [str(r) for r in base]
    assert agg.main(_argv(cur, cases, extra)) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gates"]["baseline"]["regressed"] == [
        "/pathtraver-00/BenchmarkTest00002"
    ]
    assert data["gates"]["baseline"]["held"] == 3
    assert data["failed"] is True


def test_single_hold_is_fragile_not_regressed(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    base = [_write_run(root, f"base{i}", i, HITS) for i in (1, 2, 3)]
    short = [f for f in HITS if f[0] != "/pathtraver-00/BenchmarkTest00002"]
    cur = [
        _write_run(root, "cur1", 1, HITS),
        _write_run(root, "cur2", 2, short),
        _write_run(root, "cur3", 3, short),
    ]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--baseline-runs"] + [str(r) for r in base]
    assert agg.main(_argv(cur, cases, extra)) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gates"]["baseline"]["regressed"] == []
    assert data["gates"]["baseline"]["fragile"] == ["/pathtraver-00/BenchmarkTest00002"]
    assert data["aggregate"]["mean"]["target_recall"] == pytest.approx(2 / 3, abs=1e-6)


def test_negative_corpus_false_positive_fails_gate(tmp_path):
    neg = _cases(tmp_path, [r for r in ROWS if r[3] == "false"], name="neg.csv")
    root = tmp_path / "runs"
    root.mkdir()
    hits = [*HITS, ("/pathtraver-00/BenchmarkTest00005", "traversal")]
    runs = [_write_run(root, f"run{i}", i, hits) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--negative-cases", str(neg)]
    extra += ["--negative-runs", *[str(r) for r in runs]]
    assert agg.main(_argv(runs, neg, extra)) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["gates"]["negative"]["false_positives"]) == 3
    assert data["gates"]["negative"]["passed"] is False


def test_negative_corpus_clean_runs_pass_gate(tmp_path):
    neg = _cases(tmp_path, [r for r in ROWS if r[3] == "false"], name="neg.csv")
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--negative-cases", str(neg)]
    extra += ["--negative-runs", *[str(r) for r in runs]]
    assert agg.main(_argv(runs, neg, extra)) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gates"]["negative"]["false_positives"] == []
    assert data["gates"]["negative"]["cases"] == 2
    assert data["gates"]["negative"]["passed"] is True


def test_negative_gate_ignores_exclusion_file(tmp_path, monkeypatch):
    excluded_all = _cases(tmp_path, ROWS, name="excl.txt")
    excluded_all.write_text("pathtraver-00\nxss-00\n", encoding="utf-8")
    monkeypatch.setattr(score_dast_aware, "EXCLUDE_FILE", excluded_all)
    neg = _cases(tmp_path, [r for r in ROWS if r[3] == "false"], name="neg.csv")
    root = tmp_path / "runs"
    root.mkdir()
    hits = [*HITS, ("/pathtraver-00/BenchmarkTest00005", "traversal")]
    runs = [_write_run(root, f"run{i}", i, hits) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    extra = ["--out", str(out), "--negative-cases", str(neg)]
    extra += ["--negative-runs", *[str(r) for r in runs]]
    assert agg.main(_argv(runs, neg, extra)) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["gates"]["negative"]["false_positives"]) == 3


def test_tally_agrees_with_scorer_despite_noise(tmp_path):
    csv_path = _cases(tmp_path, ROWS)
    cases = agg.read_cases(csv_path)
    root = tmp_path / "runs"
    root.mkdir()
    findings = [
        ("/pathtraver-00/BenchmarkTest00001", "traversal"),
        ("/pathtraver-00/BenchmarkTest00002", "sqli"),
        ("/pathtraver-00/BenchmarkTest00005", "sqli"),
        ("/nowhere/BenchmarkTest99999", "traversal"),
    ]
    run = _write_run(root, "run1", 1, findings)
    rows = agg.verified_rows(run, cases, csv_path)
    by = {r["urlpath"]: r for r in rows}
    assert by["/pathtraver-00/BenchmarkTest00002"]["detected"] is False
    assert by["/xss-00/BenchmarkTest00003"]["detected"] is False
    assert by["/pathtraver-00/BenchmarkTest00005"]["detected"] is False
    assert agg.confusion(rows) == (1, 0, 3, 2)


def test_tally_mismatch_raises(tmp_path, monkeypatch):
    csv_path = _cases(tmp_path, ROWS)
    cases = agg.read_cases(csv_path)
    root = tmp_path / "runs"
    root.mkdir()
    run = _write_run(root, "run1", 1, HITS)
    monkeypatch.setattr(agg, "_published", lambda d, c: (99, 99, 0, 0))
    with pytest.raises(agg.UsageError, match="per-case tally"):
        agg.verified_rows(run, cases, csv_path)


def test_non_janissary_manifest_is_a_usage_error(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS, tool="zap") for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    assert agg.main(_argv(runs, cases, ["--out", str(out)])) == 2
    assert not out.exists()


def test_duplicate_run_numbers_are_rejected(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [
        _write_run(root, "a", 1, HITS),
        _write_run(root, "b", 1, HITS),
        _write_run(root, "c", 1, HITS),
    ]
    out = tmp_path / "agg.json"
    assert agg.main(_argv(runs, cases, ["--out", str(out)])) == 2


def test_two_runs_need_allow_partial(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS) for i in (1, 2)]
    out = tmp_path / "agg.json"
    assert agg.main(_argv(runs, cases, ["--out", str(out)])) == 2
    assert agg.main(_argv(runs, cases, ["--out", str(out), "--allow-partial"])) == 0
    assert out.exists()


def test_four_runs_are_rejected(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS) for i in (1, 2, 3, 4)]
    out = tmp_path / "agg.json"
    assert agg.main(_argv(runs, cases, ["--out", str(out)])) == 2


def test_floor_fails_on_a_genuine_regression(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    full = [_write_run(root, f"full{i}", i, HITS) for i in (1, 2, 3)]
    short = [f for f in HITS if f[0] != "/pathtraver-00/BenchmarkTest00001"]
    weak = [
        _write_run(root, "weak1", 1, short),
        _write_run(root, "weak2", 2, short),
        _write_run(root, "weak3", 3, short),
    ]
    out = tmp_path / "agg.json"
    assert agg.main(_argv(full, cases, ["--out", str(out), "--floor", "0.1"])) == 0
    assert agg.main(_argv(weak, cases, ["--out", str(out), "--floor", "0.99"])) == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gates"]["floor"]["mean_recall"] == pytest.approx(0.5, abs=1e-6)


def test_negative_flag_needs_its_counterpart(tmp_path):
    cases = _cases(tmp_path, ROWS)
    root = tmp_path / "runs"
    root.mkdir()
    runs = [_write_run(root, f"run{i}", i, HITS) for i in (1, 2, 3)]
    out = tmp_path / "agg.json"
    only_neg = ["--out", str(out), "--negative-runs", str(runs[0])]
    assert agg.main(_argv(runs, cases, only_neg)) == 2
    only_neg_cases = ["--out", str(out), "--negative-cases", str(cases)]
    assert agg.main(_argv(runs, cases, only_neg_cases)) == 2
