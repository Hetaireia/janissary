import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from benchmark.track_a.runner import _retry_zero_pass


def test_retry_zero_pass_accepts_bool_vulnerable():
    """Regression: real CSV loader returns bool, not string. E2E found crash 2026-11-08."""
    with tempfile.TemporaryDirectory() as d:
        run_dir = Path(d)
        (run_dir / "findings.jsonl").write_text("", encoding="utf-8")
        cases = [
            {"testname": "BenchmarkTest00001", "vulnerable": True},
            {"testname": "BenchmarkTest00002", "vulnerable": False},
        ]

        seen = {}

        def fake_driver(rdir, sub_cases, base, env):
            seen["names"] = [c["testname"] for c in sub_cases]
            (Path(rdir) / "findings.jsonl").write_text(
                '{"url": "http://x/benchmark/a/BenchmarkTest00001"}\n',
                encoding="utf-8",
            )
            return 0

        _retry_zero_pass(run_dir, cases, "http://x/benchmark", {}, fake_driver)

        assert seen["names"] == ["BenchmarkTest00001"], seen
