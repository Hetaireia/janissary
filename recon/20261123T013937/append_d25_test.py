import pathlib

p = pathlib.Path("tests/integration/test_sarif_output.py")
src = p.read_text(encoding="utf-8")

# Guard: refuse to append if the test already exists
if "test_sarif_invocation_carries_approximate_requests" in src:
    raise SystemExit("Test already present; aborting.")

# Guard: refuse to append if file lacks the imports we rely on
for needle in (
    "from janissary.engine.scanner import ScanFinding, ScanSummary",
    "def _read_sarif",
):
    if needle not in src:
        raise SystemExit(f"Missing expected fixture: {needle!r}")

new_test = """

def test_sarif_invocation_carries_approximate_requests(tmp_path):
    \"\"\"D-25: SARIF invocation.properties must carry approximateRequests.

    The JSON envelope (_summary_to_dict) exposes both total_requests and
    approximate_requests. A SARIF consumer reading the same scan must see
    the same pair, or the two reporting surfaces silently disagree.
    \"\"\"
    summary = _summary()
    summary.total_requests = 10
    summary.approximate_requests = 15
    doc = _read_sarif(tmp_path, summary)
    props = doc[\"runs\"][0][\"invocations\"][0][\"properties\"]
    assert props[\"totalRequests\"] == 10
    assert props[\"approximateRequests\"] == 15
"""

p.write_text(src.rstrip() + new_test, encoding="utf-8", newline="\n")
print(
    "Appended test_sarif_invocation_carries_approximate_requests to test_sarif_output.py"
)
