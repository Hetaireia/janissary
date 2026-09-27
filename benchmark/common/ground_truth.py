"""Ground truth for the OWASP Benchmark corpus.

Reads the official CSV that ships with OWASP Benchmark and produces a
case -> label mapping. This module is the only source of ground truth
used by analyze.py. No re-labelling, no heuristics, no inferred labels.

CSV contract (as shipped by OWASP Benchmark)
--------------------------------------------
Header row. Required columns:
    testname    e.g. BenchmarkTest00001
    category    e.g. sqli, xss, cmdi, ...
    vulnerable  "true" or "false"
    cwe         integer CWE id (used for reporting, not scoring)
Any column not listed above is ignored.

Case URL convention
-------------------
OWASP Benchmark serves each case at /<testname>?<testname>=<value>.
The query parameter name equals the testname. Callers should not assume
a different name; if a future version changes this, the runner records
the param per case in its manifest.

Finding classification
----------------------
A tool's finding on case C is a True Positive iff:
  * case C is vulnerable per ground truth, AND
  * the finding's URL path contains C's testname.
Otherwise, if case C is NOT vulnerable and the tool emitted a finding
that maps to C, it is a False Positive. Cases with no tool finding are
True Negative (if not vulnerable) or False Negative (if vulnerable).
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Label:
    testname: str
    category: str
    cwe: int | None
    vulnerable: bool

    @property
    def kind(self) -> str:
        return "vulnerable" if self.vulnerable else "safe"


def load_labels(csv_path: Path) -> dict[str, Label]:
    """Return {testname: Label}. Raises on any malformed row."""
    labels: dict[str, Label] = {}
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError(f"{csv_path}: empty CSV (no header row)")
        required = {"testname", "category", "vulnerable"}
        missing = required - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"{csv_path}: missing columns {sorted(missing)}; "
                f"found {sorted(reader.fieldnames)}"
            )
        for row in reader:
            name = (row.get("testname") or "").strip()
            if not name:
                continue
            vuln_raw = (row.get("vulnerable") or "").strip().lower()
            vulnerable = vuln_raw in ("true", "1", "yes")
            cwe_raw = (row.get("cwe") or "").strip()
            cwe: int | None
            try:
                cwe = int(cwe_raw) if cwe_raw else None
            except ValueError:
                cwe = None
            labels[name] = Label(
                testname=name,
                category=(row.get("category") or "").strip(),
                cwe=cwe,
                vulnerable=vulnerable,
            )
    if not labels:
        raise ValueError(f"{csv_path}: no labelled rows found")
    return labels


_TESTNAME_RE = re.compile(r"/([A-Za-z]+Test\d+)(?:/|$|\?)")


def testname_from_url(url: str) -> str | None:
    """Extract the OWASP Benchmark testname from a finding URL.

    OWASP Benchmark's URL shape is /<testname> or /<testname>/... or
    /<testname>?param=value. The regex requires the literal 'Test' inside
    the name (BenchmarkTestNNNNN) so it does not match arbitrary paths.
    """
    if not url:
        return None
    try:
        path = urlsplit(url).path
    except Exception:
        return None
    m = _TESTNAME_RE.search(path)
    return m.group(1) if m else None


def label_for_finding(url: str, labels: dict[str, Label]) -> Label | None:
    name = testname_from_url(url)
    if name is None:
        return None
    return labels.get(name)


def classify_case(
    case: Label,
    tool_fired: bool,
) -> str:
    """Return TP / FP / TN / FN for a single case given whether the tool
    emitted at least one finding mapped to that case.
    """
    if case.vulnerable and tool_fired:
        return "TP"
    if case.vulnerable and not tool_fired:
        return "FN"
    if not case.vulnerable and tool_fired:
        return "FP"
    return "TN"


def map_findings_to_cases(
    finding_urls: Iterable[str],
    labels: dict[str, Label],
) -> dict[str, int]:
    """Count how many findings map to each testname.

    Findings that don't map to any labelled case are ignored here - they
    are counted separately by analyze.py as 'orphan' findings, which are
    neither TP nor FP against the corpus.
    """
    counts: dict[str, int] = {}
    for url in finding_urls:
        name = testname_from_url(url)
        if name is None or name not in labels:
            continue
        counts[name] = counts.get(name, 0) + 1
    return counts


def count_orphans(
    finding_urls: Iterable[str],
    labels: dict[str, Label],
) -> int:
    n = 0
    for url in finding_urls:
        name = testname_from_url(url)
        if name is None or name not in labels:
            n += 1
    return n
