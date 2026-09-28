"""Extract the injection-vector map for the OWASP Benchmark corpus.

Reads the pinned BenchmarkJava source (inside the target container built
per BENCHMARK.md Amendment 2) and writes benchmark/track_a/case_vectors.csv.
Deterministic: rerunning over the same pinned SHA produces byte-identical
output.

Usage:
    python -m benchmark.track_a.extract_vectors

Requires `docker cp` against a container named `janissary-owasp`.
"""
from __future__ import annotations

import csv
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SRC = "/owasp/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"
CONTAINER = "janissary-owasp"
OUT = pathlib.Path(__file__).resolve().parent / "case_vectors.csv"

URL_RE = re.compile(r'@WebServlet\(value\s*=\s*"([^"]+)"\)')
HDR_RE = re.compile(r'getHeaders?\("([^"]+)"\)')
SCR_RE = re.compile(
    r'(?:getTheValue|getTheParameter|getTheHeader|getTheCookie)\("([^"]+)"\)'
)


def classify(name: str, txt: str) -> dict:
    m = URL_RE.search(txt)
    urlpath = m.group(1) if m else ""
    cat = urlpath.rsplit("/", 1)[0].lstrip("/") if urlpath else ""

    has_cookie = "getCookies()" in txt
    has_hdr_any = "getHeaderNames()" in txt
    hdr_literals = HDR_RE.findall(txt)
    hdr_self = name in hdr_literals
    hdr_other = next((h for h in hdr_literals if h != name), "")

    scr_self = name in SCR_RE.findall(txt)
    has_param_self = f'getParameter("{name}")' in txt
    has_param_lit = f'getParameterValues("{name}")' in txt
    has_map_get = f'map.get("{name}")' in txt
    has_qs = "getQueryString()" in txt
    has_pnames = "getParameterNames()" in txt and "getParameterValues(name)" in txt
    has_session = "getSession()" in txt
    has_uri = "getRequestURI()" in txt
    has_stream = "getInputStream()" in txt
    has_direct_param = (
        has_param_self or has_param_lit or has_map_get or has_qs or scr_self
    )

    if has_cookie:
        mode = "cookie"
    elif hdr_self:
        mode = "header_self"
    elif has_hdr_any:
        mode = "header_any"
    elif hdr_other:
        mode = "header_other"
    elif has_direct_param:
        mode = "param"
    elif has_pnames:
        mode = "param_name"
    elif has_session:
        mode = "out_of_scope_session"
    elif has_uri:
        mode = "out_of_scope_uri"
    elif has_stream:
        mode = "out_of_scope_stream"
    else:
        mode = "unclassified"

    return {
        "testname": name,
        "category": cat,
        "urlpath": urlpath,
        "mode": mode,
        "header_name": hdr_other,
        "vulnerable": "",
    }


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="bench_"))
    try:
        subprocess.run(
            ["docker", "cp", f"{CONTAINER}:{SRC}", str(tmp / "tc")],
            check=True,
        )
        tc = tmp / "tc"
        rows = []
        for f in sorted(tc.glob("BenchmarkTest*.java")):
            rows.append(
                classify(f.stem, f.read_text(encoding="utf-8", errors="replace"))
            )

        gt_path = pathlib.Path(__file__).resolve().parent / "cases.csv"
        if gt_path.exists():
            gt = {}
            with gt_path.open("r", encoding="utf-8", newline="") as fh:
                for r in csv.DictReader(fh):
                    gt[(r.get("testname") or "").strip()] = (
                        (r.get("vulnerable") or "").strip().lower()
                    )
            for r in rows:
                r["vulnerable"] = gt.get(r["testname"], "")

        with OUT.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

        import collections
        c = collections.Counter(r["mode"] for r in rows)
        print(f"wrote {len(rows)} rows to {OUT}")
        for k, v in c.most_common():
            print(f"  {k:24s} {v}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
