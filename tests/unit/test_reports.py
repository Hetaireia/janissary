"""Unit tests for HTML and PDF report renderers (M19)."""

from __future__ import annotations

import pytest

from janissary.reporting.html_report import write_html_report
from janissary.reporting.pdf_report import (
    _escape_pdf_text,
    _normalize,
    _paginate,
    _wrap,
    write_pdf_report,
)


FINDING = {
    "class": "sqli",
    "severity": "critical",
    "url": "http://example.com/x?q=%27",
    "parameter": "q",
    "payload": "'",
    "detail": "SQL error",
    "raw_request": "GET /x?q=%27 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "raw_response": "HTTP/1.1 200 OK\r\n\r\n<pre>err</pre>",
    "verification_status": "verified",
    "verification_reason": "analyzer:db_error",
}

PAYLOAD = {
    "target": "http://example.com",
    "timestamp": "2026-11-04T00:00:00Z",
    "findings": [FINDING],
}


# ---- html renderer --------------------------------------------------------


def test_html_doctype_and_structure(tmp_path):
    out = tmp_path / "r.html"
    write_html_report(PAYLOAD, str(out))
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "<title>JANISSARY report" in text
    assert "http://example.com" in text
    assert "Total findings:</b> 1" in text


def test_html_renders_finding_fields(tmp_path):
    out = tmp_path / "r.html"
    write_html_report(PAYLOAD, str(out))
    text = out.read_text(encoding="utf-8")
    assert "sqli" in text
    assert "CRITICAL" in text
    assert "GET /x?q=%27" in text
    assert "analyzer:db_error" in text


def test_html_escapes_xss_in_detail(tmp_path):
    evil = dict(FINDING, detail="<script>alert(1)</script>")
    out = tmp_path / "r.html"
    write_html_report({"target": "t", "findings": [evil]}, str(out))
    text = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_html_empty_findings(tmp_path):
    out = tmp_path / "r.html"
    write_html_report({"target": "t", "findings": []}, str(out))
    text = out.read_text(encoding="utf-8")
    assert "No findings." in text
    assert "no findings" in text


def test_html_accepts_bare_findings_list(tmp_path):
    out = tmp_path / "r.html"
    write_html_report([FINDING], str(out))
    text = out.read_text(encoding="utf-8")
    assert "sqli" in text
    assert "Total findings:</b> 1" in text


def test_html_handles_garbage_payload(tmp_path):
    out = tmp_path / "r.html"
    write_html_report("not a dict or list", str(out))
    text = out.read_text(encoding="utf-8")
    assert "No findings." in text


# ---- pdf renderer ---------------------------------------------------------


def test_pdf_magic_bytes_and_trailer(tmp_path):
    out = tmp_path / "r.pdf"
    write_pdf_report(PAYLOAD, str(out))
    data = out.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"%%EOF" in data[-100:]
    assert b"xref" in data


def test_pdf_contains_font_and_finding_text(tmp_path):
    out = tmp_path / "r.pdf"
    write_pdf_report(PAYLOAD, str(out))
    data = out.read_bytes()
    assert b"Helvetica" in data
    assert b"sqli" in data
    assert b"CRITICAL" in data
    assert b"GET /x?q=%27" in data


def test_pdf_empty_findings(tmp_path):
    out = tmp_path / "r.pdf"
    write_pdf_report({"target": "t", "findings": []}, str(out))
    data = out.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"No findings." in data


def test_pdf_multipage_when_many_findings(tmp_path):
    import re

    many = [dict(FINDING, url=f"http://x/{i}") for i in range(50)]
    out = tmp_path / "r.pdf"
    write_pdf_report({"target": "t", "findings": many}, str(out))
    data = out.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    m = re.search(rb"/Count (\d+)", data)
    assert m is not None, "/Count not found in PDF"
    count = int(m.group(1))
    assert count >= 2, f"expected multi-page PDF, got /Count {count}"


def test_pdf_non_ascii_replaced(tmp_path):
    f = dict(FINDING, detail="cafe\u00e9")
    out = tmp_path / "r.pdf"
    write_pdf_report({"target": "t", "findings": [f]}, str(out))
    data = out.read_bytes()
    assert b"cafe?" in data
    assert b"caf\xe9" not in data


# ---- helper unit tests ----------------------------------------------------


def test_escape_pdf_text_specials():
    assert _escape_pdf_text("(hi)") == r"\(hi\)"
    assert _escape_pdf_text(r"a\b") == r"a\\b"
    assert _escape_pdf_text("cafe\u00e9") == "cafe?"


def test_wrap_short_and_long():
    assert _wrap("hello", 10) == ["hello"]
    long = "x" * 25
    assert _wrap(long, 10) == ["x" * 10, "x" * 10, "x" * 5]


def test_paginate_empty_returns_one_page():
    assert _paginate([]) == [[""]]


def test_paginate_splits_correctly():
    lines = [str(i) for i in range(120)]
    pages = _paginate(lines, per_page=50)
    assert len(pages) == 3
    assert len(pages[0]) == 50
    assert len(pages[2]) == 20


def test_normalize_handles_all_shapes():
    meta, findings = _normalize({"target": "t", "findings": [FINDING]})
    assert meta == {"target": "t"}
    assert findings == [FINDING]

    meta, findings = _normalize([FINDING])
    assert meta == {} and findings == [FINDING]

    meta, findings = _normalize(None)
    assert meta == {} and findings == []
