"""Unit tests for the LFI content-injection oracle (Phase 4, FN-2/FN-3)."""

from __future__ import annotations

from pathlib import Path

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.lfi_oracle import check_lfi_content_oracle

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REAL_FORM = (FIXTURES / "real_html_form.html").read_text(encoding="utf-8")
PASSWD = (FIXTURES / "etc_passwd.txt").read_text(encoding="utf-8")
MINIMAL = "<html><body>hello</body></html>"


def _snap(
    body: str, status: int = 200, content_type: str = "text/html"
) -> ResponseSnapshot:
    return ResponseSnapshot(
        status=status,
        body=body,
        normalized=body,
        fingerprint=body,
        length=len(body),
        normalized_length=len(body),
        elapsed=0.01,
        content_type=content_type,
    )


def _baseline_of(body: str, count: int = 3) -> Baseline:
    b = Baseline()
    for _ in range(count):
        b.add(_snap(body))
    return b


def test_passwd_in_body_emits():
    baseline = _baseline_of(REAL_FORM)
    snap = _snap(PASSWD)
    out = check_lfi_content_oracle(
        baseline=baseline,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert len(out) == 1
    assert out[0]["type"] == "lfi_content_oracle"
    assert out[0]["category"] == "traversal"
    assert "passwd" in out[0]["signatures"]


def test_clean_body_no_emit():
    baseline = _baseline_of(REAL_FORM)
    snap = _snap(MINIMAL)
    out = check_lfi_content_oracle(
        baseline=baseline,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_passwd_already_in_baseline_no_emit():
    baseline = _baseline_of(PASSWD)
    snap = _snap(PASSWD)
    out = check_lfi_content_oracle(
        baseline=baseline,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_non_2xx_no_emit():
    baseline = _baseline_of(REAL_FORM)
    snap = _snap(PASSWD, status=404)
    out = check_lfi_content_oracle(
        baseline=baseline,
        snapshot=snap,
        response_status=404,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_empty_body_no_emit():
    baseline = _baseline_of(REAL_FORM)
    snap = _snap("")
    out = check_lfi_content_oracle(
        baseline=baseline,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert out == []
