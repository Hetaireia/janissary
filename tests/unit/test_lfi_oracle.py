"""Unit tests for the LFI content-injection oracle (Phase 4, FN-2/FN-3)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

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


# --- ADR-028 D8: 4 new signatures + verbose flag ---


def _baseline_028(bodies):
    return SimpleNamespace(snapshots=[SimpleNamespace(body=b) for b in bodies])


def _run_lfi_028(body, baseline_bodies=None):
    return check_lfi_content_oracle(
        baseline=_baseline_028(baseline_bodies or []),
        snapshot=SimpleNamespace(body=body),
        response_status=200,
        payload_value="/p",
        payload_name="p",
    )


def test_hostname_strict_in_body_emits():
    result = _run_lfi_028("myhostname")
    assert len(result) == 1
    assert "hostname" in result[0]["signatures"]


def test_os_release_emits():
    body = (
        'NAME="Ubuntu"' + chr(10) + 'PRETTY_NAME="Ubuntu 22.04"' + chr(10) + "ID=ubuntu"
    )
    result = _run_lfi_028(body)
    assert len(result) == 1
    assert "os_release" in result[0]["signatures"]


def test_proc_version_emits():
    body = "Linux version 5.15.0-91-generic (buildd@lcy02)"
    result = _run_lfi_028(body)
    assert len(result) == 1
    assert "proc_version" in result[0]["signatures"]


def test_boot_ini_emits():
    body = "[boot loader]" + chr(10) + "timeout=30"
    result = _run_lfi_028(body)
    assert len(result) == 1
    assert "boot_ini" in result[0]["signatures"]


def test_loose_pattern_rejected_in_context():
    # Loose pattern [a-z0-9][a-z0-9-]{2,62}$ would match the trailing
    # word here (line ends with "boolean"), but strict anchoring does not.
    body = '{"valid": boolean}'
    result = _run_lfi_028(body)
    assert len(result) == 0


def test_word_at_line_end_does_not_emit():
    body = "the type returned is boolean"
    result = _run_lfi_028(body)
    assert len(result) == 0


def test_multiple_signatures_emit_all():
    body = "myhostname" + chr(10) + "NAME=Ubuntu" + chr(10) + "[boot loader]"
    result = _run_lfi_028(body)
    assert len(result) == 1
    sigs = result[0]["signatures"]
    assert "hostname" in sigs
    assert "os_release" in sigs
    assert "boot_ini" in sigs


def test_verbose_flag_default_false():
    from janissary.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["scan", "--url", "http://x/"])
    assert args.verbose is False
    args2 = parser.parse_args(["scan", "--url", "http://x/", "--verbose"])
    assert args2.verbose is True
