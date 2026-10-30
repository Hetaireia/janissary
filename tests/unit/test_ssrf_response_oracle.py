"""Unit tests for SSRF response-body oracle (Phase 4, Session B)."""

from __future__ import annotations

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.ssrf_response_oracle import check_ssrf_response_oracle


def _snap(body, status=200):
    return ResponseSnapshot(
        status=status,
        body=body,
        normalized=body,
        fingerprint=body,
        length=len(body),
        normalized_length=len(body),
        elapsed=0.01,
        content_type="text/html",
    )


def _baseline_of(body, count=3):
    b = Baseline()
    for _ in range(count):
        b.add(_snap(body))
    return b


MAILHOG_BODY = '<html><head><title>MailHog</title></head><body>Inbox messages</body></html>'
CLEAN_BODY = '<html><body>Welcome to crAPI shop</body></html>'
URL_PAYLOAD = "http://mailhog:8025/"


def test_fires_on_marker_present_not_in_baseline():
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(MAILHOG_BODY),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert len(out) == 1
    assert out[0]["type"] == "ssrf_response_oracle"
    assert out[0]["category"] == "ssrf"
    assert out[0]["severity"] == "critical"


def test_no_fire_on_reflected_payload_only():
    reflected = f'{{"error":"could not fetch {URL_PAYLOAD}"}}'
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(reflected),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert out == []


def test_no_fire_on_baseline_contains_marker():
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(MAILHOG_BODY),
        snapshot=_snap(MAILHOG_BODY),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert out == []


def test_no_fire_on_4xx():
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(MAILHOG_BODY, status=404),
        response_status=404,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert out == []


def test_no_fire_on_empty_body():
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(""),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert out == []


def test_multiple_markers_reported():
    body = '<title>MailHog</title><p>Powered by mailhog</p>'
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(body),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=["MailHog", "mailhog"],
    )
    assert len(out) == 1
    assert set(out[0]["markers"]) == {"MailHog", "mailhog"}


def test_no_fire_on_no_markers_list():
    out = check_ssrf_response_oracle(
        baseline=_baseline_of(CLEAN_BODY),
        snapshot=_snap(MAILHOG_BODY),
        response_status=200,
        payload_value=URL_PAYLOAD,
        payload_name="ssrf_mailhog_canary",
        fetch_markers=[],
    )
    assert out == []
