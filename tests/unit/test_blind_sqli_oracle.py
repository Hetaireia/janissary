"""Unit tests for blind SQLi oracle (Phase 4, FN-1)."""

from __future__ import annotations

from janissary.detection import ResponseSnapshot
from janissary.detection.blind_sqli_oracle import check_blind_sqli_oracle


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


NONREFLECTED_EXISTS = "User ID exists in the database. " + "x" * 200
NONREFLECTED_MISSING = "The ID is missing from the database. " + "y" * 200


def test_status_diff_nonreflected_emits():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap(NONREFLECTED_EXISTS, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap(NONREFLECTED_MISSING, 404), false_status=404,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert len(out) == 1
    assert out[0]["type"] == "blind_sqli_oracle"
    assert out[0]["category"] == "sqli_blind"


def test_length_diff_only_emits():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap("a" * 200, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap("a" * 300, 200), false_status=200,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert len(out) == 1


def test_identical_responses_no_emit():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap("x" * 200, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap("x" * 200, 200), false_status=200,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []


def test_reflected_status_differs_emits():
    # DVWA blind SQLi case: payload is echoed, but status code delta is real
    reflected_true = "User ID: 1' OR '1'='1 exists. " + "x" * 200
    reflected_false = "User ID: 1' AND '1'='2 missing. " + "y" * 200
    out = check_blind_sqli_oracle(
        true_snapshot=_snap(reflected_true, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap(reflected_false, 404), false_status=404,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert len(out) == 1


def test_reflected_same_status_no_emit():
    # Reflected payload + same status + same length -> guard against XSS echo
    reflected = "User ID: 1' OR '1'='1 and 1' AND '1'='2 . " + "x" * 200
    out = check_blind_sqli_oracle(
        true_snapshot=_snap(reflected, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap(reflected, 200), false_status=200,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []


def test_sql_error_in_body_no_emit():
    err = "You have an error in your SQL syntax near..." + "x" * 200
    out = check_blind_sqli_oracle(
        true_snapshot=_snap(err, 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap(NONREFLECTED_MISSING, 404), false_status=404,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []


def test_5xx_no_emit():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap("Internal Server Error " * 20, 500), true_status=500,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap("Internal Server Error " * 20, 500), false_status=500,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []


def test_empty_body_no_emit():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap("", 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap("", 200), false_status=200,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []


def test_small_length_diff_no_emit():
    out = check_blind_sqli_oracle(
        true_snapshot=_snap("x" * 200 + "HELLO", 200), true_status=200,
        true_payload="1' OR '1'='1",
        false_snapshot=_snap("x" * 200 + "WORLD", 200), false_status=200,
        false_payload="1' AND '1'='2",
        param="id",
    )
    assert out == []
