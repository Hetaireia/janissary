"""Unit tests for the finding replay / explain module (M15)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from janissary.replay import (
    ReplayError,
    _parse_raw_request,
    format_explanation,
    load_findings,
    replay_finding,
)


class FakeResp:
    def __init__(self, status=200, content=b"ok", text="ok", headers=None, reason="OK"):
        self.status_code = status
        self.content = content
        self.text = text
        self.headers = headers or {}
        self.reason = reason
        self.url = ""
        self.request = None
        self.raw = None

    def json(self):
        return json.loads(self.text)


SAMPLE = {
    "id": "jfv1:abc123",
    "class": "sqli",
    "severity": "critical",
    "url": "http://127.0.0.1:4280/vulnerabilities/sqli/?id=%27",
    "method": "GET",
    "parameter": "id",
    "payload": "'",
    "raw_request": (
        "GET /vulnerabilities/sqli/?id=%27 HTTP/1.1\r\n"
        "Host: 127.0.0.1:4280\r\n"
        "User-Agent: test\r\n"
        "\r\n"
    ),
    "raw_response": "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello\n",
    "signals": [],
    "verification_status": "verified",
    "verification_reason": "analyzer:db_error",
    "response_status": 200,
    "timestamp": "2026-11-01T06:59:51Z",
}


def test_load_jsonl_single(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_text(json.dumps(SAMPLE) + "\n", encoding="utf-8")
    found = load_findings(p)
    assert len(found) == 1
    assert found[0]["id"] == "jfv1:abc123"


def test_load_jsonl_multiple_and_blank_lines(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_text(
        json.dumps(SAMPLE) + "\n\n" + json.dumps(SAMPLE) + "\n",
        encoding="utf-8",
    )
    assert len(load_findings(p)) == 2


def test_load_json_single_object(tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(SAMPLE), encoding="utf-8")
    assert len(load_findings(p)) == 1


def test_load_json_array(tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([SAMPLE, SAMPLE]), encoding="utf-8")
    assert len(load_findings(p)) == 2


def test_load_missing_file(tmp_path):
    with pytest.raises(ReplayError, match="file not found"):
        load_findings(tmp_path / "nope.jsonl")


def test_load_invalid_jsonl_raises(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ReplayError, match="invalid JSON"):
        load_findings(p)


def test_load_empty_file_returns_empty(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_text("", encoding="utf-8")
    assert load_findings(p) == []


def test_format_explanation_contains_key_fields():
    s = format_explanation(SAMPLE)
    assert "FINDING jfv1:abc123" in s
    assert "class:        sqli" in s
    assert "severity:     critical" in s
    assert "verification: verified (analyzer:db_error)" in s
    assert "URL:          http://127.0.0.1:4280" in s
    assert "raw request" in s
    assert "raw response" in s


def test_format_explanation_handles_missing_fields():
    s = format_explanation({"id": "x"})
    assert "FINDING x" in s
    assert "class:        ?" in s


def test_parse_raw_request_extracts_method_path_headers_body():
    raw = (
        "POST /a?x=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"k":"v"}'
    )
    parsed = _parse_raw_request(raw)
    assert parsed["method"] == "POST"
    assert parsed["path"] == "/a?x=1"
    assert parsed["headers"]["Host"] == "example.com"
    assert parsed["headers"]["Content-Type"] == "application/json"
    assert parsed["body"] == '{"k":"v"}'


def test_parse_raw_request_rejects_empty():
    with pytest.raises(ReplayError, match="empty raw_request"):
        _parse_raw_request("")


def test_replay_sends_parsed_request_and_returns_match():
    mock = MagicMock()
    mock.request.return_value = FakeResp(200, content=b"ok")
    result = replay_finding(SAMPLE, timeout=5.0, session=mock)
    assert result["status"] == 200
    assert result["match"] is True
    assert result["length"] == 2
    call = mock.request.call_args
    assert call.args[0] == "GET"
    assert call.args[1] == "http://127.0.0.1:4280/vulnerabilities/sqli/?id=%27"
    assert call.kwargs["timeout"] == 5.0
    assert call.kwargs["allow_redirects"] is False


def test_replay_marks_changed_when_status_differs():
    mock = MagicMock()
    mock.request.return_value = FakeResp(500, content=b"err")
    result = replay_finding(SAMPLE, session=mock)
    assert result["status"] == 500
    assert result["match"] is False


def test_replay_missing_raw_request_raises():
    with pytest.raises(ReplayError, match="empty raw_request"):
        replay_finding({"url": "http://x/"}, session=MagicMock())


def test_replay_missing_url_raises():
    with pytest.raises(ReplayError, match="has no url"):
        replay_finding(
            {"raw_request": "GET / HTTP/1.1\r\n\r\n"},
            session=MagicMock(),
        )


def test_replay_transport_failure_raises():
    import requests

    mock = MagicMock()
    mock.request.side_effect = requests.RequestException("boom")
    with pytest.raises(ReplayError, match="replay request failed"):
        replay_finding(SAMPLE, session=mock)
