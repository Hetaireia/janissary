"""Unit tests for SSRF collaborator client (ADR-012)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from janissary.integrations.collaborator import (
    CollaboratorClient,
    CollaboratorError,
    SsrfPayload,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = ""
        self.request = None

    def json(self):
        import json

        return json.loads(self.text)


def _collab_session(responses):
    s = MagicMock()
    s.get.side_effect = list(responses)
    s.close = MagicMock()
    return s


def test_client_new_unique_id_format():
    """Uniq format is 'jns-' + 16 hex, distinct across calls."""
    c = CollaboratorClient("http://collab.example.com", session=_collab_session([]))
    u1 = c.new_unique_id()
    u2 = c.new_unique_id()
    assert u1.startswith("jns-")
    assert len(u1) == 20
    assert u1 != u2


def test_client_payload_for_renders_url():
    """Template substitution fills {uniq} and {collab}."""
    c = CollaboratorClient("http://collab.example.com", session=_collab_session([]))
    payload = SsrfPayload("test", "http://{uniq}.{collab}/")
    url = c.payload_for(payload, "jns-abc123")
    assert "jns-abc123" in url
    assert "collab.example.com" in url


def test_client_poll_empty_body_returns_empty():
    """204 No Content -> empty list, no exception."""
    c = CollaboratorClient(
        "http://collab.example.com",
        session=_collab_session([FakeResp(status=204, text="")]),
    )
    assert c.poll("jns-abc") == []


def test_client_poll_transport_error_raises():
    """Transport failure surfaces as CollaboratorError."""
    s = MagicMock()
    s.get.side_effect = requests.RequestException("boom")
    c = CollaboratorClient("http://collab.example.com", session=s)
    with pytest.raises(CollaboratorError):
        c.poll("jns-abc")
