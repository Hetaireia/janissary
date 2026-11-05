"""Unit tests for the native Interactsh OOB client (ADR-015 D7).

Covers:
- Registration state (correlation id, secret, server)
- All-servers-fail and missing-cryptography error paths
- Interface parity with CollaboratorClient (new_unique_id, payload_for)
- Poll transport / protocol error handling
- End-to-end decrypt + uniq attribution against RSA-OAEP / AES-CFB
"""

from __future__ import annotations

import base64
import json
import secrets
from unittest.mock import MagicMock

import pytest
import requests

pytest.importorskip("cryptography")

from janissary.integrations.collaborator import (
    CollaboratorError,
    SsrfPayload,
)
from janissary.integrations.interactsh import (
    DEFAULT_SERVERS,
    InteractshClient,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = ""
        self.request = None

    def json(self):
        return json.loads(self.text)


def _new_client(server="test.local"):
    """Construct an InteractshClient with a mocked requests session."""
    sess = MagicMock()
    sess.post.return_value = FakeResp(200, text="")
    sess.close = MagicMock()
    return InteractshClient(server=server, session=sess), sess


def _encrypt_aes_key(client, aes_key):
    """RSA-OAEP encrypt a 32-byte AES key against the client's public key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    pub = client._private_key.public_key()
    ct = pub.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()


def _encrypt_entry(aes_key, entry):
    """AES-CFB encrypt an entry dict as iv(16) || ct, base64-encoded."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.modes import CFB

    iv = secrets.token_bytes(16)
    encryptor = Cipher(algorithms.AES(aes_key), CFB(iv)).encryptor()
    ct = encryptor.update(json.dumps(entry).encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()


# ---- construction / registration ----------------------------------------


def test_registration_populates_state():
    client, sess = _new_client()
    assert client.server == "test.local"
    assert len(client._correlation_id) == 20
    assert client._correlation_id.isalnum()
    assert client._secret_key_b64
    assert sess.post.call_count == 1


def test_registration_all_servers_fail():
    sess = MagicMock()
    sess.post.return_value = FakeResp(500, text="down")
    sess.close = MagicMock()
    with pytest.raises(CollaboratorError, match="registration failed"):
        InteractshClient(session=sess)
    assert sess.post.call_count == len(DEFAULT_SERVERS)


def test_missing_cryptography_raises(monkeypatch):
    import janissary.integrations.interactsh as mod

    monkeypatch.setattr(mod, "_CRYPTO_AVAILABLE", False)
    with pytest.raises(CollaboratorError, match="cryptography"):
        InteractshClient(server="test.local")


# ---- interface parity with CollaboratorClient ---------------------------


def test_new_unique_id_format():
    client, _ = _new_client()
    u1 = client.new_unique_id()
    u2 = client.new_unique_id()
    assert u1.startswith("jns-")
    assert len(u1) == 20
    assert u1 != u2


def test_payload_for_renders_url():
    client, _ = _new_client()
    payload = SsrfPayload("ssrf_http", "http://{uniq}.{collab}/")
    uniq = "jns-abcdef0123456789"
    url = client.payload_for(payload, uniq)
    assert url == f"http://jns-abcdef0123456789.{client.base_domain}/"


# ---- poll: transport / protocol errors ----------------------------------


def test_poll_204_returns_empty():
    client, sess = _new_client()
    sess.get.return_value = FakeResp(204, text="")
    assert client.poll("jns-x") == []


def test_poll_500_raises():
    client, sess = _new_client()
    sess.get.return_value = FakeResp(500, text="server error")
    with pytest.raises(CollaboratorError):
        client.poll("jns-x")


def test_poll_transport_failure_raises():
    client, sess = _new_client()
    sess.get.side_effect = requests.RequestException("boom")
    with pytest.raises(CollaboratorError, match="poll failed"):
        client.poll("jns-x")


def test_poll_missing_aes_key_returns_empty():
    client, sess = _new_client()
    sess.get.return_value = FakeResp(200, text=json.dumps({"data": []}))
    assert client.poll("jns-x") == []


# ---- poll: successful decrypt + attribution -----------------------------


def test_poll_decrypts_and_attributes_hit():
    client, sess = _new_client()
    uniq = client.new_unique_id("ssrf_http")
    aes_key = secrets.token_bytes(32)
    entry = {
        "protocol": "http",
        "unique-id": uniq,
        "full-id": f"{uniq}.{client.base_domain}",
        "remote-address": "1.2.3.4",
        "timestamp": "2026-11-04T00:00:00Z",
    }
    body = {
        "aes_key": _encrypt_aes_key(client, aes_key),
        "data": [_encrypt_entry(aes_key, entry)],
    }
    sess.get.return_value = FakeResp(200, text=json.dumps(body))

    hits = client.poll(uniq)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.protocol == "http"
    assert hit.payload_name == "ssrf_http"
    assert hit.subdomain == uniq
    assert hit.source_ip == "1.2.3.4"


def test_poll_unmatched_entry_is_skipped():
    client, sess = _new_client()
    aes_key = secrets.token_bytes(32)
    entry = {
        "protocol": "http",
        "unique-id": "jns-unrelatedaaaaaaa",
        "full-id": "jns-unrelatedaaaaaaa.somewhere",
        "remote-address": "5.6.7.8",
        "timestamp": "2026-11-04T00:00:00Z",
    }
    body = {
        "aes_key": _encrypt_aes_key(client, aes_key),
        "data": [_encrypt_entry(aes_key, entry)],
    }
    sess.get.return_value = FakeResp(200, text=json.dumps(body))
    assert client.poll("jns-unknown") == []


def test_poll_tampered_entry_is_skipped():
    client, sess = _new_client()
    uniq = client.new_unique_id("ssrf_http")
    aes_key = secrets.token_bytes(32)
    body = {
        "aes_key": _encrypt_aes_key(client, aes_key),
        "data": [base64.b64encode(b"not-valid-encrypted").decode()],
    }
    sess.get.return_value = FakeResp(200, text=json.dumps(body))
    assert client.poll(uniq) == []
