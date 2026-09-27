"""Unit tests for the XML-RPC multicall harness."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from janissary.integrations import xmlrpc as x

# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_encode_scalar_string():
    assert x.encode_value("hi") == "<value><string>hi</string></value>"


def test_encode_escapes_special_chars():
    out = x.encode_value("a<b>&c")
    assert "&lt;" in out and "&gt;" in out and "&amp;" in out


def test_encode_int_bool_none():
    assert "<int>42</int>" in x.encode_value(42)
    assert "<boolean>1</boolean>" in x.encode_value(True)
    assert "<nil/>" in x.encode_value(None)


def test_encode_array_and_struct():
    arr = x.encode_value([1, "two"])
    assert "<array>" in arr and "<int>1</int>" in arr
    struct = x.encode_value({"a": 1})
    assert "<struct>" in struct and "<name>a</name>" in struct


def test_encode_rejects_unknown():
    with pytest.raises(TypeError):
        x.encode_value(object())


def test_build_call_contains_method():
    body = x.build_call("foo.bar", [1, "x"])
    assert "<methodName>foo.bar</methodName>" in body
    assert body.count("<param>") == 2


def test_build_multicall_has_structs():
    body = x.build_multicall([("a", [1]), ("b", ["x"])])
    assert "<methodName>system.multicall</methodName>" in body
    assert body.count("<struct>") == 2
    assert "<name>methodName</name>" in body


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def _response(inner: str) -> str:
    return (
        '<?xml version="1.0"?>'
        f"<methodResponse><params><param>{inner}</param></params></methodResponse>"
    )


def test_parse_string():
    result, fault = x.parse_response(_response("<value><string>ok</string></value>"))
    assert result == "ok" and fault is None


def test_parse_int():
    result, _ = x.parse_response(_response("<value><int>7</int></value>"))
    assert result == 7


def test_parse_array():
    xml = _response(
        "<value><array><data>"
        "<value><int>1</int></value>"
        "<value><string>a</string></value>"
        "</data></array></value>"
    )
    result, _ = x.parse_response(xml)
    assert result == [1, "a"]


def test_parse_struct():
    xml = _response(
        "<value><struct>"
        "<member><name>k</name><value><string>v</string></value></member>"
        "</struct></value>"
    )
    result, _ = x.parse_response(xml)
    assert result == {"k": "v"}


def test_parse_fault():
    xml = (
        '<?xml version="1.0"?>'
        "<methodResponse><fault><value><struct>"
        "<member><name>faultCode</name><value><int>3</int></value></member>"
        "<member><name>faultString</name><value><string>nope</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )
    result, fault = x.parse_response(xml)
    assert result is None
    assert fault == {"faultCode": 3, "faultString": "nope"}


def test_parse_malformed_raises():
    with pytest.raises(x.XmlRpcError):
        x.parse_response("<not-xml")


def test_parse_empty_raises():
    with pytest.raises(x.XmlRpcError):
        x.parse_response("")


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------


def test_resolve_endpoint_appends_xmlrpc():
    assert x.resolve_endpoint("http://t/") == "http://t/xmlrpc.php"


def test_resolve_endpoint_passthrough():
    assert x.resolve_endpoint("http://t/xmlrpc.php") == "http://t/xmlrpc.php"


# ---------------------------------------------------------------------------
# Client + detection
# ---------------------------------------------------------------------------


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _session(responses):
    s = MagicMock()
    s.post.side_effect = list(responses)
    return s


def test_client_call_returns_value():
    xml = _response("<value><string>hello</string></value>")
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    assert client.call("demo.sayHello") == "hello"


def test_client_call_raises_fault():
    xml = (
        '<?xml version="1.0"?>'
        "<methodResponse><fault><value><struct>"
        "<member><name>faultCode</name><value><int>1</int></value></member>"
        "<member><name>faultString</name><value><string>no</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    with pytest.raises(x.XmlRpcFault) as exc:
        client.call("x")
    assert exc.value.code == 1


def test_detect_lists_methods():
    xml = _response(
        "<value><array><data>"
        "<value><string>system.listMethods</string></value>"
        "<value><string>system.multicall</string></value>"
        "<value><string>pingback.ping</string></value>"
        "</data></array></value>"
    )
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    profile = x.detect("http://t/", client=client)
    assert profile.reachable is True
    assert "system.listMethods" in profile.methods
    assert profile.multicall_supported is True
    assert profile.pingback_supported is True


def test_detect_handles_http_error():
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(status=404)])
    )
    profile = x.detect("http://t/", client=client)
    assert profile.reachable is False
    assert any("404" in n for n in profile.notes)


# ---------------------------------------------------------------------------
# Multicall bruteforce
# ---------------------------------------------------------------------------


def test_bruteforce_parses_success_and_fault():
    # Two pairs, one succeeds, one faults.
    xml = _response(
        "<value><array><data>"
        "<value><array><data><value><string>ok</string></value></data></array></value>"
        "<value><struct>"
        "<member><name>faultCode</name><value><int>403</int></value></member>"
        "<member><name>faultString</name><value><string>bad</string></value></member>"
        "</struct></value>"
        "</data></array></value>"
    )
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    attempts = x.bruteforce_multicall(
        client,
        usernames=["admin"],
        passwords=["good", "bad"],
        batch_size=10,
        sleep=lambda _: None,
    )
    assert len(attempts) == 2
    assert attempts[0].success is True
    assert attempts[1].success is False
    assert attempts[1].fault_code == 403


def test_bruteforce_batches():
    # 3 pairs, batch size 2 -> 2 HTTP requests.
    xml = _response(
        "<value><array><data>"
        "<value><array><data><value><int>1</int></value></data></array></value>"
        "<value><array><data><value><int>1</int></value></data></array></value>"
        "</data></array></value>"
    )
    session = _session([FakeResp(text=xml), FakeResp(text=xml)])
    client = x.XmlRpcClient("http://t/xmlrpc.php", session=session)
    attempts = x.bruteforce_multicall(
        client,
        usernames=["a"],
        passwords=["1", "2", "3"],
        batch_size=2,
        sleep=lambda _: None,
    )
    assert len(attempts) == 3
    assert session.post.call_count == 2


def test_bruteforce_transport_error():
    session = MagicMock()
    import requests

    session.post.side_effect = requests.RequestException("down")
    client = x.XmlRpcClient("http://t/xmlrpc.php", session=session)
    attempts = x.bruteforce_multicall(
        client,
        usernames=["a"],
        passwords=["1"],
        sleep=lambda _: None,
    )
    assert len(attempts) == 1
    assert attempts[0].success is False
    assert "transport error" in attempts[0].fault_message


def test_bruteforce_empty_input():
    client = x.XmlRpcClient("http://t/xmlrpc.php", session=_session([]))
    assert x.bruteforce_multicall(client, [], []) == []


# ---------------------------------------------------------------------------
# Pingback
# ---------------------------------------------------------------------------


def test_pingback_probe_success():
    xml = _response("<value><string>Pingback registered</string></value>")
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    ok, msg = x.pingback_probe(client, "http://target/post", "http://src/")
    assert ok is True
    assert "Pingback" in msg


def test_pingback_probe_fault():
    xml = (
        '<?xml version="1.0"?>'
        "<methodResponse><fault><value><struct>"
        "<member><name>faultCode</name><value><int>33</int></value></member>"
        "<member><name>faultString</name><value><string>nope</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )
    client = x.XmlRpcClient(
        "http://t/xmlrpc.php", session=_session([FakeResp(text=xml)])
    )
    ok, msg = x.pingback_probe(client, "http://target/post")
    assert ok is False
    assert "33" in msg
