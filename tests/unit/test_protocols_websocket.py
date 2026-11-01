"""Tests for WebSocketNormalizer (Phase 2.2 + FN-16 part 1)."""
from janissary.protocols import BaselineNormalizer, NormalizedResponse
from janissary.protocols.websocket import (
    MessageSequence,
    WebSocketMessage,
    WebSocketNormalizer,
)


def _seq(*frames) -> MessageSequence:
    return MessageSequence(messages=list(frames))


def test_normalizer_satisfies_baseline_protocol():
    assert isinstance(WebSocketNormalizer(), BaselineNormalizer)
    assert WebSocketNormalizer.protocol_name == "websocket"


def test_empty_sequence_normalizes_to_empty_array():
    out = WebSocketNormalizer().normalize(MessageSequence())
    assert out.body == "[]"
    assert out.length == 2
    assert out.status is None


def test_single_frame_canonicalizes():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(direction="c2s", payload='{"b": 2, "a": 1}'),
    ))
    assert out.body == '[{"direction":"c2s","payload":"{\\"a\\":1,\\"b\\":2}"}]'


def test_order_preserved_across_directions():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(direction="c2s", payload="ping"),
        WebSocketMessage(direction="s2c", payload="pong"),
        WebSocketMessage(direction="c2s", payload="ping"),
    ))
    # Payloads are non-JSON; whitespace-collapsed text preserved as-is
    assert '"c2s","payload":"ping"' in out.body
    assert '"s2c","payload":"pong"' in out.body
    # Order matters: c2s appears before s2c appears before c2s
    c2s_first = out.body.find('"c2s"')
    s2c_pos = out.body.find('"s2c"')
    c2s_second = out.body.find('"c2s"', c2s_first + 1)
    assert c2s_first < s2c_pos < c2s_second


def test_timing_dropped_from_body():
    a = _seq(
        WebSocketMessage(direction="c2s", payload="ping", elapsed=0.001),
        WebSocketMessage(direction="s2c", payload="pong", elapsed=0.002),
    )
    b = _seq(
        WebSocketMessage(direction="c2s", payload="ping", elapsed=5.7),
        WebSocketMessage(direction="s2c", payload="pong", elapsed=6.1),
    )
    na = WebSocketNormalizer().normalize(a)
    nb = WebSocketNormalizer().normalize(b)
    assert na.body == nb.body
    assert "body:timing_dropped" in na.stripped
    assert "body:timing_dropped" in nb.stripped


def test_volatile_keys_stripped_from_json_payloads():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(
            direction="c2s",
            payload='{"type": "ping", "timestamp": 1234, "session_id": "abc"}',
        ),
    ))
    assert "1234" not in out.body
    assert "abc" not in out.body
    assert "ping" in out.body
    assert any("timestamp" in s for s in out.stripped)
    assert any("session_id" in s for s in out.stripped)


def test_volatile_keys_stripped_nested():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(
            direction="s2c",
            payload='{"user": {"name": "alice", "sessionId": "xyz"}}',
        ),
    ))
    assert "xyz" not in out.body
    assert "alice" in out.body
    assert any("sessionId" in s for s in out.stripped)


def test_non_json_payload_whitespace_collapsed():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(direction="c2s", payload="  hello\n\n  world  "),
    ))
    assert "hello world" in out.body
    # Should not have internal double-space
    assert '  hello' not in out.body


def test_semantically_equivalent_sequences_normalize_identically():
    """The whole point: two connections with the same traffic produce
    byte-identical canonical bodies."""
    a = _seq(
        WebSocketMessage(direction="c2s", payload='{"b": 2, "a": 1, "timestamp": 111}'),
        WebSocketMessage(direction="s2c", payload='{"result": "ok", "ts": 222}'),
    )
    b = _seq(
        WebSocketMessage(direction="c2s", payload='{"a": 1, "b": 2, "timestamp": 999}'),
        WebSocketMessage(direction="s2c", payload='{"ts": 888, "result": "ok"}'),
    )
    na = WebSocketNormalizer().normalize(a)
    nb = WebSocketNormalizer().normalize(b)
    assert na.body == nb.body


def test_different_traffic_differs():
    """Sanity: genuinely different traffic must not collide."""
    a = _seq(WebSocketMessage(direction="c2s", payload='{"type": "subscribe", "channel": "A"}'))
    b = _seq(WebSocketMessage(direction="c2s", payload='{"type": "subscribe", "channel": "B"}'))
    na = WebSocketNormalizer().normalize(a)
    nb = WebSocketNormalizer().normalize(b)
    assert na.body != nb.body


def test_wrong_input_type_reported_honestly():
    """Not a MessageSequence -> empty body + honest stripped marker,
    not a silent clean."""
    out = WebSocketNormalizer().normalize({"not": "a sequence"})
    assert out.body == ""
    assert out.length == 0
    assert "body:wrong_input_type" in out.stripped


def test_stripped_is_tuple():
    out = WebSocketNormalizer().normalize(MessageSequence())
    assert isinstance(out.stripped, tuple)


def test_length_matches_body():
    out = WebSocketNormalizer().normalize(_seq(
        WebSocketMessage(direction="c2s", payload="ping"),
    ))
    assert out.length == len(out.body)
