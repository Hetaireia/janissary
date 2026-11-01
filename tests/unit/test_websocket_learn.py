"""Tests for WebSocket learning algorithms (Phase 2.2 + FN-16 part 2)."""
import json

import pytest

from janissary.integrations.websocket_learn import (
    detect_wire_format,
    find_injectable_fields,
    set_field_value,
)
from janissary.protocols.websocket import MessageSequence, WebSocketMessage


def _seq(*frames) -> MessageSequence:
    return MessageSequence(messages=list(frames))


def _c2s(payload: str) -> WebSocketMessage:
    return WebSocketMessage(direction="c2s", payload=payload)


def _s2c(payload: str) -> WebSocketMessage:
    return WebSocketMessage(direction="s2c", payload=payload)


# ---------------- detect_wire_format ----------------


def test_wire_format_json_when_all_c2s_parse():
    s = _seq(_c2s('{"a":1}'), _c2s('[1,2]'))
    assert detect_wire_format(s) == "json"


def test_wire_format_json_majority():
    s = _seq(_c2s('{"a":1}'), _c2s('not json'))
    assert detect_wire_format(s) == "json"


def test_wire_format_text_when_minority_json():
    s = _seq(_c2s('{"a":1}'), _c2s('hello'), _c2s('world'))
    assert detect_wire_format(s) == "text"


def test_wire_format_xml():
    s = _seq(_c2s('<?xml version="1.0"?><msg/>'))
    assert detect_wire_format(s) == "xml"


def test_wire_format_unknown_when_no_c2s():
    s = _seq(_s2c('{"a":1}'), _s2c('hello'))
    assert detect_wire_format(s) == "unknown"


def test_wire_format_unknown_when_empty():
    s = _seq(_c2s(''), _c2s('   '))
    assert detect_wire_format(s) == "unknown"


def test_wire_format_ignores_s2c_when_scoring():
    s = _seq(_c2s('{"a":1}'), _s2c('not json'), _s2c('also not'))
    assert detect_wire_format(s) == "json"


# ---------------- find_injectable_fields ----------------


def test_find_flat_string_leaf():
    s = _seq(_c2s('{"name":"alice"}'))
    fields = find_injectable_fields(s)
    assert len(fields) == 1
    f = fields[0]
    assert f.message_index == 0
    assert f.path == "name"
    assert f.value_kind == "string"
    assert f.original_value == "alice"


def test_find_nested_leaf():
    s = _seq(_c2s('{"user":{"id":42,"name":"bob"}}'))
    fields = find_injectable_fields(s)
    paths = sorted(f.path for f in fields)
    assert paths == ["user.id", "user.name"]
    kinds = {f.path: f.value_kind for f in fields}
    assert kinds["user.id"] == "integer"
    assert kinds["user.name"] == "string"


def test_find_array_element():
    s = _seq(_c2s('{"items":[{"sku":"A"},{"sku":"B"}]}'))
    fields = find_injectable_fields(s)
    paths = sorted(f.path for f in fields)
    assert paths == ["items[0].sku", "items[1].sku"]


def test_find_skips_bool():
    s = _seq(_c2s('{"flag":true,"name":"x"}'))
    fields = find_injectable_fields(s)
    paths = [f.path for f in fields]
    assert "flag" not in paths
    assert "name" in paths


def test_find_skips_null():
    s = _seq(_c2s('{"a":null,"b":"x"}'))
    paths = [f.path for f in find_injectable_fields(s)]
    assert "a" not in paths
    assert "b" in paths


def test_find_finds_float():
    s = _seq(_c2s('{"price":1.99}'))
    fields = find_injectable_fields(s)
    assert len(fields) == 1
    assert fields[0].value_kind == "float"


def test_find_only_c2s_messages():
    s = _seq(_c2s('{"a":"x"}'), _s2c('{"b":"y"}'))
    fields = find_injectable_fields(s)
    assert len(fields) == 1
    assert fields[0].message_index == 0


def test_find_deterministic_order_ignores_json_key_order():
    a = _seq(_c2s('{"z":1,"a":2,"m":3}'))
    b = _seq(_c2s('{"m":3,"a":2,"z":1}'))
    pa = [f.path for f in find_injectable_fields(a)]
    pb = [f.path for f in find_injectable_fields(b)]
    assert pa == pb == ["a", "m", "z"]


def test_find_multiple_messages_index_recorded():
    s = _seq(_c2s('{"a":"x"}'), _s2c('{}'), _c2s('{"b":"y"}'))
    fields = find_injectable_fields(s)
    by_index = {f.message_index: f.path for f in fields}
    assert by_index[0] == "a"
    assert by_index[2] == "b"


def test_find_empty_when_no_c2s_json():
    s = _seq(_s2c('{"a":"x"}'), _c2s('plain text'))
    assert find_injectable_fields(s) == []


# ---------------- set_field_value ----------------


def test_set_flat_leaf():
    out = set_field_value('{"name":"alice","age":30}', "name", "MUTATED")
    parsed = json.loads(out)
    assert parsed["name"] == "MUTATED"
    assert parsed["age"] == 30
    # canonical: sorted keys, no whitespace
    assert out == '{"age":30,"name":"MUTATED"}'


def test_set_nested_leaf():
    out = set_field_value('{"user":{"id":1,"name":"x"}}', "user.name", "y")
    assert json.loads(out)["user"]["name"] == "y"


def test_set_array_element():
    out = set_field_value('{"items":[{"sku":"A"},{"sku":"B"}]}', "items[1].sku", "B2")
    assert json.loads(out)["items"][1]["sku"] == "B2"


def test_set_changes_type():
    """Injecting a string into an integer field is allowed (that's a probe)."""
    out = set_field_value('{"id":42}', "id", "'; DROP TABLE--")
    assert json.loads(out)["id"] == "'; DROP TABLE--"


def test_set_rejects_invalid_json():
    with pytest.raises(ValueError, match="not valid JSON"):
        set_field_value("not json", "a", 1)


def test_set_rejects_missing_key():
    with pytest.raises(ValueError, match="not found"):
        set_field_value('{"a":1}', "b", 2)


def test_set_rejects_container_target():
    with pytest.raises(ValueError, match="container"):
        set_field_value('{"user":{"name":"x"}}', "user", "flat")


def test_set_rejects_out_of_range_index():
    with pytest.raises(ValueError, match="out of range"):
        set_field_value('{"items":[1]}', "items[5]", 2)


def test_find_then_set_roundtrip():
    """The two functions must compose: found paths are settable."""
    payload = '{"user":{"id":7,"tags":["a","b"]},"active":true}'
    seq = _seq(_c2s(payload))
    for field in find_injectable_fields(seq):
        # Should not raise; every found path should be settable.
        new_payload = set_field_value(payload, field.path, "INJECTED")
        assert json.loads(new_payload)  # valid JSON
