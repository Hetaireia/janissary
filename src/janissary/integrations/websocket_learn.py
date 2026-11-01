"""WebSocket learning algorithms (Phase 2.2 + FN-16 part 2).

Pure functions that analyze a captured MessageSequence to determine:
- what wire format the c2s messages use (JSON, XML, text, unknown)
- which leaf values are safely injectable in c2s JSON payloads
- how to reconstruct a mutated JSON payload from a field path

The async orchestration (connect, sample traffic, call these) is
``integrations.websocket_learn.learn()`` in FN-16 part 3. These
functions are pure, deterministic, and unit-testable in isolation.

See docs/PHASE-6-PLAN.md FN-16.
"""
from __future__ import annotations

import json
import re
from typing import Any

from janissary.protocols.websocket import (
    InjectableField,
    MessageSequence,
    WireFormat,
)


_XML_PREFIX_RE = re.compile(r"^\s*<\?xml", re.IGNORECASE)


def detect_wire_format(sequence: MessageSequence) -> WireFormat:
    """Determine the wire format from c2s messages.

    Only client-to-server messages are inspected: s2c traffic is
    server-authored and we cannot inject into it, so it does not
    constrain probe strategy.

    Tie-break rule: if fewer than half of c2s messages parse as
    JSON, or if no c2s messages exist, returns "unknown". XML
    detection requires an ``<?xml`` declaration on the first
    non-empty c2s message. "text" is returned when c2s messages
    exist but are neither JSON nor XML.
    """
    c2s_payloads = [m.payload for m in sequence.messages if m.direction == "c2s"]
    non_empty = [p.strip() for p in c2s_payloads if p.strip()]
    if not non_empty:
        return "unknown"

    if _XML_PREFIX_RE.match(non_empty[0]):
        return "xml"

    json_parses = 0
    for p in non_empty:
        try:
            parsed = json.loads(p)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, (dict, list)):
            json_parses += 1

    if json_parses * 2 >= len(non_empty):
        return "json"
    return "text"


def _join_path(prefix: str, segment: str) -> str:
    if not prefix:
        return segment
    return prefix + "." + segment


def _join_index(prefix: str, index: int) -> str:
    return f"{prefix}[{index}]"


def _walk_injectables(
    value: Any,
    prefix: str,
    message_index: int,
    out: list[InjectableField],
) -> None:
    """Depth-first walk; append InjectableField for each allowed leaf.

    Injectable leaves: str, int (not bool), float. Everything else
    (dict/list containers, None, bool) is descended into or skipped.
    """
    # bool is a subclass of int in Python; check it first.
    if isinstance(value, bool):
        return
    if value is None:
        return
    if isinstance(value, str):
        out.append(InjectableField(
            message_index=message_index,
            path=prefix,
            value_kind="string",
            original_value=value,
        ))
        return
    if isinstance(value, int):
        out.append(InjectableField(
            message_index=message_index,
            path=prefix,
            value_kind="integer",
            original_value=value,
        ))
        return
    if isinstance(value, float):
        out.append(InjectableField(
            message_index=message_index,
            path=prefix,
            value_kind="float",
            original_value=value,
        ))
        return
    if isinstance(value, dict):
        # Sort keys for deterministic traversal across otherwise-equivalent
        # payloads with different JSON key ordering.
        for k in sorted(value.keys()):
            _walk_injectables(value[k], _join_path(prefix, k), message_index, out)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _walk_injectables(item, _join_index(prefix, i), message_index, out)
        return


def find_injectable_fields(sequence: MessageSequence) -> list[InjectableField]:
    """Enumerate leaf fields in c2s JSON messages that a probe can mutate.

    Non-JSON c2s messages are skipped (they are not safely mutable
    without format-specific handling). s2c messages are never walked.

    Returned order: message_index ascending, then depth-first within
    each message with dict keys sorted. Deterministic across captures
    that carry the same semantic traffic (post-normalization).
    """
    out: list[InjectableField] = []
    for msg_index, msg in enumerate(sequence.messages):
        if msg.direction != "c2s":
            continue
        payload = msg.payload.strip()
        if not payload:
            continue
        try:
            parsed = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, (dict, list)):
            continue
        _walk_injectables(parsed, "", msg_index, out)
    return out


def _split_path(path: str) -> list[tuple[str, Any]]:
    """Parse 'a.b[0].c' into [('key','a'), ('key','b'), ('index',0), ('key','c')]."""
    steps: list[tuple[str, Any]] = []
    i = 0
    n = len(path)
    buf = ""
    while i < n:
        ch = path[i]
        if ch == ".":
            if buf:
                steps.append(("key", buf))
                buf = ""
            i += 1
        elif ch == "[":
            if buf:
                steps.append(("key", buf))
                buf = ""
            j = path.find("]", i)
            if j < 0:
                raise ValueError(f"unclosed bracket in path: {path!r}")
            try:
                idx = int(path[i + 1:j])
            except ValueError as exc:
                raise ValueError(f"non-integer index in path: {path!r}") from exc
            steps.append(("index", idx))
            i = j + 1
        else:
            buf += ch
            i += 1
    if buf:
        steps.append(("key", buf))
    return steps


def set_field_value(payload: str, path: str, new_value: Any) -> str:
    """Mutate one leaf in a JSON payload; return canonical JSON.

    ``path`` is the format produced by ``find_injectable_fields``:
    ``a.b[0].c``. Only leaf writes are supported: the target must
    currently be a str/int/float, not a dict/list.

    Raises ValueError if:
    - payload is not valid JSON
    - path is malformed or does not match the structure
    - target leaf is a container (dict/list) rather than a leaf

    The mutated value is written verbatim: caller is responsible for
    type compatibility (injecting a string into an integer-typed field
    is allowed; that is the point of a probe).
    """
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"payload is not valid JSON: {exc}") from exc

    steps = _split_path(path)
    if not steps:
        raise ValueError(f"empty path: {path!r}")

    # Walk to parent, then write.
    node: Any = parsed
    for kind, seg in steps[:-1]:
        if kind == "key":
            if not isinstance(node, dict) or seg not in node:
                raise ValueError(f"path segment {seg!r} not found")
            node = node[seg]
        else:  # index
            if not isinstance(node, list) or not (0 <= seg < len(node)):
                raise ValueError(f"list index {seg} out of range")
            node = node[seg]

    # Final write.
    last_kind, last_seg = steps[-1]
    if last_kind == "key":
        if not isinstance(node, dict) or last_seg not in node:
            raise ValueError(f"final key {last_seg!r} not found")
        existing = node[last_seg]
    else:
        if not isinstance(node, list) or not (0 <= last_seg < len(node)):
            raise ValueError(f"final index {last_seg} out of range")
        existing = node[last_seg]

    if isinstance(existing, (dict, list)):
        raise ValueError(f"leaf target is a container: {path!r}")

    if last_kind == "key":
        node[last_seg] = new_value
    else:
        node[last_seg] = new_value

    return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
