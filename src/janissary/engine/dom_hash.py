"""DOM structural hashing — ADR-002, Phase 1.3a.

Pure primitives only. No baseline arming (1.3b), no gated corroborator
(1.3c), no I/O.

ADR-002 forbids built-in hash(): it is PYTHONHASHSEED-randomised and a
baseline fingerprint computed in one process would be meaningless against
a payload fingerprint computed in another. This module calls mmh3
(MurmurHash3, deterministic) with a blake2b(digest_size=8) fallback.
See tests/test_dom_hash.py::test_4_no_builtin_hash_static — a static AST
check enforces the constraint.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Final

from selectolax.lexbor import LexborHTMLParser

try:
    import mmh3 as _mmh3
except ImportError:  # pragma: no cover
    _mmh3 = None  # type: ignore[assignment]

HASH_BACKEND: Final[str] = "mmh3" if _mmh3 is not None else "blake2b"

SHINGLE_SIZE: Final[int] = 3
SIMHASH_BITS: Final[int] = 64

IGNORED_TAGS: Final[frozenset[str]] = frozenset(
    {"script", "style", "noscript", "svg", "path"}
)

VOID_ELEMENTS: Final[frozenset[str]] = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


@dataclass(frozen=True)
class StructuralFingerprint:
    """64-bit SimHash over the tag skeleton, plus counts for 1.3c gating."""

    value: int
    token_count: int
    shingle_count: int

    def distance(self, other: StructuralFingerprint) -> int:
        return hamming(self.value, other.value)


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def extract_skeleton(html: str) -> list[str]:
    """Ordered tag tokens; text, attrs, comments, and IGNORED_TAGS' subtrees removed."""
    tree = LexborHTMLParser(html)
    root = tree.root
    if root is None:
        return []

    out: list[str] = []
    stack: list[tuple[Any, bool]] = [(root, False)]
    while stack:
        node, closing = stack.pop()
        tag = node.tag
        if not isinstance(tag, str) or tag.startswith("-"):
            continue
        tag = tag.lower()
        if tag in IGNORED_TAGS:
            continue
        if closing:
            out.append(f"</{tag}>")
            continue
        out.append(f"<{tag}>")
        if tag in VOID_ELEMENTS:
            continue
        stack.append((node, True))
        kids: list[Any] = []
        child = node.child
        while child is not None:
            if child.tag is not None:
                kids.append(child)
            child = child.next
        for kid in reversed(kids):
            stack.append((kid, False))
    return out


def _shingles(tokens: list[str], k: int) -> Iterator[str]:
    for i in range(len(tokens) - k + 1):
        yield "".join(tokens[i : i + k])


def _shingle_hash(s: str) -> int:
    if _mmh3 is not None:
        return _mmh3.hash64(s, 0, signed=False)[0]
    return int.from_bytes(
        hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(), "big"
    )


def simhash_tokens(tokens: list[str]) -> StructuralFingerprint:
    if not tokens:
        return StructuralFingerprint(0, 0, 0)
    k = min(SHINGLE_SIZE, len(tokens))
    votes = [0] * SIMHASH_BITS
    n = 0
    for shingle in _shingles(tokens, k):
        h = _shingle_hash(shingle)
        for bit in range(SIMHASH_BITS):
            votes[bit] += 1 if (h >> bit) & 1 else -1
        n += 1
    value = 0
    for bit in range(SIMHASH_BITS):
        if votes[bit] > 0:  # tie -> 0, documented
            value |= 1 << bit
    return StructuralFingerprint(value, len(tokens), n)


def fingerprint(html: str) -> StructuralFingerprint:
    return simhash_tokens(extract_skeleton(html))
