"""LFI content-injection oracle (Phase 4, FN-3 / FN-2).

The traversal collapse oracle (collapse_oracle.py) catches cases where
traversal *removes* page structure. It cannot catch in-page LFI where a
page keeps its structure and injects the file's content into one cell
(bWAPP, DVWA). This oracle detects that independently of arming: signature
strings from well-known files (passwd, shadow, hosts, win.ini, group) that
appear in the payload response and NOT in any baseline snapshot.

Pure. No I/O.
"""

from __future__ import annotations

import re

from janissary.detection.analyzer import Baseline, ResponseSnapshot

# _LINE_START matches a line boundary, a <br /> tag, or an HTML-tag newline
# context. The \s* handles indentation inside <td> content (e.g. bwapp
# indents passwd output four spaces).
_LINE_START = r"(?:^|<br\s*/?>|\n)\s*"

_PASSWD_LINE = re.compile(
    _LINE_START + r"[a-z_][a-z0-9_-]*:[^:\n]+:\d+:\d+:[^:\n]*:/[^:\n]*:[^\n]+",
    re.I,
)
_SHADOW_LINE = re.compile(
    _LINE_START + r"[a-z_][a-z0-9_-]*:\$[0-9a-z]+\$[^\n:]+",
    re.I,
)
_HOSTS_LINE = re.compile(
    _LINE_START + r"127\.0\.0\.1\s+localhost",
    re.I,
)
_WIN_INI = re.compile(r"\[(?:extensions|fonts|files|mci extensions)\]", re.I)
_GROUP_LINE = re.compile(
    _LINE_START + r"[a-z_][a-z0-9_-]*:[^:\n]*:\d+:[a-z0-9_,\s-]+",
    re.I,
)

_SIGNATURES: dict[str, re.Pattern] = {
    "passwd": _PASSWD_LINE,
    "shadow": _SHADOW_LINE,
    "hosts": _HOSTS_LINE,
    "win_ini": _WIN_INI,
    "group": _GROUP_LINE,
}


def _has_sig(body: str, pattern: re.Pattern) -> bool:
    return bool(pattern.search(body or ""))


def check_lfi_content_oracle(
    *,
    baseline: Baseline,
    snapshot: ResponseSnapshot,
    response_status: int,
    payload_value: str,
    payload_name: str,
) -> list[dict]:
    """Return zero or one finding dict.

    Fires once when the payload response contains at least one known-file
    signature that does NOT appear in any baseline snapshot.
    """
    if not (200 <= response_status < 400):
        return []
    body = snapshot.body or ""
    if not body:
        return []

    baseline_bodies = [s.body or "" for s in baseline.snapshots]
    baseline_joined = "\n".join(baseline_bodies)

    hits: list[str] = []
    for sig_name, pattern in _SIGNATURES.items():
        if not _has_sig(body, pattern):
            continue
        if _has_sig(baseline_joined, pattern):
            continue
        hits.append(sig_name)

    if not hits:
        return []

    return [
        {
            "type": "lfi_content_oracle",
            "category": "traversal",
            "severity": "critical",
            "reason": "lfi_content_injection",
            "signatures": hits,
            "detail": (
                f"LFI content injection: {', '.join(hits)} file signature(s) "
                f"appeared in {payload_name}={payload_value[:40]!r} response "
                f"but not in baseline"
            ),
        }
    ]
