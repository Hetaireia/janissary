"""Stable finding identity — cross-scan fingerprint.

A finding fingerprint identifies a bug instance across scans of the
same target. Two findings from two scans describe the same bug if and
only if their fingerprints match.

Derivation: SHA-256 over ``(canonical_target, discriminator, category,
finding_type)``, joined with ASCII Unit Separator (0x1F) to prevent
field-boundary collisions. Output format ``jfv1:<32-hex>``.

Deliberately excluded from the input: payload, response body, severity,
detail, timing. All vary between scans or are evidence-level; including
them breaks the cross-scan stability guarantee that makes the
fingerprint useful.

See ADR-007.
"""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

FP_PREFIX = "jfv1:"
"""Version prefix. A future scheme uses ``jfv2:`` and coexists."""

FP_HEX_WIDTH = 32
"""SHA-256 hex truncation width (128 bits). Matches legacy dedup_key."""


VOLATILE_PARAMS: frozenset[str] = frozenset(
    {
        # Session identifiers — essentially guaranteed volatile.
        "session",
        "sessionid",
        "jsessionid",
        "phpsessid",
        # CSRF / anti-automation nonces — regenerate per request.
        "csrf",
        "csrftoken",
        "nonce",
        # Cache-busters and timestamps — jQuery ``_`` and ``ts``.
        "_",
        "ts",
        "timestamp",
        # Auth tokens that appear in query strings.
        "jwt",
    }
)
"""Query parameters whose values vary per-session but whose presence
marks the same endpoint.

Conservative on purpose. Only parameters that are essentially
guaranteed to be volatile are stripped. Names like ``key``, ``auth``,
``token``, ``t``, ``sid`` are **not** stripped: they are frequently
legitimate resource identifiers, and stripping them would merge
distinct bugs into one fingerprint. False merges (two bugs collapsed
to one) are worse than false splits (one bug reported twice) because
the analyst never sees the second bug in a merge. See ADR-007 D2."""


def canonicalize_target(raw: str, exclude: str = "") -> str:
    """Return the canonical form of a target URL for fingerprint input.

    - Lowercase scheme and host.
    - Preserve path and path case. Two URLs differing only in path case
      may be different resources on case-sensitive servers.
    - Drop fragment.
    - Drop ``exclude`` (the injectable parameter name) from the query.
    - Drop :data:`VOLATILE_PARAMS` from the query.
    - Sort remaining query parameters.
    - Drop ``?`` entirely if no query parameters remain.

    Non-URL strings (file paths, repository identifiers, bare
    hostnames) fall through to lowercased, whitespace-stripped form —
    identity is preserved without URL semantics.
    """
    if not raw:
        return ""
    parsed = urlparse(raw)
    if not parsed.scheme and not parsed.netloc:
        return raw.strip().lower()

    exclude_lc = exclude.lower()
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = sorted(
        (k, v)
        for k, v in pairs
        if k.lower() not in VOLATILE_PARAMS and k.lower() != exclude_lc
    )
    query = urlencode(kept, doseq=False)

    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            "",  # drop ;params
            query,
            "",  # drop fragment
        )
    )


def compute_fingerprint(
    *,
    target: str,
    discriminator: str,
    category: str,
    finding_type: str,
) -> str:
    """Return the ``jfv1:`` fingerprint for a finding.

    Pure. Deterministic across processes, Python versions, and
    machines for the same input tuple.

    The four inputs are joined with the ASCII Unit Separator (0x1F),
    which cannot appear in any legitimate component (category and
    finding_type are identifiers; discriminator is a parameter or
    resource name; target is either URL-canonicalized or
    whitespace-stripped-lowercased). This prevents field-boundary
    ambiguity: ``"a|b" + "c"`` cannot collide with ``"a" + "b|c"``.
    """
    normalized = canonicalize_target(target, exclude=discriminator)
    blob = "\x1f".join(
        (
            normalized,
            discriminator or "",
            category or "",
            finding_type or "",
        )
    ).encode("utf-8")
    return FP_PREFIX + hashlib.sha256(blob).hexdigest()[:FP_HEX_WIDTH]
