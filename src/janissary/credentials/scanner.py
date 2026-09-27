"""Credential scanner.

Runs three engines over a text blob:

  1. Gitleaks-style provider rules     (regex, optional entropy floor)
  2. Keyhunter high-signal patterns    (regex, provider-specific)
  3. TruffleHog-style entropy fallback (no provider context)

Findings are redacted before leaving this module. The un-redacted
value is kept in the "full_token" field for callers that need to
verify liveness, but never written to disk by any export path unless
explicitly requested.

Path handling
-------------
scan_directory walks a caller-supplied root and reads every regular
file it finds (subject to skip-list and size cap). There is no CWD
anchor and no allowlist of "safe" parents. The original prototype
gated every file read behind safe_file_open(path, allowed_base="."),
which silently returned [] for any file outside the CWD. That is why
janissary --scan-creds /other/dir reported "0 tokens found" for
directories that plainly had tokens.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone

from .rules import ALL_RULES

# -------------------------------------------------------------------
# CONSTANTS
# -------------------------------------------------------------------

CONFIG_EXTS: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".properties",
    ".tf",
    ".tfvars",
    ".cfg",
    ".config",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
)

TEXT_EXTS: tuple[str, ...] = (
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".fish",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".properties",
    ".tf",
    ".tfvars",
    ".env",
    ".txt",
    ".md",
    ".cfg",
    ".config",
    ".xml",
    ".html",
    ".liquid",
    ".vue",
    ".svelte",
    ".sql",
    ".graphql",
    ".gql",
    ".dockerfile",
    ".makefile",
    ".mk",
    ".editorconfig",
    ".gitignore",
    ".npmrc",
    ".yarnrc",
)

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        ".cache",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "vendor",
        "site-packages",
        "playwright-report",
        "test-results",
        ".terraform",
    }
)

MAX_FILE_BYTES: int = 5 * 1024 * 1024

BARE_TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "dockerfile",
        "makefile",
        ".env",
        ".npmrc",
        ".yarnrc",
        ".editorconfig",
        ".gitignore",
        ".dockerignore",
    }
)


# -------------------------------------------------------------------
# ENTROPY
# -------------------------------------------------------------------


def shannon_entropy(data: str, charset: str = "base64") -> float:
    """Shannon entropy in bits per character over the given charset."""
    if not data:
        return 0.0
    if charset == "hex":
        allowed = set("0123456789abcdefABCDEF")
    else:
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
    filtered = [c for c in data if c in allowed]
    if not filtered:
        return 0.0
    freq = Counter(filtered)
    length = len(filtered)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# -------------------------------------------------------------------
# REDACTION
# -------------------------------------------------------------------


def redact_token(token: str) -> str:
    """Return a fingerprint that is safe to print.

    The visible portion is always a small subset of the original:

      len < 8      entirely masked ("***")
      8 <= len <= 20   first 2 + "..." + last 2
      len > 20     if underscored: prefix_Nhex...Mhex
                   otherwise:      first 8 + "..." + last 4

    The earlier policy (first 4 + last 4 for anything <= 20 chars)
    leaked the entire token at the scanner's minimum secret length of 8,
    and leaked 8 of 20 characters at the upper bound.
    """
    if not token:
        return ""
    if len(token) < 8:
        return "*" * min(len(token), 3)
    if len(token) <= 20:
        return token[:2] + "..." + token[-2:]
    prefix, _, hexpart = token.partition("_")
    if len(hexpart) >= 12:
        return f"{prefix}_{hexpart[:8]}...{hexpart[-4:]}"
    return token[:8] + "..." + token[-4:]


def _iter_secret_matches(
    text: str,
    enable_entropy: bool = True,
    min_entropy: float = 4.0,
    min_entropy_length: int = 20,
) -> Iterator[tuple[dict, str, int, int]]:
    """Yield (rule, secret, start, end) tuples for every match in text.

    Provider rules run first. Their spans are collected, and the entropy
    fallback then skips any candidate that overlaps an existing span —
    this prevents a single token from being reported twice (once by the
    provider rule, once by entropy).

    Entropy candidates additionally must exhibit at least two distinct
    character classes (uppercase, lowercase, digit, special). A run of
    only lowercase letters, or only digits, is never a secret; without
    this check, ordinary words like "abcdefghijklmnopqrstuvwxyz" trip
    the fallback.
    """
    spans: list[tuple[int, int]] = []

    for rule in ALL_RULES:
        pattern = rule["regex"]
        group = rule.get("secret_group", 1)
        threshold = rule.get("entropy", 0.0)
        allow = rule.get("allowlist", [])
        for m in pattern.finditer(text):
            try:
                secret = m.group(group)
            except IndexError:
                continue
            if not secret or len(secret) < 8:
                continue
            if any(a.search(secret) for a in allow):
                continue
            ent = shannon_entropy(secret, "base64") if threshold > 0.0 else 0.0
            if threshold > 0.0 and ent < threshold:
                continue
            spans.append((m.start(group), m.end(group)))
            yield rule, secret, m.start(group), m.end(group)

    if not enable_entropy:
        return

    def _overlaps(start: int, end: int) -> bool:
        return any(start < s_end and s_start < end for s_start, s_end in spans)

    def _classes_ok(candidate: str) -> bool:
        classes = 0
        if any(c.islower() for c in candidate):
            classes += 1
        if any(c.isupper() for c in candidate):
            classes += 1
        if any(c.isdigit() for c in candidate):
            classes += 1
        if any(c in "+/=" for c in candidate):
            classes += 1
        return classes >= 2

    for charset, pattern in (
        ("base64", re.compile(r"[A-Za-z0-9+/=]{20,}")),
        ("hex", re.compile(r"[0-9a-fA-F]{20,}")),
    ):
        for m in pattern.finditer(text):
            candidate = m.group(0)
            if len(candidate) < min_entropy_length:
                continue
            if _overlaps(m.start(), m.end()):
                continue
            if not _classes_ok(candidate):
                continue
            ent = shannon_entropy(candidate, charset)
            if ent >= min_entropy:
                synthetic = {
                    "id": "entropy_" + charset,
                    "description": "High-entropy " + charset + " string",
                    "entropy": 0.0,
                }
                yield synthetic, candidate, m.start(), m.end()


def scan_text_for_secrets(
    text: str,
    source_label: str,
    line_offset: int = 0,
    enable_entropy: bool = True,
    min_entropy: float = 4.0,
    min_entropy_length: int = 20,
) -> list[dict]:
    """Scan a text blob. Returns a list of finding dicts."""
    if not text:
        return []
    findings: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for rule, secret, start, end in _iter_secret_matches(
        text,
        enable_entropy=enable_entropy,
        min_entropy=min_entropy,
        min_entropy_length=min_entropy_length,
    ):
        line_num = line_offset + text[:start].count("\n") + 1
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end < 0:
            line_end = len(text)
        context_raw = text[line_start:line_end].strip()
        redacted = redact_token(secret)
        context = context_raw.replace(secret, redacted)[:200]
        threshold = rule.get("entropy", 0.0)
        ent = shannon_entropy(secret, "base64") if threshold > 0.0 else 0.0
        findings.append(
            {
                "token_type": rule["id"],
                "description": rule.get("description", ""),
                "redacted": redacted,
                "full_token": secret,
                "source": source_label,
                "line": line_num,
                "context": context,
                "severity": "high",
                "entropy": round(ent, 3),
                "timestamp": now,
            }
        )
    return findings


# -------------------------------------------------------------------
# FILE / DIRECTORY
# -------------------------------------------------------------------


def _is_text_file(path: str) -> bool:
    base = os.path.basename(path).lower()
    if base in BARE_TEXT_FILENAMES:
        return True
    _, ext = os.path.splitext(base)
    return ext.lower() in TEXT_EXTS


def scan_file_for_secrets(
    path: str,
    enable_entropy: bool = True,
    min_entropy: float = 4.0,
) -> list[dict]:
    """Read one file and scan it. Returns [] on any OS-level failure."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size > MAX_FILE_BYTES:
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text_for_secrets(
        text,
        source_label=path,
        enable_entropy=enable_entropy,
        min_entropy=min_entropy,
    )


def iter_candidate_files(root: str, env_only: bool = False) -> Iterator[str]:
    """Walk root, respecting skip-list and text-file filter."""
    root_abs = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if env_only:
                base = fn.lower()
                is_config = base.startswith(".env") or any(
                    base.endswith(e) for e in CONFIG_EXTS
                )
                if not is_config:
                    continue
            elif not _is_text_file(full):
                continue
            yield full


def scan_directory(
    root: str,
    env_only: bool = False,
    verbose: bool = False,
    enable_entropy: bool = True,
    min_entropy: float = 4.0,
) -> list[dict]:
    """Recursively scan a directory. Returns all findings."""
    root_abs = os.path.abspath(root)
    if not os.path.isdir(root_abs):
        raise NotADirectoryError(f"not a directory: {root_abs}")
    findings: list[dict] = []
    for full in iter_candidate_files(root_abs, env_only=env_only):
        hits = scan_file_for_secrets(
            full,
            enable_entropy=enable_entropy,
            min_entropy=min_entropy,
        )
        findings.extend(hits)
        if verbose and hits:
            for h in hits:
                print(
                    f"  [{h['token_type']}] {h['source']}:{h['line']} "
                    f"-> {h['redacted']}"
                )
    return findings
