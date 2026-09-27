"""Unit tests for the credential scanner.

All tokens in this file are structurally-correct but obviously fake
(repeating alphabets, well-known public examples). They are safe to
commit. The scanner's own source passes through a self-scan test that
must return zero findings — a regression guard against over-broad rules.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from janissary.credentials.export import export_credentials
from janissary.credentials.rules import ALL_RULES, GITLEAKS_RULES, KEYHUNTER_PATTERNS
from janissary.credentials.scanner import (
    redact_token,
    scan_directory,
    scan_file_for_secrets,
    scan_text_for_secrets,
    shannon_entropy,
)

# -------------------------------------------------------------------
# RULES SANITY
# -------------------------------------------------------------------


def test_all_rules_have_required_keys():
    required = {"id", "description", "regex", "secret_group", "entropy", "allowlist"}
    for r in ALL_RULES:
        assert required.issubset(r.keys()), f"rule {r.get('id')} missing keys"


def test_rule_ids_are_unique():
    ids = [r["id"] for r in ALL_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids"


def test_expected_rule_counts():
    # Guards against someone accidentally deleting a whole block.
    assert len(GITLEAKS_RULES) == 32
    assert len(KEYHUNTER_PATTERNS) == 9
    assert len(ALL_RULES) == 41


# -------------------------------------------------------------------
# ENTROPY
# -------------------------------------------------------------------


def test_entropy_of_uniform_string_is_zero():
    assert shannon_entropy("a" * 40) == 0.0


def test_entropy_of_random_base64_is_high():
    # 22-char base64 with mixed case + digits
    assert shannon_entropy("QWxhZGRpbjpvcGVuIHNlc2FtZQ") > 4.0


def test_entropy_respects_charset():
    # Same input, different charsets: hex is narrower, entropy is lower.
    sample = "abcdef0123456789abcdef0123456789"
    b64 = shannon_entropy(sample, "base64")
    hex_ = shannon_entropy(sample, "hex")
    assert b64 > 0
    assert hex_ > 0
    # base64 charset includes hex chars, so freq is spread over a
    # wider alphabet -- entropy must be at least as high as hex.
    assert b64 >= hex_


# -------------------------------------------------------------------
# PROVIDER RULES
# -------------------------------------------------------------------


def test_github_pat_fires():
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    ids = [h["token_type"] for h in hits]
    assert "github-pat" in ids


def test_aws_example_is_suppressed():
    # AWS's own documented example key must not fire.
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    hits = scan_text_for_secrets(text, "test")
    assert hits == []


def test_generic_key_with_your_prefix_is_suppressed():
    text = "api_key = YOUR_abcdefghijklmnopqrstuvwxyz"
    hits = scan_text_for_secrets(text, "test")
    assert hits == []


def test_private_key_block_fires():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    hits = scan_text_for_secrets(text, "test")
    assert any(h["token_type"] == "private-key" for h in hits)


# -------------------------------------------------------------------
# ENTROPY FALLBACK
# -------------------------------------------------------------------


def test_entropy_fallback_fires_on_random_base64():
    blob = "value=QWxhZGRpbjpvcGVuIHNlc2FtZQpBQkNERUZHSElKS0xNTk9Q"
    hits = scan_text_for_secrets(blob, "test")
    ids = [h["token_type"] for h in hits]
    assert any(i.startswith("entropy_") for i in ids)


def test_entropy_fallback_suppressed_when_disabled():
    blob = "value=QWxhZGRpbjpvcGVuIHNlc2FtZQpBQkNERUZHSElKS0xNTk9Q"
    hits = scan_text_for_secrets(blob, "test", enable_entropy=False)
    ids = [h["token_type"] for h in hits]
    assert not any(i.startswith("entropy_") for i in ids)


def test_entropy_fallback_requires_multiple_char_classes():
    # 40 lowercase letters: high entropy but no digit/upper/special.
    # Must not trip the fallback.
    text = "value=abcdefghijklmnopqrstuvwxyzabcdefghijklmn"
    hits = scan_text_for_secrets(text, "test")
    ids = [h["token_type"] for h in hits]
    assert not any(i.startswith("entropy_") for i in ids)


def test_provider_span_suppresses_overlapping_entropy():
    # The github-pat rule matches; the entropy fallback must not
    # double-report the same span.
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    ids = [h["token_type"] for h in hits]
    assert ids.count("github-pat") == 1
    assert not any(i.startswith("entropy_") for i in ids)


# -------------------------------------------------------------------
# REDACTION
# -------------------------------------------------------------------


def test_redact_short_token():
    # Empty string passes through
    assert redact_token("") == ""
    # Under 8 chars: fully masked (at most 3 asterisks)
    assert redact_token("abc") == "***"
    assert redact_token("abcde") == "***"
    # 8..20 chars: only first and last two characters visible
    assert redact_token("12345678") == "12...78"
    assert redact_token("12345678901234567890") == "12...90"
    # Critically: an 8-char token must not be fully visible
    out8 = redact_token("abcdefgh")
    assert "abcdefgh" not in out8


def test_redact_long_underscore_token():
    out = redact_token("ghp_abcdefghijklmnopqrstuvwxyz1234567890")
    assert out.startswith("ghp_")
    assert "..." in out
    # never includes enough characters to reconstruct
    assert len(out) < len("ghp_abcdefghijklmnopqrstuvwxyz1234567890")


def test_finding_never_drops_full_token_from_payload():
    # The raw finding dict still carries full_token for callers that
    # need it; the redacted form is separate.
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    assert hits
    assert "full_token" in hits[0]
    assert "redacted" in hits[0]
    assert hits[0]["redacted"] != hits[0]["full_token"]


# -------------------------------------------------------------------
# FILE SCAN
# -------------------------------------------------------------------


def test_scan_file_for_secrets(tmp_path: Path):
    f = tmp_path / "creds.env"
    f.write_text("TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n", encoding="utf-8")
    hits = scan_file_for_secrets(str(f))
    assert any(h["token_type"] == "github-pat" for h in hits)
    assert hits[0]["source"] == str(f)


def test_scan_file_missing_returns_empty():
    assert scan_file_for_secrets("Z:\\nope\\not\\a\\file") == []


# -------------------------------------------------------------------
# DIRECTORY SCAN
# -------------------------------------------------------------------


def test_scan_directory_skips_venv(tmp_path: Path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "leak.py").write_text(
        "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    hits = scan_directory(str(tmp_path))
    # Nothing in .venv should have been scanned.
    assert hits == []


def test_scan_directory_env_only(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )
    (tmp_path / "secrets.env").write_text(
        "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )
    hits = scan_directory(str(tmp_path), env_only=True)
    sources = [h["source"] for h in hits]
    assert any(s.endswith("secrets.env") for s in sources)
    assert not any(s.endswith("app.py") for s in sources)


def test_scan_directory_does_not_require_cwd():
    # Regression: the prototype's safe_file_open(allowed_base=".")
    # silently returned [] for any path outside the CWD.
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "leak.env"
        p.write_text(
            "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n", encoding="utf-8"
        )
        hits = scan_directory(td)
        assert hits, "scan must work outside CWD"


def test_scan_directory_not_a_directory():
    import pytest

    with pytest.raises(NotADirectoryError):
        scan_directory("definitely_not_a_dir_xyz")


# -------------------------------------------------------------------
# EXPORT
# -------------------------------------------------------------------


def test_export_json_omits_full_token_by_default(tmp_path: Path):
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    out = tmp_path / "out.json"
    export_credentials(hits, str(out))
    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["finding_count"] == len(hits)
    for f in data["findings"]:
        assert "full_token" not in f


def test_export_json_can_include_full_token(tmp_path: Path):
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    out = tmp_path / "out.json"
    export_credentials(hits, str(out), include_full_token=True)
    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    assert any("full_token" in f for f in data["findings"])


def test_export_csv(tmp_path: Path):
    text = "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    hits = scan_text_for_secrets(text, "test")
    out = tmp_path / "out.csv"
    export_credentials(hits, str(out))
    body = out.read_text(encoding="utf-8")
    assert "token_type" in body
    assert "github-pat" in body


# -------------------------------------------------------------------
# SELF-SCAN
# -------------------------------------------------------------------


def test_scanner_does_not_flag_its_own_source():
    """If our own rules are too broad, they fire on our own code."""
    here = Path(__file__).resolve().parents[2] / "src" / "janissary" / "credentials"
    hits = scan_directory(str(here), enable_entropy=False)
    assert hits == [], f"self-scan flagged: {[h['token_type'] for h in hits]}"
