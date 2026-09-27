"""Unit tests for the Terms-of-Use acceptance gate."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from janissary import legal

# ---------------------------------------------------------------------------
# Marker round-trip
# ---------------------------------------------------------------------------


def test_marker_path_under_home():
    p = legal.marker_path()
    assert p.name == legal.MARKER_FILENAME
    assert p.parent.name == legal.MARKER_DIRNAME


def test_is_accepted_false_when_missing(tmp_path: Path):
    assert legal.is_accepted(tmp_path / "nope.json") is False


def test_record_then_is_accepted(tmp_path: Path):
    p = tmp_path / "marker.json"
    legal.record_acceptance(p)
    assert p.exists()
    assert legal.is_accepted(p) is True


def test_record_writes_version_and_timestamp(tmp_path: Path):
    p = tmp_path / "marker.json"
    legal.record_acceptance(p)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["terms_version"] == legal.TERMS_VERSION
    assert "accepted_at" in data


def test_version_mismatch_invalidates(tmp_path: Path):
    p = tmp_path / "marker.json"
    p.write_text(
        json.dumps({"terms_version": legal.TERMS_VERSION + 1}),
        encoding="utf-8",
    )
    assert legal.is_accepted(p) is False


def test_corrupt_marker_treated_as_missing(tmp_path: Path):
    p = tmp_path / "marker.json"
    p.write_text("not json", encoding="utf-8")
    assert legal.is_accepted(p) is False


# ---------------------------------------------------------------------------
# Gate behaviour
# ---------------------------------------------------------------------------


def test_non_gated_command_returns_immediately(tmp_path: Path):
    # "creds" is not in GATED_COMMANDS; must not raise or prompt.
    legal.require_acceptance("creds", path=tmp_path / "marker.json")


def test_help_like_command_returns_immediately(tmp_path: Path):
    legal.require_acceptance("terms", path=tmp_path / "marker.json")


def test_gated_command_with_current_marker_returns(tmp_path: Path):
    p = tmp_path / "marker.json"
    legal.record_acceptance(p)
    legal.require_acceptance("scan", path=p)


def test_env_var_records_and_proceeds(tmp_path: Path, monkeypatch):
    p = tmp_path / "marker.json"
    monkeypatch.setenv(legal.ACCEPTANCE_ENV, "1")
    legal.require_acceptance("scan", path=p)
    assert p.exists()


def test_non_tty_exits_64(tmp_path: Path, monkeypatch, capsys):
    # Force stdin to look non-interactive.
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit) as exc:
        legal.require_acceptance("scan", path=tmp_path / "marker.json")
    assert exc.value.code == 64
    err = capsys.readouterr().err
    assert legal.ACCEPTANCE_ENV in err


def test_tty_prompt_accepts_exact_token(tmp_path: Path, monkeypatch):
    p = tmp_path / "marker.json"

    class FakeStdin(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", FakeStdin("I AGREE\n"))
    legal.require_acceptance("scan", path=p)
    assert legal.is_accepted(p) is True


def test_tty_prompt_rejects_wrong_token(tmp_path: Path, monkeypatch):
    p = tmp_path / "marker.json"

    class FakeStdin(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", FakeStdin("yes\n"))
    with pytest.raises(SystemExit) as exc:
        legal.require_acceptance("scan", path=p)
    assert exc.value.code == 64
    assert not p.exists()


def test_tty_prompt_rejects_case_mismatch(tmp_path: Path, monkeypatch):
    p = tmp_path / "marker.json"

    class FakeStdin(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", FakeStdin("i agree\n"))
    with pytest.raises(SystemExit):
        legal.require_acceptance("scan", path=p)


# ---------------------------------------------------------------------------
# Terms content invariants
# ---------------------------------------------------------------------------


def test_terms_text_non_empty():
    assert len(legal.TERMS_TEXT) > 500


def test_terms_text_has_required_clauses():
    text = legal.TERMS_TEXT.lower()
    for required in (
        "authorised use",
        "indemnity",
        "limitation of liability",
        "export control",
        "good-faith",
        "governing law",
    ):
        assert required in text, f"missing clause: {required}"


def test_terms_text_names_victoria():
    assert "victoria" in legal.TERMS_TEXT.lower()


def test_legal_md_exists_and_matches_version():
    root = Path(__file__).resolve().parents[2]
    md = root / "LEGAL.md"
    assert md.exists(), "LEGAL.md not found at project root"
    body = md.read_text(encoding="utf-8").lower()
    for required in (
        "authorised use",
        "indemnity",
        "limitation of liability",
        "export control",
        "good-faith",
        "governing law",
    ):
        assert required in body, f"LEGAL.md missing clause: {required}"


def test_gated_commands_set():
    for cmd in ("scan", "fingerprint", "graphql", "ws", "admin"):
        assert cmd in legal.GATED_COMMANDS
    for cmd in ("creds", "terms"):
        assert cmd not in legal.GATED_COMMANDS
