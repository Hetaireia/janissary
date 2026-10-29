"""Unit tests for track_c scorer abort-awareness (cmd-86/87)."""
from __future__ import annotations
import json
from pathlib import Path

from benchmark.track_c import score as S


def test_load_exit_codes_roundtrip(tmp_path: Path):
    p = tmp_path / "exit_codes.json"
    p.write_text(json.dumps([
        {"path": "/a", "method": "GET", "param": "x", "exit": 0, "aborted": False},
        {"path": "/b", "method": "GET", "param": "y", "exit": 2, "aborted": True},
    ]), encoding="utf-8")
    m = S.load_exit_codes(tmp_path)
    assert m["/a|GET|x"]["aborted"] is False
    assert m["/b|GET|y"]["aborted"] is True


def test_load_exit_codes_missing(tmp_path: Path):
    assert S.load_exit_codes(tmp_path) == {}


def test_load_exit_codes_malformed(tmp_path: Path):
    (tmp_path / "exit_codes.json").write_text("not json", encoding="utf-8")
    assert S.load_exit_codes(tmp_path) == {}


def test_load_exit_codes_missing_keys(tmp_path: Path):
    (tmp_path / "exit_codes.json").write_text(
        json.dumps([{"path": "/a"}]), encoding="utf-8"
    )
    assert S.load_exit_codes(tmp_path) == {}
