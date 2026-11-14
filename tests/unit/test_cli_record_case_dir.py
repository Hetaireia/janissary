"""M83 Stage 3: --record-case-dir CLI validation tests."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from janissary.cli import _validate_record_case_dir, build_parser, cmd_scan


def _base_args(**kw):
    base = {
        "show_version": False,
        "url": "http://x/",
        "openapi": None,
        "dry_run": False,
        "sessions": None,
        "cookie": None,
        "bearer": None,
        "idor": False,
        "record_case_dir": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


# ---- _validate_record_case_dir direct tests ----


def test_validate_ok(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    assert _validate_record_case_dir(str(d)) is None


def test_validate_rejects_nonexistent(tmp_path):
    err = _validate_record_case_dir(str(tmp_path / "missing"))
    assert err is not None
    assert "does not exist" in err


def test_validate_rejects_file_not_dir(tmp_path):
    f = tmp_path / "file1"
    f.write_text("x")
    err = _validate_record_case_dir(str(f))
    assert err is not None
    assert "not a directory" in err


def test_validate_rejects_dotdot_segments(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    err = _validate_record_case_dir(str(d) + "/..")
    assert err is not None
    assert ".." in err


def test_validate_rejects_symlink(tmp_path):
    real = tmp_path / "real1"
    real.mkdir()
    link = tmp_path / "link1"
    link.symlink_to(real, target_is_directory=True)
    err = _validate_record_case_dir(str(link))
    assert err is not None
    assert "symlink" in err


def test_validate_rejects_prior_recordings(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    (d / "case_records_raw.jsonl").write_text("")
    err = _validate_record_case_dir(str(d))
    assert err is not None
    assert "prior recordings" in err


def test_validate_rejects_unsanitized_basename(tmp_path):
    d = tmp_path / "test.case"
    d.mkdir()
    err = _validate_record_case_dir(str(d))
    assert err is not None
    assert "basename" in err


def test_validate_rejects_not_writable(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    try:
        os.chmod(d, 0o500)
        if os.access(str(d), os.W_OK):
            pytest.skip("filesystem grants write despite chmod (likely root)")
        err = _validate_record_case_dir(str(d))
        assert err is not None
        assert "not writable" in err
    finally:
        os.chmod(d, 0o700)


# ---- cmd_scan: validation timing and outcomes ----


def test_cmd_scan_rejects_invalid_dir_before_url_check(tmp_path, capsys):
    missing = tmp_path / "missing"
    args = _base_args(url=None, record_case_dir=str(missing))
    rc = cmd_scan(args)
    err = capsys.readouterr().err
    assert rc == 64
    assert "record-case-dir" in err
    assert "does not exist" in err
    assert "requires --url" not in err


def test_cmd_scan_valid_dir_passes_validation(tmp_path, capsys):
    d = tmp_path / "case1"
    d.mkdir()
    args = _base_args(url=None, record_case_dir=str(d))
    rc = cmd_scan(args)
    err = capsys.readouterr().err
    assert rc == 64
    assert "requires --url" in err
    assert "record-case-dir" not in err


def test_cmd_scan_no_dir_unchanged(capsys):
    args = _base_args(url=None)
    rc = cmd_scan(args)
    err = capsys.readouterr().err
    assert rc == 64
    assert "requires --url" in err


# ---- _build_scanner forwarding ----


def test_build_scanner_forwards_record_case_dir(tmp_path, monkeypatch):
    from janissary import cli

    captured = {}

    def fake_scanner(**kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(cli, "Scanner", fake_scanner)
    args = _base_args()
    args.method = "GET"
    args.timeout = 10.0
    args.baseline_count = 10
    args.delay = 0.0
    args.stealth = False
    args.no_waf = False
    args.baseline_value = ""
    args.ssrf_timeout = 10.0
    args.ssrf_redirector = None
    args.heuristic = False
    args.idor = False
    args.verbose = False
    args.record_case_dir = tmp_path

    auth_cfg = SimpleNamespace(is_empty=True, sessions=None)
    cli._build_scanner(
        args,
        target="http://x/",
        params=["p"],
        method="GET",
        inject_in="auto",
        proxies=None,
        session=None,
        collaborator=None,
        auth_cfg=auth_cfg,
        json_template=None,
    )
    assert captured["record_case_dir"] == tmp_path


# ---- argparse wiring ----


def test_parser_accepts_record_case_dir():
    parser = build_parser()
    args = parser.parse_args(["scan", "-u", "http://x/", "--record-case-dir", "/tmp/d"])
    assert args.record_case_dir == "/tmp/d"


def test_parser_record_case_dir_defaults_to_none():
    parser = build_parser()
    args = parser.parse_args(["scan", "-u", "http://x/"])
    assert args.record_case_dir is None


def test_validate_preserves_existing_probe_file(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    probe = d / ".janissary_write_probe"
    probe.write_text("user data that must survive", encoding="utf-8")
    err = _validate_record_case_dir(str(d))
    assert err is None
    assert probe.exists()
    assert probe.read_text(encoding="utf-8") == "user data that must survive"


def test_validate_permits_unrelated_files(tmp_path):
    d = tmp_path / "case1"
    d.mkdir()
    (d / "notes.txt").write_text("unrelated", encoding="utf-8")
    (d / "some_random.jsonl").write_text("{}\n", encoding="utf-8")
    err = _validate_record_case_dir(str(d))
    assert err is None


def test_validate_uses_unique_write_probe(tmp_path, monkeypatch):
    import tempfile as tempfile_module

    d = tmp_path / "case1"
    d.mkdir()
    original = tempfile_module.mkstemp
    observed = {}

    def tracked_mkstemp(*args, **kwargs):
        observed["prefix"] = kwargs.get("prefix")
        observed["dir"] = kwargs.get("dir")
        result = original(*args, **kwargs)
        observed["name"] = result[1]
        return result

    monkeypatch.setattr(tempfile_module, "mkstemp", tracked_mkstemp)

    err = _validate_record_case_dir(str(d))

    assert err is None
    assert observed["prefix"] == ".janissary_write_probe_"
    assert observed["dir"] == d
    assert not os.path.exists(observed["name"])
    assert not (d / ".janissary_write_probe").exists()
