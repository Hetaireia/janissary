"""Unit tests for the Nuclei runner.

These tests mock subprocess.run so no real nuclei binary is invoked.
The runner's job is command construction, JSONL parsing, and error
handling — all testable without the external tool.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from janissary.attack import nuclei as n


def _fake_proc(returncode=0, stdout="", stderr=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


def _jsonl(**kwargs) -> str:
    return json.dumps(kwargs)


# ---------------------------------------------------------------------------
# Confirmation gate
# ---------------------------------------------------------------------------


def test_requires_attack_confirm():
    with pytest.raises(n.AttackConfirmationRequired):
        n.NucleiRunner(
            target="http://t/",
            templates=["/tmp/x.yaml"],
            attack_confirm=False,
            nuclei_path="/usr/bin/nuclei",
        )


def test_confirm_allows_construction():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/tmp/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    assert r.target == "http://t/"


def test_requires_non_empty_templates():
    with pytest.raises(ValueError):
        n.NucleiRunner(
            target="http://t/",
            templates=[],
            attack_confirm=True,
            nuclei_path="/usr/bin/nuclei",
        )


def test_requires_nuclei_binary():
    with patch("shutil.which", return_value=None), pytest.raises(n.NucleiNotFound):
        n.NucleiRunner(
            target="http://t/",
            templates=["/tmp/x.yaml"],
            attack_confirm=True,
        )


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


def test_build_command_minimal():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/tmp/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    cmd = r.build_command()
    assert cmd[0] == "/usr/bin/nuclei"
    assert "-target" in cmd and "http://t/" in cmd
    assert "-jsonl" in cmd
    assert "-t" in cmd and "/tmp/x.yaml" in cmd


def test_build_command_severity_and_tags():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/tmp/x.yaml"],
        attack_confirm=True,
        severity="high,critical",
        tags=["cve", "rce"],
        nuclei_path="/usr/bin/nuclei",
    )
    cmd = r.build_command()
    assert "-severity" in cmd
    assert "high,critical" in cmd
    assert "-tags" in cmd
    assert "cve,rce" in cmd


def test_build_command_multiple_templates():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/a.yaml", "/b.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    cmd = r.build_command()
    # Two -t flags, one per template.
    assert cmd.count("-t") == 2


def test_timeout_clamped():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        timeout=99999,
        nuclei_path="/usr/bin/nuclei",
    )
    assert r.timeout == n.MAX_TIMEOUT


# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------


def test_parse_blank_line_returns_none():
    assert n.parse_nuclei_line("") is None
    assert n.parse_nuclei_line("   ") is None


def test_parse_non_json_returns_none():
    assert n.parse_nuclei_line("not json") is None


def test_parse_non_dict_returns_none():
    assert n.parse_nuclei_line("[1,2,3]") is None


def test_parse_missing_template_id_returns_none():
    line = _jsonl(info={"name": "n", "severity": "high"})
    assert n.parse_nuclei_line(line) is None


def test_parse_full_finding():
    line = _jsonl(
        **{
            "template-id": "cve-2021-1234",
            "info": {
                "name": "Example CVE",
                "severity": "critical",
                "tags": ["cve", "rce"],
                "reference": ["https://example.com/advisory"],
                "description": "a bad one",
            },
            "matched-at": "http://t/vuln",
            "host": "t",
            "type": "http",
        }
    )
    f = n.parse_nuclei_line(line)
    assert f is not None
    assert f.template_id == "cve-2021-1234"
    assert f.severity == "critical"
    assert f.tags == ["cve", "rce"]
    assert f.reference == ["https://example.com/advisory"]
    assert f.matched_at == "http://t/vuln"


def test_parse_tags_from_string():
    line = _jsonl(
        **{
            "template-id": "x",
            "info": {"name": "n", "severity": "low", "tags": "a, b"},
            "matched-at": "http://t/",
        }
    )
    f = n.parse_nuclei_line(line)
    assert f.tags == ["a", "b"]


def test_parse_reference_from_string():
    line = _jsonl(
        **{
            "template-id": "x",
            "info": {"name": "n", "severity": "low", "reference": "https://x"},
            "matched-at": "http://t/",
        }
    )
    f = n.parse_nuclei_line(line)
    assert f.reference == ["https://x"]


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------


def test_run_parses_findings():
    stdout = "\n".join(
        [
            _jsonl(
                **{
                    "template-id": "a",
                    "info": {"name": "A", "severity": "high"},
                    "matched-at": "http://t/1",
                }
            ),
            _jsonl(
                **{
                    "template-id": "b",
                    "info": {"name": "B", "severity": "low"},
                    "matched-at": "http://t/2",
                }
            ),
        ]
    )

    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )

    with patch("subprocess.run", return_value=_fake_proc(stdout=stdout)):
        result = r.run()

    assert result.exit_code == 0
    assert len(result.findings) == 2
    assert result.findings[0].template_id == "a"
    assert result.findings[1].template_id == "b"
    assert result.stdout_lines == 2
    assert result.aborted is False


def test_run_ignores_non_finding_lines():
    stdout = "\n".join(
        [
            "",  # blank
            "not json",  # garbage
            _jsonl(info={"name": "n"}),  # no template-id
            _jsonl(
                **{
                    "template-id": "ok",
                    "info": {"name": "n", "severity": "info"},
                    "matched-at": "http://t/",
                }
            ),
        ]
    )
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch("subprocess.run", return_value=_fake_proc(stdout=stdout)):
        result = r.run()
    assert len(result.findings) == 1
    assert result.findings[0].template_id == "ok"


def test_run_nuclei_exit_1_is_not_aborted():
    """Nuclei returns 1 when it finds something — that is not an error."""
    stdout = _jsonl(
        **{
            "template-id": "x",
            "info": {"name": "n", "severity": "high"},
            "matched-at": "http://t/",
        }
    )
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch("subprocess.run", return_value=_fake_proc(returncode=1, stdout=stdout)):
        result = r.run()
    assert result.aborted is False
    assert result.exit_code == 1


def test_run_error_exit_code_aborts():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch("subprocess.run", return_value=_fake_proc(returncode=2, stderr="boom")):
        result = r.run()
    assert result.aborted is True
    assert "exited with code 2" in result.abort_reason
    assert "boom" in result.stderr_tail


def test_run_timeout_aborts():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        timeout=1.0,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=1.0),
    ):
        result = r.run()
    assert result.aborted is True
    assert "timed out" in result.abort_reason


def test_run_file_not_found_aborts():
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch("subprocess.run", side_effect=FileNotFoundError("gone")):
        result = r.run()
    assert result.aborted is True
    assert "vanished" in result.abort_reason


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_run_to_dict_roundtrip():
    stdout = _jsonl(
        **{
            "template-id": "x",
            "info": {"name": "n", "severity": "high"},
            "matched-at": "http://t/",
        }
    )
    r = n.NucleiRunner(
        target="http://t/",
        templates=["/x.yaml"],
        attack_confirm=True,
        nuclei_path="/usr/bin/nuclei",
    )
    with patch("subprocess.run", return_value=_fake_proc(stdout=stdout)):
        result = r.run()
    d = result.to_dict()
    assert d["target"] == "http://t/"
    assert d["templates"] == ["/x.yaml"]
    assert len(d["findings"]) == 1
    assert d["findings"][0]["template_id"] == "x"
