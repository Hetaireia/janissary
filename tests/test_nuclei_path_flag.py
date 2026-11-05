# JANISSARY-FN-5
import contextlib
import unittest.mock as _m

import janissary.attack.nuclei as _nuclei_mod
import janissary.cli as cli


class _FakeRunner:
    seen = {}

    def __init__(self, *a, **kw):
        _FakeRunner.seen = dict(kw)

    def run(self, *a, **kw):
        return {"aborted": False, "findings": []}


def test_nuclei_path_reaches_runner():
    _FakeRunner.seen = {}
    with _m.patch.object(_nuclei_mod, "NucleiRunner", _FakeRunner):  # noqa: SIM117
        with contextlib.suppress(Exception, SystemExit):
            cli.main(
                [
                    "attack",
                    "nuclei",
                    "http://127.0.0.1:5000",
                    "--templates",
                    "x",
                    "--attack-confirm",
                    "--nuclei-path",
                    r"C:\fake\nuclei.exe",
                ]
            )
    assert _FakeRunner.seen.get("nuclei_path") == r"C:\fake\nuclei.exe", (
        _FakeRunner.seen
    )
