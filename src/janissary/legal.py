"""Terms of use and first-run acceptance gate.

JANISSARY is a dual-use security tool. This module implements the
clickwrap acceptance step that makes the supplemental Terms of Use in
LEGAL.md contractually binding on the standard user path.

It does not modify the Apache-2.0 code licence. It adds a separate
acceptance record that the CLI checks before any network command runs.

The canonical terms text lives in TERMS_TEXT below. LEGAL.md contains
the same clauses in a human-readable form. A unit test cross-checks
that both sources carry the same required clause headings, so they
cannot silently diverge.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TERMS_VERSION = 1

ACCEPTANCE_ENV = "JANISSARY_ACCEPT_TERMS"

MARKER_DIRNAME = ".janissary"
MARKER_FILENAME = "terms-accepted.json"

# Commands that touch a remote target and therefore require acceptance.
GATED_COMMANDS = frozenset({"scan", "fingerprint", "graphql", "ws", "admin", "attack"})

ACCEPT_PROMPT = "Type I AGREE to continue: "
ACCEPT_TOKEN = "I AGREE"

NON_TTY_MESSAGE = (
    "JANISSARY requires acceptance of its Terms of Use before any\n"
    "network command can run, and stdin is not a terminal.\n"
    "\n"
    "To accept non-interactively, run one of:\n"
    "\n"
    "    janissary terms accept\n"
    "\n"
    "or set the environment variable:\n"
    "\n"
    "    JANISSARY_ACCEPT_TERMS=1\n"
    "\n"
    "Full terms: see LEGAL.md in the project root.\n"
)


TERMS_TEXT = """\
JANISSARY TERMS OF USE - version 1

JANISSARY is a security testing tool. It is intended for use only
against systems you own, or systems you have explicit written
permission to test.

1. AUTHORISED USE
You must not use JANISSARY to access, scan, probe, extract data from,
or interfere with any system, network, or data unless you have the
prior, explicit, written authorisation of the system owner. In
Australia, unauthorised access to restricted data is an offence under
s 478.1 of the Criminal Code Act 1995 (Cth), carrying up to 2 years
imprisonment; aggravated offences carry up to 10 years. In the United
States, unauthorised access is an offence under 18 U.S.C. s 1030
(CFAA), with civil and criminal penalties.

2. INDEMNITY
You agree to indemnify, defend, and hold harmless the developer,
contributors, and copyright holders of JANISSARY (each an
"Indemnified Party") from and against any and all claims, demands,
actions, suits, losses, liabilities, damages, costs, and expenses
(including reasonable legal fees) arising out of or in connection
with:
  (a) your use of JANISSARY;
  (b) your breach of clause 1 of these Terms;
  (c) your unauthorised access to any system, network, or data; or
  (d) any modification you make to JANISSARY.
This indemnity does not extend to claims arising from the wilful
misconduct or gross negligence of the Indemnified Party.

3. LIMITATION OF LIABILITY
To the maximum extent permitted by law, the developer, contributors,
and copyright holders of JANISSARY will not be liable for any damages
arising from the use or inability to use JANISSARY, whether in
contract, tort (including negligence), statute, or otherwise. Where
liability cannot be excluded but may be limited, total aggregate
liability is limited to the amount you paid for JANISSARY, which for
this open-source distribution is zero (AUD 0.00). Nothing in this
clause excludes liability that cannot lawfully be excluded, including
under the Australian Consumer Law where applicable.

4. EXPORT CONTROL
JANISSARY may be subject to export control and sanctions laws,
including Australia's Defence and Strategic Goods List (DSGL) and the
United States Export Administration Regulations (EAR). You must not
use, export, re-export, or transfer JANISSARY in violation of those
laws, or to any person or entity subject to sanctions.

5. GOOD-FAITH RESEARCH
JANISSARY is designed for good-faith security testing and research.
Use it only in a way that avoids harm to individuals and the public,
and use the information it produces primarily to improve the security
of the affected systems.

6. NO WARRANTY
JANISSARY is provided "as is", without warranty of any kind, as set
out in the Apache License 2.0. These Terms supplement, and do not
replace, the Apache License 2.0.

7. GOVERNING LAW
These Terms are governed by the laws of Victoria, Australia. The
parties submit to the exclusive jurisdiction of the courts of
Victoria, Australia.

By typing I AGREE, you confirm that you have read these Terms, that
you accept them, and that you will comply with clause 1 (Authorised
Use) in every use of JANISSARY.
"""


def marker_path() -> Path:
    """Return the path to the acceptance marker file."""
    return Path.home() / MARKER_DIRNAME / MARKER_FILENAME


def is_accepted(path: Path | None = None) -> bool:
    """True if the marker file exists and records the current version."""
    p = path or marker_path()
    if not p.exists():
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return data.get("terms_version") == TERMS_VERSION


def record_acceptance(path: Path | None = None) -> Path:
    """Write the acceptance marker and return its path."""
    p = path or marker_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "terms_version": TERMS_VERSION,
        "accepted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def require_acceptance(
    command: str,
    path: Path | None = None,
) -> None:
    """Gate the given command behind Terms-of-Use acceptance.

    - Non-gated commands return immediately.
    - Setting JANISSARY_ACCEPT_TERMS=1 records acceptance and proceeds.
    - A current marker file proceeds silently.
    - Otherwise, prompt on a TTY; on a non-TTY, exit with code 64.
    """
    if command not in GATED_COMMANDS:
        return

    # Environment-variable acceptance. Best-effort record; the
    # invocation proceeds even if the record cannot be written.
    if os.environ.get(ACCEPTANCE_ENV) == "1":
        with contextlib.suppress(Exception):
            record_acceptance(path)
        return

    if is_accepted(path):
        return

    if not sys.stdin.isatty():
        print(NON_TTY_MESSAGE, file=sys.stderr)
        raise SystemExit(64)

    # Interactive prompt.
    print()
    print(TERMS_TEXT)
    print()
    print("Full terms: LEGAL.md in the project root.")
    print("To skip this prompt in future: janissary terms accept")
    print()
    sys.stdout.write(ACCEPT_PROMPT)
    sys.stdout.flush()

    try:
        response = sys.stdin.readline()
    except KeyboardInterrupt:
        print("\nAcceptance not given.", file=sys.stderr)
        raise SystemExit(64) from None

    if response.strip() != ACCEPT_TOKEN:
        print()
        print("Acceptance not given. JANISSARY will not run.", file=sys.stderr)
        raise SystemExit(64)

    recorded = record_acceptance(path)
    print()
    print(f"Terms version {TERMS_VERSION} accepted.")
    print(f"Recorded at {recorded}")
    print()
