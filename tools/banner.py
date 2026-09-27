"""Janissary terminal banner.

Renders the JANISSARY wordmark in ANSI Shadow (cyan) with the project
tagline and the "Created by Oracle Mode" maker's mark.

Honours NO_COLOR and non-TTY stdout by emitting plain text.
"""
from __future__ import annotations

import contextlib
import os
import sys

CYAN = "\033[1;36m"
GREY = "\033[38;5;244m"
PURPLE = "\033[38;5;135m"
RESET = "\033[0m"

JANISSARY_ART = """     ██╗ █████╗ ███╗   ██╗██╗███████╗███████╗ █████╗ ██████╗ ██╗   ██╗
     ██║██╔══██╗████╗  ██║██║██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
     ██║███████║██╔██╗ ██║██║███████╗███████╗███████║██████╔╝ ╚████╔╝
██   ██║██╔══██║██║╚██╗██║██║╚════██║╚════██║██╔══██║██╔══██╗  ╚██╔╝
╚█████╔╝██║  ██║██║ ╚████║██║███████║███████║██║  ██║██║  ██║   ██║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
                                                                      """

TAGLINE = "DIFFERENTIAL DAST FOR TEAMS WHO NEED RESULTS THEY CAN TRUST"
RULE = "\u2550" * 70
SIGNATURE = "Created by Oracle Mode"


def _colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def render(stream=None) -> None:
    if stream is None:
        stream = sys.stdout
        if hasattr(stream, "reconfigure"):
            with contextlib.suppress(Exception):
                stream.reconfigure(encoding="utf-8")
    if _colour_enabled():
        stream.write(f"{CYAN}{JANISSARY_ART}{RESET}\n")
        stream.write(f"{GREY}{RULE}{RESET}\n")
        stream.write(f"{GREY}  {TAGLINE}{RESET}\n")
        stream.write(f"{GREY}{RULE}{RESET}\n")
        stream.write(f"  Created by {PURPLE}Oracle Mode{RESET}\n")
    else:
        stream.write(JANISSARY_ART + "\n")
        stream.write(RULE + "\n")
        stream.write("  " + TAGLINE + "\n")
        stream.write(RULE + "\n")
        stream.write("  " + SIGNATURE + "\n")


if __name__ == "__main__":
    render()
