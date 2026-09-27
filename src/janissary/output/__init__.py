"""Machine-readable output for JANISSARY (schema v1.0).

Public surface:
    OutputFormat      - HUMAN | JSON | JSONL
    OutputEmitter     - serialize findings to stdout in the requested format
    add_output_flags  - register --json/--jsonl on an argparse subparser
    SCHEMA_VERSION    - current schema version string
"""

from .emitter import (
    SCHEMA_VERSION,
    OutputEmitter,
    OutputFormat,
    add_output_flags,
)

__all__ = [
    "SCHEMA_VERSION",
    "OutputEmitter",
    "OutputFormat",
    "add_output_flags",
]
