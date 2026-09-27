"""Export credential findings to JSON or CSV.

The export never writes the un-redacted token unless include_full_token
is explicitly True. That default is the safe choice for CI logs and
shared artifacts.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone

CSV_COLUMNS = [
    "token_type",
    "description",
    "redacted",
    "source",
    "line",
    "context",
    "severity",
    "entropy",
    "timestamp",
]


def export_credentials(
    findings: list[dict],
    export_path: str,
    include_full_token: bool = False,
) -> None:
    """Write findings to export_path (.json or .csv)."""
    payload = []
    for f in findings:
        entry = {k: v for k, v in f.items() if k != "full_token"}
        if include_full_token:
            entry["full_token"] = f.get("full_token")
        payload.append(entry)

    ext = os.path.splitext(export_path)[1].lower()
    if ext == ".csv":
        with open(export_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=CSV_COLUMNS,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(payload)
    else:
        with open(export_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "finding_count": len(payload),
                    "findings": payload,
                },
                fh,
                indent=2,
            )
    print(f"[*] credential findings exported to {export_path}")
