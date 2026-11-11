"""Convert imported OpenAPI operations into scanner targets (ADR-030 Stage 5).

One target per distinct parameter location. Scanner.inject_in is a
single mode per scanner instance, so an operation declaring parameters
in three locations needs three scanners -- hence three targets.

No scanner import, no network, no I/O. Pure transformation so it can
be tested without standing up a target.
"""

from __future__ import annotations

from janissary.importers.openapi import Operation

LOCATION_TO_MODE: dict[str, str] = {
    "path": "path",
    "query": "param-name",
    "header": "header",
    "cookie": "cookie",
    # Body parameters are not injected by name: the importer does not
    # capture request-body schemas, so Scanner's json-body mode has no
    # json_template to work with and raises on construction. The endpoint
    # is still scanned in "auto" mode; see BODY_LIMITATION_NOTE.
    "body": "auto",
}

BODY_LIMITATION_NOTE = (
    "body parameters are not injected by name "
    "(ADR-030 Stage 5 limitation); endpoint is still scanned"
)

LOCATION_ORDER: list[str] = [
    "path",
    "query",
    "header",
    "cookie",
    "body",
]


def _join_url(base_url: str, path: str) -> str:
    if not base_url:
        return path
    if base_url.endswith("/") and path.startswith("/"):
        return base_url[:-1] + path
    if not base_url.endswith("/") and not path.startswith("/"):
        return base_url + "/" + path
    return base_url + path


def build_scan_targets(op: Operation) -> list[dict]:
    """Return one scan target per parameter location on this operation.

    Operations with no parameters produce a single target with mode
    "auto" and an empty params list -- the endpoint still needs
    scanning, it just has nothing to inject into by name.
    """
    url = _join_url(op.base_url, op.path)
    locations = op.parameter_locations or {}

    grouped: dict[str, list[str]] = {}
    for name in op.parameter_names:
        loc = locations.get(name)
        if loc not in LOCATION_TO_MODE:
            continue
        grouped.setdefault(loc, []).append(name)

    targets: list[dict] = []
    for loc in LOCATION_ORDER:
        if loc not in grouped:
            continue
        if loc == "body":
            targets.append(
                {
                    "location": loc,
                    "url": url,
                    "params": [],
                    "inject_in": LOCATION_TO_MODE[loc],
                    "method": op.method,
                    "json_template": None,
                    "note": BODY_LIMITATION_NOTE,
                }
            )
            continue
        targets.append(
            {
                "location": loc,
                "url": url,
                "params": grouped[loc],
                "inject_in": LOCATION_TO_MODE[loc],
                "method": op.method,
                "json_template": None,
            }
        )

    if not targets:
        targets.append(
            {
                "location": "none",
                "url": url,
                "params": [],
                "inject_in": "auto",
                "method": op.method,
                "json_template": None,
            }
        )

    return targets
