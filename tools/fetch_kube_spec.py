"""Fetch the Kubernetes OpenAPI spec for the Stage 3 torture test.

Usage:
    python tools/fetch_kube_spec.py

Downloads to tests/fixtures/openapi/large/kube-openapi.json, which is
gitignored. The test that consumes it skips with an explicit message
when the file is absent, naming this command as the prerequisite.

The spec is Swagger 2.0 (~3 MB). The published source is the
Kubernetes repository's api/openapi-spec/swagger.json, which is what
the ADR calls kube-openapi.json.
"""
from pathlib import Path
from urllib.request import urlretrieve

URL = (
    "https://raw.githubusercontent.com/kubernetes/kubernetes/"
    "master/api/openapi-spec/swagger.json"
)
DEST = Path("tests/fixtures/openapi/large/kube-openapi.json")


def main() -> None:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    print("fetching " + URL)
    urlretrieve(URL, DEST)
    print("wrote " + str(DEST) + " (" + str(DEST.stat().st_size) + " bytes)")


if __name__ == "__main__":
    main()
