import pathlib

content = """name: Publish to PyPI

on:
  push:
    tags:
      - "v*"

jobs:
  build:
    name: Build distribution
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: actions/setup-python@v6
        with:
          python-version: "3.x"
      - name: Install build
        run: python -m pip install build --user
      - name: Build sdist and wheel
        run: python -m build
      - name: Store distributions
        uses: actions/upload-artifact@v5
        with:
          name: python-package-distributions
          path: dist/

  publish-to-pypi:
    name: Publish to PyPI
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/janissary
    permissions:
      id-token: write
    steps:
      - name: Download distributions
        uses: actions/download-artifact@v6
        with:
          name: python-package-distributions
          path: dist/
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
"""
p = pathlib.Path(".github/workflows/release.yml")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(content, encoding="utf-8", newline="\n")
print(f"Wrote {p} ({p.stat().st_size} bytes)")
