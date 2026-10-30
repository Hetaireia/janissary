"""JANISSARY — differential DAST scanner."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("janissary")
except PackageNotFoundError:
    # Not installed (e.g. running straight from a source checkout
    # without `pip install -e .`). A stale constant is worse than
    # an obviously-wrong placeholder because the wrong number looks
    # authoritative. Fail loudly.
    __version__ = "0.0.0+source-uninstalled"
