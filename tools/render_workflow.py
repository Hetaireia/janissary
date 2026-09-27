"""Render WORKFLOW.md to HTML and open it in the default browser."""
from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

from markdown_it import MarkdownIt

CSS = """
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         max-width: 900px; margin: 2rem auto; padding: 0 1rem;
         line-height: 1.55; color: #1a1a1a; background: #fafafa; }
  h1 { border-bottom: 2px solid #333; padding-bottom: .3rem; }
  h2 { border-bottom: 1px solid #ccc; padding-bottom: .2rem; margin-top: 2rem; }
  h3 { margin-top: 1.5rem; }
  code, pre { background: #f0f0f0; padding: .1rem .35rem; border-radius: 3px;
              font-family: Consolas, "Cascadia Mono", monospace; font-size: .92em; }
  pre { padding: .8rem; overflow-x: auto; }
  ul { padding-left: 1.4rem; }
  li { margin: .15rem 0; }
  hr { border: none; border-top: 1px solid #ddd; margin: 2rem 0; }
  .meta { color: #666; font-size: .85rem; }
"""


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    src = repo_root / "WORKFLOW.md"
    if not src.is_file():
        print(f"WORKFLOW.md not found at {src}", file=sys.stderr)
        return 1

    text = src.read_text(encoding="utf-8")
    md = MarkdownIt("commonmark", {"linkify": True, "typographer": True})
    body = md.render(text)

    html = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>JANISSARY - Workflow Tracker</title>\n"
        f"<style>{CSS}</style>\n"
        "</head><body>\n"
        f"{body}\n"
        "</body></html>\n"
    )

    out = src.with_suffix(".html")
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out}")
    webbrowser.open(out.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
