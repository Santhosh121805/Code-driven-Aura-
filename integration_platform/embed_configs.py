"""Copy the real config files into the public home page's code tabs: `python -m integration_platform.embed_configs`.

The home page is static (it calls no protected API), so the YAML is embedded at build time. Every
`<pre ... data-file="configs/...">` block is replaced with the file's current, HTML-escaped content.
tests/test_public.py fails if an embedded copy drifts from its file.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "integration_platform" / "static" / "landing.html"
BLOCK = re.compile(r'(<pre[^>]*\bdata-file="(?P<file>configs/[^"]+)"[^>]*>)(?P<body>.*?)(</pre>)', re.S)


def embedded_files(page: str) -> dict[str, str]:
    """{config path: embedded text (unescaped)} for every code block in the page."""
    return {m["file"]: html.unescape(m["body"]) for m in BLOCK.finditer(page)}


def config_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n")


def embed(page: str) -> str:
    return BLOCK.sub(lambda m: m.group(1) + html.escape(config_text(m["file"]), quote=False) + m.group(4), page)


if __name__ == "__main__":
    text = PAGE.read_text(encoding="utf-8")
    PAGE.write_text(embed(text), encoding="utf-8")
    print(f"embedded {len(embedded_files(embed(text)))} config files into {PAGE.relative_to(ROOT)}")
