from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path


SOURCE_URL_DEFAULT = "https://raw.githubusercontent.com/cure53/HTTPLeaks/main/leak.html"
LICENSE_URL_DEFAULT = "https://raw.githubusercontent.com/cure53/HTTPLeaks/main/LICENSE"


@dataclass(frozen=True)
class Section:
    title: str
    body: str


_SECTION_COMMENT_RE = re.compile(r"<!--(?P<body>[\s\S]*?)-->", re.MULTILINE)
_SECTION_TITLE_RE = re.compile(r"^\s*%\s*(?P<title>.+?)\s*$", re.MULTILINE)


def _slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-") or "section"


def _first_tag_name(payload_html: str) -> str:
    # Find the first actual tag name. (Skip leading whitespace/newlines.)
    m = re.search(r"<\s*([A-Za-z][A-Za-z0-9:-]*)", payload_html)
    return m.group(1).lower() if m else "snippet"


def _first_leaking_url(payload_html: str) -> str | None:
    m = re.search(r"https?://leaking\.via/[^\s\"'>)]+", payload_html)
    return m.group(0) if m else None


def _extract_sections(source_html: str) -> list[Section]:
    matches = list(_SECTION_COMMENT_RE.finditer(source_html))
    sections: list[Section] = []

    for i, m in enumerate(matches):
        comment_body = m.group("body")
        title_match = _SECTION_TITLE_RE.search(comment_body)
        if not title_match:
            continue
        title = title_match.group("title").strip()

        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source_html)
        body = source_html[start:end]
        sections.append(Section(title=title, body=body))

    return sections


_MULTILINE_STARTERS = (
    "<style",
    "<svg",
    "<math",
    "<script",
    "<!--[if",
)

_MULTILINE_END_MARKERS = (
    "</style>",
    "</svg>",
    "</math>",
    "</script>",
    "<![endif]-->",
)


_CONTAINER_TAGS = {
    # HTML containers that appear in leak.html as multi-line blocks.
    "picture",
    "video",
    "audio",
    "object",
    "map",
    "table",
    "frameset",
    "menu",
    # Data islands
    "xml",
    # VML
    "line",
    "vmlframe",
}


def _split_section_into_items(section_body: str) -> list[str]:
    lines = [ln.rstrip("\r") for ln in section_body.splitlines()]

    items: list[str] = []

    def is_blank(ln: str) -> bool:
        return not ln.strip()

    def startswith_ci(ln: str, prefix: str) -> bool:
        return ln.lstrip().lower().startswith(prefix)

    i = 0
    while i < len(lines):
        line = lines[i]

        if is_blank(line):
            i += 1
            continue

        # Skip closing-tag-only lines. If a container block is handled correctly
        # we should never reach these.
        if line.lstrip().startswith("</"):
            i += 1
            continue

        # 1) <style> blocks: keep until </style>, and include immediate follow-up
        # elements (e.g. <a>...</a>) until blank line or next <style> block.
        if startswith_ci(line, "<style"):
            buf = [line]
            i += 1
            while i < len(lines):
                buf.append(lines[i])
                if "</style>" in lines[i].lower():
                    i += 1
                    break
                i += 1
            while i < len(lines) and not is_blank(lines[i]) and not startswith_ci(lines[i], "<style"):
                buf.append(lines[i])
                i += 1
            snippet = "\n".join(buf).strip("\n")
            if snippet.strip():
                items.append(snippet)
            continue

        # 2) Other known multi-line blocks.
        if startswith_ci(line, "<svg") or startswith_ci(line, "<math") or startswith_ci(line, "<script"):
            end_marker = "</svg>"
            if startswith_ci(line, "<math"):
                end_marker = "</math>"
            elif startswith_ci(line, "<script"):
                end_marker = "</script>"

            buf = [line]
            i += 1
            while i < len(lines):
                buf.append(lines[i])
                if end_marker in lines[i].lower():
                    i += 1
                    break
                i += 1
            snippet = "\n".join(buf).strip("\n")
            if snippet.strip():
                items.append(snippet)
            continue

        # 3) Conditional comments: keep until <![endif]-->.
        if startswith_ci(line, "<!--[if"):
            buf = [line]
            i += 1
            while i < len(lines):
                buf.append(lines[i])
                if "<![endif]-->" in lines[i].lower():
                    i += 1
                    break
                i += 1
            snippet = "\n".join(buf).strip("\n")
            if snippet.strip():
                items.append(snippet)
            continue

        # 4) Multi-line start tags (e.g. <b style="\n ... \n">MNO</b>)
        # If we see a '<' but no '>', keep lines until we reach a line containing '>'.
        if "<" in line and ">" not in line:
            buf = [line]
            i += 1
            while i < len(lines):
                buf.append(lines[i])
                if ">" in lines[i]:
                    i += 1
                    break
                i += 1
            snippet = "\n".join(buf).strip("\n")
            if snippet.strip():
                items.append(snippet)
            continue

        # 5) Container blocks (e.g. <picture> ... </picture>).
        m = re.match(r"^\s*<\s*([A-Za-z][A-Za-z0-9:-]*)\b", line)
        if m:
            tag = m.group(1).lower()
            if tag in _CONTAINER_TAGS and not line.lstrip().startswith("</"):
                buf = [line]
                i += 1
                close_re = re.compile(rf"</\s*{re.escape(tag)}\s*>", re.IGNORECASE)
                while i < len(lines):
                    buf.append(lines[i])
                    if close_re.search(lines[i]):
                        i += 1
                        break
                    i += 1
                snippet = "\n".join(buf).strip("\n")
                if snippet.strip():
                    items.append(snippet)
                continue

        # 6) Default: treat as a single-line snippet.
        items.append(line.strip("\n"))
        i += 1

    return items


def _payload_context_for(payload_html: str) -> str:
    return "http_leak"


def build_vectors(source_html: str) -> list[dict]:
    vectors: list[dict] = []
    sections = _extract_sections(source_html)

    for section in sections:
        slug = _slugify(section.title)
        for payload_html in _split_section_into_items(section.body):
            tag = _first_tag_name(payload_html)
            url = _first_leaking_url(payload_html)
            h = hashlib.sha1(payload_html.encode("utf-8")).hexdigest()[:10]
            vid = f"httpleaks-{slug}-{tag}-{h}"
            url_suffix = f" ({url})." if url else ""
            desc = f"HTTPLeaks leak.html: {section.title}: <{tag}> snippet{url_suffix}"

            vectors.append(
                {
                    "id": vid,
                    "description": desc,
                    "payload_html": payload_html,
                    "payload_context": _payload_context_for(payload_html),
                }
            )
    return vectors


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--input", type=Path, default=None)
    ap.add_argument("--source-url", default=SOURCE_URL_DEFAULT)
    ap.add_argument("--license-url", default=LICENSE_URL_DEFAULT)
    args = ap.parse_args(argv)

    if args.input is not None:
        source_html = args.input.read_text(encoding="utf-8", errors="replace")
        source_url = args.source_url
    else:
        with urllib.request.urlopen(args.source_url) as resp:
            source_html = resp.read().decode("utf-8", "replace")
        source_url = args.source_url

    vectors = build_vectors(source_html)

    doc = {
        "schema": "xssbench.vectorfile.v1",
        "meta": {
            "tool": "xssbench",
            "source_url": source_url,
            "notes": (
                "External-request leak primitives extracted from cure53/HTTPLeaks leak.html, split by "
                "its HTML comment section markers. This pack is intentionally NOT filtered to the benchmark's "
                "shared allowlist; it is meant to establish a 'noop baseline' of which primitives trigger "
                "observable external requests in the harness."
            ),
            "license": {
                "spdx": "BSD-2-Clause",
                "url": args.license_url,
                "file": "vectors/httpleaks-LICENSE.txt",
            },
        },
        "vectors": vectors,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, ensure_ascii=False, indent="\t") + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
