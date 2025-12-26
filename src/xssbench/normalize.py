from __future__ import annotations

import html
import re
import unicodedata


_ASCII_WS_RE = re.compile(r"[\t\n\r\f\v ]+")


def _normalize_newlines(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


def _collapse_ascii_whitespace_to_space(s: str) -> str:
    return _ASCII_WS_RE.sub(" ", s)


def _maybe_lowercase_url_scheme(value: str) -> str:
    # URL schemes are case-insensitive.
    # Example: JaVaScRiPt:alert(1) => javascript:alert(1)
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", value, flags=re.DOTALL)
    if not m:
        return value
    scheme, rest = m.group(1), m.group(2)
    return scheme.lower() + ":" + rest


def _normalize_attr_value(raw_value: str) -> str:
    v = html.unescape(raw_value)
    v = unicodedata.normalize("NFKC", v)
    v = _normalize_newlines(v)
    v = v.strip()
    v = _collapse_ascii_whitespace_to_space(v)
    v = _maybe_lowercase_url_scheme(v)
    return v


def _parse_html_tag(s: str, start: int) -> tuple[str, int] | None:
    # Minimal tag parser to canonicalize:
    # - tag name case
    # - attribute name case
    # - attribute ordering
    # - quote style
    # While being robust to broken markup (returns None on failure).
    if start >= len(s) or s[start] != "<":
        return None

    def _is_ascii_alnum(c: str) -> bool:
        o = ord(c)
        return (48 <= o <= 57) or (65 <= o <= 90) or (97 <= o <= 122)

    def _is_attr_name_char(c: str) -> bool:
        # Mirrors the previous regex: [A-Za-z0-9_:\-]
        o = ord(c)
        return (48 <= o <= 57) or (65 <= o <= 90) or (97 <= o <= 122) or c in ("_", ":", "-")

    i = start + 1
    if i >= len(s):
        return None

    # Comments / doctype: normalize spacing only, keep as-is-ish.
    if s.startswith("<!--", start):
        end = s.find("-->", i)
        if end == -1:
            return None
        inner = s[start : end + 3]
        inner = _collapse_ascii_whitespace_to_space(_normalize_newlines(inner)).strip()
        return inner, end + 3

    if s.startswith("<!", start) or s.startswith("<?", start):
        # Consume until next '>' not in quotes.
        quote: str | None = None
        while i < len(s):
            ch = s[i]
            if quote is None and ch in ('"', "'"):
                quote = ch
            elif quote is not None and ch == quote:
                quote = None
            elif quote is None and ch == ">":
                raw = s[start : i + 1]
                raw = _collapse_ascii_whitespace_to_space(_normalize_newlines(raw)).strip()
                return raw, i + 1
            i += 1
        return None

    # Closing tag?
    is_close = False
    if i < len(s) and s[i] == "/":
        is_close = True
        i += 1

    # Parse tag name.
    name_start = i
    while i < len(s) and _is_ascii_alnum(s[i]):
        i += 1
    if i == name_start:
        return None

    tag_name = s[name_start:i].lower()

    # Skip whitespace.
    while i < len(s) and s[i].isspace():
        i += 1

    # Closing tag should end now.
    if is_close:
        while i < len(s) and s[i].isspace():
            i += 1
        if i < len(s) and s[i] == ">":
            return f"</{tag_name}>", i + 1
        return None

    # Parse attributes.
    attrs: list[tuple[str, str | None]] = []
    self_closing = False

    while i < len(s):
        ch = s[i]
        if ch == ">":
            i += 1
            break

        if ch == "/":
            # Potential '/>'
            j = i + 1
            while j < len(s) and s[j].isspace():
                j += 1
            if j < len(s) and s[j] == ">":
                self_closing = True
                i = j + 1
                break

        if ch.isspace():
            i += 1
            continue

        # attr name
        attr_name_start = i
        while i < len(s) and _is_attr_name_char(s[i]):
            i += 1
        if i == attr_name_start:
            return None

        attr_name = s[attr_name_start:i].lower()

        while i < len(s) and s[i].isspace():
            i += 1

        attr_value: str | None = None
        if i < len(s) and s[i] == "=":
            i += 1
            while i < len(s) and s[i].isspace():
                i += 1
            if i >= len(s):
                return None

            if s[i] in ('"', "'"):
                q = s[i]
                i += 1
                val_start = i
                while i < len(s) and s[i] != q:
                    i += 1
                if i >= len(s):
                    return None
                raw_val = s[val_start:i]
                i += 1
                attr_value = _normalize_attr_value(raw_val)
            else:
                val_start = i
                while i < len(s) and (not s[i].isspace()) and s[i] not in (">", "/"):
                    i += 1
                raw_val = s[val_start:i]
                attr_value = _normalize_attr_value(raw_val)

        attrs.append((attr_name, attr_value))

    # Canonical attribute ordering: by name, then value.
    attrs.sort(key=lambda kv: (kv[0], "" if kv[1] is None else kv[1]))

    if not attrs:
        return (f"<{tag_name}/>" if self_closing else f"<{tag_name}>", i)

    rendered_attrs: list[str] = []
    for name, value in attrs:
        if value is None:
            rendered_attrs.append(name)
        else:
            escaped = value.replace('"', "&quot;")
            rendered_attrs.append(f'{name}="{escaped}"')

    suffix = "/>" if self_closing else ">"
    return f"<{tag_name} " + " ".join(rendered_attrs) + suffix, i


def _collapse_js_whitespace_outside_quotes(s: str) -> str:
    # Best-effort: collapse ASCII whitespace to a single space, but only when
    # not inside single/double/backtick quotes.
    out: list[str] = []
    quote: str | None = None
    esc = False
    pending_space = False

    def _is_wordish(c: str) -> bool:
        # Minimal JS token heuristic: keep spaces between word-ish tokens to
        # avoid joining identifiers/keywords/numbers.
        return c.isalnum() or c in ("_", "$")

    def _is_punct(c: str) -> bool:
        # Characters where surrounding whitespace is almost always ignorable.
        return c in "()[]{}.,;:+-*/%<>=!&|^~?"

    for ch in s:
        if quote is not None:
            out.append(ch)
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == quote:
                quote = None
            continue

        # Not in quote
        if ch in ("'", '"', "`"):
            if pending_space and out and out[-1] != " ":
                out.append(" ")
            pending_space = False
            out.append(ch)
            quote = ch
            continue

        if ch in (" ", "\t", "\n", "\r", "\f", "\v"):
            pending_space = True
            continue

        if pending_space:
            prev = out[-1] if out else ""
            # Drop whitespace around punctuation; keep a single space between
            # two word-ish tokens.
            if prev and _is_wordish(prev) and _is_wordish(ch):
                out.append(" ")
            pending_space = False
        out.append(ch)

    # drop trailing space
    while out and out[-1] == " ":
        out.pop()
    return "".join(out)


def normalize_payload(payload: str) -> str:
    """Return a canonical string suitable for duplicate detection.

    This is intentionally conservative and stdlib-only.

    What it normalizes (best-effort):
    - Unicode normalization (NFKC)
    - Newline normalization (CRLF/CR -> LF)
    - Leading/trailing whitespace
    - HTML tag/attribute case, attribute ordering, and quote style
    - Collapses runs of ASCII whitespace
    - Lowercases URL schemes (e.g. JaVaScRiPt: => javascript:)

    It is *not* a full HTML5 parser; malformed markup may be normalized less.
    """

    if payload is None:  # type: ignore[truthy-bool]
        payload = ""

    s = str(payload)
    s = s.replace("\x00", "")
    s = unicodedata.normalize("NFKC", s)
    s = _normalize_newlines(s)
    s = s.strip()

    out: list[str] = []
    i = 0
    raw_mode: str | None = None  # 'script' | 'style'

    while i < len(s):
        if raw_mode is not None:
            # In raw mode, only look for a closing tag.
            lower = s.lower()
            close_pat = f"</{raw_mode}"
            j = lower.find(close_pat, i)
            if j == -1:
                chunk = s[i:]
                chunk = _collapse_js_whitespace_outside_quotes(chunk)
                out.append(chunk)
                i = len(s)
                continue

            chunk = s[i:j]
            chunk = _collapse_js_whitespace_outside_quotes(chunk)
            out.append(chunk)
            i = j
            raw_mode = None
            continue

        if s[i] == "<":
            parsed = _parse_html_tag(s, i)
            if parsed is not None:
                normalized_tag, next_i = parsed
                out.append(normalized_tag)

                # Enter raw mode for <script> / <style>
                m = re.match(r"^<\s*([a-z0-9]+)\b", normalized_tag)
                if m:
                    tag = m.group(1)
                    if tag in ("script", "style") and not normalized_tag.startswith("</"):
                        raw_mode = tag

                i = next_i
                continue

            # Not a valid/parseable tag start (often malformed markup like
            # '<<script' or stray '<'). Treat it as literal text and advance.
            out.append("<")
            i += 1
            continue

        # Text node: normalize whitespace.
        j = s.find("<", i)
        if j == -1:
            j = len(s)
        text = s[i:j]
        text = html.unescape(text)
        text = unicodedata.normalize("NFKC", text)
        text = _normalize_newlines(text)
        text = _collapse_ascii_whitespace_to_space(text)
        out.append(text)
        i = j

    normalized = "".join(out).strip()
    # Remove whitespace-only text nodes between tags.
    normalized = re.sub(r">\s+<", "><", normalized)
    return normalized
