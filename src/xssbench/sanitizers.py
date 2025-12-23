from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .harness import PayloadContext


@dataclass(frozen=True, slots=True)
class Sanitizer:
    name: str
    description: str
    sanitize: Callable[[str], str]
    supported_contexts: set[PayloadContext] | None = None


def noop(html: str) -> str:
    """No-op sanitizer.

    Useful as a baseline to verify that the harness correctly detects execution.
    """

    return html


def _maybe_bleach() -> Sanitizer | None:
    try:
        import bleach  # type: ignore
    except Exception:
        return None

    # A "rich" allowlist that aims to keep useful markup while blocking XSS.
    # Intentionally does NOT allow inline CSS (style=...) by default.
    from bleach.sanitizer import Cleaner  # type: ignore

    allowed_tags: list[str] = [
        # Text / structure
        "p",
        "br",
        "div",
        "span",
        "blockquote",
        "pre",
        "code",
        "hr",
        # Emphasis
        "b",
        "strong",
        "i",
        "em",
        "u",
        "s",
        "sub",
        "sup",
        # Lists
        "ul",
        "ol",
        "li",
        # Headings
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        # Links & media
        "a",
        "img",
        # Tables
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td",
    ]

    def _bleach_attr_filter(tag: str, name: str, value: str) -> bool:
        # Global attributes
        if name in {"class", "id", "title", "lang", "dir"}:
            return True
        if name.startswith("data-") or name.startswith("aria-"):
            return True

        # Tag-specific
        if tag == "a" and name in {"href", "rel", "target", "name"}:
            return True
        if tag == "img" and name in {"src", "alt", "title", "width", "height", "loading"}:
            return True
        if tag in {"th", "td"} and name in {"colspan", "rowspan"}:
            return True

        return False

    cleaner = Cleaner(
        tags=allowed_tags,
        attributes=_bleach_attr_filter,
        protocols=["http", "https", "mailto", "tel"],
        strip=True,
        strip_comments=True,
    )

    def _sanitize(html: str) -> str:
        return cleaner.clean(html)

    return Sanitizer(
        name="bleach",
        description="bleach Cleaner rich allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # bleach is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )


def _maybe_bleach_default() -> Sanitizer | None:
    try:
        import bleach  # type: ignore
    except Exception:
        return None

    def _sanitize(html: str) -> str:
        return bleach.clean(html)

    return Sanitizer(
        name="bleach_default",
        description="bleach.clean(html) with default settings (often very strict)",
        sanitize=_sanitize,
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )


def _maybe_nh3() -> Sanitizer | None:
    try:
        import nh3  # type: ignore
    except Exception:
        return None

    allowed_tags: set[str] = {
        "p",
        "br",
        "div",
        "span",
        "blockquote",
        "pre",
        "code",
        "hr",
        "b",
        "strong",
        "i",
        "em",
        "u",
        "s",
        "sub",
        "sup",
        "ul",
        "ol",
        "li",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "a",
        "img",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td",
    }

    # nh3 uses allowlisted attributes by tag, plus a global "*" entry.
    allowed_attributes: dict[str, set[str]] = {
        "*": {"class", "id", "title", "lang", "dir"},
        # NOTE: do not allow `rel` here.
        # nh3 (ammonia) manages link rel via the separate `link_rel=` setting and
        # will panic if `rel` is configured as an allowed attribute.
        "a": {"href", "target", "name"},
        "img": {"src", "alt", "title", "width", "height", "loading"},
        "th": {"colspan", "rowspan"},
        "td": {"colspan", "rowspan"},
    }

    def _sanitize(html: str) -> str:
        # Keep the call signature conservative to avoid version-specific args.
        return nh3.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            url_schemes={"http", "https", "mailto", "tel"},
        )

    return Sanitizer(
        name="nh3",
        description="nh3 rich allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # nh3 is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )


def _maybe_nh3_default() -> Sanitizer | None:
    try:
        import nh3  # type: ignore
    except Exception:
        return None

    def _sanitize(html: str) -> str:
        return nh3.clean(html)

    return Sanitizer(
        name="nh3_default",
        description="nh3.clean(html) with default settings (often very strict)",
        sanitize=_sanitize,
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )


def _maybe_lxml_html_clean() -> Sanitizer | None:
    try:
        from lxml_html_clean import Cleaner  # type: ignore
    except Exception:
        return None

    # Configure lxml-html-clean to approximate our "rich allowlist" policy used
    # for bleach/nh3: preserve common markup, but strip scripts/events/styles,
    # and avoid rewriting HTML fragments into full documents.
    allowed_tags: set[str] = {
        # Text / structure
        "p",
        "br",
        "div",
        "span",
        "blockquote",
        "pre",
        "code",
        "hr",
        # Emphasis
        "b",
        "strong",
        "i",
        "em",
        "u",
        "s",
        "sub",
        "sup",
        # Lists
        "ul",
        "ol",
        "li",
        # Headings
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        # Links & media
        "a",
        "img",
        # Tables
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "th",
        "td",
    }

    # lxml-html-clean's attribute allowlist is global (not per-tag). Keep it
    # conservative and aligned with our other rich sanitizers.
    safe_attrs: frozenset[str] = frozenset(
        {
            # Global
            "class",
            "id",
            "title",
            "lang",
            "dir",
            # Links
            "href",
            "rel",
            "target",
            "name",
            # Images
            "src",
            "alt",
            "width",
            "height",
            "loading",
            # Table cells
            "colspan",
            "rowspan",
        }
    )

    cleaner = Cleaner(
        # XSS primitives
        scripts=True,
        javascript=True,
        comments=True,
        style=True,
        processing_instructions=True,
        # Do not turn fragments into full documents / add <body> wrappers.
        page_structure=False,
        # Remove tags not in our allowlist (including svg/math).
        allow_tags=allowed_tags,
        # NOTE: lxml-html-clean forbids combining allow_tags + remove_unknown_tags.
        # allow_tags is sufficient for our purposes.
        remove_unknown_tags=False,
        safe_attrs_only=True,
        safe_attrs=safe_attrs,
        # Keep external-link behavior aligned with other sanitizers (no auto rel).
        add_nofollow=False,
    )

    def _sanitize(html: str) -> str:
        cleaned = cleaner.clean_html(html)
        if isinstance(cleaned, str):
            return cleaned

        # lxml-html-clean may return an element/document; serialize best-effort.
        try:
            from lxml import etree  # type: ignore

            return etree.tostring(cleaned, encoding="unicode", method="html")
        except Exception:
            return str(cleaned)

    return Sanitizer(
        name="lxml_html_clean",
        description="lxml-html-clean Cleaner rich allowlist (configured to match bleach/nh3 style)",
        sanitize=_sanitize,
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )


def available_sanitizers() -> dict[str, Sanitizer]:
    """Return all sanitizers available in the current environment.

    Third-party sanitizers are returned only if their libraries are installed.
    """

    sanitizers: dict[str, Sanitizer] = {
        "noop": Sanitizer(
            name="noop",
            description="Baseline: returns HTML unchanged",
            sanitize=noop,
            supported_contexts=None,
        ),
    }

    for maybe in (
        _maybe_bleach(),
        _maybe_bleach_default(),
        _maybe_nh3(),
        _maybe_nh3_default(),
        _maybe_lxml_html_clean(),
    ):
        if maybe is not None:
            sanitizers[maybe.name] = maybe

    return sanitizers


def default_sanitizers() -> dict[str, Sanitizer]:
    """Return the default sanitizer set for `xssbench`.

    The goal is to represent "rich" HTML sanitization (preserve useful markup)
    rather than "escape everything" baselines.
    """

    all_sanitizers = available_sanitizers()
    prefer: list[str] = [
        "noop",
        "bleach",
        "nh3",
        "lxml_html_clean",
    ]

    out: dict[str, Sanitizer] = {}
    for name in prefer:
        s = all_sanitizers.get(name)
        if s is not None:
            out[name] = s
    # If optional sanitizers aren't installed, still run at least noop.
    if not out and "noop" in all_sanitizers:
        out["noop"] = all_sanitizers["noop"]
    return out


def get_sanitizer(name: str) -> Sanitizer:
    sanitizers = available_sanitizers()
    try:
        return sanitizers[name]
    except KeyError as exc:
        available = ", ".join(sorted(sanitizers.keys()))
        raise KeyError(f"Unknown sanitizer {name!r}. Available: {available}") from exc
