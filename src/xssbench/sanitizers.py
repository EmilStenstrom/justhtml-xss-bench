from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .harness import PayloadContext


# Shared sanitization policy
#
# Goal: preserve common structure/semantics (including div/span and tables)
# while stripping scripting primitives, event handlers, and unsafe URLs.
DEFAULT_ALLOWED_TAGS: tuple[str, ...] = (
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
    "strong",
    "em",
    "b",
    "i",
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
)


DEFAULT_ALLOWED_TAGS_SET: frozenset[str] = frozenset(DEFAULT_ALLOWED_TAGS)


_GLOBAL_ATTRS: frozenset[str] = frozenset({"class", "id", "title", "lang", "dir", "style"})

_A_ATTRS: frozenset[str] = frozenset({"href", "title"})

_IMG_ATTRS: frozenset[str] = frozenset({"src", "alt", "title", "width", "height", "loading"})

_TABLE_CELL_ATTRS: frozenset[str] = frozenset({"colspan", "rowspan"})

_URL_PROTOCOLS: tuple[str, ...] = ("http", "https", "mailto", "tel")


def allowed_url_protocols() -> tuple[str, ...]:
    return _URL_PROTOCOLS


def allowed_attributes_for_tag(tag: str) -> frozenset[str]:
    """Return the allowlisted attributes for a given tag (shared policy).

    This is used both by sanitizer configuration (bleach/nh3/lxml-html-clean)
    and by the benchmark when interpreting `expected_tags` attribute requirements.
    """

    t = str(tag).strip().lower()
    if not t:
        return frozenset()

    if t == "a":
        return frozenset(set(_GLOBAL_ATTRS) | set(_A_ATTRS))
    if t == "img":
        return frozenset(set(_GLOBAL_ATTRS) | set(_IMG_ATTRS))
    if t in {"th", "td"}:
        return frozenset(set(_GLOBAL_ATTRS) | set(_TABLE_CELL_ATTRS))
    return _GLOBAL_ATTRS


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

    # Shared allowlist policy (see module constants).
    from bleach.sanitizer import Cleaner  # type: ignore

    css_sanitizer = None
    try:
        from bleach.css_sanitizer import CSSSanitizer  # type: ignore

        css_sanitizer = CSSSanitizer()
    except Exception:
        css_sanitizer = None

    def _bleach_attr_filter(tag: str, name: str, value: str) -> bool:
        if name in _GLOBAL_ATTRS:
            return True
        if tag == "a" and name in _A_ATTRS:
            return True
        if tag == "img" and name in _IMG_ATTRS:
            return True
        if tag in {"th", "td"} and name in _TABLE_CELL_ATTRS:
            return True
        return False

    cleaner_kwargs = dict(
        tags=list(DEFAULT_ALLOWED_TAGS),
        attributes=_bleach_attr_filter,
        protocols=list(_URL_PROTOCOLS),
        strip=True,
        strip_comments=True,
    )
    if css_sanitizer is not None:
        cleaner_kwargs["css_sanitizer"] = css_sanitizer
    cleaner = Cleaner(**cleaner_kwargs)

    def _sanitize(html: str) -> str:
        return cleaner.clean(html)

    return Sanitizer(
        name="bleach",
        description="bleach Cleaner shared allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # bleach is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer"},
    )


def _maybe_nh3() -> Sanitizer | None:
    try:
        import nh3  # type: ignore
    except Exception:
        return None

    allowed_tags: set[str] = set(DEFAULT_ALLOWED_TAGS)

    # nh3 uses allowlisted attributes by tag, plus a global "*" entry.
    allowed_attributes: dict[str, set[str]] = {
        "*": set(_GLOBAL_ATTRS),
        # NOTE: do not allow `rel` here.
        # nh3 (ammonia) manages link rel via the separate `link_rel=` setting and
        # will panic if `rel` is configured as an allowed attribute.
        "a": set(_A_ATTRS),
        "img": set(_IMG_ATTRS),
        "th": set(_TABLE_CELL_ATTRS),
        "td": set(_TABLE_CELL_ATTRS),
    }

    def _sanitize(html: str) -> str:
        # Keep the call signature conservative to avoid version-specific args.
        return nh3.clean(
            html,
            tags=allowed_tags,
            attributes=allowed_attributes,
            url_schemes=set(_URL_PROTOCOLS),
            link_rel=None,  # Disable automatic rel management.
        )

    return Sanitizer(
        name="nh3",
        description="nh3 shared allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # nh3 is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer"},
    )


def _maybe_lxml_html_clean() -> Sanitizer | None:
    try:
        from lxml_html_clean import Cleaner  # type: ignore
    except Exception:
        return None

    # Configure lxml-html-clean to match the shared allowlist policy.
    allowed_tags: set[str] = set(DEFAULT_ALLOWED_TAGS)

    # lxml-html-clean's attribute allowlist is global (not per-tag).
    safe_attrs: frozenset[str] = frozenset(
        set(_GLOBAL_ATTRS) | set(_A_ATTRS) | set(_IMG_ATTRS) | set(_TABLE_CELL_ATTRS)
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
        if not html.strip():
            return ""
        try:
            cleaned = cleaner.clean_html(html)
        except Exception:
            # lxml-html-clean may raise ParserError on some malformed/empty inputs.
            # Treat as fully stripped output rather than a sanitizer error.
            return ""
        if isinstance(cleaned, str):
            return cleaned

        # lxml-html-clean may return an element/document; serialize best-effort.
        try:
            from lxml import etree  # type: ignore

            serialized = etree.tostring(cleaned, encoding="unicode", method="html")
        except Exception:
            serialized = str(cleaned)

        return serialized

    return Sanitizer(
        name="lxml_html_clean",
        description="lxml-html-clean Cleaner shared allowlist (configured to match bleach/nh3 style)",
        sanitize=_sanitize,
        supported_contexts={"html", "html_head", "html_outer"},
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
            supported_contexts={
                "html",
                "html_head",
                "html_outer",
                "js",
                "js_arg",
                "js_string",
                "js_string_double",
                "onerror_attr",
            },
        ),
    }

    for maybe in (
        _maybe_bleach(),
        _maybe_nh3(),
        _maybe_lxml_html_clean(),
    ):
        if maybe is not None:
            sanitizers[maybe.name] = maybe

    return sanitizers


def default_sanitizers() -> dict[str, Sanitizer]:
    """Return the default sanitizer set for `xssbench`.

    The goal is to represent a "semantic" HTML sanitization policy (preserve meaningful
    markup for content), rather than "escape everything" baselines.
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
