from __future__ import annotations

from dataclasses import dataclass
import re
from typing import AbstractSet, Callable, Mapping

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

# Disallow all URL protocols by default.
# (Relative URLs may still be allowed by some sanitizers depending on their API.)
_URL_PROTOCOLS: tuple[str, ...] = ()


# Shared CSS allowlist (inline style sanitization)
#
# Intent: allow a realistic subset of inline CSS while still relying on the
# underlying sanitizer to *sanitize values* (e.g. strip/neutralize `url()` with
# unsafe schemes, IE `expression()`, etc). If we allow `style` at the attribute
# level but do not allow common properties here, most style-bearing payloads
# end up with an empty `style` and some sanitizers will drop the attribute.
#
# Note: `justhtml` will *drop the entire style attribute* if, after sanitization,
# no allowed properties remain. Keeping this list reasonably broad avoids
# unnecessary `lossy` results for style-heavy corpora.
DEFAULT_ALLOWED_CSS_PROPERTIES: tuple[str, ...] = (
    # Typography
    "color",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "line-height",
    "letter-spacing",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "white-space",
    "vertical-align",
    # Box model / layout
    "display",
    "float",
    "clear",
    "width",
    "height",
    "min-width",
    "min-height",
    "max-width",
    "max-height",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-color",
    "border-style",
    "border-width",
    "border-radius",
    # Backgrounds (URL-bearing; used in some XSS/HTTP-leak vectors)
    "background",
    "background-color",
    "background-image",
    # Lists (URL-bearing for list-style-image)
    "list-style",
    "list-style-type",
    "list-style-position",
    "list-style-image",
    # Images / shapes (URL-bearing)
    "border-image",
    "border-image-source",
    "-moz-border-image",
    "-webkit-border-image",
    "shape-outside",
    "-webkit-shape-outside",
    # Cursor (URL-bearing)
    "cursor",
    # Motion / effects (commonly present in modern content)
    "transform",
    "transition",
    "transition-property",
    "transition-duration",
    "transition-timing-function",
    "transition-delay",
    "animation",
    "animation-name",
    "animation-duration",
    "animation-timing-function",
    "animation-delay",
    "animation-iteration-count",
    "animation-direction",
    "animation-fill-mode",
    "animation-play-state",
)


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
    sanitize: Callable[..., str]
    supported_contexts: set[PayloadContext] | None = None


class SanitizerConfigUnsupported(Exception):
    """Raised when a sanitizer library cannot represent the requested allowlist."""


def _override_allowlist_raw(
    *,
    allow_tags: AbstractSet[str] | None,
    allow_attrs: Mapping[str, AbstractSet[str]] | None,
) -> tuple[AbstractSet[str], Mapping[str, AbstractSet[str]]]:
    """Return override allowlist without validation/normalization.

    Intentionally does not normalize case, filter invalid tag names, or strip
    processing-instruction pseudo tags.
    """

    return (allow_tags or frozenset()), (allow_attrs or {})


def noop(html: str, *, allow_tags=None, allow_attrs=None) -> str:
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

        # Align Bleach's inline CSS sanitization with the shared policy.
        # If tinycss2 isn't installed, this import fails and we fall back to not
        # sanitizing CSS (Bleach will still keep/drop `style` based on attrs).
        css_sanitizer = CSSSanitizer(allowed_css_properties=set(DEFAULT_ALLOWED_CSS_PROPERTIES))
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

    base_cleaner_kwargs = dict(
        tags=list(DEFAULT_ALLOWED_TAGS),
        attributes=_bleach_attr_filter,
        protocols=list(_URL_PROTOCOLS),
        strip=True,
        strip_comments=True,
    )
    if css_sanitizer is not None:
        base_cleaner_kwargs["css_sanitizer"] = css_sanitizer
    base_cleaner = Cleaner(**base_cleaner_kwargs)
    override_cache: dict[tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]], Cleaner] = {}

    def _sanitize(html: str, *, allow_tags=None, allow_attrs=None) -> str:
        if allow_tags is None and allow_attrs is None:
            return base_cleaner.clean(html)

        tags_raw, attrs_map_raw = _override_allowlist_raw(allow_tags=allow_tags, allow_attrs=allow_attrs)
        tags_list = list(tags_raw)
        attrs_map = dict(attrs_map_raw)

        key = None
        try:
            key = (
                tuple(sorted(tags_list)),
                tuple(sorted((t, tuple(sorted(a))) for (t, a) in attrs_map.items())),
            )
        except Exception:
            key = None

        cleaner = override_cache.get(key) if key is not None else None
        if cleaner is None:
            cleaner_kwargs = dict(base_cleaner_kwargs)
            cleaner_kwargs["tags"] = tags_list
            # Let bleach handle invalid config if present.
            cleaner_kwargs["attributes"] = {t: list(a) for (t, a) in attrs_map.items()}
            cleaner = Cleaner(**cleaner_kwargs)
            if key is not None:
                override_cache[key] = cleaner
        return cleaner.clean(html)

    return Sanitizer(
        name="bleach",
        description="bleach Cleaner shared allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # bleach is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "http_leak"},
    )


def _maybe_nh3() -> Sanitizer | None:
    try:
        import nh3  # type: ignore
    except Exception:
        return None

    def _is_pyo3_panic(exc: BaseException) -> bool:
        # nh3 is backed by Rust via pyo3; a Rust panic can surface as
        # pyo3_runtime.PanicException, which may not inherit from Exception.
        try:
            return exc.__class__.__name__ == "PanicException" and exc.__class__.__module__.startswith("pyo3_runtime")
        except Exception:
            return False

    # nh3 uses allowlisted attributes by tag, plus a global "*" entry.
    base_allowed_tags: set[str] = set(DEFAULT_ALLOWED_TAGS)
    base_allowed_attributes: dict[str, set[str]] = {
        "*": set(_GLOBAL_ATTRS),
        # NOTE: do not allow `rel` here.
        # nh3 (ammonia) manages link rel via the separate `link_rel=` setting and
        # will panic if `rel` is configured as an allowed attribute.
        "a": set(_A_ATTRS),
        "img": set(_IMG_ATTRS),
        "th": set(_TABLE_CELL_ATTRS),
        "td": set(_TABLE_CELL_ATTRS),
    }

    # nh3/ammonia has special handling for tags whose *content* should be
    # cleaned (notably <script> and <style>). ammonia panics if a tag appears in
    # both `clean_content_tags` and the main `tags` allowlist.
    base_clean_content_tags: set[str] = {"script", "style"}

    def _sanitize(html: str, *, allow_tags=None, allow_attrs=None) -> str:
        if allow_tags is None and allow_attrs is None:
            tags = base_allowed_tags
            attributes = base_allowed_attributes
        else:
            tags_raw, attrs_map_raw = _override_allowlist_raw(allow_tags=allow_tags, allow_attrs=allow_attrs)
            if any("rel" in s for s in attrs_map_raw.values()):
                raise SanitizerConfigUnsupported("nh3 cannot allow the 'rel' attribute (ammonia limitation)")
            tags = set(tags_raw)
            attributes = {t: set(a) for (t, a) in dict(attrs_map_raw).items()}

        clean_content_tags = set(base_clean_content_tags) - set(tags)

        # Keep the call signature conservative to avoid version-specific args.
        try:
            return nh3.clean(
                html,
                tags=tags,
                clean_content_tags=clean_content_tags,
                attributes=attributes,
                url_schemes=set(_URL_PROTOCOLS),
                link_rel=None,  # Disable automatic rel management.
                filter_style_properties=set(DEFAULT_ALLOWED_CSS_PROPERTIES),
            )
        except BaseException as exc:
            if _is_pyo3_panic(exc):
                raise RuntimeError(f"nh3 panic: {exc}") from None
            raise

    return Sanitizer(
        name="nh3",
        description="nh3 shared allowlist (keep common markup; strip dangerous)",
        sanitize=_sanitize,
        # nh3 is an HTML sanitizer; JS-string/JS-code and event-handler JS are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "http_leak"},
    )


def _maybe_lxml_html_clean() -> Sanitizer | None:
    try:
        from lxml_html_clean import Cleaner  # type: ignore
    except Exception:
        return None

    # Configure lxml-html-clean to match the shared allowlist policy.
    base_allowed_tags: set[str] = set(DEFAULT_ALLOWED_TAGS)

    # lxml-html-clean's attribute allowlist is global (not per-tag).
    base_safe_attrs: frozenset[str] = frozenset(
        set(_GLOBAL_ATTRS) | set(_A_ATTRS) | set(_IMG_ATTRS) | set(_TABLE_CELL_ATTRS)
    )

    base_cleaner = Cleaner(
        # XSS primitives
        scripts=True,
        javascript=True,
        comments=True,
        # Keep inline `style="..."` attributes (they are allowlisted by the shared policy).
        # Tags like <style> are still removed since they are not in allow_tags.
        style=False,
        processing_instructions=True,
        # Do not turn fragments into full documents / add <body> wrappers.
        page_structure=False,
        # Remove tags not in our allowlist (including svg/math).
        allow_tags=base_allowed_tags,
        # NOTE: lxml-html-clean forbids combining allow_tags + remove_unknown_tags.
        # allow_tags is sufficient for our purposes.
        remove_unknown_tags=False,
        safe_attrs_only=True,
        safe_attrs=base_safe_attrs,
        # Keep external-link behavior aligned with other sanitizers (no auto rel).
        add_nofollow=False,
    )

    override_cache: dict[tuple[tuple[str, ...], tuple[str, ...]], Cleaner] = {}

    def _sanitize(html: str, *, allow_tags=None, allow_attrs=None) -> str:
        if not html.strip():
            return ""

        if allow_tags is None and allow_attrs is None:
            cleaner = base_cleaner
        else:
            tags_raw, attrs_map_raw = _override_allowlist_raw(allow_tags=allow_tags, allow_attrs=allow_attrs)
            attrs_map = dict(attrs_map_raw)
            safe_attrs = set()
            for a in attrs_map.values():
                safe_attrs.update(a)
            key = (tuple(sorted(tags_raw)), tuple(sorted(safe_attrs)))
            cleaner = override_cache.get(key)
            if cleaner is None:
                cleaner = Cleaner(
                    scripts=True,
                    javascript=True,
                    comments=True,
                    style=False,
                    processing_instructions=True,
                    page_structure=False,
                    allow_tags=set(tags_raw),
                    remove_unknown_tags=False,
                    safe_attrs_only=True,
                    safe_attrs=frozenset(safe_attrs),
                    add_nofollow=False,
                )
                override_cache[key] = cleaner
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
        supported_contexts={"html", "html_head", "html_outer", "http_leak"},
    )


def _maybe_justhtml() -> Sanitizer | None:
    """Adapter for the `justhtml` project.

    Configure `justhtml`'s sanitizer to match the shared allowlist policy used by
    the other cleaners in this benchmark.
    """

    try:
        from justhtml import JustHTML  # type: ignore
        from justhtml.context import FragmentContext  # type: ignore
        from justhtml.sanitize import SanitizationPolicy, UrlPolicy, UrlRule  # type: ignore
    except Exception:
        return None

    fragment_context = FragmentContext("div")

    _URL_ATTRS: frozenset[str] = frozenset(
        {
            "href",
            "src",
            "srcset",
            "poster",
            "data",
            "codebase",
            "background",
            "manifest",
            "content",
            "action",
        }
    )

    def _make_policy(*, tags: AbstractSet[str], attrs: Mapping[str, AbstractSet[str]]) -> SanitizationPolicy:
        # Note: `justhtml` merges per-tag allowlists with the global "*" allowlist.
        allow_rules = {}
        for tag, attrset in attrs.items():
            if tag == "*":
                continue
            for attr in attrset:
                if attr not in _URL_ATTRS:
                    continue
                allow_rules[(tag, attr)] = UrlRule(
                    allow_fragment=True,
                    resolve_protocol_relative="https",
                    allowed_schemes=set(_URL_PROTOCOLS),
                    allowed_hosts=None,
                )

        return SanitizationPolicy(
            allowed_tags=set(tags),
            allowed_attributes={k: set(v) for (k, v) in attrs.items()},
            allowed_css_properties=set(DEFAULT_ALLOWED_CSS_PROPERTIES),
            url_policy=UrlPolicy(
                default_handling="allow",
                default_allow_relative=True,
                allow_rules=allow_rules,
            ),
        )

    base_policy = _make_policy(
        tags=set(DEFAULT_ALLOWED_TAGS),
        attrs={
            "*": set(_GLOBAL_ATTRS),
            "a": set(_A_ATTRS),
            "img": set(_IMG_ATTRS),
            "th": set(_TABLE_CELL_ATTRS),
            "td": set(_TABLE_CELL_ATTRS),
        },
    )

    policy_cache: dict[tuple[tuple[str, ...], tuple[tuple[str, tuple[str, ...]], ...]], SanitizationPolicy] = {}

    def _sanitize(html: str, *, allow_tags=None, allow_attrs=None) -> str:
        if not html:
            return ""

        if allow_tags is None and allow_attrs is None:
            policy = base_policy
        else:
            tags_raw, attrs_map_raw = _override_allowlist_raw(allow_tags=allow_tags, allow_attrs=allow_attrs)
            attrs_full: dict[str, AbstractSet[str]] = dict(attrs_map_raw)

            key = (
                tuple(sorted(tags_raw)),
                tuple(sorted((t, tuple(sorted(a))) for (t, a) in attrs_full.items() if t != "*")),
            )
            policy = policy_cache.get(key)
            if policy is None:
                policy = _make_policy(tags=set(tags_raw), attrs=attrs_full)
                policy_cache[key] = policy

        # Parse as a fragment to avoid adding document/body wrappers.
        doc = JustHTML(html, fragment=True, fragment_context=fragment_context)
        # Keep output stable for the harness/expected_tags checks.
        return doc.to_html(pretty=False, safe=True, policy=policy)

    return Sanitizer(
        name="justhtml",
        description="justhtml sanitizer configured to shared allowlist policy",
        sanitize=_sanitize,
        supported_contexts={"html", "html_head", "html_outer", "http_leak"},
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
                "http_leak",
                "js",
                "js_arg",
                "js_string",
                "js_string_double",
                "onerror_attr",
                "href",
            },
        ),
    }

    for maybe in (
        _maybe_bleach(),
        _maybe_nh3(),
        _maybe_lxml_html_clean(),
        _maybe_justhtml(),
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
        "justhtml",
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
