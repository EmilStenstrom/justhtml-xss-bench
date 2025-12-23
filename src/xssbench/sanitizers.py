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

    def _sanitize(html: str) -> str:
        # Keep this intentionally conservative/vanilla: users can fork/tune.
        return bleach.clean(html)

    return Sanitizer(
        name="bleach",
        description="bleach.clean(html) with default settings",
        sanitize=_sanitize,
        # bleach is an HTML sanitizer; JS-string and JS-code contexts are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "href", "onerror_attr"},
    )


def _maybe_nh3() -> Sanitizer | None:
    try:
        import nh3  # type: ignore
    except Exception:
        return None

    def _sanitize(html: str) -> str:
        return nh3.clean(html)

    return Sanitizer(
        name="nh3",
        description="nh3.clean(html) with default settings",
        sanitize=_sanitize,
        # nh3 is an HTML sanitizer; JS-string and JS-code contexts are out of scope.
        supported_contexts={"html", "html_head", "html_outer", "href", "onerror_attr"},
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

    for maybe in (_maybe_bleach(), _maybe_nh3()):
        if maybe is not None:
            sanitizers[maybe.name] = maybe

    return sanitizers


def get_sanitizer(name: str) -> Sanitizer:
    sanitizers = available_sanitizers()
    try:
        return sanitizers[name]
    except KeyError as exc:
        available = ", ".join(sorted(sanitizers.keys()))
        raise KeyError(f"Unknown sanitizer {name!r}. Available: {available}") from exc
