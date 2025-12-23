from __future__ import annotations

from dataclasses import dataclass
import re
import json
from pathlib import Path
import string
from typing import Callable, Iterable

from .harness import (
    BrowserName,
    BrowserHarness,
    PayloadContext,
    VectorResult,
    render_html_document,
    run_vector_in_browser,
)
from .sanitizers import Sanitizer


@dataclass(frozen=True, slots=True)
class Vector:
    id: str
    description: str
    payload_html: str
    payload_context: PayloadContext = "html"
    # Tags we expect to survive sanitization.
    # - None: no preservation expectation (backwards-compatible for old vector packs)
    # - (): explicitly expect NO tags to remain after sanitization
    # - ("a", "p", ...): expect these tags to remain after sanitization
    expected_tags: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class BenchCaseResult:
    sanitizer: str
    browser: str
    vector_id: str
    payload_context: PayloadContext
    run_payload_context: PayloadContext
    outcome: str  # 'pass' | 'xss' | 'lossy' | 'skip' | 'error'
    executed: bool
    details: str
    sanitizer_input_html: str
    sanitized_html: str
    rendered_html: str


@dataclass(frozen=True, slots=True)
class BenchSummary:
    total_cases: int
    total_executed: int
    total_errors: int
    total_lossy: int
    results: list[BenchCaseResult]


class _TagCollector:
    def __init__(self) -> None:
        from html.parser import HTMLParser

        class _P(HTMLParser):
            def __init__(self, outer: "_TagCollector") -> None:
                super().__init__(convert_charrefs=True)
                self._outer = outer

            def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
                self._outer.tags.add(tag.lower())

            def handle_startendtag(self, tag: str, attrs) -> None:  # type: ignore[override]
                self._outer.tags.add(tag.lower())

        self.tags: set[str] = set()
        self._parser = _P(self)

    def feed(self, html: str) -> set[str]:
        try:
            self._parser.feed(html)
            self._parser.close()
        except Exception:
            # Best-effort: if parsing fails, return what we saw.
            pass
        return self.tags


def _missing_expected_tags(*, expected_tags: Iterable[str], sanitized_html: str) -> list[str]:
    expected = {str(t).lower() for t in expected_tags if str(t).strip()}
    if not expected:
        return []

    tags = _TagCollector().feed(sanitized_html)
    missing = sorted(expected - tags)
    return missing


def _unexpected_tags_when_none_expected(*, sanitized_html: str) -> list[str]:
    tags = sorted(_TagCollector().feed(sanitized_html))
    return tags


def _normalize_expected_tag(tag: str) -> str:
    t = str(tag).strip().lower()
    if not t:
        raise ValueError("expected_tags entries must be non-empty")
    # Keep this intentionally permissive (HTML + SVG + MathML + custom elements).
    # Reject obvious garbage that would make the check meaningless.
    if any(ch.isspace() for ch in t) or "<" in t or ">" in t:
        raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    # Quick sanity: must start with a letter, and contain only reasonable name chars.
    if t[0] not in string.ascii_lowercase:
        raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    for ch in t:
        if ch not in (string.ascii_lowercase + string.digits + "-:"):
            raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    return t


def load_vectors(paths: Iterable[str | Path]) -> list[Vector]:
    vectors: list[Vector] = []

    allowed_contexts: set[str] = {
        "html",
        "html_head",
        "html_outer",
        "href",
        "js",
        "js_arg",
        "js_string",
        "js_string_double",
        "onerror_attr",
    }

    # Duplicate handling:
    # - Always error on duplicate (id, context).
    #
    # Note: payload deduplication is intentionally NOT done here. Do it once at
    # vector-pack compilation time (see `xssbench.compile`) so runtime loads are
    # transparent.
    seen_id_ctx: set[tuple[str, str]] = set()

    for raw_path in paths:
        path = Path(raw_path)
        data = json.loads(path.read_text(encoding="utf-8"))

        # Backwards-compatible schema:
        # - legacy: JSON list of vectors
        # - v1: JSON object with header metadata: {"schema": "xssbench.vectorfile.v1", "meta": {...}, "vectors": [...]}
        if isinstance(data, dict):
            if "vectors" not in data:
                raise ValueError(
                    f"Vector file object must contain a 'vectors' key: {path}"
                )

            data = data["vectors"]

        if not isinstance(data, list):
            raise ValueError(
                f"Vector file must contain a JSON list, or an object with 'vectors': {path}"
            )

        for item in data:
            if not isinstance(item, dict):
                raise ValueError(f"Vector items must be JSON objects: {path}")
            missing = {"id", "description", "payload_html"} - set(item.keys())
            if missing:
                raise ValueError(f"Vector missing keys {sorted(missing)}: {path}")

            raw_context = item.get("payload_context")
            expected_tags_key_present = "expected_tags" in item
            raw_expected_tags = item.get("expected_tags")
            if raw_context is None:
                contexts: list[str] = ["html"]
            elif isinstance(raw_context, str):
                contexts = [raw_context]
            elif isinstance(raw_context, list):
                if not raw_context:
                    raise ValueError(f"payload_context list must be non-empty: {path}")
                if not all(isinstance(x, str) for x in raw_context):
                    raise ValueError(f"payload_context list must contain only strings: {path}")
                contexts = list(raw_context)
            else:
                raise ValueError(
                    f"payload_context must be a string or list of strings (got {type(raw_context)!r}): {path}"
                )

            for payload_context in contexts:
                payload_context = str(payload_context)
                if payload_context not in allowed_contexts:
                    raise ValueError(
                        f"Invalid payload_context {payload_context!r} in {path}. "
                        f"Allowed: {sorted(allowed_contexts)}"
                    )

                vector_id = str(item["id"])
                id_key = (vector_id, payload_context)
                if id_key in seen_id_ctx:
                    raise ValueError(f"Duplicate vector id+context: {vector_id}@{payload_context}")
                seen_id_ctx.add(id_key)

                payload_html = str(item["payload_html"])

                expected_tags: tuple[str, ...] | None
                if not expected_tags_key_present:
                    expected_tags = None
                elif raw_expected_tags is None:
                    raise ValueError(f"expected_tags must be a list of strings (got null): {path}")
                elif isinstance(raw_expected_tags, list):
                    if not all(isinstance(x, str) for x in raw_expected_tags):
                        raise ValueError(f"expected_tags must contain only strings: {path}")
                    normalized = [_normalize_expected_tag(x) for x in raw_expected_tags]
                    # preserve order but de-dup
                    seen: set[str] = set()
                    deduped: list[str] = []
                    for t in normalized:
                        if t not in seen:
                            seen.add(t)
                            deduped.append(t)
                    expected_tags = tuple(deduped)
                else:
                    raise ValueError(
                        f"expected_tags must be a list of strings (got {type(raw_expected_tags)!r}): {path}"
                    )

                vectors.append(
                    Vector(
                        id=vector_id,
                        description=str(item["description"]),
                        payload_html=payload_html,
                        payload_context=payload_context,  # type: ignore[arg-type]
                        expected_tags=expected_tags,
                    )
                )

    return vectors


Runner = Callable[..., VectorResult]


Progress = Callable[[int, int, BenchCaseResult], None]


def run_bench(
    *,
    vectors: list[Vector],
    sanitizers: list[Sanitizer],
    browsers: list[BrowserName] | None = None,
    timeout_ms: int | None = None,
    runner: Runner = run_vector_in_browser,
    progress: Progress | None = None,
    fail_fast: bool = False,
) -> BenchSummary:
    def _prepare_for_sanitizer(
        *, vector: Vector, sanitizer: Sanitizer
    ) -> tuple[str, str, PayloadContext]:
        # Our vector files include contexts like `href` where the payload is not
        # an HTML fragment by itself (it's an attribute value). HTML sanitizers
        # such as nh3/bleach generally expect to see the attribute in context.
        #
        # For these, we wrap the payload in minimal HTML before sanitizing, and
        # then run the sanitized HTML in normal `html` context.
        if vector.payload_context == "href":
            sanitizer_input_html = f'<a href="{vector.payload_html}">x</a>'
            return sanitizer_input_html, sanitizer.sanitize(sanitizer_input_html), "html"

        if vector.payload_context == "onerror_attr":
            sanitizer_input_html = (
                f'<img src="nonexistent://x" onerror="{vector.payload_html}">'
            )
            return sanitizer_input_html, sanitizer.sanitize(sanitizer_input_html), "html"

        sanitizer_input_html = vector.payload_html
        return sanitizer_input_html, sanitizer.sanitize(sanitizer_input_html), vector.payload_context
    def _auto_timeout_ms(*, payload_html: str, sanitized_html: str) -> int:
        # Conservative-but-fast heuristics. Most vectors are synchronous; only a
        # handful need longer to execute.
        blob = (payload_html + "\n" + sanitized_html).lower()

        # Explicit async patterns.
        if any(
            token in blob
            for token in (
                "settimeout",
                "setinterval",
                "requestanimationframe",
                "promiseresolve",
                "new promise",
                "async ",
                "await ",
            )
        ):
            return 250

        # Navigation/refresh-ish.
        if "http-equiv" in blob and "refresh" in blob:
            return 400

        # Common event-based vectors (we synthesize events, but give the engine a beat).
        if re.search(r"\bon(load|error)\s*=", blob):
            return 25

        # Default: don't wait. Sync execution is detected via the harness hook.
        return 0

    def _timeout_for_case(*, payload_html: str, sanitized_html: str) -> int:
        return timeout_ms if timeout_ms is not None else _auto_timeout_ms(
            payload_html=payload_html, sanitized_html=sanitized_html
        )

    results: list[BenchCaseResult] = []

    if browsers is None:
        browsers = ["chromium"]

    total_planned = len(sanitizers) * len(browsers) * len(vectors)
    case_index = 0

    # Optimized path: reuse one browser/page per engine.
    if runner is run_vector_in_browser:
        for browser in browsers:
            with BrowserHarness(browser=browser, headless=True) as harness:
                for sanitizer in sanitizers:
                    for vector in vectors:
                        if (
                            sanitizer.supported_contexts is not None
                            and vector.payload_context not in sanitizer.supported_contexts
                        ):
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=vector.payload_context,
                                outcome="skip",
                                executed=False,
                                details=(
                                    f"Skipped: {sanitizer.name} does not support context {vector.payload_context}"
                                ),
                                sanitizer_input_html="",
                                sanitized_html="",
                                rendered_html="",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue
                        try:
                            sanitizer_input_html, sanitized_html, payload_context_to_run = _prepare_for_sanitizer(
                                vector=vector, sanitizer=sanitizer
                            )
                        except Exception as exc:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=vector.payload_context,
                                outcome="error",
                                executed=False,
                                details=f"Sanitizer error: {exc!r}",
                                sanitizer_input_html="",
                                sanitized_html="",
                                rendered_html="",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue

                        if vector.expected_tags is not None:
                            if len(vector.expected_tags) == 0:
                                unexpected = _unexpected_tags_when_none_expected(
                                    sanitized_html=sanitized_html
                                )
                                if unexpected:
                                    result = BenchCaseResult(
                                        sanitizer=sanitizer.name,
                                        browser=browser,
                                        vector_id=vector.id,
                                        payload_context=vector.payload_context,
                                        run_payload_context=payload_context_to_run,
                                        outcome="lossy",
                                        executed=False,
                                        details=(
                                            "Expected no tags after sanitization, but found: "
                                            + ", ".join(unexpected[:20])
                                        ),
                                        sanitizer_input_html=sanitizer_input_html,
                                        sanitized_html=sanitized_html,
                                        rendered_html="",
                                    )
                                    results.append(result)
                                    case_index += 1
                                    if progress is not None:
                                        progress(case_index, total_planned, result)
                                    continue
                            else:
                                missing_tags = _missing_expected_tags(
                                    expected_tags=vector.expected_tags,
                                    sanitized_html=sanitized_html,
                                )
                                if missing_tags:
                                    result = BenchCaseResult(
                                        sanitizer=sanitizer.name,
                                        browser=browser,
                                        vector_id=vector.id,
                                        payload_context=vector.payload_context,
                                        run_payload_context=payload_context_to_run,
                                        outcome="lossy",
                                        executed=False,
                                        details=(
                                            "Missing expected tags after sanitization: "
                                            + ", ".join(missing_tags)
                                        ),
                                        sanitizer_input_html=sanitizer_input_html,
                                        sanitized_html=sanitized_html,
                                        rendered_html="",
                                    )
                                    results.append(result)
                                    case_index += 1
                                    if progress is not None:
                                        progress(case_index, total_planned, result)
                                    continue

                        try:
                            rendered_html = render_html_document(
                                sanitized_html=sanitized_html,
                                payload_context=payload_context_to_run,
                            )
                            per_case_timeout_ms = _timeout_for_case(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html,
                            )
                            vector_result = harness.run(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html,
                                payload_context=payload_context_to_run,
                                timeout_ms=per_case_timeout_ms,
                            )
                        except Exception as exc:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=payload_context_to_run,
                                outcome="error",
                                executed=False,
                                details=f"Harness error: {exc}",
                                sanitizer_input_html=sanitizer_input_html,
                                sanitized_html=sanitized_html,
                                rendered_html=rendered_html if "rendered_html" in locals() else "",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue

                        outcome = "xss" if vector_result.executed else "pass"
                        result = BenchCaseResult(
                            sanitizer=sanitizer.name,
                            browser=browser,
                            vector_id=vector.id,
                            payload_context=vector.payload_context,
                            run_payload_context=payload_context_to_run,
                            outcome=outcome,
                            executed=vector_result.executed,
                            details=vector_result.details,
                            sanitizer_input_html=sanitizer_input_html,
                            sanitized_html=sanitized_html,
                            rendered_html=rendered_html,
                        )
                        results.append(result)
                        case_index += 1
                        if progress is not None:
                            progress(case_index, total_planned, result)
                        if fail_fast and result.outcome == "xss":
                            total_cases = len(results)
                            total_executed = sum(1 for r in results if r.executed)
                            total_errors = sum(1 for r in results if r.outcome == "error")
                            total_lossy = sum(1 for r in results if r.outcome == "lossy")
                            return BenchSummary(
                                total_cases=total_cases,
                                total_executed=total_executed,
                                total_errors=total_errors,
                                total_lossy=total_lossy,
                                results=results,
                            )

        total_cases = len(results)
        total_executed = sum(1 for r in results if r.executed)
        total_errors = sum(1 for r in results if r.outcome == "error")
        total_lossy = sum(1 for r in results if r.outcome == "lossy")

        return BenchSummary(
            total_cases=total_cases,
            total_executed=total_executed,
            total_errors=total_errors,
            total_lossy=total_lossy,
            results=results,
        )

    for sanitizer in sanitizers:
        for browser in browsers:
            for vector in vectors:
                try:
                    if (
                        sanitizer.supported_contexts is not None
                        and vector.payload_context not in sanitizer.supported_contexts
                    ):
                        result = BenchCaseResult(
                            sanitizer=sanitizer.name,
                            browser=browser,
                            vector_id=vector.id,
                            payload_context=vector.payload_context,
                            run_payload_context=vector.payload_context,
                            outcome="skip",
                            executed=False,
                            details=(
                                f"Skipped: {sanitizer.name} does not support context {vector.payload_context}"
                            ),
                            sanitizer_input_html="",
                            sanitized_html="",
                            rendered_html="",
                        )
                        results.append(result)
                        case_index += 1
                        if progress is not None:
                            progress(case_index, total_planned, result)
                        continue
                    sanitizer_input_html, sanitized_html, payload_context_to_run = _prepare_for_sanitizer(
                        vector=vector, sanitizer=sanitizer
                    )
                except Exception as exc:
                    result = BenchCaseResult(
                        sanitizer=sanitizer.name,
                        browser=browser,
                        vector_id=vector.id,
                        payload_context=vector.payload_context,
                        run_payload_context=vector.payload_context,
                        outcome="error",
                        executed=False,
                        details=f"Sanitizer error: {exc!r}",
                        sanitizer_input_html="",
                        sanitized_html="",
                        rendered_html="",
                    )
                    results.append(result)
                    case_index += 1
                    if progress is not None:
                        progress(case_index, total_planned, result)
                    continue

                if vector.expected_tags is not None:
                    if len(vector.expected_tags) == 0:
                        unexpected = _unexpected_tags_when_none_expected(
                            sanitized_html=sanitized_html
                        )
                        if unexpected:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=payload_context_to_run,
                                outcome="lossy",
                                executed=False,
                                details=(
                                    "Expected no tags after sanitization, but found: "
                                    + ", ".join(unexpected[:20])
                                ),
                                sanitizer_input_html=sanitizer_input_html,
                                sanitized_html=sanitized_html,
                                rendered_html="",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue
                    else:
                        missing_tags = _missing_expected_tags(
                            expected_tags=vector.expected_tags,
                            sanitized_html=sanitized_html,
                        )
                        if missing_tags:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=payload_context_to_run,
                                outcome="lossy",
                                executed=False,
                                details=(
                                    "Missing expected tags after sanitization: "
                                    + ", ".join(missing_tags)
                                ),
                                sanitizer_input_html=sanitizer_input_html,
                                sanitized_html=sanitized_html,
                                rendered_html="",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue

                try:
                    rendered_html = render_html_document(
                        sanitized_html=sanitized_html,
                        payload_context=payload_context_to_run,
                    )
                    per_case_timeout_ms = _timeout_for_case(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html,
                    )
                    vector_result = runner(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html,
                        payload_context=payload_context_to_run,
                        browser=browser,
                        timeout_ms=per_case_timeout_ms,
                    )
                except Exception as exc:
                    result = BenchCaseResult(
                        sanitizer=sanitizer.name,
                        browser=browser,
                        vector_id=vector.id,
                        payload_context=vector.payload_context,
                        run_payload_context=payload_context_to_run,
                        outcome="error",
                        executed=False,
                        details=f"Harness error: {exc}",
                        sanitizer_input_html=sanitizer_input_html,
                        sanitized_html=sanitized_html,
                        rendered_html=rendered_html if "rendered_html" in locals() else "",
                    )
                    results.append(result)
                    case_index += 1
                    if progress is not None:
                        progress(case_index, total_planned, result)
                    continue

                outcome = "xss" if vector_result.executed else "pass"

                result = BenchCaseResult(
                    sanitizer=sanitizer.name,
                    browser=browser,
                    vector_id=vector.id,
                    payload_context=vector.payload_context,
                    run_payload_context=payload_context_to_run,
                    outcome=outcome,
                    executed=vector_result.executed,
                    details=vector_result.details,
                    sanitizer_input_html=sanitizer_input_html,
                    sanitized_html=sanitized_html,
                    rendered_html=rendered_html,
                )
                results.append(result)
                case_index += 1
                if progress is not None:
                    progress(case_index, total_planned, result)
                if fail_fast and result.outcome == "xss":
                    total_cases = len(results)
                    total_executed = sum(1 for r in results if r.executed)
                    total_errors = sum(1 for r in results if r.outcome == "error")
                    total_lossy = sum(1 for r in results if r.outcome == "lossy")
                    return BenchSummary(
                        total_cases=total_cases,
                        total_executed=total_executed,
                        total_errors=total_errors,
                        total_lossy=total_lossy,
                        results=results,
                    )

    total_cases = len(results)
    total_executed = sum(1 for r in results if r.executed)
    total_errors = sum(1 for r in results if r.outcome == "error")
    total_lossy = sum(1 for r in results if r.outcome == "lossy")

    return BenchSummary(
        total_cases=total_cases,
        total_executed=total_executed,
        total_errors=total_errors,
        total_lossy=total_lossy,
        results=results,
    )
