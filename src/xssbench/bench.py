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
from .sanitizers import allowed_attributes_for_tag


@dataclass(frozen=True, slots=True)
class ExpectedTag:
    tag: str
    attrs: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Vector:
    id: str
    description: str
    payload_html: str
    payload_context: PayloadContext = "html"
    # Tags/attributes we expect to survive sanitization.
    # - (): explicitly expect NO tags to remain after sanitization
    # - (ExpectedTag("a", {"href"}), ...): expect tag+attrs to remain
    expected_tags: tuple[ExpectedTag, ...] = ()


@dataclass(frozen=True, slots=True)
class BenchCaseResult:
    sanitizer: str
    browser: str
    vector_id: str
    payload_context: PayloadContext
    run_payload_context: PayloadContext
    outcome: str  # 'pass' | 'xss' | 'external' | 'skip' | 'error'
    executed: bool
    lossy: bool
    lossy_details: str
    details: str
    sanitizer_input_html: str
    sanitized_html: str
    rendered_html: str


@dataclass(frozen=True, slots=True)
class BenchSummary:
    total_cases: int
    total_executed: int
    total_external: int
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
                t = tag.lower()
                self._outer.tags.add(t)
                if attrs is not None:
                    s = set()
                    for name, _value in attrs:
                        if name:
                            s.add(str(name).lower())
                    self._outer.attr_sets_by_tag.setdefault(t, []).append(s)
                    self._outer.elements.append((t, s))
                else:
                    self._outer.elements.append((t, set()))

            def handle_startendtag(self, tag: str, attrs) -> None:  # type: ignore[override]
                t = tag.lower()
                self._outer.tags.add(t)
                if attrs is not None:
                    s = set()
                    for name, _value in attrs:
                        if name:
                            s.add(str(name).lower())
                    self._outer.attr_sets_by_tag.setdefault(t, []).append(s)
                    self._outer.elements.append((t, s))
                else:
                    self._outer.elements.append((t, set()))

        self.tags: set[str] = set()
        self.attr_sets_by_tag: dict[str, list[set[str]]] = {}
        self.elements: list[tuple[str, set[str]]] = []
        self._parser = _P(self)

    def feed(self, html: str) -> set[str]:
        try:
            self._parser.feed(html)
            self._parser.close()
        except Exception:
            # Best-effort: if parsing fails, return what we saw.
            pass
        return self.tags


_EXPECTED_TAG_WITH_ATTRS_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9:-]*)\[(.*)\]\s*$")
_EXPECTED_TAG_ONLY_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9:-]*)\s*$")


def _normalize_expected_tag_name(tag: str) -> str:
    t = str(tag).strip().lower()
    if not t:
        raise ValueError("expected_tags entries must have a tag name")
    if any(ch.isspace() for ch in t) or "<" in t or ">" in t:
        raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    if t[0] not in string.ascii_lowercase:
        raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    for ch in t:
        if ch not in (string.ascii_lowercase + string.digits + "-:"):
            raise ValueError(f"Invalid tag name in expected_tags: {tag!r}")
    return t


def _normalize_expected_attr_name(attr: str) -> str:
    a = str(attr).strip().lower()
    if not a:
        raise ValueError("expected_tags attribute names must be non-empty")
    if any(ch.isspace() for ch in a) or "<" in a or ">" in a:
        raise ValueError(f"Invalid attribute name in expected_tags: {attr!r}")
    if a[0] not in string.ascii_lowercase:
        raise ValueError(f"Invalid attribute name in expected_tags: {attr!r}")
    for ch in a:
        if ch not in (string.ascii_lowercase + string.digits + "-_:"):
            raise ValueError(f"Invalid attribute name in expected_tags: {attr!r}")
    return a


def _parse_expected_tag_spec(spec: str) -> ExpectedTag:
    raw = str(spec)
    m = _EXPECTED_TAG_WITH_ATTRS_RE.match(raw)
    if m:
        tag_name = _normalize_expected_tag_name(m.group(1))
        attrs_raw = m.group(2).strip()
        if attrs_raw == "":
            raise ValueError(f"expected_tags entry {spec!r} must not use empty brackets; use {tag_name!r} instead")
    else:
        m2 = _EXPECTED_TAG_ONLY_RE.match(raw)
        if not m2:
            raise ValueError(
                "expected_tags entries must use the form tag or tag[attrs], e.g. 'p', 'p[class]' or 'a[href, style]'"
            )
        tag_name = _normalize_expected_tag_name(m2.group(1))
        attrs_raw = ""

    if not attrs_raw:
        return ExpectedTag(tag=tag_name, attrs=frozenset())

    parts = [p.strip() for p in attrs_raw.split(",")]
    if any(p == "" for p in parts):
        raise ValueError(f"Invalid expected_tags attribute list: {spec!r}")
    attrs = {_normalize_expected_attr_name(p) for p in parts}

    allowed = allowed_attributes_for_tag(tag_name)
    illegal = sorted(a for a in attrs if a not in allowed)
    if illegal:
        raise ValueError(f"Attributes not allowed by the shared sanitization policy for <{tag_name}>: {illegal}")
    return ExpectedTag(tag=tag_name, attrs=frozenset(attrs))


def _expected_tags_allowed_for_context(payload_context: PayloadContext) -> bool:
    # expected_tags is a notion for HTML-fragment sanitization.
    # It is explicitly forbidden for href and all js* contexts.
    if payload_context == "href":
        return False
    if payload_context.startswith("js"):
        return False
    return True


def _missing_expected_tags(*, expected_tags: Iterable[ExpectedTag], sanitized_html: str) -> list[str]:
    expected_list = list(expected_tags)
    if not expected_list:
        return []

    collector = _TagCollector()
    collector.feed(sanitized_html)
    elements = collector.elements

    def _fmt(exp: ExpectedTag) -> str:
        if exp.attrs:
            return f"{exp.tag}[{', '.join(sorted(exp.attrs))}]"
        return exp.tag

    def _fmt_el(tag: str, attrs: set[str]) -> str:
        if attrs:
            return f"{tag}[{', '.join(sorted(attrs))}]"
        return tag

    def _matches(exp: ExpectedTag, tag: str, attrs: set[str]) -> bool:
        if tag != exp.tag:
            return False
        if exp.attrs:
            return all(a in attrs for a in exp.attrs)
        # Bare tag means: must be attribute-free.
        return len(attrs) == 0

    # Exact mode (default): the sanitized output must contain exactly the
    # expected tags, in that order (no extras, and no skipping/re-using).
    mismatches: list[str] = []
    common = min(len(expected_list), len(elements))
    for idx in range(common):
        exp = expected_list[idx]
        tag, attrs = elements[idx]
        if not _matches(exp, tag, attrs):
            mismatches.append(f"pos {idx + 1}: expected {_fmt(exp)} got {_fmt_el(tag, attrs)}")

    if len(expected_list) > len(elements):
        for idx in range(common, len(expected_list)):
            mismatches.append(f"pos {idx + 1}: missing {_fmt(expected_list[idx])}")
    elif len(elements) > len(expected_list):
        for idx in range(common, len(elements)):
            tag, attrs = elements[idx]
            mismatches.append(f"pos {idx + 1}: unexpected {_fmt_el(tag, attrs)}")

    return mismatches


def _unexpected_tags_when_none_expected(*, sanitized_html: str) -> list[str]:
    tags = sorted(_TagCollector().feed(sanitized_html))
    return tags


def _normalize_expected_tag(tag: str) -> str:
    # Backwards-compatible helper name kept for internal imports/tests, but now
    # it validates tag / tag[attrs] syntax and returns a normalized string.
    parsed = _parse_expected_tag_spec(tag)
    if not parsed.attrs:
        return parsed.tag
    return f"{parsed.tag}[{', '.join(sorted(parsed.attrs))}]"


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
    # Note: payload deduplication is intentionally NOT done here.
    seen_id_ctx: set[tuple[str, str]] = set()

    for raw_path in paths:
        path = Path(raw_path)
        data = json.loads(path.read_text(encoding="utf-8"))

        # Vector file schema (strict):
        # {"schema": "xssbench.vectorfile.v1", "meta": {...}, "vectors": [...]}
        if not isinstance(data, dict):
            raise ValueError(
                f"Vector file must be a v1 object with schema 'xssbench.vectorfile.v1' (got {type(data)!r}): {path}"
            )

        schema = data.get("schema")
        if schema != "xssbench.vectorfile.v1":
            raise ValueError(f"Vector file schema must be 'xssbench.vectorfile.v1' (got {schema!r}): {path}")

        if "vectors" not in data:
            raise ValueError(f"Vector file object must contain a 'vectors' key: {path}")

        data = data["vectors"]

        if not isinstance(data, list):
            raise ValueError(f"Vector file 'vectors' must be a JSON list: {path}")

        for item in data:
            if not isinstance(item, dict):
                raise ValueError(f"Vector items must be JSON objects: {path}")
            missing = {"id", "description", "payload_html"} - set(item.keys())
            if missing:
                raise ValueError(f"Vector missing keys {sorted(missing)}: {path}")

            raw_context = item.get("payload_context")
            raw_expected_tags = item.get("expected_tags")

            if "expected_tags_ordered" in item:
                raise ValueError(
                    f"expected_tags_ordered is no longer supported; expected_tags are always ordered: {path}"
                )
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
                        f"Invalid payload_context {payload_context!r} in {path}. Allowed: {sorted(allowed_contexts)}"
                    )

                vector_id = str(item["id"])
                id_key = (vector_id, payload_context)
                if id_key in seen_id_ctx:
                    raise ValueError(f"Duplicate vector id+context: {vector_id}@{payload_context}")
                seen_id_ctx.add(id_key)

                payload_html = str(item["payload_html"])

                expected_tags: tuple[ExpectedTag, ...] = ()
                if _expected_tags_allowed_for_context(payload_context):
                    if raw_expected_tags is None:
                        raise ValueError(f"expected_tags is required for payload_context {payload_context!r}: {path}")
                    if not isinstance(raw_expected_tags, list):
                        raise ValueError(
                            f"expected_tags must be a list of strings (got {type(raw_expected_tags)!r}): {path}"
                        )
                    if not all(isinstance(x, str) for x in raw_expected_tags):
                        raise ValueError(f"expected_tags must contain only strings: {path}")

                    if len(raw_expected_tags) == 0:
                        expected_tags = ()
                    else:
                        expected_tags = tuple(_parse_expected_tag_spec(x) for x in raw_expected_tags)
                else:
                    if "expected_tags" in item:
                        raise ValueError(
                            f"expected_tags is not allowed for payload_context {payload_context!r}: {path}"
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
    def _prepare_for_sanitizer(*, vector: Vector, sanitizer: Sanitizer) -> tuple[str, str, PayloadContext, str]:
        if vector.payload_context == "onerror_attr":
            sanitizer_input_html = f'<img src="nonexistent://x" onerror="{vector.payload_html}">'
            sanitized_html = sanitizer.sanitize(sanitizer_input_html)
            return sanitizer_input_html, sanitized_html, "html", sanitized_html

        sanitizer_input_html = vector.payload_html
        sanitized_html = sanitizer.sanitize(sanitizer_input_html)
        return (
            sanitizer_input_html,
            sanitized_html,
            vector.payload_context,
            sanitized_html,
        )

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
        return (
            timeout_ms
            if timeout_ms is not None
            else _auto_timeout_ms(payload_html=payload_html, sanitized_html=sanitized_html)
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
                        if vector.payload_context == "href" and (
                            sanitizer.supported_contexts is None or "href" not in sanitizer.supported_contexts
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
                                    f"Skipped: {sanitizer.name} does not declare href attribute cleaning support"
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
                                lossy=False,
                                lossy_details="",
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
                            (
                                sanitizer_input_html,
                                sanitized_html,
                                payload_context_to_run,
                                sanitized_html_to_run,
                            ) = _prepare_for_sanitizer(vector=vector, sanitizer=sanitizer)
                        except Exception as exc:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                run_payload_context=vector.payload_context,
                                outcome="error",
                                executed=False,
                                lossy=False,
                                lossy_details="",
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

                        lossy = False
                        lossy_details = ""
                        if _expected_tags_allowed_for_context(vector.payload_context):
                            if len(vector.expected_tags) == 0:
                                unexpected = _unexpected_tags_when_none_expected(sanitized_html=sanitized_html)
                                if unexpected:
                                    lossy = True
                                    lossy_details = "Expected no tags after sanitization, but found: " + ", ".join(
                                        unexpected[:20]
                                    )
                            else:
                                missing_tags = _missing_expected_tags(
                                    expected_tags=vector.expected_tags,
                                    sanitized_html=sanitized_html,
                                )
                                if missing_tags:
                                    lossy = True
                                    lossy_details = "Missing expected tags after sanitization: " + ", ".join(
                                        missing_tags
                                    )

                        try:
                            rendered_html = render_html_document(
                                sanitized_html=sanitized_html_to_run,
                                payload_context=payload_context_to_run,
                            )
                            per_case_timeout_ms = _timeout_for_case(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html,
                            )
                            vector_result = harness.run(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html_to_run,
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
                                lossy=lossy,
                                lossy_details=lossy_details,
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

                        signal = str(getattr(vector_result, "signal", "") or "")
                        if signal == "external":
                            outcome = "external"
                            executed = False
                        else:
                            outcome = "xss" if vector_result.executed else "pass"
                            executed = bool(vector_result.executed)
                        result = BenchCaseResult(
                            sanitizer=sanitizer.name,
                            browser=browser,
                            vector_id=vector.id,
                            payload_context=vector.payload_context,
                            run_payload_context=payload_context_to_run,
                            outcome=outcome,
                            executed=executed,
                            lossy=lossy,
                            lossy_details=lossy_details,
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
                            total_external = sum(1 for r in results if r.outcome == "external")
                            total_errors = sum(1 for r in results if r.outcome == "error")
                            total_lossy = sum(1 for r in results if r.lossy)
                            return BenchSummary(
                                total_cases=total_cases,
                                total_executed=total_executed,
                                total_external=total_external,
                                total_errors=total_errors,
                                total_lossy=total_lossy,
                                results=results,
                            )

        total_cases = len(results)
        total_executed = sum(1 for r in results if r.executed)
        total_external = sum(1 for r in results if r.outcome == "external")
        total_errors = sum(1 for r in results if r.outcome == "error")
        total_lossy = sum(1 for r in results if r.lossy)

        return BenchSummary(
            total_cases=total_cases,
            total_executed=total_executed,
            total_external=total_external,
            total_errors=total_errors,
            total_lossy=total_lossy,
            results=results,
        )

    for sanitizer in sanitizers:
        for browser in browsers:
            for vector in vectors:
                try:
                    if vector.payload_context == "href" and (
                        sanitizer.supported_contexts is None or "href" not in sanitizer.supported_contexts
                    ):
                        result = BenchCaseResult(
                            sanitizer=sanitizer.name,
                            browser=browser,
                            vector_id=vector.id,
                            payload_context=vector.payload_context,
                            run_payload_context=vector.payload_context,
                            outcome="skip",
                            executed=False,
                            lossy=False,
                            lossy_details="",
                            details=(f"Skipped: {sanitizer.name} does not declare href attribute cleaning support"),
                            sanitizer_input_html="",
                            sanitized_html="",
                            rendered_html="",
                        )
                        results.append(result)
                        case_index += 1
                        if progress is not None:
                            progress(case_index, total_planned, result)
                        continue
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
                            lossy=False,
                            lossy_details="",
                            details=(f"Skipped: {sanitizer.name} does not support context {vector.payload_context}"),
                            sanitizer_input_html="",
                            sanitized_html="",
                            rendered_html="",
                        )
                        results.append(result)
                        case_index += 1
                        if progress is not None:
                            progress(case_index, total_planned, result)
                        continue
                    (
                        sanitizer_input_html,
                        sanitized_html,
                        payload_context_to_run,
                        sanitized_html_to_run,
                    ) = _prepare_for_sanitizer(vector=vector, sanitizer=sanitizer)
                except Exception as exc:
                    result = BenchCaseResult(
                        sanitizer=sanitizer.name,
                        browser=browser,
                        vector_id=vector.id,
                        payload_context=vector.payload_context,
                        run_payload_context=vector.payload_context,
                        outcome="error",
                        executed=False,
                        lossy=False,
                        lossy_details="",
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

                lossy = False
                lossy_details = ""
                if _expected_tags_allowed_for_context(vector.payload_context):
                    if len(vector.expected_tags) == 0:
                        unexpected = _unexpected_tags_when_none_expected(sanitized_html=sanitized_html)
                        if unexpected:
                            lossy = True
                            lossy_details = "Expected no tags after sanitization, but found: " + ", ".join(
                                unexpected[:20]
                            )
                    else:
                        missing_tags = _missing_expected_tags(
                            expected_tags=vector.expected_tags,
                            sanitized_html=sanitized_html,
                        )
                        if missing_tags:
                            lossy = True
                            lossy_details = "Missing expected tags after sanitization: " + ", ".join(missing_tags)

                try:
                    rendered_html = render_html_document(
                        sanitized_html=sanitized_html_to_run,
                        payload_context=payload_context_to_run,
                    )
                    per_case_timeout_ms = _timeout_for_case(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html,
                    )
                    vector_result = runner(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html_to_run,
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
                        lossy=lossy,
                        lossy_details=lossy_details,
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

                signal = str(getattr(vector_result, "signal", "") or "")
                if signal == "external":
                    outcome = "external"
                    executed = False
                else:
                    outcome = "xss" if vector_result.executed else "pass"
                    executed = bool(vector_result.executed)

                result = BenchCaseResult(
                    sanitizer=sanitizer.name,
                    browser=browser,
                    vector_id=vector.id,
                    payload_context=vector.payload_context,
                    run_payload_context=payload_context_to_run,
                    outcome=outcome,
                    executed=executed,
                    lossy=lossy,
                    lossy_details=lossy_details,
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
                    total_external = sum(1 for r in results if r.outcome == "external")
                    total_errors = sum(1 for r in results if r.outcome == "error")
                    total_lossy = sum(1 for r in results if r.lossy)
                    return BenchSummary(
                        total_cases=total_cases,
                        total_executed=total_executed,
                        total_external=total_external,
                        total_errors=total_errors,
                        total_lossy=total_lossy,
                        results=results,
                    )

    total_cases = len(results)
    total_executed = sum(1 for r in results if r.executed)
    total_external = sum(1 for r in results if r.outcome == "external")
    total_errors = sum(1 for r in results if r.outcome == "error")
    total_lossy = sum(1 for r in results if r.lossy)

    return BenchSummary(
        total_cases=total_cases,
        total_executed=total_executed,
        total_external=total_external,
        total_errors=total_errors,
        total_lossy=total_lossy,
        results=results,
    )
