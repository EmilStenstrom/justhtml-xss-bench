from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Callable, Iterable

from .harness import (
    BrowserName,
    BrowserHarness,
    PayloadContext,
    VectorResult,
    run_vector_in_browser,
)
from .sanitizers import Sanitizer


@dataclass(frozen=True, slots=True)
class Vector:
    id: str
    description: str
    payload_html: str
    payload_context: PayloadContext = "html"


@dataclass(frozen=True, slots=True)
class BenchCaseResult:
    sanitizer: str
    browser: str
    vector_id: str
    payload_context: PayloadContext
    outcome: str  # 'pass' | 'xss' | 'error'
    executed: bool
    details: str
    sanitized_html: str


@dataclass(frozen=True, slots=True)
class BenchSummary:
    total_cases: int
    total_executed: int
    total_errors: int
    results: list[BenchCaseResult]


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

                vectors.append(
                    Vector(
                        id=vector_id,
                        description=str(item["description"]),
                        payload_html=payload_html,
                        payload_context=payload_context,  # type: ignore[arg-type]
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
                        try:
                            sanitized_html = sanitizer.sanitize(vector.payload_html)
                        except Exception as exc:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                outcome="error",
                                executed=False,
                                details=f"Sanitizer error: {exc!r}",
                                sanitized_html="",
                            )
                            results.append(result)
                            case_index += 1
                            if progress is not None:
                                progress(case_index, total_planned, result)
                            continue

                        try:
                            per_case_timeout_ms = _timeout_for_case(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html,
                            )
                            vector_result = harness.run(
                                payload_html=vector.payload_html,
                                sanitized_html=sanitized_html,
                                payload_context=vector.payload_context,
                                timeout_ms=per_case_timeout_ms,
                            )
                        except Exception as exc:
                            result = BenchCaseResult(
                                sanitizer=sanitizer.name,
                                browser=browser,
                                vector_id=vector.id,
                                payload_context=vector.payload_context,
                                outcome="error",
                                executed=False,
                                details=f"Harness error: {exc}",
                                sanitized_html=sanitized_html,
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
                            outcome=outcome,
                            executed=vector_result.executed,
                            details=vector_result.details,
                            sanitized_html=sanitized_html,
                        )
                        results.append(result)
                        case_index += 1
                        if progress is not None:
                            progress(case_index, total_planned, result)
                        if fail_fast and result.outcome == "xss":
                            total_cases = len(results)
                            total_executed = sum(1 for r in results if r.executed)
                            total_errors = sum(1 for r in results if r.outcome == "error")
                            return BenchSummary(
                                total_cases=total_cases,
                                total_executed=total_executed,
                                total_errors=total_errors,
                                results=results,
                            )

        total_cases = len(results)
        total_executed = sum(1 for r in results if r.executed)
        total_errors = sum(1 for r in results if r.outcome == "error")

        return BenchSummary(
            total_cases=total_cases,
            total_executed=total_executed,
            total_errors=total_errors,
            results=results,
        )

    for sanitizer in sanitizers:
        for browser in browsers:
            for vector in vectors:
                try:
                    sanitized_html = sanitizer.sanitize(vector.payload_html)
                except Exception as exc:
                    result = BenchCaseResult(
                        sanitizer=sanitizer.name,
                        browser=browser,
                        vector_id=vector.id,
                        payload_context=vector.payload_context,
                        outcome="error",
                        executed=False,
                        details=f"Sanitizer error: {exc!r}",
                        sanitized_html="",
                    )
                    results.append(result)
                    case_index += 1
                    if progress is not None:
                        progress(case_index, total_planned, result)
                    continue

                try:
                    per_case_timeout_ms = _timeout_for_case(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html,
                    )
                    vector_result = runner(
                        payload_html=vector.payload_html,
                        sanitized_html=sanitized_html,
                        payload_context=vector.payload_context,
                        browser=browser,
                        timeout_ms=per_case_timeout_ms,
                    )
                except Exception as exc:
                    result = BenchCaseResult(
                        sanitizer=sanitizer.name,
                        browser=browser,
                        vector_id=vector.id,
                        payload_context=vector.payload_context,
                        outcome="error",
                        executed=False,
                        details=f"Harness error: {exc}",
                        sanitized_html=sanitized_html,
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
                    outcome=outcome,
                    executed=vector_result.executed,
                    details=vector_result.details,
                    sanitized_html=sanitized_html,
                )
                results.append(result)
                case_index += 1
                if progress is not None:
                    progress(case_index, total_planned, result)
                if fail_fast and result.outcome == "xss":
                    total_cases = len(results)
                    total_executed = sum(1 for r in results if r.executed)
                    total_errors = sum(1 for r in results if r.outcome == "error")
                    return BenchSummary(
                        total_cases=total_cases,
                        total_executed=total_executed,
                        total_errors=total_errors,
                        results=results,
                    )

    total_cases = len(results)
    total_executed = sum(1 for r in results if r.executed)
    total_errors = sum(1 for r in results if r.outcome == "error")

    return BenchSummary(
        total_cases=total_cases,
        total_executed=total_executed,
        total_errors=total_errors,
        results=results,
    )
