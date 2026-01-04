from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import math
import multiprocessing
from pathlib import Path
import sys
import threading
import time
import re
import queue

from .bench import BenchCaseResult, load_vectors, run_bench, sanitizer_overrides_for_vector
from .harness import BrowserName
from .portswigger import ensure_portswigger_vectors_file
from .sanitizers import SanitizerConfigUnsupported, available_sanitizers, default_sanitizers, get_sanitizer


_WORKER_VECTOR_PATHS: tuple[str, ...] | None = None
_WORKER_VECTORS = None


def _normalize_id_args(raw_ids: list[str]) -> list[str]:
    # Allow either: --ids a b c  OR  --ids a,b,c
    ids: list[str] = []
    for item in raw_ids:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                ids.append(part)
    return ids


def _select_vectors_by_id(vectors, ids: list[str]):
    # Preserve the user-provided ID order; ignore duplicates.
    by_id = {v.id: v for v in vectors}
    out = []
    seen = set()
    missing: list[str] = []
    for vid in ids:
        if vid in seen:
            continue
        seen.add(vid)
        v = by_id.get(vid)
        if v is None:
            missing.append(vid)
        else:
            out.append(v)
    return out, missing


def _worker_init(vector_paths: list[str]) -> None:
    global _WORKER_VECTOR_PATHS, _WORKER_VECTORS
    _WORKER_VECTOR_PATHS = tuple(vector_paths)
    _WORKER_VECTORS = None


def _worker_run(
    task: tuple[int, int, str, str, int | None, bool],
) -> list[BenchCaseResult]:
    # task = (start, end, sanitizer_names_json, browsers_json, timeout_ms, fail_fast)
    global _WORKER_VECTORS
    start, end, sanitizer_names_json, browsers_json, timeout_ms, fail_fast = task

    if _WORKER_VECTOR_PATHS is None:
        raise RuntimeError("Worker not initialized")

    if _WORKER_VECTORS is None:
        _WORKER_VECTORS = load_vectors(_WORKER_VECTOR_PATHS)

    vectors = _WORKER_VECTORS[start:end]

    sanitizer_names = json.loads(sanitizer_names_json)
    browsers = json.loads(browsers_json)
    sanitizers = [get_sanitizer(str(n)) for n in sanitizer_names]

    summary = run_bench(
        vectors=vectors,
        sanitizers=sanitizers,
        browsers=browsers,
        timeout_ms=timeout_ms,
        fail_fast=bool(fail_fast),
    )
    return summary.results


def _queue_worker_main(
    *,
    vector_paths: list[str],
    vector_ids: list[str] | None,
    sanitizer_names: list[str],
    browsers: list[BrowserName],
    timeout_ms: int | None,
    fail_fast: bool,
    task_queue,
    result_queue,
    stop_event,
) -> None:
    # Use Playwright's Async API in parallel workers.
    #
    # On Python 3.15, the Sync API can incorrectly trip its "Sync API inside the
    # asyncio loop" guard even when no loop is running in the calling thread.
    # Using the Async API avoids that check entirely.

    def _prepare_for_sanitizer(*, vector, sanitizer):
        sanitizer_kwargs = sanitizer_overrides_for_vector(vector)

        if vector.payload_context == "href":
            sanitizer_input_html = f'<a href="{vector.payload_html}">x</a>'
            return (
                sanitizer_input_html,
                sanitizer.sanitize(sanitizer_input_html, **sanitizer_kwargs),
                "html",
            )

        if vector.payload_context == "onerror_attr":
            sanitizer_input_html = f'<img src="nonexistent://x" onerror="{vector.payload_html}">'
            return (
                sanitizer_input_html,
                sanitizer.sanitize(sanitizer_input_html, **sanitizer_kwargs),
                "html",
            )

        sanitizer_input_html = vector.payload_html
        return (
            sanitizer_input_html,
            sanitizer.sanitize(sanitizer_input_html, **sanitizer_kwargs),
            vector.payload_context,
        )

    def _auto_timeout_ms(*, payload_html: str, sanitized_html: str) -> int:
        blob = (payload_html + "\n" + sanitized_html).lower()

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

        if "http-equiv" in blob and "refresh" in blob:
            return 400

        if re.search(r"\bon(load|error)\s*=", blob):
            return 25

        return 0

    def _timeout_for_case(*, payload_html: str, sanitized_html: str) -> int:
        return (
            int(timeout_ms)
            if timeout_ms is not None
            else _auto_timeout_ms(payload_html=payload_html, sanitized_html=sanitized_html)
        )

    async def _async_main() -> None:
        vectors = load_vectors(vector_paths)
        if vector_ids:
            vectors, missing = _select_vectors_by_id(vectors, vector_ids)
            if missing:
                raise RuntimeError(f"Unknown vector id(s): {', '.join(missing)}")
        sanitizers = [get_sanitizer(str(n)) for n in sanitizer_names]

        # Keep browsers open for the lifetime of the worker so small tasks don't
        # pay browser startup overhead.
        from contextlib import AsyncExitStack

        from .harness import AsyncBrowserHarness, render_html_document
        from .bench import (
            _expected_tags_allowed_for_context,
            _missing_allowlisted_primitives,
            _missing_expected_tags,
            _unexpected_tags_when_none_expected,
        )

        try:
            async with AsyncExitStack() as stack:
                harnesses = {
                    b: await stack.enter_async_context(AsyncBrowserHarness(browser=b, headless=True)) for b in browsers
                }

                while True:
                    try:
                        item = task_queue.get(timeout=0.5)
                    except Exception:
                        if stop_event.is_set():
                            break
                        continue

                    if item is None:
                        try:
                            task_queue.task_done()
                        except Exception:
                            pass
                        break

                    task_id, start_i, end_i = item

                    if stop_event.is_set():
                        try:
                            task_queue.task_done()
                        except Exception:
                            pass
                        continue

                    part: list[BenchCaseResult] = []
                    hit_xss = False

                    for browser in browsers:
                        harness = harnesses[browser]
                        for sanitizer in sanitizers:
                            for vector in vectors[start_i:end_i]:
                                if stop_event.is_set():
                                    break

                                if (
                                    sanitizer.supported_contexts is not None
                                    and vector.payload_context not in sanitizer.supported_contexts
                                ):
                                    part.append(
                                        BenchCaseResult(
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
                                    )
                                    continue

                                try:
                                    (
                                        sanitizer_input_html,
                                        sanitized_html,
                                        payload_context_to_run,
                                    ) = _prepare_for_sanitizer(vector=vector, sanitizer=sanitizer)
                                except SanitizerConfigUnsupported as exc:
                                    part.append(
                                        BenchCaseResult(
                                            sanitizer=sanitizer.name,
                                            browser=browser,
                                            vector_id=vector.id,
                                            payload_context=vector.payload_context,
                                            run_payload_context=vector.payload_context,
                                            outcome="skip",
                                            executed=False,
                                            lossy=False,
                                            lossy_details="",
                                            details=f"Skipped: {sanitizer.name} cannot represent the requested allowlist: {exc}",
                                            sanitizer_input_html="",
                                            sanitized_html="",
                                            rendered_html="",
                                        )
                                    )
                                    continue
                                except Exception as exc:
                                    part.append(
                                        BenchCaseResult(
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
                                    )
                                    continue

                                lossy = False
                                lossy_details = ""
                                if (
                                    _expected_tags_allowed_for_context(vector.payload_context)
                                    and vector.expected_tags is not None
                                ):
                                    if len(vector.expected_tags) == 0:
                                        unexpected = _unexpected_tags_when_none_expected(sanitized_html=sanitized_html)
                                        if unexpected:
                                            lossy = True
                                            lossy_details = (
                                                "Expected no tags after sanitization, but found: "
                                                + ", ".join(unexpected[:20])
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

                                # Note: we intentionally do not mark http_leak cases as `lossy`.
                                # The purpose of these vectors is to measure external-request behavior,
                                # and sanitizers may legitimately prevent leaks by stripping URL-bearing
                                # tags/attributes entirely.

                                try:
                                    rendered_html = render_html_document(
                                        sanitized_html=sanitized_html,
                                        payload_context=payload_context_to_run,
                                    )
                                    per_case_timeout_ms = _timeout_for_case(
                                        payload_html=vector.payload_html,
                                        sanitized_html=sanitized_html,
                                    )
                                    vector_result = await harness.run(
                                        payload_html=vector.payload_html,
                                        sanitized_html=sanitized_html,
                                        payload_context=payload_context_to_run,
                                        timeout_ms=per_case_timeout_ms,
                                    )
                                except Exception as exc:
                                    part.append(
                                        BenchCaseResult(
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
                                    )
                                    continue

                                signal = str(getattr(vector_result, "signal", "") or "")
                                executed = bool(vector_result.executed)
                                if executed:
                                    outcome = "xss"
                                elif signal == "http_leak":
                                    outcome = "http_leak"
                                else:
                                    outcome = "pass"
                                part.append(
                                    BenchCaseResult(
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
                                )

                                if fail_fast and outcome == "xss":
                                    hit_xss = True
                                    stop_event.set()
                                    break

                            if stop_event.is_set():
                                break
                        if stop_event.is_set():
                            break

                    if stop_event.is_set():
                        break

                    result_queue.put((task_id, part, hit_xss))
                    try:
                        task_queue.task_done()
                    except Exception:
                        pass
        except Exception as exc:
            # If Playwright blows up in some environments, include enough context
            # to debug without spamming successful runs.
            try:
                import asyncio

                try:
                    asyncio.get_running_loop()
                    loop_running = True
                except RuntimeError:
                    loop_running = False
            except Exception:
                loop_running = None

            print(
                f"worker error: process={multiprocessing.current_process().name} "
                f"thread={threading.current_thread().name} loop_running={loop_running}: {exc}",
                file=sys.stderr,
                flush=True,
            )
            raise

    try:
        import asyncio

        asyncio.run(_async_main())
    except Exception:
        raise


def _default_vector_globs() -> list[str]:
    # Prefer vectors relative to the current working directory.
    # This makes `xssbench` usable when installed via pip (where `__file__`
    # resolves inside site-packages and does not include the repo's `vectors/`).
    for root in (Path.cwd(), Path(__file__).resolve().parents[2]):
        vectors_dir = root / "vectors"
        if vectors_dir.exists():
            return [str(p) for p in sorted(vectors_dir.glob("*.json")) if p.name != "portswigger-expectations.json"]
    return []


def _parse_run_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="xssbench",
        description="Run XSS execution vectors in a real browser against one or more sanitizers.",
    )

    parser.add_argument(
        "--vectors",
        nargs="+",
        default=None,
        help="One or more vector JSON files (default: vectors/*.json)",
    )

    parser.add_argument(
        "--sanitizers",
        nargs="+",
        default=None,
        help="One or more sanitizer names (default: rich HTML sanitizers)",
    )

    parser.add_argument(
        "--ids",
        nargs="+",
        default=None,
        help="Only run the vectors with these IDs (space-separated, or a single comma-separated value)",
    )

    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=None,
        help="How long to wait for async execution in each case. If omitted, uses an adaptive per-vector timeout.",
    )

    parser.add_argument(
        "--browser",
        choices=["chromium", "firefox", "webkit", "all"],
        default="all",
        help="Browser engine to run in (default: all)",
    )

    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Write full results to a JSON file",
    )

    parser.add_argument(
        "--progress-every",
        type=int,
        default=25,
        help="Print progress every N cases (0 disables). Use 1 for test-style dot progress (default: 25)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Run in parallel using N worker processes (default: 1)",
    )

    parser.add_argument(
        "--worker-task-timeout-s",
        type=int,
        default=3600,
        help=(
            "In parallel mode, kill and restart the worker pool if a single chunk runs longer than this many seconds. "
            "Timed-out chunks are recorded as errors so the run can finish (default: 3600, set 0 to disable)."
        ),
    )

    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop at the first XSS and print it",
    )

    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress output",
    )

    parser.add_argument(
        "--list-sanitizers",
        action="store_true",
        help="List available sanitizers and exit",
    )

    return parser.parse_args(argv)


def _repr_truncated(value: str, *, limit: int = 400) -> str:
    s = repr(value)
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 3)] + "..."


def _print_table(summary) -> None:
    def _is_js_context(ctx: str) -> bool:
        c = str(ctx)
        return c.startswith("js") or c == "onerror_attr"

    # Build per-sanitizer+browser counts.
    per = {}
    for r in summary.results:
        key = (r.sanitizer, r.browser)
        row = per.setdefault(
            key,
            {
                "xss": 0,
                "lossy": 0,
                "errors": 0,
                "passed": 0,
                "js_total": 0,
                "js_skipped": 0,
                "js_xss": 0,
                "href_total": 0,
                "href_skipped": 0,
                "href_xss": 0,
                "http_leak_total": 0,
                "http_leak_skipped": 0,
                "http_leak_hits": 0,
            },
        )

        if r.outcome == "xss":
            row["xss"] += 1
        if bool(getattr(r, "lossy", False)):
            row["lossy"] += 1
        if r.outcome == "error":
            row["errors"] += 1
        if r.outcome == "pass" and not bool(getattr(r, "lossy", False)):
            row["passed"] += 1

        ctx = str(getattr(r, "payload_context", ""))
        if _is_js_context(ctx):
            row["js_total"] += 1
            row["js_skipped"] += 1 if r.outcome == "skip" else 0
            row["js_xss"] += 1 if r.outcome == "xss" else 0
        elif ctx == "href":
            row["href_total"] += 1
            row["href_skipped"] += 1 if r.outcome == "skip" else 0
            row["href_xss"] += 1 if r.outcome == "xss" else 0
        elif ctx == "http_leak":
            row["http_leak_total"] += 1
            row["http_leak_skipped"] += 1 if r.outcome == "skip" else 0
            row["http_leak_hits"] += 1 if r.outcome == "http_leak" else 0

    xss = [r for r in summary.results if r.outcome == "xss"]
    http_leak = [r for r in summary.results if r.outcome == "http_leak"]
    errors = [r for r in summary.results if r.outcome == "error"]
    lossy = [r for r in summary.results if getattr(r, "lossy", False)]

    # Put detailed output first; print the summary table last.
    if xss:
        print("XSS:")
        for r in xss:
            print(f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}")
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            if r.sanitized_html:
                print(f"  sanitized_html={_repr_truncated(r.sanitized_html)}")

    if http_leak:
        if xss:
            print("")
        print("HTTP leaks (non-script external fetches):")
        for r in http_leak:
            print(f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}")
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            if r.sanitized_html:
                print(f"  sanitized_html={_repr_truncated(r.sanitized_html)}")

    if errors:
        if xss or http_leak:
            print("")
        print("Errors:")
        for r in errors:
            print(f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}")
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            if r.sanitized_html:
                print(f"  sanitized_html={_repr_truncated(r.sanitized_html)}")

    if lossy:
        if xss or http_leak or errors:
            print("")
        print("Lossy (expected tags stripped):")
        for r in lossy:
            msg = getattr(r, "lossy_details", "") or "(lossy)"
            print(f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {msg}")
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            # Always print sanitized_html for lossy cases, even if it's empty.
            # An empty string is often the most important signal when debugging.
            print(f"  sanitized_html={_repr_truncated(getattr(r, 'sanitized_html', ''))}")

    if xss or http_leak or errors or lossy:
        print("")

    header = (
        f"{'sanitizer':<22}  {'browser':<8}"
        f"  {'xss':>6}  {'lossy':>6}  {'errors':>6}"
        f"  {'js':>6}  {'href':>6}  {'http_leak':>9}"
        f"  {'passed':>6}"
    )
    print(header)
    print("-" * len(header))
    for name, browser in sorted(per.keys()):
        row = per[(name, browser)]

        def _skip_or_num(*, total: int, skipped: int, value: int) -> str:
            if total == 0:
                return "-"
            if skipped == total:
                return "skip"
            return str(value)

        js_cell = _skip_or_num(total=int(row["js_total"]), skipped=int(row["js_skipped"]), value=int(row["js_xss"]))
        href_cell = _skip_or_num(
            total=int(row["href_total"]), skipped=int(row["href_skipped"]), value=int(row["href_xss"])
        )
        http_leak_cell = _skip_or_num(
            total=int(row["http_leak_total"]),
            skipped=int(row["http_leak_skipped"]),
            value=int(row["http_leak_hits"]),
        )

        print(
            f"{name:<22}  {browser:<8}"
            f"  {row['xss']:>6}  {row['lossy']:>6}  {row['errors']:>6}"
            f"  {js_cell:>6}  {href_cell:>6}  {http_leak_cell:>9}"
            f"  {row['passed']:>6}"
        )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    args = _parse_run_args(argv)

    if args.list_sanitizers:
        for name, s in sorted(available_sanitizers().items()):
            print(f"{name}: {s.description}")
        return 0

    vector_paths = args.vectors if args.vectors is not None else _default_vector_globs()
    if not vector_paths:
        print(
            "No vector files found. By default xssbench looks for ./vectors/*.json in the current directory. "
            "Pass --vectors /path/to/vectors/*.json (or run from the repo root).",
            file=sys.stderr,
        )
        return 2

    # First-run convenience: fetch PortSwigger cheat sheet data and generate a
    # refs-only artifact under `.xssbench/` (git-ignored). Best-effort only.
    try:
        # Write run artifacts under the current directory.
        # When installed via pip, `__file__` may live in site-packages.
        repo_root = Path.cwd()
        ensure_portswigger_vectors_file(repo_root=repo_root, against_paths=vector_paths)
    except Exception as exc:
        print(
            f"warning: could not generate PortSwigger vectors file: {exc}",
            file=sys.stderr,
        )

    vectors = load_vectors(vector_paths)
    vector_ids = _normalize_id_args(args.ids) if args.ids else None
    if vector_ids:
        vectors, missing = _select_vectors_by_id(vectors, vector_ids)
        if missing:
            print(
                f"Unknown vector id(s): {', '.join(missing)}",
                file=sys.stderr,
            )
            return 2

    if args.sanitizers is None:
        sanitizers = list(default_sanitizers().values())
    else:
        sanitizers = [get_sanitizer(n) for n in args.sanitizers]

    if args.browser == "all":
        browsers: list[BrowserName] = ["chromium", "firefox", "webkit"]
    else:
        browsers = [args.browser]

    try:
        started = time.monotonic()
        xss_so_far = 0
        errors_so_far = 0
        dot_count = 0

        def progress(i: int, total: int, result: BenchCaseResult) -> None:
            nonlocal xss_so_far, errors_so_far, dot_count
            if args.no_progress or args.progress_every <= 0:
                return

            if result.outcome == "error":
                errors_so_far += 1
            elif result.executed:
                xss_so_far += 1

            # Test-runner style output: one character per case.
            if args.progress_every == 1:
                if result.outcome == "error":
                    ch = "E"
                elif getattr(result, "lossy", False):
                    ch = "L"
                elif result.executed:
                    ch = "X"
                else:
                    ch = "."

                sys.stderr.write(ch)
                dot_count += 1
                # Avoid flushing on every write; still provide regular heartbeat.
                if (dot_count % 50) == 0 or i == total:
                    if i == total:
                        sys.stderr.write("\n")
                    sys.stderr.flush()
                return

            if i == 1 or i == total or (i % args.progress_every) == 0:
                elapsed_s = time.monotonic() - started
                print(
                    f"[{i}/{total}] {elapsed_s:0.1f}s  xss={xss_so_far}  errors={errors_so_far}  "
                    f"{result.sanitizer} / {result.browser} / {result.vector_id} ({result.payload_context})",
                    file=sys.stderr,
                    flush=True,
                )

        if args.workers and int(args.workers) > 1:
            # Parallel mode: do not use per-case progress callbacks.
            workers = max(1, int(args.workers))
            n = len(vectors)

            total_planned = len(sanitizers) * len(browsers) * n
            done_cases = 0
            xss_so_far = 0
            errors_so_far = 0
            last_bucket = -1

            # Global queue: each worker pulls the next vector batch when ready.
            # This keeps progress flowing and avoids waiting for one huge slice.
            actual_workers = min(workers, n) if n > 0 else 1

            cases_per_vector = max(1, len(sanitizers) * len(browsers))
            vectors_per_task = 1
            if args.progress_every and args.progress_every > 0:
                vectors_per_task = max(1, math.ceil(int(args.progress_every) / cases_per_vector))

            # If the user forces a long per-case timeout, large chunks make the
            # progress output look "stuck" because we only report after a chunk
            # completes. Cap the chunk size so we still get regular updates.
            #
            # Example: with --timeout-ms 12000 and the default --progress-every 25,
            # a chunk would take ~25 * 12s = 300s before the first progress line.
            if args.timeout_ms is not None and int(args.timeout_ms) > 0:
                target_chunk_s = 5
                max_vectors_by_timeout = max(1, (target_chunk_s * 1000) // int(args.timeout_ms))
                vectors_per_task = min(vectors_per_task, int(max_vectors_by_timeout))

            if not args.no_progress and args.progress_every > 0:
                print(
                    f"[0/{total_planned}] starting {actual_workers} workers (vectors_per_task={vectors_per_task}, cases_per_vector={cases_per_vector})",
                    file=sys.stderr,
                    flush=True,
                )

            ctx = multiprocessing.get_context("spawn")
            task_queue = ctx.JoinableQueue(maxsize=max(1, actual_workers * 4))
            result_queue = ctx.Queue()
            stop_event = ctx.Event()

            sanitizer_names = [s.name for s in sanitizers]
            results: list[BenchCaseResult] = []

            procs: list[multiprocessing.Process] = []
            for _ in range(actual_workers):
                p = ctx.Process(
                    target=_queue_worker_main,
                    kwargs={
                        "vector_paths": list(vector_paths),
                        "vector_ids": list(vector_ids) if vector_ids else None,
                        "sanitizer_names": sanitizer_names,
                        "browsers": list(browsers),
                        "timeout_ms": args.timeout_ms,
                        "fail_fast": bool(args.fail_fast),
                        "task_queue": task_queue,
                        "result_queue": result_queue,
                        "stop_event": stop_event,
                    },
                )
                p.start()
                procs.append(p)

            task_id = 0
            pending: dict[int, tuple[int, int]] = {}
            deferred: list[tuple[int, int, int]] = []

            def _task_iter():
                nonlocal task_id
                for start_i in range(0, n, vectors_per_task):
                    end_i = min(n, start_i + vectors_per_task)
                    yield (task_id, start_i, end_i)
                    task_id += 1

            task_iter = _task_iter()

            def _feed_tasks() -> None:
                # Don't block the parent while workers are still starting.
                # Fill the queue opportunistically, and enqueue more as results arrive.
                while not stop_event.is_set():
                    if deferred:
                        tid, start_i, end_i = deferred.pop(0)
                    else:
                        try:
                            tid, start_i, end_i = next(task_iter)
                        except StopIteration:
                            return
                    try:
                        task_queue.put_nowait((tid, start_i, end_i))
                    except queue.Full:
                        deferred.insert(0, (tid, start_i, end_i))
                        return
                    pending[tid] = (start_i, end_i)

            _feed_tasks()

            completed_tasks = 0
            last_result_time = time.monotonic()
            watchdog_s = int(getattr(args, "worker_task_timeout_s", 0) or 0)
            last_heartbeat_time = time.monotonic()

            while pending and not stop_event.is_set():
                # If a worker has crashed, stop instead of deadlocking on a full queue.
                dead = next((p for p in procs if p.exitcode not in (None, 0)), None)
                if dead is not None:
                    stop_event.set()
                    if not args.no_progress:
                        print(
                            f"error: worker exited with code {dead.exitcode}; marking remaining work as errors",
                            file=sys.stderr,
                            flush=True,
                        )
                    for _tid, (start_i, end_i) in list(pending.items()):
                        for v in vectors[start_i:end_i]:
                            for s in sanitizers:
                                for b in browsers:
                                    results.append(
                                        BenchCaseResult(
                                            sanitizer=s.name,
                                            browser=b,
                                            vector_id=v.id,
                                            payload_context=v.payload_context,
                                            run_payload_context=v.payload_context,
                                            outcome="error",
                                            executed=False,
                                            lossy=False,
                                            lossy_details="",
                                            details=f"Worker crashed (exitcode={dead.exitcode})",
                                            sanitizer_input_html="",
                                            sanitized_html="",
                                            rendered_html="",
                                        )
                                    )
                                    done_cases += 1
                    pending.clear()
                    break

                try:
                    got_task_id, part, hit_xss = result_queue.get(timeout=0.5)
                except Exception:
                    if not args.no_progress and args.progress_every > 0:
                        now = time.monotonic()
                        # If workers are still starting/loading vectors, we might have
                        # no completed tasks for a while. Print a lightweight heartbeat.
                        if (now - last_heartbeat_time) > 10 and done_cases == 0:
                            last_heartbeat_time = now
                            elapsed_s = now - started
                            alive = sum(1 for p in procs if p.is_alive())
                            print(
                                f"[0/{total_planned}] {elapsed_s:0.1f}s  starting...  workers_alive={alive}",
                                file=sys.stderr,
                                flush=True,
                            )
                    if watchdog_s > 0 and (time.monotonic() - last_result_time) > watchdog_s:
                        # No completed tasks for too long: assume a stall and mark remaining work as errors.
                        if not args.no_progress:
                            print(
                                f"warning: no completed chunks for {watchdog_s}s; marking remaining work as errors",
                                file=sys.stderr,
                                flush=True,
                            )
                        for _tid, (start_i, end_i) in list(pending.items()):
                            for v in vectors[start_i:end_i]:
                                for s in sanitizers:
                                    for b in browsers:
                                        results.append(
                                            BenchCaseResult(
                                                sanitizer=s.name,
                                                browser=b,
                                                vector_id=v.id,
                                                payload_context=v.payload_context,
                                                run_payload_context=v.payload_context,
                                                outcome="error",
                                                executed=False,
                                                lossy=False,
                                                lossy_details="",
                                                details=f"Parallel run stalled (no completed chunks for {watchdog_s}s)",
                                                sanitizer_input_html="",
                                                sanitized_html="",
                                                rendered_html="",
                                            )
                                        )
                                        done_cases += 1
                        pending.clear()
                        stop_event.set()
                        break
                    continue

                last_result_time = time.monotonic()
                pending.pop(int(got_task_id), None)
                completed_tasks += 1

                # As workers finish, feed more work into the queue.
                _feed_tasks()

                if args.fail_fast and hit_xss:
                    hit = next((r for r in part if r.outcome == "xss"), None)
                    if hit is not None:
                        print(
                            f"FAIL-FAST: {hit.sanitizer} / {hit.browser} / {hit.vector_id} ({hit.payload_context}): {hit.details}",
                            file=sys.stderr,
                            flush=True,
                        )
                        if hit.sanitized_html:
                            print(
                                f"sanitized_html={_repr_truncated(hit.sanitized_html)}",
                                file=sys.stderr,
                                flush=True,
                            )
                        if getattr(hit, "sanitizer_input_html", ""):
                            print(
                                f"sanitizer_input_html={_repr_truncated(getattr(hit, 'sanitizer_input_html'), limit=2000)}",
                                file=sys.stderr,
                                flush=True,
                            )
                    stop_event.set()
                    break

                results.extend(part)

                if not args.no_progress and args.progress_every > 0 and part:
                    done_cases += len(part)
                    errors_so_far += sum(1 for r in part if r.outcome == "error")
                    xss_so_far += sum(1 for r in part if r.executed and r.outcome != "error")

                    every = 1 if args.progress_every == 1 else args.progress_every
                    bucket = done_cases // every
                    if bucket != last_bucket or done_cases == total_planned:
                        last_bucket = bucket
                        elapsed_s = time.monotonic() - started
                        last = part[-1]
                        print(
                            f"[{done_cases}/{total_planned}] {elapsed_s:0.1f}s  xss={xss_so_far}  errors={errors_so_far}  "
                            f"{last.sanitizer} / {last.browser} / {last.vector_id} ({last.payload_context})",
                            file=sys.stderr,
                            flush=True,
                        )

            # Tell workers to exit.
            for _ in range(actual_workers):
                task_queue.put(None)
            try:
                task_queue.join()
            except Exception:
                pass

            for p in procs:
                p.join(timeout=5)
                if p.is_alive():
                    p.terminate()
                    p.join(timeout=2)

            summary = type(
                "Summary",
                (),
                {
                    "total_cases": len(results),
                    "total_executed": sum(1 for r in results if r.executed),
                    "total_external": sum(1 for r in results if r.outcome == "http_leak"),
                    "total_errors": sum(1 for r in results if r.outcome == "error"),
                    "total_lossy": sum(1 for r in results if getattr(r, "lossy", False)),
                    "results": results,
                },
            )()
        else:
            summary = run_bench(
                vectors=vectors,
                sanitizers=sanitizers,
                browsers=browsers,
                timeout_ms=args.timeout_ms,
                progress=progress,
                fail_fast=bool(args.fail_fast),
            )
    except RuntimeError as exc:
        # Raised by the Playwright harness with actionable install messages.
        print(str(exc), file=sys.stderr)
        return 2

    if args.fail_fast and summary.total_executed > 0:
        hit = next((r for r in summary.results if r.outcome == "xss"), None)
        if hit is not None:
            print(
                f"FAIL-FAST: {hit.sanitizer} / {hit.browser} / {hit.vector_id} ({hit.payload_context}): {hit.details}",
                file=sys.stderr,
                flush=True,
            )
            if hit.sanitized_html:
                print(
                    f"sanitized_html={_repr_truncated(hit.sanitized_html, limit=2000)}",
                    file=sys.stderr,
                    flush=True,
                )
            if getattr(hit, "sanitizer_input_html", ""):
                print(
                    f"sanitizer_input_html={_repr_truncated(getattr(hit, 'sanitizer_input_html'), limit=2000)}",
                    file=sys.stderr,
                    flush=True,
                )
        return 1

    _print_table(summary)

    if args.json_out:
        out_path = Path(args.json_out)
        # Convenience: allow passing a directory hint (e.g. `--json-out .xssbench`)
        # and auto-create parent directories.
        if out_path.suffix == "" or (out_path.exists() and out_path.is_dir()):
            out_path = out_path / "results.json"
        payload = {
            "total_cases": summary.total_cases,
            "total_executed": summary.total_executed,
            # Backwards-compatible key (previously named 'external').
            "total_external": getattr(summary, "total_external", 0),
            # Preferred name.
            "total_http_leak": getattr(summary, "total_external", 0),
            "total_errors": summary.total_errors,
            "total_lossy": getattr(summary, "total_lossy", 0),
            "results": [
                {
                    "sanitizer": r.sanitizer,
                    "browser": r.browser,
                    "vector_id": r.vector_id,
                    "payload_context": r.payload_context,
                    "run_payload_context": getattr(r, "run_payload_context", r.payload_context),
                    "outcome": r.outcome,
                    "executed": r.executed,
                    "lossy": getattr(r, "lossy", False),
                    "lossy_details": getattr(r, "lossy_details", ""),
                    "details": r.details,
                    "sanitizer_input_html": getattr(r, "sanitizer_input_html", ""),
                    "sanitized_html": r.sanitized_html,
                    "rendered_html": getattr(r, "rendered_html", ""),
                }
                for r in summary.results
            ],
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if summary.total_errors > 0 or getattr(summary, "total_lossy", 0) > 0:
        return 2
    return 1 if summary.total_executed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
