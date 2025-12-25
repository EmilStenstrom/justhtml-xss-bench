from __future__ import annotations

import argparse
import json
import multiprocessing
from pathlib import Path
import sys
import time

from .bench import BenchCaseResult, load_vectors, run_bench
from .harness import BrowserName
from .portswigger import ensure_portswigger_vectors_file
from .sanitizers import available_sanitizers, default_sanitizers, get_sanitizer


_WORKER_VECTOR_PATHS: tuple[str, ...] | None = None
_WORKER_VECTORS = None


def _worker_init(vector_paths: list[str]) -> None:
    global _WORKER_VECTOR_PATHS, _WORKER_VECTORS
    _WORKER_VECTOR_PATHS = tuple(vector_paths)
    _WORKER_VECTORS = None


def _worker_run(task: tuple[int, int, str, str, int | None, bool]) -> list[BenchCaseResult]:
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


def _default_vector_globs() -> list[str]:
    # Prefer vectors relative to the current working directory.
    # This makes `xssbench` usable when installed via pip (where `__file__`
    # resolves inside site-packages and does not include the repo's `vectors/`).
    for root in (Path.cwd(), Path(__file__).resolve().parents[2]):
        vectors_dir = root / "vectors"
        if vectors_dir.exists():
            return [str(p) for p in sorted(vectors_dir.glob("*.json"))]
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
    # Build per-sanitizer+browser counts.
    per = {}
    for r in summary.results:
        key = (r.sanitizer, r.browser)
        per.setdefault(key, {"total": 0, "executed": 0, "errors": 0, "lossy": 0, "skipped": 0})
        per[key]["total"] += 1
        per[key]["executed"] += 1 if r.executed else 0
        per[key]["errors"] += 1 if r.outcome == "error" else 0
        per[key]["lossy"] += 1 if r.outcome == "lossy" else 0
        per[key]["skipped"] += 1 if r.outcome == "skip" else 0

    xss = [r for r in summary.results if r.outcome == "xss"]
    errors = [r for r in summary.results if r.outcome == "error"]
    lossy = [r for r in summary.results if r.outcome == "lossy"]

    # Put detailed output first; print the summary table last.
    if xss:
        print("XSS:")
        for r in xss:
            print(
                f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}"
            )
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            if r.sanitized_html:
                print(f"  sanitized_html={_repr_truncated(r.sanitized_html)}")

    if errors:
        if xss:
            print("")
        print("Errors:")
        for r in errors:
            print(
                f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}"
            )
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            if r.sanitized_html:
                print(f"  sanitized_html={_repr_truncated(r.sanitized_html)}")

    if lossy:
        if xss or errors:
            print("")
        print("Lossy (expected tags stripped):")
        for r in lossy:
            print(
                f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}"
            )
            if getattr(r, "sanitizer_input_html", ""):
                print(f"  sanitizer_input_html={_repr_truncated(getattr(r, 'sanitizer_input_html'))}")
            # Always print sanitized_html for lossy cases, even if it's empty.
            # An empty string is often the most important signal when debugging.
            print(f"  sanitized_html={_repr_truncated(getattr(r, 'sanitized_html', ''))}")

    if xss or errors or lossy:
        print("")

    header = f"{'sanitizer':<22}  {'browser':<8}  {'xss':>6}  {'lossy':>6}  {'errors':>6}  {'skipped':>7}  {'total':>5}"
    print(header)
    print("-" * len(header))
    for (name, browser) in sorted(per.keys()):
        row = per[(name, browser)]
        print(
            f"{name:<22}  {browser:<8}  {row['executed']:>6}  {row['lossy']:>6}  {row['errors']:>6}  {row['skipped']:>7}  {row['total']:>5}"
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
        print(f"warning: could not generate PortSwigger vectors file: {exc}", file=sys.stderr)

    vectors = load_vectors(vector_paths)

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
                elif result.outcome == "lossy":
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

            # Split vectors evenly across workers. Each worker runs *all* selected
            # sanitizers and browsers for its slice, which avoids launching a new
            # browser per chunk.
            actual_workers = min(workers, n) if n > 0 else 1
            base = n // actual_workers
            rem = n % actual_workers
            starts = []
            cur = 0
            for i in range(actual_workers):
                size = base + (1 if i < rem else 0)
                starts.append((cur, cur + size))
                cur += size

            sanitizer_names_json = json.dumps([s.name for s in sanitizers])
            browsers_json = json.dumps(list(browsers))

            tasks: list[tuple[int, int, str, str, int | None, bool]] = [
                (start, end, sanitizer_names_json, browsers_json, args.timeout_ms, bool(args.fail_fast))
                for (start, end) in starts
            ]

            ctx = multiprocessing.get_context("spawn")
            results: list[BenchCaseResult] = []
            with ctx.Pool(processes=actual_workers, initializer=_worker_init, initargs=(vector_paths,)) as pool:
                for part in pool.imap_unordered(_worker_run, tasks, chunksize=1):
                    if args.fail_fast:
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
                            pool.terminate()
                            return 1

                    results.extend(part)

                    # Aggregated progress output.
                    if not args.no_progress and args.progress_every > 0 and part:
                        done_cases += len(part)
                        errors_so_far += sum(1 for r in part if r.outcome == "error")
                        xss_so_far += sum(1 for r in part if r.executed and r.outcome != "error")

                        # Dot-style output is too noisy in parallel mode; treat
                        # it as a request for frequent updates.
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

            summary = type("Summary", (), {
                "total_cases": len(results),
                "total_executed": sum(1 for r in results if r.executed),
                "total_errors": sum(1 for r in results if r.outcome == "error"),
                "total_lossy": sum(1 for r in results if r.outcome == "lossy"),
                "results": results,
            })()
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
