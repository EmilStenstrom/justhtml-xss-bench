from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from .bench import BenchCaseResult, load_vectors, run_bench
from .harness import BrowserName
from .sanitizers import available_sanitizers, get_sanitizer


def _default_vector_globs() -> list[str]:
    root = Path(__file__).resolve().parents[2]
    vectors_dir = root / "vectors"
    if not vectors_dir.exists():
        return []
    return [str(p) for p in sorted(vectors_dir.glob("*.json"))]


def _parse_args(argv: list[str]) -> argparse.Namespace:
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
        help="One or more sanitizer names (default: all available)",
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


def _print_table(summary) -> None:
    # Build per-sanitizer+browser counts.
    per = {}
    for r in summary.results:
        key = (r.sanitizer, r.browser)
        per.setdefault(key, {"total": 0, "executed": 0, "errors": 0})
        per[key]["total"] += 1
        per[key]["executed"] += 1 if r.executed else 0
        per[key]["errors"] += 1 if r.outcome == "error" else 0

    xss = [r for r in summary.results if r.outcome == "xss"]
    errors = [r for r in summary.results if r.outcome == "error"]

    # Put detailed output first; print the summary table last.
    if xss:
        print("XSS:")
        for r in xss:
            print(
                f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}"
            )

    if errors:
        if xss:
            print("")
        print("Errors:")
        for r in errors:
            print(
                f"- {r.sanitizer} / {r.browser} / {r.vector_id} ({r.payload_context}): {r.details}"
            )

    if xss or errors:
        print("")

    header = f"{'sanitizer':<22}  {'browser':<8}  {'xss':>6}  {'errors':>6}  {'total':>5}"
    print(header)
    print("-" * len(header))
    for (name, browser) in sorted(per.keys()):
        row = per[(name, browser)]
        print(
            f"{name:<22}  {browser:<8}  {row['executed']:>6}  {row['errors']:>6}  {row['total']:>5}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if args.list_sanitizers:
        for name, s in sorted(available_sanitizers().items()):
            print(f"{name}: {s.description}")
        return 0

    vector_paths = args.vectors if args.vectors is not None else _default_vector_globs()
    if not vector_paths:
        print("No vector files found. Pass --vectors vectors/*.json", file=sys.stderr)
        return 2

    vectors = load_vectors(vector_paths)

    if args.sanitizers is None:
        sanitizers = list(available_sanitizers().values())
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

        summary = run_bench(
            vectors=vectors,
            sanitizers=sanitizers,
            browsers=browsers,
            timeout_ms=args.timeout_ms,
            progress=progress,
        )
    except RuntimeError as exc:
        # Raised by the Playwright harness with actionable install messages.
        print(str(exc), file=sys.stderr)
        return 2

    _print_table(summary)

    if args.json_out:
        out_path = Path(args.json_out)
        payload = {
            "total_cases": summary.total_cases,
            "total_executed": summary.total_executed,
            "total_errors": summary.total_errors,
            "results": [
                {
                    "sanitizer": r.sanitizer,
                    "browser": r.browser,
                    "vector_id": r.vector_id,
                    "payload_context": r.payload_context,
                    "outcome": r.outcome,
                    "executed": r.executed,
                    "details": r.details,
                    "sanitized_html": r.sanitized_html,
                }
                for r in summary.results
            ],
        }
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if summary.total_errors > 0:
        return 2
    return 1 if summary.total_executed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
