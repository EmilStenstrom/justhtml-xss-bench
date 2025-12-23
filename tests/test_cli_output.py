from __future__ import annotations

import io
from contextlib import redirect_stdout

from xssbench.bench import BenchCaseResult
from xssbench.cli import _print_table


def test_cli_prints_sanitized_html_for_lossy_even_if_empty() -> None:
    r = BenchCaseResult(
        sanitizer="nh3",
        browser="chromium",
        vector_id="payloadbox-xss-payload-list-00086",
        payload_context="html",
        run_payload_context="html",
        outcome="lossy",
        executed=False,
        details="Missing expected tags after sanitization: a",
        sanitizer_input_html="<svg><a xlink:href=?></a></svg>",
        sanitized_html="",
        rendered_html="",
    )

    summary = type("S", (), {"results": [r]})()

    buf = io.StringIO()
    with redirect_stdout(buf):
        _print_table(summary)

    out = buf.getvalue()
    assert "Lossy (expected tags stripped):" in out
    assert "sanitizer_input_html" in out
    # The key requirement: even empty strings are printed.
    assert "sanitized_html=''" in out
