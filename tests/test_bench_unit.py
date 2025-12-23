from __future__ import annotations

import json
from pathlib import Path
import tempfile

from xssbench.bench import run_bench, Vector
from xssbench.sanitizers import Sanitizer


def test_run_bench_uses_runner_and_counts_executed() -> None:
    vectors = [
        Vector(id="v1", description="", payload_html="<img src=x onerror=1>", payload_context="html"),
        Vector(id="v2", description="", payload_html="<b>ok</b>", payload_context="html"),
    ]

    sanitizer = Sanitizer(
        name="noop",
        description="",
        sanitize=lambda html: html,
    )

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        # Flag one vector as executing, one as not.
        if "onerror" in sanitized_html:
            return type("VR", (), {"executed": True, "details": "hit"})()
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 2
    assert summary.total_executed == 1
    assert summary.total_errors == 0
    assert [r.vector_id for r in summary.results if r.executed] == ["v1"]


def test_run_bench_external_script_request_counts_as_xss() -> None:
    vectors = [
        Vector(id="v1", description="", payload_html="<b>ok</b>", payload_context="html"),
        Vector(
            id="v2",
            description="",
            payload_html='<script src="https://example.com/x.js"></script>',
            payload_context="html",
        ),
        Vector(id="v3", description="", payload_html="<b>ok2</b>", payload_context="html"),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        if "script src" in sanitized_html:
            return type("VR", (), {"executed": True, "details": "external script"})()
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 3
    assert summary.total_errors == 0
    assert summary.total_executed == 1
    assert [r.vector_id for r in summary.results if r.outcome == "xss"] == ["v2"]


def test_load_vectors_accepts_meta_wrapper() -> None:
    from xssbench.bench import load_vectors

    payload = {
        "schema": "xssbench.vectorfile.v1",
        "meta": {
            "tool": "xssbench",
            "source_url": "https://example.invalid/",
            "license": {
                "spdx": "MIT",
                "url": "https://spdx.org/licenses/MIT.html",
                "file": "vectors/example-LICENSE.txt",
            },
        },
        "vectors": [
            {
                "id": "v1",
                "description": "d",
                "payload_html": "<img src=x onerror=alert(1)>",
                "payload_context": "html",
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        vectors = load_vectors([p])

    assert [v.id for v in vectors] == ["v1"]


def test_run_bench_fail_fast_stops_after_first_xss() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(id="v1", description="", payload_html="<img src=x onerror=1>", payload_context="html"),
        Vector(id="v2", description="", payload_html="<b>ok</b>", payload_context="html"),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    calls: list[str] = []

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        calls.append(payload_html)
        return type("VR", (), {"executed": True, "details": "hit"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner, fail_fast=True)

    assert summary.total_cases == 1
    assert summary.total_executed == 1
    assert calls == ["<img src=x onerror=1>"]


def test_run_bench_wraps_href_payload_before_sanitizing() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(id="v1", description="", payload_html="javascript:alert(1)", payload_context="href"),
    ]

    seen_inputs: list[str] = []
    seen_payload_contexts: list[str] = []

    def sanitize(html: str) -> str:
        seen_inputs.append(html)
        # Simulate a sanitizer that strips javascript: to '#'
        return '<a href="#">x</a>'

    sanitizer = Sanitizer(name="s", description="", sanitize=sanitize)

    def fake_runner(*, payload_html: str, sanitized_html: str, payload_context: str, timeout_ms: int, **_kwargs):
        seen_payload_contexts.append(payload_context)
        # No execution
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert seen_inputs == ['<a href="javascript:alert(1)">x</a>']
    assert seen_payload_contexts == ["html"]


def test_run_bench_wraps_js_payload_before_sanitizing() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(id="v1", description="", payload_html="alert(1)", payload_context="js"),
    ]

    seen_inputs: list[str] = []
    seen_payload_contexts: list[str] = []

    def sanitize(html: str) -> str:
        seen_inputs.append(html)
        return html

    sanitizer = Sanitizer(name="s", description="", sanitize=sanitize)

    def fake_runner(*, payload_html: str, sanitized_html: str, payload_context: str, timeout_ms: int, **_kwargs):
        seen_payload_contexts.append(payload_context)
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert seen_inputs == ["<script>alert(1)</script>"]
    assert seen_payload_contexts == ["html"]


def test_run_bench_wraps_onerror_attr_payload_before_sanitizing() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(id="v1", description="", payload_html="alert(1)", payload_context="onerror_attr"),
    ]

    seen_inputs: list[str] = []
    seen_payload_contexts: list[str] = []

    def sanitize(html: str) -> str:
        seen_inputs.append(html)
        return html

    sanitizer = Sanitizer(name="s", description="", sanitize=sanitize)

    def fake_runner(*, payload_html: str, sanitized_html: str, payload_context: str, timeout_ms: int, **_kwargs):
        seen_payload_contexts.append(payload_context)
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert seen_inputs == ['<img src="nonexistent://x" onerror="alert(1)">']
    assert seen_payload_contexts == ["html"]
