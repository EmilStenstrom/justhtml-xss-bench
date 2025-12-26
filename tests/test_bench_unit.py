from __future__ import annotations

import json
from pathlib import Path
import tempfile

from xssbench.bench import run_bench, Vector
from xssbench.sanitizers import Sanitizer


def test_run_bench_uses_runner_and_counts_executed() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<img src=x onerror=1>",
            payload_context="html",
            expected_tags=("img",),
        ),
        Vector(
            id="v2",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
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
    assert summary.total_lossy == 0
    assert [r.vector_id for r in summary.results if r.executed] == ["v1"]


def test_run_bench_external_script_request_counts_as_xss() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
        Vector(
            id="v2",
            description="",
            payload_html='<script src="https://example.com/x.js"></script>',
            payload_context="html",
            expected_tags=("script",),
        ),
        Vector(
            id="v3",
            description="",
            payload_html="<b>ok2</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        if "script src" in sanitized_html:
            return type("VR", (), {"executed": True, "details": "external script"})()
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 3
    assert summary.total_errors == 0
    assert summary.total_lossy == 0
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
                "expected_tags": [],
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


def test_load_vectors_ignores_unknown_meta_keys() -> None:
    from xssbench.bench import load_vectors

    payload = {
        "schema": "xssbench.vectorfile.v1",
        "meta": {
            "tool": "xssbench",
            "source_url": "https://example.invalid/",
            "some_unknown_flag": True,
            "license": {
                "spdx": "MIT",
                "url": "https://spdx.org/licenses/MIT.html",
                "file": "vectors/example-LICENSE.txt",
            },
        },
        "vectors": [
            {
                "id": "v1",
                "expected_tags": [],
                "description": "d",
                "payload_html": "<b>ok</b><img src=x onerror=alert(1)>",
                "payload_context": "html",
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        vectors = load_vectors([p])

    assert vectors[0].expected_tags == ()


def test_run_bench_fail_fast_stops_after_first_xss() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<img src=x onerror=1>",
            payload_context="html",
            expected_tags=("img",),
        ),
        Vector(
            id="v2",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    calls: list[str] = []

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        calls.append(payload_html)
        return type("VR", (), {"executed": True, "details": "hit"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner, fail_fast=True)

    assert summary.total_cases == 1
    assert summary.total_executed == 1
    assert summary.total_lossy == 0
    assert calls == ["<img src=x onerror=1>"]


def test_run_bench_skips_href_without_attribute_cleaning_support() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="javascript:alert(1)",
            payload_context="href",
        ),
    ]

    seen_inputs: list[str] = []
    called = {"n": 0}

    def sanitize(html: str) -> str:
        seen_inputs.append(html)
        # Simulate a sanitizer that strips javascript: to '#'
        return '<a href="#">x</a>'

    sanitizer = Sanitizer(name="s", description="", sanitize=sanitize)

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 0
    assert summary.results[0].outcome == "skip"
    assert called["n"] == 0
    assert seen_inputs == []


def test_load_vectors_forbids_expected_tags_for_href_context() -> None:
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
                "payload_html": "javascript:alert(1)",
                "payload_context": "href",
                "expected_tags": ["a"],
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        try:
            load_vectors([p])
            raise AssertionError("Expected load_vectors to reject expected_tags for href")
        except ValueError as exc:
            assert "expected_tags is not allowed" in str(exc)


def test_load_vectors_forbids_expected_tags_for_js_context() -> None:
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
                "payload_html": "alert(1)",
                "payload_context": "js",
                "expected_tags": [],
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        try:
            load_vectors([p])
            raise AssertionError("Expected load_vectors to reject expected_tags for js")
        except ValueError as exc:
            assert "expected_tags is not allowed" in str(exc)


def test_run_bench_runs_href_if_sanitizer_supports_it() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="javascript:alert(1)",
            payload_context="href",
        ),
    ]

    seen_inputs: list[str] = []
    seen_payload_contexts: list[str] = []
    seen_sanitized_html: list[str] = []

    def sanitize(value: str) -> str:
        seen_inputs.append(value)
        return "#"

    sanitizer = Sanitizer(
        name="s",
        description="",
        sanitize=sanitize,
        supported_contexts={"html", "html_head", "html_outer", "href"},
    )

    def fake_runner(*, sanitized_html: str, payload_context: str, **_kwargs):
        seen_payload_contexts.append(payload_context)
        seen_sanitized_html.append(sanitized_html)
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_cases == 1
    assert summary.results[0].outcome == "pass"
    assert seen_inputs == ["javascript:alert(1)"]
    assert seen_payload_contexts == ["href"]
    assert seen_sanitized_html == ["#"]


def test_run_bench_does_not_wrap_js_payload_before_sanitizing() -> None:
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

    def fake_runner(
        *,
        payload_html: str,
        sanitized_html: str,
        payload_context: str,
        timeout_ms: int,
        **_kwargs,
    ):
        seen_payload_contexts.append(payload_context)
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 0
    assert seen_inputs == ["alert(1)"]
    assert seen_payload_contexts == ["js"]


def test_run_bench_skips_unsupported_contexts() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(id="v1", description="", payload_html="alert(1)", payload_context="js"),
        Vector(
            id="v2",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
    ]

    sanitizer = Sanitizer(
        name="htmlonly",
        description="",
        sanitize=lambda html: html,
        supported_contexts={"html", "href", "html_head", "html_outer", "onerror_attr"},
    )

    summary = run_bench(
        vectors=vectors,
        sanitizers=[sanitizer],
        runner=lambda **_: type("VR", (), {"executed": False, "details": "no"})(),
    )

    assert summary.total_cases == 2
    assert summary.total_lossy == 0
    outcomes = {r.vector_id: r.outcome for r in summary.results}
    assert outcomes["v1"] == "skip"
    assert outcomes["v2"] == "pass"


def test_run_bench_wraps_onerror_attr_payload_before_sanitizing() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="alert(1)",
            payload_context="onerror_attr",
            expected_tags=("img",),
        ),
    ]

    seen_inputs: list[str] = []
    seen_payload_contexts: list[str] = []

    def sanitize(html: str) -> str:
        seen_inputs.append(html)
        return html

    sanitizer = Sanitizer(name="s", description="", sanitize=sanitize)

    def fake_runner(
        *,
        payload_html: str,
        sanitized_html: str,
        payload_context: str,
        timeout_ms: int,
        **_kwargs,
    ):
        seen_payload_contexts.append(payload_context)
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 0
    assert seen_inputs == ['<img src="nonexistent://x" onerror="alert(1)">']
    assert seen_payload_contexts == ["html"]


def test_run_bench_marks_missing_expected_tags_as_lossy_and_skips_runner() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>keep</b>",
            payload_context="html",
            expected_tags=("b",),
        ),
    ]

    sanitizer = Sanitizer(name="s", description="", sanitize=lambda _html: "keep")

    called = {"n": 0}

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_executed == 0
    assert summary.total_errors == 0
    assert summary.total_lossy == 1
    assert called["n"] == 0
    assert summary.results[0].outcome == "lossy"


def test_run_bench_empty_expected_tags_means_no_tags_allowed() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>keep</b>",
            payload_context="html",
            expected_tags=(),
        ),
    ]

    sanitizer = Sanitizer(name="s", description="", sanitize=lambda _html: "<b>still here</b>")

    called = {"n": 0}

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 1
    assert called["n"] == 0
    assert summary.results[0].outcome == "lossy"
