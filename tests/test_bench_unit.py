from __future__ import annotations

import json
from pathlib import Path
import tempfile

from xssbench.bench import ExpectedTag, run_bench, Vector
from xssbench.sanitizers import Sanitizer


def test_run_bench_uses_runner_and_counts_executed() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<img src=x onerror=1>",
            payload_context="html",
            expected_tags=(ExpectedTag("img", frozenset({"src"})),),
        ),
        Vector(
            id="v2",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
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
            expected_tags=(ExpectedTag("b"),),
        ),
        Vector(
            id="v2",
            description="",
            payload_html='<img src="https://example.com/x.js">',
            payload_context="html",
            expected_tags=(ExpectedTag("img", frozenset({"src"})),),
        ),
        Vector(
            id="v3",
            description="",
            payload_html="<b>ok2</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
        ),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        if 'src="https://example.com/x.js"' in sanitized_html:
            return type("VR", (), {"executed": True, "details": "external script"})()
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 3
    assert summary.total_errors == 0
    assert summary.total_lossy == 0
    assert summary.total_executed == 1
    assert [r.vector_id for r in summary.results if r.outcome == "xss"] == ["v2"]


def test_run_bench_external_script_takes_precedence_over_external_signal() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html='<script src="https://example.com/x.js"></script>',
            payload_context="html",
            expected_tags=None,
        )
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        # Simulate the harness observing both an external fetch and an external script.
        # XSS must win.
        return type(
            "VR",
            (),
            {
                "executed": True,
                "details": "Executed: external-script:https://example.com/x.js; External fetch: image:https://example.com/x.png",
                "signal": "http_leak",
            },
        )()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_cases == 1
    assert summary.results[0].outcome == "xss"


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


def test_load_vectors_accepts_bare_tag_expected_tags() -> None:
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
                "expected_tags": ["img"],
                "description": "d",
                "payload_html": "<img src=x>",
                "payload_context": "html",
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        vectors = load_vectors([p])

    assert vectors[0].expected_tags == (ExpectedTag("img"),)


def test_load_vectors_rejects_empty_bracket_expected_tags() -> None:
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
                "expected_tags": ["img[]"],
                "description": "d",
                "payload_html": "<img>",
                "payload_context": "html",
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        try:
            load_vectors([p])
            raise AssertionError("Expected load_vectors to reject empty-bracket expected_tags")
        except ValueError as exc:
            assert "must not use empty brackets" in str(exc)


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


def test_load_vectors_can_ignore_expected_tags_via_options() -> None:
    from xssbench.bench import load_vectors

    payload = {
        "schema": "xssbench.vectorfile.v1",
        "options": {"expected_tags": "ignore"},
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
                "payload_html": "<img src=x>",
                "payload_context": "html",
            }
        ],
    }

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "vectors.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        vectors = load_vectors([p])

    assert vectors[0].expected_tags is None


def test_run_bench_fail_fast_stops_after_first_xss() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<img src=x onerror=1>",
            payload_context="html",
            expected_tags=(ExpectedTag("img", frozenset({"src"})),),
        ),
        Vector(
            id="v2",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
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


def test_expected_tags_are_ordered_and_match_distinct_elements_in_order() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html='<div id="a"><div id="b"><div class="c">X</div></div></div>',
            payload_context="html",
            expected_tags=(
                ExpectedTag("div", frozenset({"id"})),
                ExpectedTag("div", frozenset({"id"})),
                ExpectedTag("div", frozenset({"class"})),
            ),
        )
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*_args, **_kwargs):
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_lossy == 0


def test_expected_tags_require_multiple_matches_for_duplicates() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html='<div id="a"><div style="color:red">X</div></div>',
            payload_context="html",
            expected_tags=(
                ExpectedTag("div", frozenset({"id"})),
                ExpectedTag("div", frozenset({"id"})),
            ),
        )
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*_args, **_kwargs):
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_lossy == 1
    assert summary.results[0].outcome == "pass"
    assert summary.results[0].lossy is True
    assert "div[id]" in summary.results[0].lossy_details


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
            expected_tags=(ExpectedTag("b"),),
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
            expected_tags=(ExpectedTag("img", frozenset({"src"})),),
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


def test_run_bench_marks_missing_expected_tags_as_lossy_but_still_runs_runner() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>keep</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
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
    assert called["n"] == 1
    assert summary.results[0].outcome == "pass"
    assert summary.results[0].lossy is True
    assert "Missing expected tags" in summary.results[0].lossy_details


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
    assert called["n"] == 1
    assert summary.results[0].outcome == "pass"
    assert summary.results[0].lossy is True
    assert "Expected no tags" in summary.results[0].lossy_details


def test_run_bench_skips_expected_tags_checks_when_none() -> None:
    from xssbench.bench import run_bench, Vector
    from xssbench.sanitizers import Sanitizer

    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=None,
        ),
    ]
    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda html: html)

    def fake_runner(*, payload_html: str, sanitized_html: str, timeout_ms: int, **_kwargs):
        return type("VR", (), {"executed": False, "details": "nope"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 0
    assert summary.results[0].lossy is False


def test_run_bench_expected_tags_exact_matches_attrs() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<a href='#'>x</a>",
            payload_context="html",
            expected_tags=(ExpectedTag("a", frozenset({"href"})),),
        ),
    ]

    # Exact semantics: the first surviving element must match the expectation.
    sanitizer = Sanitizer(
        name="s",
        description="",
        sanitize=lambda _html: "<a href='#'>y</a>",
    )

    called = {"n": 0}

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 0
    assert called["n"] == 1
    assert summary.results[0].outcome == "pass"


def test_run_bench_expected_tags_exact_fails_on_extra_tags() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>ok</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
        ),
    ]

    sanitizer = Sanitizer(
        name="s",
        description="",
        sanitize=lambda _html: "<b>ok</b><i>extra</i>",
    )

    called = {"n": 0}

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)

    assert summary.total_cases == 1
    assert summary.total_lossy == 1
    assert called["n"] == 1
    assert summary.results[0].outcome == "pass"
    assert summary.results[0].lossy is True
    assert "unexpected" in summary.results[0].lossy_details


def test_run_bench_bare_tag_disallows_attributes() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<a href='#'>x</a>",
            payload_context="html",
            expected_tags=(ExpectedTag("a"),),
        ),
    ]

    sanitizer = Sanitizer(
        name="s",
        description="",
        sanitize=lambda _html: "<a href='#'>y</a>",
    )

    called = {"n": 0}

    def fake_runner(**_kwargs):
        called["n"] += 1
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_cases == 1
    assert summary.total_lossy == 1
    assert called["n"] == 1
    assert summary.results[0].outcome == "pass"
    assert summary.results[0].lossy is True
    assert "a" in summary.results[0].lossy_details

    sanitizer2 = Sanitizer(
        name="s2",
        description="",
        sanitize=lambda _html: "<a>y</a>",
    )
    summary2 = run_bench(vectors=vectors, sanitizers=[sanitizer2], runner=fake_runner)
    assert summary2.total_cases == 1
    assert summary2.total_lossy == 0
    assert summary2.results[0].outcome == "pass"


def test_run_bench_can_be_both_lossy_and_xss() -> None:
    vectors = [
        Vector(
            id="v1",
            description="",
            payload_html="<b>expected</b>",
            payload_context="html",
            expected_tags=(ExpectedTag("b"),),
        ),
    ]

    sanitizer = Sanitizer(name="noop", description="", sanitize=lambda _html: "<img src=x onerror=1>")

    def fake_runner(*, sanitized_html: str, **_kwargs):
        if "onerror" in sanitized_html:
            return type("VR", (), {"executed": True, "details": "hit"})()
        return type("VR", (), {"executed": False, "details": "no"})()

    summary = run_bench(vectors=vectors, sanitizers=[sanitizer], runner=fake_runner)
    assert summary.total_cases == 1
    assert summary.total_lossy == 1
    assert summary.total_executed == 1
    assert summary.results[0].outcome == "xss"
    assert summary.results[0].lossy is True
