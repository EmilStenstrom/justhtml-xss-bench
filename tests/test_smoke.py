from __future__ import annotations

import json
from pathlib import Path

import pytest

from xssbench.harness import run_vector
from xssbench.sanitizers import noop


VECTORS_PATH = Path(__file__).resolve().parents[1] / "vectors" / "smoke.json"


def _load_vectors() -> list[dict[str, str]]:
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert data.get("schema") == "xssbench.vectorfile.v1"
    vectors = data.get("vectors")
    assert isinstance(vectors, list)
    return vectors  # type: ignore[return-value]


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["id"])
def test_smoke_no_execution(vector: dict[str, str]) -> None:
    payload_html = vector["payload_html"]
    payload_context = vector.get("payload_context", "html")
    sanitized_html = noop(payload_html)

    try:
        result = run_vector(
            payload_html=payload_html,
            sanitized_html=sanitized_html,
            payload_context=payload_context,  # type: ignore[arg-type]
            timeout_ms=1500,
        )
    except RuntimeError as exc:
        pytest.skip(str(exc))

    if vector["id"] == "css-background-external":
        assert result.signal == "http_leak", result.details
        assert result.executed is False, result.details
    else:
        assert result.executed is True, result.details


def test_external_script_fetch_counts_as_executed() -> None:
    payload_html = '<script src="https://example.com/x.js"></script>'
    sanitized_html = noop(payload_html)

    try:
        result = run_vector(
            payload_html=payload_html,
            sanitized_html=sanitized_html,
            timeout_ms=1500,
        )
    except RuntimeError as exc:
        # Playwright missing / browser engine not installed / missing OS deps.
        pytest.skip(str(exc))

    assert result.executed is True


def test_css_background_image_external_fetch_counts_as_external_signal() -> None:
    # Ensure the element has non-zero size so browsers actually attempt to
    # fetch/paint the background image.
    payload_html = "<div style=\"width:10px;height:10px;background-image:url('http://google.com/x.png')\">x</div>"
    sanitized_html = noop(payload_html)

    try:
        result = run_vector(
            payload_html=payload_html,
            sanitized_html=sanitized_html,
            payload_context="html",
            timeout_ms=2500,
        )
    except RuntimeError as exc:
        # Playwright missing / browser engine not installed / missing OS deps.
        pytest.skip(str(exc))

    assert result.signal == "http_leak", result.details
    assert result.executed is False, result.details


def test_lxml_html_clean_does_not_add_wrapper_div() -> None:
    from xssbench.sanitizers import available_sanitizers

    sanitizers = available_sanitizers()
    s = sanitizers.get("lxml_html_clean")
    if s is None:
        return

    out = s.sanitize("<b>Hello</b>")
    assert out.strip().lower() == "<b>hello</b>"


def test_lxml_html_clean_empty_input_is_ok() -> None:
    from xssbench.sanitizers import available_sanitizers

    sanitizers = available_sanitizers()
    s = sanitizers.get("lxml_html_clean")
    if s is None:
        return

    assert s.sanitize("") == ""
    assert s.sanitize("   ") == ""
