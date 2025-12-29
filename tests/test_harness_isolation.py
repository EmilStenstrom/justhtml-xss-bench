from __future__ import annotations

import time

import pytest

from xssbench.harness import BrowserHarness


def test_previous_vector_timer_does_not_leak_navigation() -> None:
    """A timer scheduled by one vector must not affect the next vector run.

    Without cleanup, a payload that schedules repeated navigations (e.g. via
    setInterval) can cause the *next* vector to be marked as executed even if
    its sanitized output is benign.
    """

    try:
        with BrowserHarness(browser="chromium", headless=True) as h:
            payload1 = "setInterval(() => { try { location.href = 'http://xssbench.local/'; } catch(e) {} }, 5)"
            r1 = h.run(payload_html=payload1, sanitized_html=payload1, payload_context="js", timeout_ms=50)
            assert r1.executed is True

            # Give any leaked timers a chance to fire.
            time.sleep(0.05)

            payload2 = '<noscript onmouseout="alert(1)">test</noscript>'
            r2 = h.run(payload_html=payload2, sanitized_html="test", payload_context="html", timeout_ms=0)

    except RuntimeError as exc:
        # Playwright missing / browser engine not installed / missing OS deps.
        pytest.skip(str(exc))

    assert r2.executed is False, r2.details
