from __future__ import annotations

from dataclasses import dataclass
import importlib
from typing import Any
from typing import Literal


_MAX_PLAYWRIGHT_TIMEOUT_MS = 5000


def _looks_like_navigation_context_destroyed(exc: Exception) -> bool:
    msg = str(exc)
    return (
        "Execution context was destroyed" in msg
        or "most likely because of a navigation" in msg
    )


@dataclass(frozen=True, slots=True)
class VectorResult:
    executed: bool
    details: str


BrowserName = Literal["chromium", "firefox", "webkit"]


PayloadContext = Literal[
    "html",
    "html_head",
    "html_outer",
    "href",
    "js",
    "js_arg",
    "js_string",
    "js_string_double",
    "onerror_attr",
]


_HTML_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
                __XSSBENCH_PRELUDE__
    </head>
  <body>
    <div id=\"root\">__XSSBENCH_PAYLOAD__</div>
  </body>
</html>
"""


_HTML_HEAD_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
        __XSSBENCH_PAYLOAD__
    </head>
    <body>
        <div id=\"root\"></div>
    </body>
</html>
"""


_HTML_OUTER_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    __XSSBENCH_PAYLOAD__
</html>
"""


_HREF_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    <body>
        <a id=\"xssbench-link\" href=\"__XSSBENCH_PAYLOAD__\">x</a>
    </body>
</html>
"""


_JS_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    <body>
        <script>__XSSBENCH_PAYLOAD__</script>
    </body>
</html>
"""


_JS_ARG_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    <body>
        <script>setTimeout(function(){}, __XSSBENCH_PAYLOAD__);</script>
    </body>
</html>
"""


_JS_STRING_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    <body>
        <script>var __xssbench = '__XSSBENCH_PAYLOAD__';</script>
    </body>
</html>
"""


_JS_STRING_DOUBLE_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
        __XSSBENCH_PRELUDE__
    </head>
    <body>
        <script>var __xssbench = "__XSSBENCH_PAYLOAD__";</script>
    </body>
</html>
"""


_ONERROR_ATTR_TEMPLATE = """<!doctype html>
<html>
    <head>
        <meta charset=\"utf-8\">
        <base href=\"http://xssbench.local/\">
                __XSSBENCH_PRELUDE__
    </head>
    <body>
        <img id=\"xssbench-img\" src=\"nonexistent://x\" onerror=\"__XSSBENCH_PAYLOAD__\">
    </body>
</html>
"""


_XSSBENCH_PRELUDE_HTML = """<script>
(() => {
    try {
        if (!window.__xssbench) window.__xssbench = { executed: false, details: '' };
        const mark = (kind, args) => {
            try {
                if (window.__xssbench.executed) return;
                window.__xssbench.executed = true;
                const msg = (args && args.length) ? String(args[0]) : '';
                window.__xssbench.details = kind + ':' + msg;
            } catch { /* ignore */ }
        };

        window.alert = function(...args) { mark('alert', args); };
        window.confirm = function(...args) { mark('confirm', args); return true; };
        window.prompt = function(...args) { mark('prompt', args); return ''; };
    } catch { /* ignore */ }
})();
</script>"""


_TRIGGER_EVENTS_JS = """
() => {
  const root = document.getElementById('root');
  const scope = root || document;

  const elements = Array.from(scope.querySelectorAll('*'));
    const mouseEvents = ['mouseover', 'mouseenter', 'click'];
    const focusEvents = ['focus', 'focusin'];
    const directEvents = ['load', 'error'];

  for (const el of elements) {
        for (const type of mouseEvents) {
            try {
                el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of focusEvents) {
            try {
                el.dispatchEvent(new FocusEvent(type, { bubbles: true, cancelable: true }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

    for (const type of directEvents) {
      try {
        el.dispatchEvent(new Event(type));
      } catch { /* ignore */ }
    }

    try {
      if (typeof el.focus === 'function') el.focus();
    } catch { /* ignore */ }
  }
}
"""


_DETECT_JAVASCRIPT_URLS_JS = """
() => {
    const attrs = ['href', 'src', 'action', 'formaction', 'data'];
    const hits = [];

    const normalize = (value) => {
        if (value == null) return '';
        const s = String(value).toLowerCase();
        let out = '';
        for (let i = 0; i < s.length; i++) {
            // Remove ASCII whitespace/control chars (<= space) to normalize obfuscation.
            if (s.charCodeAt(i) <= 0x20) continue;
            out += s[i];
        }
        return out;
    };

    const elements = document.querySelectorAll('*');
    for (const el of elements) {
        for (const attr of attrs) {
            try {
                if (!el.hasAttribute(attr)) continue;
                const raw = el.getAttribute(attr);
                if (normalize(raw).startsWith('javascript:')) {
                    hits.push({ tag: (el.tagName || '').toLowerCase(), attr, value: raw });
                    if (hits.length >= 5) return hits;
                }
            } catch {
                // ignore
            }
        }
    }
    return hits;
}
"""


class BrowserHarness:
    def __init__(self, *, browser: BrowserName, headless: bool = True):
        self._browser_name = browser
        self._headless = headless
        self._pw_cm: Any | None = None
        self._pw: Any | None = None
        self._browser_instance: Any | None = None
        self._page: Any | None = None
        self._timeout_error: type[Exception] | None = None
        self._external_script_requests: list[str] = []
        self._navigation_requests: list[str] = []
        self._dialog_events: list[str] = []
        self._base_navigation_count: int = 0
        self._current_html: str = ""
        self._base_url: str = "http://xssbench.local/"

    def __enter__(self) -> "BrowserHarness":
        try:
            sync_api = importlib.import_module("playwright.sync_api")
            sync_playwright = sync_api.sync_playwright
            self._timeout_error = sync_api.TimeoutError
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Playwright is not installed. Install with: pip install -e '.[test]'"
            ) from exc

        self._pw_cm = sync_playwright()
        self._pw = self._pw_cm.__enter__()

        browser_type = {
            "chromium": self._pw.chromium,
            "firefox": self._pw.firefox,
            "webkit": self._pw.webkit,
        }[self._browser_name]

        try:
            launch_kwargs: dict[str, Any] = {"headless": self._headless}
            if self._browser_name == "chromium":
                launch_kwargs["args"] = [
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--mute-audio",
                ]
            self._browser_instance = browser_type.launch(**launch_kwargs)
        except Exception as exc:  # pragma: no cover
            message = str(exc)
            hint = (
                f"Failed to launch Playwright {self._browser_name}. "
                f"If the engine is installed, your host may be missing OS dependencies. "
                f"Try: playwright install-deps {self._browser_name} (or: playwright install-deps)."
            )
            raise RuntimeError(
                f"{hint}\nOriginal error: {message}\n"
                f"If the engine isn't installed yet, run: playwright install {self._browser_name}"
            ) from exc

        self._page = self._browser_instance.new_page()

        # Keep runtime low and avoid long stalls (Playwright defaults to ~30s).
        # Individual operations that pass an explicit timeout (e.g. our adaptive
        # per-vector waits) will still use their smaller timeouts.
        try:
            self._page.set_default_timeout(_MAX_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            pass
        try:
            self._page.set_default_navigation_timeout(_MAX_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            pass

        def _on_dialog(dialog) -> None:
            try:
                dialog_type = getattr(dialog, "type", "")
                dialog_message = getattr(dialog, "message", "")
                details = f"dialog:{dialog_type}:{dialog_message}"
            except Exception:
                details = "dialog"

            self._dialog_events.append(details)

            # Always handle dialogs to avoid deadlocks.
            try:
                if dialog_type == "prompt":
                    default_value = ""
                    try:
                        default_value = str(getattr(dialog, "default_value", "") or "")
                    except Exception:
                        default_value = ""
                    dialog.accept(default_value)
                else:
                    dialog.accept()
            except Exception:
                try:
                    dialog.dismiss()
                except Exception:
                    pass

        self._page.on("dialog", _on_dialog)

        def _on_frame_navigated(frame) -> None:
            try:
                url = frame.url
            except Exception:
                return
            if not url:
                return

            if url == self._base_url:
                # Initial navigation to the synthetic document is expected.
                # If we see subsequent navigations back to the same URL, that's
                # likely a META refresh / reload induced by the payload.
                self._base_navigation_count += 1
                if self._base_navigation_count > 1:
                    self._navigation_requests.append(url)
                return

            self._navigation_requests.append(url)

        self._page.on("framenavigated", _on_frame_navigated)

        def _route(route) -> None:
            req = route.request
            # Serve our synthetic document at a stable URL so scheme-relative URLs (//...) resolve.
            if req.resource_type == "document" and req.url == self._base_url:
                route.fulfill(status=200, content_type="text/html", body=self._current_html)
                return

            # If the payload causes a navigation (e.g. META refresh), treat that as execution.
            # We still keep the run deterministic by aborting the navigation request.
            if req.resource_type == "document":
                self._navigation_requests.append(req.url)

            # Deterministic by default: block all network.
            # If a payload attempts to fetch an external script, treat it as execution.
            if req.resource_type == "script" and req.url.startswith(("http://", "https://")):
                self._external_script_requests.append(req.url)

            route.abort()

        self._page.route("**/*", _route)

        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._browser_instance is not None:
                self._browser_instance.close()
        finally:
            if self._pw_cm is not None:
                self._pw_cm.__exit__(exc_type, exc, tb)

    def run(
        self,
        *,
        payload_html: str,
        sanitized_html: str,
        payload_context: PayloadContext = "html",
        timeout_ms: int = 1500,
    ) -> VectorResult:
        if self._page is None or self._timeout_error is None:
            raise RuntimeError("Harness not initialized")

        self._external_script_requests.clear()
        self._navigation_requests.clear()
        self._dialog_events.clear()
        self._base_navigation_count = 0

        template = {
            "html": _HTML_TEMPLATE,
            "html_head": _HTML_HEAD_TEMPLATE,
            "html_outer": _HTML_OUTER_TEMPLATE,
            "href": _HREF_TEMPLATE,
            "js": _JS_TEMPLATE,
            "js_arg": _JS_ARG_TEMPLATE,
            "js_string": _JS_STRING_TEMPLATE,
            "js_string_double": _JS_STRING_DOUBLE_TEMPLATE,
            "onerror_attr": _ONERROR_ATTR_TEMPLATE,
        }.get(payload_context)
        if template is None:
            raise ValueError(f"Unknown payload_context: {payload_context!r}")

        html = template.replace("__XSSBENCH_PAYLOAD__", sanitized_html)
        html = html.replace("__XSSBENCH_PRELUDE__", _XSSBENCH_PRELUDE_HTML)
        self._current_html = html
        # In WebKit, vectors that synchronously trigger a navigation (e.g. via `location = ...`)
        # can prevent the `load` event from ever settling, causing `goto(..., wait_until="load")`
        # to hang until Playwright's default 30s timeout.
        #
        # We only need a parsed DOM for our triggers and post-load checks, so `domcontentloaded`
        # is both faster and more stable across engines.
        try:
            self._page.goto(
                self._base_url,
                wait_until="domcontentloaded",
                timeout=_MAX_PLAYWRIGHT_TIMEOUT_MS,
            )
        except Exception as exc:
            # If a payload immediately triggers navigation, consider that execution.
            if self._timeout_error is not None and isinstance(exc, self._timeout_error):
                if self._navigation_requests:
                    urls = ", ".join(self._navigation_requests[:3])
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:{urls}; payload={payload_html!r}",
                    )
                if self._external_script_requests:
                    urls = ", ".join(self._external_script_requests[:3])
                    return VectorResult(
                        executed=True,
                        details=f"Executed: external-script:{urls}; payload={payload_html!r}",
                    )
                if self._dialog_events:
                    details = self._dialog_events[0]
                    return VectorResult(
                        executed=True,
                        details=f"Executed: {details}; payload={payload_html!r}",
                    )
                return VectorResult(
                    executed=True,
                    details=f"Executed: navigation:goto-timeout; payload={payload_html!r}",
                )

            if _looks_like_navigation_context_destroyed(exc):
                return VectorResult(
                    executed=True,
                    details=f"Executed: navigation:context-destroyed; payload={payload_html!r}",
                )
            raise

        def _hook_details() -> str:
            try:
                return str(
                    self._page.evaluate(
                        "() => (window.__xssbench && window.__xssbench.executed) ? String(window.__xssbench.details || '') : ''"
                    )
                    or ""
                )
            except Exception:
                return ""

        # Deterministic signal: if the DOM contains any `javascript:` URL attributes,
        # treat that as execution/risk even if a particular engine doesn't reliably
        # execute it for that element type.
        try:
            js_urls = self._page.evaluate(_DETECT_JAVASCRIPT_URLS_JS)
        except Exception:
            js_urls = []

        if js_urls:
            first = js_urls[0]
            return VectorResult(
                executed=True,
                details=(
                    "Executed: javascript-url:"
                    f"{first.get('tag')}[{first.get('attr')}]={first.get('value')}; payload={payload_html!r}"
                ),
            )

        hook = _hook_details()
        if hook:
            return VectorResult(
                executed=True,
                details=f"Executed: hook:{hook}; payload={payload_html!r}",
            )

        if self._dialog_events:
            details = self._dialog_events[0]
            return VectorResult(
                executed=True,
                details=f"Executed: {details}; payload={payload_html!r}",
            )

        if self._navigation_requests:
            urls = ", ".join(self._navigation_requests[:3])
            return VectorResult(
                executed=True,
                details=f"Executed: navigation:{urls}; payload={payload_html!r}",
            )

        if self._external_script_requests:
            urls = ", ".join(self._external_script_requests[:3])
            return VectorResult(
                executed=True,
                details=f"Executed: external-script:{urls}; payload={payload_html!r}",
            )

        if payload_context == "href":
            # `javascript:` URIs often require a real click gesture.
            try:
                self._page.click("#xssbench-link", no_wait_after=True, timeout=timeout_ms)
            except Exception:
                pass

            hook = _hook_details()
            if hook:
                return VectorResult(
                    executed=True,
                    details=f"Executed: hook:{hook}; payload={payload_html!r}",
                )
        else:
            try:
                self._page.evaluate(_TRIGGER_EVENTS_JS)
            except Exception as exc:
                if self._navigation_requests:
                    urls = ", ".join(self._navigation_requests[:3])
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:{urls}; payload={payload_html!r}",
                    )
                if _looks_like_navigation_context_destroyed(exc):
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:context-destroyed; payload={payload_html!r}",
                    )
                raise exc

            hook = _hook_details()
            if hook:
                return VectorResult(
                    executed=True,
                    details=f"Executed: hook:{hook}; payload={payload_html!r}",
                )

            # Ensure `javascript:`-ish links are clicked with a trusted gesture.
            try:
                anchors = self._page.query_selector_all("a[href], area[href]")
                for h in anchors:
                    try:
                        href = h.get_attribute("href") or ""
                        normalized = "".join(ch for ch in href.lower() if ch not in " \t\r\n\f\v")
                        if normalized.startswith("javascript:"):
                            h.click(timeout=timeout_ms, force=True)
                    except Exception:
                        continue
            except Exception:
                pass

        # Some payloads execute by causing a navigation rather than calling alert().
        # If we observed any document navigation attempt at any point, treat it as execution.
        if self._navigation_requests:
            urls = ", ".join(self._navigation_requests[:3])
            return VectorResult(
                executed=True,
                details=f"Executed: navigation:{urls}; payload={payload_html!r}",
            )

        # Fast path: most synchronous payloads will have already tripped the hook
        # (or a navigation/external-script signal). Only wait when asked.
        if self._timeout_error is None:  # pragma: no cover
            raise RuntimeError("Harness not initialized")

        if timeout_ms > 0:
            try:
                self._page.wait_for_function(
                    "() => (window.__xssbench && window.__xssbench.executed) === true",
                    timeout=timeout_ms,
                )
            except self._timeout_error:
                pass
            except Exception as exc:
                if self._navigation_requests:
                    urls = ", ".join(self._navigation_requests[:3])
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:{urls}; payload={payload_html!r}",
                    )
                if _looks_like_navigation_context_destroyed(exc):
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:context-destroyed; payload={payload_html!r}",
                    )
                raise exc

        hook = _hook_details()
        if hook:
            return VectorResult(
                executed=True,
                details=f"Executed: hook:{hook}; payload={payload_html!r}",
            )

        if self._dialog_events:
            details = self._dialog_events[0]
            return VectorResult(
                executed=True,
                details=f"Executed: {details}; payload={payload_html!r}",
            )

        return VectorResult(executed=False, details="No execution detected")


def run_vector(
    *,
    payload_html: str,
    sanitized_html: str,
    payload_context: PayloadContext = "html",
    timeout_ms: int = 1500,
) -> VectorResult:
    """Backward-compatible wrapper: runs in Chromium."""

    return run_vector_in_browser(
        payload_html=payload_html,
        sanitized_html=sanitized_html,
        payload_context=payload_context,
        browser="chromium",
        timeout_ms=timeout_ms,
    )


def run_vector_in_browser(
    *,
    payload_html: str,
    sanitized_html: str,
    payload_context: PayloadContext = "html",
    browser: BrowserName = "chromium",
    timeout_ms: int = 1500,
) -> VectorResult:
    """Run a single vector in the requested browser engine.

    This uses the same mechanics as `BrowserHarness`, but does not reuse the browser.
    """

    with BrowserHarness(browser=browser, headless=True) as harness:
        return harness.run(
            payload_html=payload_html,
            sanitized_html=sanitized_html,
            payload_context=payload_context,
            timeout_ms=timeout_ms,
        )
