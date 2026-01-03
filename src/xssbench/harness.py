from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import importlib
import importlib.resources
from typing import Any
from typing import Literal
from urllib.parse import urlsplit


_MAX_PLAYWRIGHT_TIMEOUT_MS = 5000


def render_html_document(*, sanitized_html: str, payload_context: "PayloadContext") -> str:
    if payload_context == "http_leak":
        template = _template_for_http_leak_payload(sanitized_html)
    else:
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
    return html


def _is_ignorable_navigation_url(url: str) -> bool:
    # Chromium shows this for aborted/blocked navigations.
    if url.startswith("chrome-error://"):
        return True
    # Can appear transiently during navigations.
    if url == "about:blank":
        return True
    return False


def _filter_navigation_urls_for_execution(
    urls: list[str],
    *,
    base_url: str,
    payload_context: "PayloadContext",
    expected_href_click_url: str | None,
) -> list[str]:
    out: list[str] = []
    for url in urls:
        if not url:
            continue
        if _is_ignorable_navigation_url(url):
            continue
        # Ignore same-document hash navigations like `http://xssbench.local/#...`.
        if url.startswith(base_url + "#"):
            continue

        if payload_context == "href" and expected_href_click_url:
            # In href-context we intentionally click the link.
            # A plain navigation to the link target is not XSS; it just means the URL was allowed.
            if url == expected_href_click_url:
                continue
        out.append(url)
    return out


def _looks_like_navigation_context_destroyed(exc: Exception) -> bool:
    msg = str(exc)
    return "Execution context was destroyed" in msg or "most likely because of a navigation" in msg


@dataclass(frozen=True, slots=True)
class VectorResult:
    executed: bool
    details: str
    # Optional classification hint for callers.
    # - "none": no execution/risk detected
    # - "http_leak": non-script external network request attempt detected
    signal: str = "none"


BrowserName = Literal["chromium", "firefox", "webkit"]


PayloadContext = Literal[
    "html",
    "html_head",
    "html_outer",
    "http_leak",
    "href",
    "js",
    "js_arg",
    "js_string",
    "js_string_double",
    "onerror_attr",
]


def _template_for_http_leak_payload(sanitized_html: str) -> str:
    # Heuristic placement for HTTP-leak primitives.
    # We keep the vector payloads raw but still want head-only tags like <meta>
    # and <link> to land in <head> when possible.
    import re

    m = re.search(r"<\s*([A-Za-z][A-Za-z0-9:-]*)", sanitized_html)
    tag = m.group(1).lower() if m else ""

    if tag in {"meta", "base", "link", "style", "title"}:
        return _HTML_HEAD_TEMPLATE
    if tag in {"html", "body", "frameset"}:
        return _HTML_OUTER_TEMPLATE
    return _HTML_TEMPLATE


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


@lru_cache(maxsize=None)
def _read_js_asset_text(name: str) -> str:
    return importlib.resources.files("xssbench").joinpath("js").joinpath(name).read_text(encoding="utf-8")


def _script_tag(js: str) -> str:
    return f"<script>\n{js}\n</script>"


_XSSBENCH_PRELUDE_HTML = _script_tag(_read_js_asset_text("prelude.js").strip("\n"))

_TRIGGER_EVENTS_JS = _read_js_asset_text("trigger_events.js")

_DETECT_JAVASCRIPT_URLS_JS = _read_js_asset_text("detect_javascript_urls.js")


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
        self._external_network_requests: list[tuple[str, str]] = []
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
            raise RuntimeError("Playwright is not installed. Install with: pip install -e '.[test]'") from exc

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

            # Ignore same-document hash navigations like `http://xssbench.local/#...`.
            # These are often benign side-effects of anchor interactions and are
            # not a reliable XSS execution signal.
            if url.startswith(self._base_url + "#"):
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
            base = urlsplit(self._base_url)
            req_parts = urlsplit(req.url)
            is_http = req_parts.scheme in {"http", "https"}
            is_same_origin = (
                is_http
                and bool(req_parts.netloc)
                and req_parts.scheme == base.scheme
                and req_parts.netloc == base.netloc
            )
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

            # Record other external http(s) request attempts (images, stylesheets, XHR/fetch, fonts, etc).
            # This is useful as a strong "risk" signal even when it isn't immediate JS execution.
            if (
                req.resource_type not in {"document", "script"}
                and req.url.startswith(("http://", "https://"))
                and not is_same_origin
            ):
                try:
                    rtype = str(getattr(req, "resource_type", "") or "")
                except Exception:
                    rtype = ""
                self._external_network_requests.append((rtype, req.url))

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

        # Best-effort cleanup: the harness reuses a single Page across vectors.
        # If a previous vector scheduled work (e.g. setInterval) that triggers
        # a navigation slightly later, it can be mis-attributed to the next
        # vector run.
        try:
            self._page.evaluate(
                "() => { try { window.__xssbench && window.__xssbench.cleanup && window.__xssbench.cleanup(); } catch (e) {} }"
            )
        except Exception:
            pass

        self._external_script_requests.clear()
        self._external_network_requests.clear()
        self._navigation_requests.clear()
        self._dialog_events.clear()
        self._base_navigation_count = 0

        expected_href_click_url: str | None = None
        first_external_network: tuple[str, str] | None = None

        def _execution_navigation_urls() -> list[str]:
            return _filter_navigation_urls_for_execution(
                self._navigation_requests,
                base_url=self._base_url,
                payload_context=payload_context,
                expected_href_click_url=expected_href_click_url,
            )

        self._current_html = render_html_document(sanitized_html=sanitized_html, payload_context=payload_context)
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
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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
                if self._external_network_requests:
                    rtype, url = self._external_network_requests[0]
                    return VectorResult(
                        executed=False,
                        details=f"External fetch: {rtype}:{url}; payload={payload_html!r}",
                        signal="http_leak",
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

        # The harness reuses a single Page across vectors. If the previous vector
        # triggered an in-flight reload/navigation to the base URL, Chromium can
        # report an extra `framenavigated` to the same URL during this initial
        # `goto()`. That would otherwise be mis-attributed to the current vector.
        #
        # We only discard navigations to the base URL here; navigations to other
        # URLs are still meaningful execution signals.
        try:
            if self._navigation_requests:
                self._navigation_requests[:] = [u for u in self._navigation_requests if u != self._base_url]
            if self._base_navigation_count < 1:
                self._base_navigation_count = 1
        except Exception:
            pass

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
                    "Executed: dangerous-url:"
                    f"{first.get('tag')}[{first.get('attr')}]={first.get('value')}; payload={payload_html!r}"
                ),
            )

        hook = _hook_details()
        if hook:
            return VectorResult(
                executed=True,
                details=f"Executed: hook:{hook}; payload={payload_html!r}",
            )

        if self._external_script_requests:
            urls = ", ".join(self._external_script_requests[:3])
            return VectorResult(
                executed=True,
                details=f"Executed: external-script:{urls}; payload={payload_html!r}",
            )

        if self._external_network_requests:
            first_external_network = self._external_network_requests[0]

        if payload_context == "href":
            try:
                # Use the resolved absolute link target so relative values match what the
                # browser will navigate to.
                expected_href_click_url = str(
                    self._page.evaluate(
                        "() => { const a = document.getElementById('xssbench-link'); return a ? String(a.href || '') : ''; }"
                    )
                    or ""
                )
            except Exception:
                expected_href_click_url = None

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
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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
                        # Use resolved `href` so we match what the browser will actually execute.
                        resolved_href = ""
                        try:
                            resolved_href = str(self._page.evaluate("(el) => String(el.href || '')", h) or "")
                        except Exception:
                            resolved_href = h.get_attribute("href") or ""
                        normalized = resolved_href.strip().lower()
                        if normalized.startswith("javascript:"):
                            h.click(timeout=timeout_ms, force=True)
                    except Exception:
                        continue
            except Exception:
                pass

        # Some payloads execute by causing a navigation rather than calling alert().
        # If we observed any document navigation attempt at any point, treat it as execution.
        exec_nav = _execution_navigation_urls()
        if exec_nav:
            urls = ", ".join(exec_nav[:3])
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
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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

        if first_external_network is not None:
            rtype, url = first_external_network
            return VectorResult(
                executed=False,
                details=f"External fetch: {rtype}:{url}; payload={payload_html!r}",
                signal="http_leak",
            )

        return VectorResult(executed=False, details="No execution detected")


class AsyncBrowserHarness:
    def __init__(self, *, browser: BrowserName, headless: bool = True):
        self._browser_name = browser
        self._headless = headless
        self._pw_cm: Any | None = None
        self._pw: Any | None = None
        self._browser_instance: Any | None = None
        self._page: Any | None = None
        self._timeout_error: type[Exception] | None = None
        self._external_script_requests: list[str] = []
        self._external_network_requests: list[tuple[str, str]] = []
        self._navigation_requests: list[str] = []
        self._dialog_events: list[str] = []
        self._base_navigation_count: int = 0
        self._current_html: str = ""
        self._base_url: str = "http://xssbench.local/"

    async def __aenter__(self) -> "AsyncBrowserHarness":
        try:
            async_api = importlib.import_module("playwright.async_api")
            async_playwright = async_api.async_playwright
            self._timeout_error = async_api.TimeoutError
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("Playwright is not installed. Install with: pip install -e '.[test]'") from exc

        self._pw_cm = async_playwright()
        self._pw = await self._pw_cm.__aenter__()

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
            self._browser_instance = await browser_type.launch(**launch_kwargs)
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

        self._page = await self._browser_instance.new_page()

        try:
            self._page.set_default_timeout(_MAX_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            pass
        try:
            self._page.set_default_navigation_timeout(_MAX_PLAYWRIGHT_TIMEOUT_MS)
        except Exception:
            pass

        import asyncio

        def _on_dialog(dialog) -> None:
            try:
                dialog_type = getattr(dialog, "type", "")
                dialog_message = getattr(dialog, "message", "")
                details = f"dialog:{dialog_type}:{dialog_message}"
            except Exception:
                details = "dialog"

            self._dialog_events.append(details)

            async def _handle() -> None:
                try:
                    if dialog_type == "prompt":
                        default_value = ""
                        try:
                            default_value = str(getattr(dialog, "default_value", "") or "")
                        except Exception:
                            default_value = ""
                        await dialog.accept(default_value)
                    else:
                        await dialog.accept()
                except Exception:
                    try:
                        await dialog.dismiss()
                    except Exception:
                        pass

            try:
                asyncio.get_running_loop().create_task(_handle())
            except Exception:
                # If we can't schedule it, best effort: do nothing.
                pass

        self._page.on("dialog", _on_dialog)

        def _on_frame_navigated(frame) -> None:
            try:
                url = frame.url
            except Exception:
                return
            if not url:
                return

            if url.startswith(self._base_url + "#"):
                return

            if url == self._base_url:
                self._base_navigation_count += 1
                if self._base_navigation_count > 1:
                    self._navigation_requests.append(url)
                return

            self._navigation_requests.append(url)

        self._page.on("framenavigated", _on_frame_navigated)

        async def _route(route) -> None:
            req = route.request
            base = urlsplit(self._base_url)
            req_parts = urlsplit(req.url)
            is_http = req_parts.scheme in {"http", "https"}
            is_same_origin = (
                is_http
                and bool(req_parts.netloc)
                and req_parts.scheme == base.scheme
                and req_parts.netloc == base.netloc
            )
            if req.resource_type == "document" and req.url == self._base_url:
                await route.fulfill(status=200, content_type="text/html", body=self._current_html)
                return

            if req.resource_type == "document":
                self._navigation_requests.append(req.url)

            if req.resource_type == "script" and req.url.startswith(("http://", "https://")):
                self._external_script_requests.append(req.url)

            if (
                req.resource_type not in {"document", "script"}
                and req.url.startswith(("http://", "https://"))
                and not is_same_origin
            ):
                try:
                    rtype = str(getattr(req, "resource_type", "") or "")
                except Exception:
                    rtype = ""
                self._external_network_requests.append((rtype, req.url))

            await route.abort()

        await self._page.route("**/*", _route)

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            if self._browser_instance is not None:
                await self._browser_instance.close()
        finally:
            if self._pw_cm is not None:
                await self._pw_cm.__aexit__(exc_type, exc, tb)

    async def run(
        self,
        *,
        payload_html: str,
        sanitized_html: str,
        payload_context: PayloadContext = "html",
        timeout_ms: int = 1500,
    ) -> VectorResult:
        if self._page is None or self._timeout_error is None:
            raise RuntimeError("Harness not initialized")

        # Best-effort cleanup: the harness reuses a single Page across vectors.
        # If a previous vector scheduled work (e.g. setInterval) that triggers
        # a navigation slightly later, it can be mis-attributed to the next
        # vector run.
        try:
            await self._page.evaluate(
                "() => { try { window.__xssbench && window.__xssbench.cleanup && window.__xssbench.cleanup(); } catch (e) {} }"
            )
        except Exception:
            pass

        self._external_script_requests.clear()
        self._external_network_requests.clear()
        self._navigation_requests.clear()
        self._dialog_events.clear()
        self._base_navigation_count = 0

        first_external_network: tuple[str, str] | None = None

        expected_href_click_url: str | None = None

        def _execution_navigation_urls() -> list[str]:
            return _filter_navigation_urls_for_execution(
                self._navigation_requests,
                base_url=self._base_url,
                payload_context=payload_context,
                expected_href_click_url=expected_href_click_url,
            )

        html = render_html_document(sanitized_html=sanitized_html, payload_context=payload_context)
        self._current_html = html

        try:
            await self._page.goto(
                self._base_url,
                wait_until="domcontentloaded",
                timeout=_MAX_PLAYWRIGHT_TIMEOUT_MS,
            )
        except Exception as exc:
            if self._timeout_error is not None and isinstance(exc, self._timeout_error):
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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
                if self._external_network_requests:
                    rtype, url = self._external_network_requests[0]
                    return VectorResult(
                        executed=False,
                        details=f"External fetch: {rtype}:{url}; payload={payload_html!r}",
                        signal="http_leak",
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

        # See sync harness `run()` for rationale.
        try:
            if self._navigation_requests:
                self._navigation_requests[:] = [u for u in self._navigation_requests if u != self._base_url]
            if self._base_navigation_count < 1:
                self._base_navigation_count = 1
        except Exception:
            pass

        async def _hook_details() -> str:
            try:
                return str(
                    (
                        await self._page.evaluate(
                            "() => (window.__xssbench && window.__xssbench.executed) ? String(window.__xssbench.details || '') : ''"
                        )
                    )
                    or ""
                )
            except Exception:
                return ""

        try:
            js_urls = await self._page.evaluate(_DETECT_JAVASCRIPT_URLS_JS)
        except Exception:
            js_urls = []

        if js_urls:
            first = js_urls[0]
            return VectorResult(
                executed=True,
                details=(
                    "Executed: dangerous-url:"
                    f"{first.get('tag')}[{first.get('attr')}]={first.get('value')}; payload={payload_html!r}"
                ),
            )

        hook = await _hook_details()
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

        exec_nav = _execution_navigation_urls()
        if exec_nav:
            urls = ", ".join(exec_nav[:3])
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

        if self._external_network_requests:
            first_external_network = self._external_network_requests[0]

        if payload_context == "href":
            try:
                expected_href_click_url = str(
                    (
                        await self._page.evaluate(
                            "() => { const a = document.getElementById('xssbench-link'); return a ? String(a.href || '') : ''; }"
                        )
                    )
                    or ""
                )
            except Exception:
                expected_href_click_url = None

            try:
                await self._page.click("#xssbench-link", no_wait_after=True, timeout=timeout_ms)
            except Exception:
                pass

            hook = await _hook_details()
            if hook:
                return VectorResult(
                    executed=True,
                    details=f"Executed: hook:{hook}; payload={payload_html!r}",
                )
        else:
            try:
                await self._page.evaluate(_TRIGGER_EVENTS_JS)
            except Exception as exc:
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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

            hook = await _hook_details()
            if hook:
                return VectorResult(
                    executed=True,
                    details=f"Executed: hook:{hook}; payload={payload_html!r}",
                )

            try:
                anchors = await self._page.query_selector_all("a[href], area[href]")
                for h in anchors:
                    try:
                        resolved_href = ""
                        try:
                            resolved_href = str((await self._page.evaluate("(el) => String(el.href || '')", h)) or "")
                        except Exception:
                            resolved_href = (await h.get_attribute("href")) or ""
                        normalized = resolved_href.strip().lower()
                        if normalized.startswith("javascript:"):
                            await h.click(timeout=timeout_ms, force=True)
                    except Exception:
                        continue
            except Exception:
                pass

        exec_nav = _execution_navigation_urls()
        if exec_nav:
            urls = ", ".join(exec_nav[:3])
            return VectorResult(
                executed=True,
                details=f"Executed: navigation:{urls}; payload={payload_html!r}",
            )

        if timeout_ms > 0:
            try:
                await self._page.wait_for_function(
                    "() => (window.__xssbench && window.__xssbench.executed) === true",
                    timeout=timeout_ms,
                )
            except self._timeout_error:
                pass
            except Exception as exc:
                exec_nav = _execution_navigation_urls()
                if exec_nav:
                    urls = ", ".join(exec_nav[:3])
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
                if self._external_network_requests:
                    rtype, url = self._external_network_requests[0]
                    return VectorResult(
                        executed=False,
                        details=f"External fetch: {rtype}:{url}; payload={payload_html!r}",
                        signal="http_leak",
                    )
                if _looks_like_navigation_context_destroyed(exc):
                    return VectorResult(
                        executed=True,
                        details=f"Executed: navigation:context-destroyed; payload={payload_html!r}",
                    )
                raise exc

        hook = await _hook_details()
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

        if first_external_network is not None:
            rtype, url = first_external_network
            return VectorResult(
                executed=False,
                details=f"External fetch: {rtype}:{url}; payload={payload_html!r}",
                signal="http_leak",
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
