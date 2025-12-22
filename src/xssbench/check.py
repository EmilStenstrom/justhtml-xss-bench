from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable, Iterator

from .normalize import normalize_payload


@dataclass(frozen=True, slots=True)
class Occurrence:
    file: str
    vector_id: str
    payload_context: str
    payload_html: str


@dataclass(frozen=True, slots=True)
class CheckResult:
    file: str
    index: int
    payload_context: str
    payload_html: str
    already_tested: bool
    matched: list[Occurrence]


_ALLOWED_CONTEXTS: set[str] = {
    "html",
    "html_head",
    "html_outer",
    "href",
    "js",
    "js_arg",
    "js_string",
    "js_string_double",
    "onerror_attr",
}


def _iter_vector_items(path: Path) -> Iterator[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if "vectors" not in data:
            raise ValueError(f"Vector file object must contain a 'vectors' key: {path}")
        data = data["vectors"]

    if not isinstance(data, list):
        raise ValueError(
            f"Vector file must contain a JSON list, or an object with 'vectors': {path}"
        )

    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"Vector items must be JSON objects: {path}")
        yield item


def iter_occurrences(paths: Iterable[str | Path]) -> Iterator[Occurrence]:
    for raw_path in paths:
        path = Path(raw_path)
        for item in _iter_vector_items(path):
            missing = {"id", "description", "payload_html"} - set(item.keys())
            if missing:
                raise ValueError(f"Vector missing keys {sorted(missing)}: {path}")

            raw_context = item.get("payload_context")
            if raw_context is None:
                contexts: list[str] = ["html"]
            elif isinstance(raw_context, str):
                contexts = [raw_context]
            elif isinstance(raw_context, list):
                if not raw_context:
                    raise ValueError(f"payload_context list must be non-empty: {path}")
                if not all(isinstance(x, str) for x in raw_context):
                    raise ValueError(f"payload_context list must contain only strings: {path}")
                contexts = list(raw_context)
            else:
                raise ValueError(
                    f"payload_context must be a string or list of strings (got {type(raw_context)!r}): {path}"
                )

            vector_id = str(item["id"])
            payload_html = str(item["payload_html"])

            for payload_context in contexts:
                payload_context = str(payload_context)
                if payload_context not in _ALLOWED_CONTEXTS:
                    raise ValueError(
                        f"Invalid payload_context {payload_context!r} in {path}. "
                        f"Allowed: {sorted(_ALLOWED_CONTEXTS)}"
                    )
                yield Occurrence(
                    file=str(path),
                    vector_id=vector_id,
                    payload_context=payload_context,
                    payload_html=payload_html,
                )


def _iter_candidates(path: Path) -> Iterator[tuple[int, str, str]]:
    """Yield (index, payload_context, payload_html) from a candidate file.

    Supported formats:
    - JSON list of strings (payload_html, context defaults to 'html')
    - JSON list of objects with keys:
        - payload_html (required)
        - payload_context (optional, default 'html')
    - JSON object wrapper with "vectors": [...] using the same object format

    NOTE: candidate objects may optionally include "id" and "description"; we ignore them.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "vectors" in data:
        data = data["vectors"]

    if not isinstance(data, list):
        raise ValueError(
            f"Candidate file must be a JSON list (or object with 'vectors'): {path}"
        )

    for i, item in enumerate(data):
        if isinstance(item, str):
            yield (i, "html", item)
            continue

        if not isinstance(item, dict):
            raise ValueError(f"Candidate items must be strings or objects: {path}")

        if "payload_html" not in item:
            raise ValueError(f"Candidate item missing payload_html: {path}")

        ctx = item.get("payload_context", "html")
        if not isinstance(ctx, str):
            raise ValueError(f"Candidate payload_context must be a string: {path}")
        if ctx not in _ALLOWED_CONTEXTS:
            raise ValueError(
                f"Invalid candidate payload_context {ctx!r} in {path}. Allowed: {sorted(_ALLOWED_CONTEXTS)}"
            )
        yield (i, ctx, str(item["payload_html"]))


def check_candidates(
    *,
    new_paths: Iterable[str | Path],
    against_paths: Iterable[str | Path],
) -> list[CheckResult]:
    # Build lookup of existing tested vectors.
    by_norm: dict[tuple[str, str], list[Occurrence]] = {}
    for occ in iter_occurrences(against_paths):
        key = (occ.payload_context, normalize_payload(occ.payload_html))
        by_norm.setdefault(key, []).append(occ)

    results: list[CheckResult] = []
    for raw_path in new_paths:
        path = Path(raw_path)
        for index, ctx, payload_html in _iter_candidates(path):
            key = (ctx, normalize_payload(payload_html))
            matched = by_norm.get(key, [])
            results.append(
                CheckResult(
                    file=str(path),
                    index=index,
                    payload_context=ctx,
                    payload_html=payload_html,
                    already_tested=bool(matched),
                    matched=matched,
                )
            )

    return results
