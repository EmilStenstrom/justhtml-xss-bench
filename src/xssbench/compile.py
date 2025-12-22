from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import unicodedata
from typing import Iterable


@dataclass(frozen=True, slots=True)
class CompileStats:
    expanded_vectors: int
    written_vectors: int
    skipped_unuseful_duplicates: int


def _canonical_for_unuseful_duplicate(payload: str) -> str:
    # Only normalize things that are almost never meaningful for sanitizer
    # behavior (file formatting / copy-paste artifacts). We intentionally do NOT
    # unescape entities, lowercase, reorder attributes, etc., because those
    # differences can be important bypass variants.
    s = str(payload).replace("\x00", "")
    s = unicodedata.normalize("NFKC", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s.strip()


def compile_vectors(
    *,
    paths: Iterable[str | Path],
    out_path: str | Path,
    dedupe_unuseful: bool = True,
) -> CompileStats:
    allowed_contexts: set[str] = {
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

    out: list[dict[str, str]] = []
    expanded = 0
    skipped = 0

    seen_id_ctx: set[tuple[str, str]] = set()
    seen_payload_ctx: set[tuple[str, str]] = set()

    for raw_path in paths:
        path = Path(raw_path)
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
            description = str(item["description"])

            for payload_context in contexts:
                payload_context = str(payload_context)
                if payload_context not in allowed_contexts:
                    raise ValueError(
                        f"Invalid payload_context {payload_context!r} in {path}. "
                        f"Allowed: {sorted(allowed_contexts)}"
                    )

                expanded += 1

                id_key = (vector_id, payload_context)
                if id_key in seen_id_ctx:
                    raise ValueError(
                        f"Duplicate vector id+context: {vector_id}@{payload_context}"
                    )
                seen_id_ctx.add(id_key)

                if dedupe_unuseful:
                    payload_key = (
                        payload_context,
                        _canonical_for_unuseful_duplicate(payload_html),
                    )
                    if payload_key in seen_payload_ctx:
                        skipped += 1
                        continue
                    seen_payload_ctx.add(payload_key)

                out.append(
                    {
                        "id": vector_id,
                        "description": description,
                        "payload_html": payload_html,
                        "payload_context": payload_context,
                    }
                )

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return CompileStats(
        expanded_vectors=expanded,
        written_vectors=len(out),
        skipped_unuseful_duplicates=skipped,
    )
