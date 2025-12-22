from __future__ import annotations

import json
from pathlib import Path

import pytest

from xssbench.compile import compile_vectors


def _read_compiled(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert all(isinstance(x, dict) for x in data)
    return data  # type: ignore[return-value]


def test_compile_vectors_skips_exact_duplicate_payloads_same_context(tmp_path: Path) -> None:
    payload = {
        "schema": "xssbench.vectorfile.v1",
        "meta": {"tool": "xssbench"},
        "vectors": [
            {"id": "a", "description": "d", "payload_html": "alert(1)", "payload_context": "js"},
            {"id": "b", "description": "d", "payload_html": "alert(1)", "payload_context": "js"},
            {"id": "c", "description": "d", "payload_html": "\nalert(1)\r\n", "payload_context": "js"},
            {"id": "d", "description": "d", "payload_html": "alert(1)", "payload_context": "html"},
        ],
    }

    p = tmp_path / "in.json"
    out = tmp_path / "out.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    stats = compile_vectors(paths=[p], out_path=out)
    compiled = _read_compiled(out)

    assert stats.expanded_vectors == 4
    assert stats.written_vectors == 2
    assert stats.skipped_unuseful_duplicates == 2

    # Keep first occurrence in the context; skip later duplicates.
    assert [(v["id"], v["payload_context"]) for v in compiled] == [("a", "js"), ("d", "html")]


def test_compile_vectors_keeps_obfuscation_variants(tmp_path: Path) -> None:
    payload = [
        {
            "id": "v1",
            "description": "tab entity",
            "payload_html": '<a href="jav&#x09;ascript:alert(1)">x</a>',
            "payload_context": "html",
        },
        {
            "id": "v2",
            "description": "literal spaces",
            "payload_html": '<a href="jav   ascript:alert(1)">x</a>',
            "payload_context": "html",
        },
    ]

    p = tmp_path / "in.json"
    out = tmp_path / "out.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    compile_vectors(paths=[p], out_path=out)
    compiled = _read_compiled(out)
    assert [v["id"] for v in compiled] == ["v1", "v2"]


def test_compile_vectors_still_errors_on_duplicate_id_context(tmp_path: Path) -> None:
    payload = [
        {"id": "dup", "description": "d", "payload_html": "a", "payload_context": "html"},
        {"id": "dup", "description": "d", "payload_html": "a", "payload_context": "html"},
    ]

    p = tmp_path / "in.json"
    out = tmp_path / "out.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=r"Duplicate vector id\+context"):
        compile_vectors(paths=[p], out_path=out)
