from __future__ import annotations

import json
from pathlib import Path

from xssbench.check import check_candidates


def test_check_candidates_reports_tested_by_normalized_payload(tmp_path: Path) -> None:
    existing = [
        {
            "id": "e1",
            "description": "d",
            "payload_html": '<IMG SRC=x ONERROR=alert(1)>' ,
            "payload_context": "html",
        }
    ]

    candidates = [
        # Same thing, different casing/spacing that normalize_payload should canonicalize.
        {"payload_html": '<img src=x onerror = alert(1)>', "payload_context": "html"},
        # Something else.
        {"payload_html": "<b>ok</b>", "payload_context": "html"},
    ]

    p_existing = tmp_path / "vectors.json"
    p_existing.write_text(json.dumps(existing), encoding="utf-8")

    p_new = tmp_path / "incoming.json"
    p_new.write_text(json.dumps(candidates), encoding="utf-8")

    results = check_candidates(new_paths=[p_new], against_paths=[p_existing])
    assert [r.already_tested for r in results] == [True, False]
    assert results[0].matched and results[0].matched[0].vector_id == "e1"


def test_check_candidates_defaults_context_for_string_items(tmp_path: Path) -> None:
    existing = [
        {
            "id": "e1",
            "description": "d",
            "payload_html": "<b>x</b>",
            "payload_context": "html",
        }
    ]

    candidates = [
        "<b>x</b>",
    ]

    p_existing = tmp_path / "vectors.json"
    p_existing.write_text(json.dumps(existing), encoding="utf-8")

    p_new = tmp_path / "incoming.json"
    p_new.write_text(json.dumps(candidates), encoding="utf-8")

    results = check_candidates(new_paths=[p_new], against_paths=[p_existing])
    assert len(results) == 1
    assert results[0].payload_context == "html"
    assert results[0].already_tested is True


def test_check_candidates_respects_context(tmp_path: Path) -> None:
    existing = [
        {
            "id": "e1",
            "description": "d",
            "payload_html": "alert(1)",
            "payload_context": "js",
        }
    ]

    # Same payload but different context should be treated as not-yet-tested.
    candidates = [
        {"payload_html": "alert(1)", "payload_context": "html"},
    ]

    p_existing = tmp_path / "vectors.json"
    p_existing.write_text(json.dumps(existing), encoding="utf-8")

    p_new = tmp_path / "incoming.json"
    p_new.write_text(json.dumps(candidates), encoding="utf-8")

    results = check_candidates(new_paths=[p_new], against_paths=[p_existing])
    assert len(results) == 1
    assert results[0].already_tested is False
