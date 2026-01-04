from __future__ import annotations

from xssbench.bench import Vector
from xssbench.cli import _normalize_id_args, _select_vectors_by_id


def test_normalize_id_args_allows_csv() -> None:
    assert _normalize_id_args(["a,b", "c"]) == ["a", "b", "c"]


def test_select_vectors_by_id_preserves_id_order_and_reports_missing() -> None:
    vectors = [
        Vector(id="v1", description="", payload_html="", payload_context="html", expected_tags=[]),
        Vector(id="v2", description="", payload_html="", payload_context="html", expected_tags=[]),
        Vector(id="v3", description="", payload_html="", payload_context="html", expected_tags=[]),
    ]

    selected, missing = _select_vectors_by_id(vectors, ["v3", "missing", "v1", "v3"])

    assert [v.id for v in selected] == ["v3", "v1"]
    assert missing == ["missing"]
