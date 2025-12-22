from __future__ import annotations

import json
from pathlib import Path

from xssbench.portswigger import ensure_portswigger_refs_file


def test_ensure_portswigger_refs_file_is_noop_if_exists(tmp_path: Path) -> None:
    repo_root = tmp_path
    out_dir = repo_root / ".xssbench"
    out_dir.mkdir()
    out_path = out_dir / "portswigger-xss-cheatsheet-data-refs.json"
    out_path.write_text("{}", encoding="utf-8")

    got = ensure_portswigger_refs_file(repo_root=repo_root, against_paths=[])
    assert got == out_path


def test_portswigger_refs_file_generation_works_with_local_repo(tmp_path: Path, monkeypatch) -> None:
    # Create a fake repo checkout in the expected vendor location.
    repo_root = tmp_path
    vendor_repo = repo_root / ".xssbench" / "vendor" / "portswigger-xss-cheatsheet-data"
    (vendor_repo / "json").mkdir(parents=True)

    # Fake a commit.
    def fake_run_git(args, cwd=None):
        class CP:
            returncode = 0
            stdout = "deadbeef\n"
            stderr = ""

        # Only rev-parse needs stdout.
        return CP()

    import xssbench.portswigger as ps

    monkeypatch.setattr(ps, "_run_git", lambda args, cwd=None: fake_run_git(args, cwd=cwd))

    # One payload in PortSwigger, one existing vector matching it.
    (vendor_repo / "json" / "classic.json").write_text(
        json.dumps(
            {
                "onload": {
                    "description": "d",
                    "tags": [
                        {
                            "tag": "img",
                            "code": "<img src=x onerror=alert(1)>",
                            "browsers": ["chrome"],
                            "interaction": False,
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    existing_vectors = repo_root / "vectors.json"
    existing_vectors.write_text(
        json.dumps(
            [
                {
                    "id": "e1",
                    "description": "d",
                    "payload_html": "<IMG SRC=x ONERROR=alert(1)>",
                    "payload_context": "html",
                }
            ]
        ),
        encoding="utf-8",
    )

    out_path = ensure_portswigger_refs_file(repo_root=repo_root, against_paths=[existing_vectors])
    data = json.loads(out_path.read_text("utf-8"))

    assert data["schema"] == "xssbench.vectorfile.refs.v1"
    assert data["meta"]["source_commit"] == "deadbeef"
    # Matched, so no new refs.
    assert data["refs"] == []
