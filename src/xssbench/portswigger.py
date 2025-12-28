from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Iterable

from .bench import load_vectors
from .normalize import normalize_payload


_PORTSWIGGER_REPO_URL = "https://github.com/PortSwigger/xss-cheatsheet-data"


def _vectors_out_path(*, repo_root: Path) -> Path:
    return repo_root / "vectors" / "portswigger-xss-cheatsheet-data.json"


def _run_git(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd is not None else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _ensure_repo_clone(*, vendor_dir: Path) -> Path:
    repo_dir = vendor_dir / "portswigger-xss-cheatsheet-data"

    if (repo_dir / "json").exists():
        return repo_dir

    # If something exists but is incomplete/corrupt, remove it.
    if repo_dir.exists():
        for p in sorted(repo_dir.rglob("*"), reverse=True):
            try:
                if p.is_file() or p.is_symlink():
                    p.unlink()
                else:
                    p.rmdir()
            except Exception:
                # Best-effort cleanup; if it fails, we'll fall back to cloning to a new dir.
                pass
        try:
            repo_dir.rmdir()
        except Exception:
            pass

    vendor_dir.mkdir(parents=True, exist_ok=True)

    cp = _run_git(["clone", "--depth", "1", _PORTSWIGGER_REPO_URL, str(repo_dir)])
    if cp.returncode != 0:
        raise RuntimeError(
            "Failed to clone PortSwigger repo. "
            "Ensure `git` is installed and network access is available. "
            f"stderr={cp.stderr.strip()}"
        )

    return repo_dir


def _get_commit(repo_dir: Path) -> str:
    cp = _run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    if cp.returncode != 0:
        raise RuntimeError(f"Failed to read PortSwigger repo commit: {cp.stderr.strip()}")
    return cp.stdout.strip()


def _build_new_vectors(
    *,
    repo_dir: Path,
    against_paths: Iterable[str | Path],
    expectations: dict[str, list[str]],
) -> tuple[str, dict[str, int], list[dict]]:
    # Existing tested vectors in this repo.
    existing: set[tuple[str, str]] = set()

    # Filter out the file we are about to generate, and the expectations file.
    filtered_paths = [
        p
        for p in against_paths
        if Path(p).name not in ("portswigger-xss-cheatsheet-data.json", "portswigger-expectations.json")
    ]

    for v in load_vectors(filtered_paths):
        existing.add((v.payload_context, normalize_payload(v.payload_html)))

    # Extract candidates from PortSwigger's json/*.json
    json_dir = repo_dir / "json"
    paths = sorted(json_dir.glob("*.json"))

    candidates_total = 0
    seen_norm: set[tuple[str, str]] = set()
    matched = 0
    new = 0
    vectors: list[dict] = []

    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(data, dict):
            continue

        for top_key, entry in data.items():
            if not isinstance(entry, dict):
                continue

            tags = entry.get("tags")
            if not isinstance(tags, list):
                continue

            for tag_index, tag_entry in enumerate(tags):
                if not isinstance(tag_entry, dict):
                    continue

                code = tag_entry.get("code")
                if not isinstance(code, str) or not code.strip():
                    continue

                candidates_total += 1

                payload_context = "html"
                norm = normalize_payload(code)
                key = (payload_context, norm)

                if key in seen_norm:
                    continue
                seen_norm.add(key)

                if key in existing:
                    matched += 1
                    continue

                new += 1
                sha = hashlib.sha256(norm.encode("utf-8")).hexdigest()
                vector_id = f"portswigger-{sha[:12]}"

                # Allow looking up expectations by stable location ID (filename#key#index)
                # so they survive payload updates.
                stable_id = f"{path.name}#{top_key}#{tag_index}"
                expected = expectations.get(vector_id)
                if expected is None:
                    expected = expectations.get(stable_id, [])

                vectors.append(
                    {
                        "id": vector_id,
                        "description": (
                            f"PortSwigger xss-cheatsheet-data {path.name}#{top_key} "
                            f"tag_index={tag_index} tag={tag_entry.get('tag')!s}"
                        ),
                        "payload_html": code,
                        "payload_context": payload_context,
                        # PortSwigger entries are attack payloads; by default we
                        # expect sanitization to remove all markup.
                        "expected_tags": expected,
                    }
                )

    source_commit = _get_commit(repo_dir)
    counts = {
        "candidates_total": candidates_total,
        "candidates_unique_normalized": len(seen_norm),
        "matched_existing_html": matched,
        "new_not_in_existing_html": new,
    }

    return source_commit, counts, vectors


def ensure_portswigger_vectors_file(
    *,
    repo_root: Path,
    against_paths: Iterable[str | Path],
) -> Path:
    """Ensure a PortSwigger-derived vector pack exists under `vectors/`.

    This is a first-run convenience that clones PortSwigger's repo locally and
    writes a normal `xssbench.vectorfile.v1` file containing *new* candidates
    (not already covered by `against_paths`).

    The output is intended to be git-ignored because upstream does not provide
    a license for redistributing payload contents.
    """

    out_path = _vectors_out_path(repo_root=repo_root)
    if out_path.exists():
        return out_path

    vendor_dir = repo_root / ".xssbench" / "vendor"
    repo_dir = _ensure_repo_clone(vendor_dir=vendor_dir)

    expectations_path = repo_root / "vectors" / "portswigger-expectations.json"
    expectations: dict[str, list[str]] = {}
    if expectations_path.exists():
        try:
            expectations = json.loads(expectations_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    source_commit, counts, vectors = _build_new_vectors(
        repo_dir=repo_dir, against_paths=against_paths, expectations=expectations
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema": "xssbench.vectorfile.v1",
        "meta": {
            "tool": "xssbench",
            "source_url": _PORTSWIGGER_REPO_URL,
            "source_commit": source_commit,
            "license_note": "Upstream repo states no license is provided; do not redistribute payload contents.",
            "counts": counts,
        },
        "vectors": vectors,
    }

    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    return out_path
