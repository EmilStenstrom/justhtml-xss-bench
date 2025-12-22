from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Iterable

from .check import iter_occurrences
from .normalize import normalize_payload


_PORTSWIGGER_REPO_URL = "https://github.com/PortSwigger/xss-cheatsheet-data"


@dataclass(frozen=True, slots=True)
class PortSwiggerRefsStats:
    candidates_total: int
    candidates_unique_normalized: int
    matched_existing_html: int
    new_not_in_existing_html: int
    source_commit: str


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


def _build_new_refs(*, repo_dir: Path, against_paths: Iterable[str | Path]) -> tuple[PortSwiggerRefsStats, list[dict]]:
    # Existing tested vectors in this repo.
    existing: set[tuple[str, str]] = set()
    for occ in iter_occurrences(against_paths):
        existing.add((occ.payload_context, normalize_payload(occ.payload_html)))

    # Extract candidates from PortSwigger's json/*.json
    json_dir = repo_dir / "json"
    paths = sorted(json_dir.glob("*.json"))

    candidates_total = 0
    seen_norm: set[tuple[str, str]] = set()
    matched = 0
    new = 0
    refs: list[dict] = []

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

                refs.append(
                    {
                        "source_path": f"json/{path.name}",
                        "source_key": str(top_key),
                        "tag_index": tag_index,
                        "tag": tag_entry.get("tag"),
                        "browsers": tag_entry.get("browsers"),
                        "interaction": tag_entry.get("interaction"),
                        "payload_context": payload_context,
                        "normalized_sha256": sha,
                    }
                )

    source_commit = _get_commit(repo_dir)

    stats = PortSwiggerRefsStats(
        candidates_total=candidates_total,
        candidates_unique_normalized=len(seen_norm),
        matched_existing_html=matched,
        new_not_in_existing_html=new,
        source_commit=source_commit,
    )

    return stats, refs


def ensure_portswigger_refs_file(
    *,
    repo_root: Path,
    against_paths: Iterable[str | Path],
) -> Path:
    """Ensure `.xssbench/portswigger-xss-cheatsheet-data-refs.json` exists.

    This is a first-run convenience that clones PortSwigger's repo locally and
    generates a refs-only artifact (no payload contents) for the patterns that
    are not already covered by this repo's vector packs.

    The output is stored under `.xssbench/` (git-ignored).
    """

    out_dir = repo_root / ".xssbench"
    out_path = out_dir / "portswigger-xss-cheatsheet-data-refs.json"
    if out_path.exists():
        return out_path

    vendor_dir = out_dir / "vendor"
    repo_dir = _ensure_repo_clone(vendor_dir=vendor_dir)

    stats, refs = _build_new_refs(repo_dir=repo_dir, against_paths=against_paths)

    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema": "xssbench.vectorfile.refs.v1",
        "meta": {
            "tool": "xssbench",
            "source_url": _PORTSWIGGER_REPO_URL,
            "source_commit": stats.source_commit,
            "license_note": "Upstream repo states no license is provided; do not redistribute payload contents.",
            "counts": {
                "candidates_total": stats.candidates_total,
                "candidates_unique_normalized": stats.candidates_unique_normalized,
                "matched_existing_html": stats.matched_existing_html,
                "new_not_in_existing_html": stats.new_not_in_existing_html,
            },
        },
        "refs": refs,
    }

    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return out_path
