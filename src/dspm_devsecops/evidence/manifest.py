from __future__ import annotations
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

@dataclass(frozen=True)
class HashEntry:
    path: str
    sha256: str
    bytes: int

def sha256_file(fp: Path) -> HashEntry:
    h = hashlib.sha256()
    size = 0
    with fp.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return HashEntry(path=fp.as_posix(), sha256=h.hexdigest(), bytes=size)

def build_manifest(root: Path, include_globs: List[str]) -> Dict[str, object]:
    files: List[Path] = []
    for g in include_globs:
        files.extend(sorted(root.glob(g)))
    seen = set()
    entries: List[Dict[str, object]] = []
    for fp in files:
        if fp.is_dir():
            for f2 in sorted(fp.rglob("*")):
                if f2.is_file() and f2.as_posix() not in seen:
                    seen.add(f2.as_posix())
                    e = sha256_file(f2)
                    entries.append({"path": e.path, "sha256": e.sha256, "bytes": e.bytes})
        else:
            if fp.is_file() and fp.as_posix() not in seen:
                seen.add(fp.as_posix())
                e = sha256_file(fp)
                entries.append({"path": e.path, "sha256": e.sha256, "bytes": e.bytes})
    return {"entries": entries, "count": len(entries)}
