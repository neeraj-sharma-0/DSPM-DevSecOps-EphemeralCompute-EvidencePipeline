import os
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class RepoPaths:
    root: Path
    examples_iac: Path
    out_dir: Path
    evidence_dir: Path

def default_paths(repo_root: Path) -> RepoPaths:
    # Optional override for CI/Colab runs
    override = os.environ.get("DSPM_OUT_DIR")
    out_dir = Path(override).resolve() if override else (repo_root / "out")
    return RepoPaths(
        root=repo_root,
        examples_iac=repo_root / "examples" / "iac",
        out_dir=out_dir,
        evidence_dir=out_dir / "evidence",
    )
