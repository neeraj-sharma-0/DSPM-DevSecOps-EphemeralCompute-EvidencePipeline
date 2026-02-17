import argparse
import os
from pathlib import Path

from dspm_devsecops.orchestration.pipeline import run_pipeline

def _set_out(out: str | None) -> None:
    if out:
        os.environ["DSPM_OUT_DIR"] = str(Path(out).resolve())

def main() -> None:
    p = argparse.ArgumentParser(prog="dspm-devsecops")
    p.add_argument("--repo-root", default=".", help="Path to repo root (contains examples/ etc.)")

    sub = p.add_subparsers(dest="cmd", required=False)

    # Default: run full pipeline to repo-root/out
    sub.add_parser("run", help="Run the full pipeline (default)")

    p_demo = sub.add_parser("demo", help="Run pipeline writing outputs to --out (safe local demo)")
    p_demo.add_argument("--out", required=True, help="Output directory for artifacts")

    p_ci = sub.add_parser("ci", help="Run pipeline writing outputs to --out (CI simulation)")
    p_ci.add_argument("--out", required=True, help="Output directory for artifacts")

    args = p.parse_args()
    repo_root = Path(args.repo_root).resolve()

    if args.cmd in (None, "run"):
        run_pipeline(repo_root)
        return

    if args.cmd in ("demo", "ci"):
        _set_out(args.out)
        run_pipeline(repo_root)
        return

    raise SystemExit(f"Unknown command: {args.cmd}")

if __name__ == "__main__":
    main()
