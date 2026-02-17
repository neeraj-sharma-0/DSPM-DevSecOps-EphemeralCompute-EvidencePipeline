from pathlib import Path
from dspm_devsecops.orchestration.pipeline import run_pipeline

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[1]
    run_pipeline(repo_root)
