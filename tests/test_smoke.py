from pathlib import Path
import json
from dspm_devsecops.orchestration.pipeline import run_pipeline

def test_pipeline_smoke(tmp_path):
    # copy minimal repo bits? For demo, run against the real repo structure by locating project root.
    repo_root = Path(__file__).resolve().parents[1]
    run_pipeline(repo_root)
    assert (repo_root / "out" / "risk_score.json").exists()
    risk = json.loads((repo_root / "out" / "risk_score.json").read_text())
    assert 0 <= risk["normalized_0_100"] <= 100
