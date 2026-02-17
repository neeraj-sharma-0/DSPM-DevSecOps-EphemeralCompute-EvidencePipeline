# %% [markdown]
# # DSPM + DevSecOps (#3) — Colab-Style Walkthrough (Cells)
#
# This file is intentionally written as a **cell-based Python script** (`# %%`) so it can be pasted into Colab/Jupyter.
# It runs the demo pipeline and then inspects the generated evidence bundle.

# %% [markdown]
# ## 1) Install deps (Colab)
# Uncomment in Colab:
# ```
# !pip -q install -r requirements.txt
# ```

# %% 
from pathlib import Path
import json

# %% 
# Run pipeline
import subprocess, sys
subprocess.check_call([sys.executable, "scripts/run_demo.py"])

# %% 
# Inspect risk score
risk = json.loads(Path("out/risk_score.json").read_text())
risk

# %% 
# Inspect trigger graph
tg = json.loads(Path("out/trigger_graph.json").read_text())
tg["nodes"][:5], tg["edges"][:5]

# %% 
# Inspect evidence manifest
manifest = json.loads(Path("out/evidence/manifest.sha256.json").read_text())
manifest["count"]
