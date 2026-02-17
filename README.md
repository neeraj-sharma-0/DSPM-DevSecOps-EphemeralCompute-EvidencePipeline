# DSPM + DevSecOps (#3): Evidence Pipelines for Ephemeral Compute (Serverless Included)

This repository is Post #3 in the DSPM series (following Zero Trust and Subnetting).

It demonstrates how **DSPM intelligence becomes enforceable inside DevSecOps** by producing **machine-verifiable evidence** for *policy, risk, drift,* and *destroy* — across both persistent and ephemeral compute, including **Serverless**.


**What you get**

**1) IaC posture checks (multi-plane)**
- Terraform scanning (VPC/network + storage + serverless patterns)
- Serverless framework YAML scanning (functions, triggers, env, VPC attachment)
- “Event trigger drift” detection (what events can invoke what compute)
- 
**2) DSPM risk normalization**
Deterministic risk scoring for:
- data sensitivity
- identity privilege breadth
- network egress surface
- trigger exposure (public/event-bus)
- logging/retention controls
  
**3) Evidence bundles (audit-hash + receipts)**
- Reproducible evidence bundle builder
- Hash manifest (SHA-256) for every artifact
- Signed-style “receipt” JSON for:
   - CREATE (baseline)
   - MAINTAIN (drift snapshots)
   - AUDIT (evidence pack)
   - DESTROY (closure proof)
  
**4) CI-style pipeline simulation**
A local pipeline runner that simulates:

- pre-commit posture gates
- PR checks
- release evidence packaging


**Repo layout**
.

├── src/dspm_devsecops/

│   ├── cli.py

│   ├── config.py

│   ├── iac/

│   │   ├── terraform_scan.py

│   │   ├── serverless_scan.py

│   │   └── trigger_graph.py

│   ├── risk/

│   │   ├── scoring.py

│   │   └── policy.py

│   ├── evidence/

│   │   ├── manifest.py

│   │   └── receipts.py

│   └── orchestration/

│       ├── pipeline.py

│       └── destroy.py

├── examples/

│   ├── iac/

│   │   ├── terraform/

│   │   ├── serverless/

│   │   └── bicep_gcp_samples/

│   └── data/

├── notebooks/

│   └── colab_cells.py

├── .github/workflows/ci.yml

└── scripts/

    └── run_demo.py


**Quickstart**
1) Create a venv and install deps
```
python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

2) Run the full pipeline demo (includes Serverless checks)
python scripts/run_demo.py

- Outputs are written to:


  - out/ (scan results, risk scores, trigger graph)
  - out/evidence/ (hash manifest + receipts)


**What “serverless included” means here**

This repo treats serverless as ephemeral compute risk and models:

- **identity → trigger → execution → data → logs**
- VPC-attached functions and indirect egress (NAT / endpoints)
- trigger surface (HTTP/API Gateway, event bus, queue, object events)
- lifecycle closure proof (trigger deregistration + IAM revocation + log retention)


**Series alignment**
- **Post #1** (Zero Trust): identity-centric trust boundaries
- **Post #2** (Subnetting): CIDR-aware blast radius + deterministic destroy
- **Post #3** (this repo): CI/CD enforcement + ephemeral compute governance (serverless)


**License**
MIT (see LICENSE).


**How to run**
```
python -m dspm_devsecops.cli --repo-root .
```
**Policy DSL**
See `policies/policies.yml` for rule syntax.

