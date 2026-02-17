# DSPM + DevSecOps: Ephemeral Compute Evidence Pipeline

Enterprise-style demonstration of a Data Security Posture Management
(DSPM) lifecycle integrated with DevSecOps CI gating for
Infrastructure-as-Code (IaC) and Serverless workloads.

------------------------------------------------------------------------

## What This Project Demonstrates

-   IaC scanning (Terraform + Serverless)
-   Canonical asset normalization
-   Deterministic risk computation
-   Policy-as-code gating
-   Evidence manifest generation (SHA256)
-   Lifecycle receipts (create / maintain / audit / destroy)
-   Destroy closure proof
-   CI simulation mode

------------------------------------------------------------------------

## Architecture Flow

IaC Scan → Normalize Assets → Compute Risk → Evaluate Policy DSL → Gate
(PASS/FAIL) → Generate Evidence → Lifecycle Receipts

Artifacts are written to `_ci_out/` when executed.

------------------------------------------------------------------------

## Quick Start

Clone the repository:

``` bash
git clone <your-repo-url>
cd DSPM-DevSecOps-EphemeralCompute-EvidencePipeline
```

Install dependencies (editable install required due to src-layout):

``` bash
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Run CI simulation mode:

``` bash
dspm-devsecops --repo-root . ci --out _ci_out
```

Alternative invocation:

``` bash
python -m dspm_devsecops.cli --repo-root . ci --out _ci_out
```

------------------------------------------------------------------------

## Expected Output Structure

    _ci_out/
    ├── scans/
    │   ├── terraform_findings.json
    │   └── serverless_findings.json
    ├── normalized_assets.json
    ├── risk_score_base.json
    ├── policy_results.json
    ├── gate_status.json
    ├── trigger_graph.json
    ├── destroy_closure.json
    └── evidence/
        ├── manifest.sha256.json
        ├── receipt_create.json
        ├── receipt_maintain.json
        ├── receipt_audit.json
        └── receipt_destroy.json

The gate result depends on policy rules defined in:

    policies/policies.yml

------------------------------------------------------------------------

## Notebooks

-   01_Quickstart_Evidence_Pipeline.ipynb
-   02_Policy_Gating_and_Risk.ipynb
-   03_CI_Simulation_Evidence_Artifacts.ipynb

Generate `_ci_out/` before running notebook #3.

------------------------------------------------------------------------

## Testing

``` bash
pytest -q
```

------------------------------------------------------------------------

## Security Notes

-   All data is synthetic.
-   No credentials or live cloud integrations are included.
-   Generated artifacts (`_ci_out/`) are not tracked in version control.

------------------------------------------------------------------------

## License

Add your preferred open-source license (e.g., MIT or Apache 2.0).
