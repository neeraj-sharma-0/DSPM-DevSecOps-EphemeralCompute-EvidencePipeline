from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml
from rich.console import Console
from rich.table import Table

from dspm_devsecops.config import default_paths
from dspm_devsecops.iac.terraform_scan import scan_terraform_dir
from dspm_devsecops.iac.serverless_scan import scan_serverless_yaml
from dspm_devsecops.iac.trigger_graph import TriggerEdge, build_trigger_graph, graph_to_json
from dspm_devsecops.risk.scoring import score_findings, adjust_risk
from dspm_devsecops.normalization.cloud_map import normalize_resource_type
from dspm_devsecops.classification.pii import classify_text
from dspm_devsecops.tenancy.model import TenantModel, infer_cross_tenant
from dspm_devsecops.policy_dsl.evaluator import evaluate_policies, gate
from dspm_devsecops.evidence.manifest import build_manifest
from dspm_devsecops.evidence.receipts import receipt, write_receipt
from dspm_devsecops.orchestration.destroy import simulate_destroy

console = Console()

def _load_tenant_model(repo_root: Path) -> TenantModel:
    yml = repo_root / "examples" / "tenancy" / "tenants.yml"
    data = yaml.safe_load(yml.read_text(encoding="utf-8"))
    tenants = list(data.get("tenants", []))
    asset_tenant = dict(data.get("asset_tenant", {}))
    principal_tenant = dict(data.get("principal_tenant", {}))
    return TenantModel(tenants=tenants, asset_tenant=asset_tenant, principal_tenant=principal_tenant)

def _load_policies(repo_root: Path) -> List[Dict[str, Any]]:
    yml = repo_root / "policies" / "policies.yml"
    data = yaml.safe_load(yml.read_text(encoding="utf-8"))
    return list(data.get("policies", []))

def _load_synthetic_records(repo_root: Path) -> List[Dict[str, Any]]:
    p = repo_root / "examples" / "data" / "synthetic" / "records.jsonl"
    records: List[Dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records

def run_pipeline(repo_root: Path) -> None:
    paths = default_paths(repo_root)
    paths.out_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_dir.mkdir(parents=True, exist_ok=True)

    tenant_model = _load_tenant_model(repo_root)
    policies = _load_policies(repo_root)

    # 1) Scan IaC
    tf_dir = paths.examples_iac / "terraform"
    sls_yml = paths.examples_iac / "serverless" / "serverless.yml"

    tf_findings = scan_terraform_dir(tf_dir)
    sls_findings = scan_serverless_yaml(sls_yml)

    (paths.out_dir / "scans").mkdir(parents=True, exist_ok=True)
    (paths.out_dir / "scans" / "terraform_findings.json").write_text(
        json.dumps([f.__dict__ for f in tf_findings], indent=2), encoding="utf-8"
    )
    (paths.out_dir / "scans" / "serverless_findings.json").write_text(
        json.dumps([f.__dict__ for f in sls_findings], indent=2), encoding="utf-8"
    )

    # 2) Build trigger graph (from serverless events)
    edges: List[TriggerEdge] = []
    for f in sls_findings:
        if "HTTP-triggered" in f.message:
            edges.append(TriggerEdge(source="http:public", target=f"lambda:{f.function}", meta={"surface": "public"}))
        if "Event-triggered" in f.message:
            edges.append(TriggerEdge(source="eventbus:demo", target=f"lambda:{f.function}", meta={"surface": "event"}))
    g = build_trigger_graph(edges)
    (paths.out_dir / "trigger_graph.json").write_text(json.dumps(graph_to_json(g), indent=2), encoding="utf-8")

    # 3) Base risk scoring from IaC findings
    base_rs = score_findings(tf_findings, sls_findings)
    (paths.out_dir / "risk_score_base.json").write_text(json.dumps(base_rs.__dict__, indent=2), encoding="utf-8")

    # 4) v1.1: classification + cross-cloud normalization + multi-tenant + policy DSL
    records = _load_synthetic_records(repo_root)

    normalized_assets: List[Dict[str, Any]] = []
    policy_evals: List[Dict[str, Any]] = []

    # Determine which functions are publicly reachable from trigger graph
    public_functions = {e.target.split("lambda:")[-1] for e in edges if e.source == "http:public"}

    for r in records:
        asset_id = r["asset_id"]
        provider = r["provider"]
        native_type = r["native_type"]
        text = r.get("text", "")

        # Classification
        c = classify_text(asset_id, text)

        # Canonicalize
        canonical = normalize_resource_type(provider, native_type)

        # Demo exposure surfaces: infer compute principal(s)
        if "payments" in asset_id or "lambda-auth" in asset_id:
            principal = "lambda:api"
        else:
            principal = "lambda:ingest"

        exposure = "public" if principal.replace("lambda:", "") in public_functions else "event"

        asset_tenant = tenant_model.asset_tenant.get(asset_id, "retail")
        principal_tenant = tenant_model.principal_tenant.get(principal, "retail")
        cross_tenant = infer_cross_tenant(asset_tenant, principal_tenant)

        normalized_risk = adjust_risk(
            base_risk_0_100=base_rs.normalized_0_100,
            classification=c.classification,
            cross_tenant=cross_tenant,
            provider=provider,
            canonical_type=canonical,
        )

        ctx = {
            "asset_id": asset_id,
            "provider": provider,
            "native_type": native_type,
            "canonical_type": canonical,
            "tenant": asset_tenant,
            "principal": principal,
            "principal_tenant": principal_tenant,
            "cross_tenant": cross_tenant,
            "classification": c.classification,
            "exposure": "public" if exposure == "public" else "event",
            "risk_0_100": normalized_risk,
        }

        decisions = evaluate_policies(policies, ctx)
        g_out = gate(decisions)

        normalized_assets.append({
            **ctx,
            "classification_signals": c.signals,
        })
        policy_evals.append({
            "asset_id": asset_id,
            "gate": g_out,
            "decisions": [d.__dict__ for d in decisions],
        })

    (paths.out_dir / "normalized_assets.json").write_text(json.dumps(normalized_assets, indent=2), encoding="utf-8")
    (paths.out_dir / "policy_results.json").write_text(json.dumps(policy_evals, indent=2), encoding="utf-8")

    # Compute overall gate status (any FAIL => FAIL; else any WARN => WARN)
    statuses = [pe["gate"]["status"] for pe in policy_evals]
    if "FAIL" in statuses:
        overall_gate = "FAIL"
    elif "WARN" in statuses:
        overall_gate = "WARN"
    else:
        overall_gate = "PASS"
    (paths.out_dir / "gate_status.json").write_text(json.dumps({"status": overall_gate}, indent=2), encoding="utf-8")

    # 5) Evidence manifest
    manifest = build_manifest(
        paths.out_dir,
        include_globs=[
            "scans",
            "trigger_graph.json",
            "risk_score_base.json",
            "normalized_assets.json",
            "policy_results.json",
            "gate_status.json",
        ],
    )
    (paths.evidence_dir / "manifest.sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # 6) Receipts (CREATE/MAINTAIN/AUDIT/DESTROY)
    create_r = receipt("CREATE", inputs={"iac_root": str(paths.examples_iac)}, outputs={"scans": "out/scans"})
    write_receipt(paths.evidence_dir / "receipt_create.json", create_r)

    maintain_r = receipt(
        "MAINTAIN",
        inputs={"drift_window": "demo"},
        outputs={"base_risk": base_rs.__dict__, "gate": overall_gate},
    )
    write_receipt(paths.evidence_dir / "receipt_maintain.json", maintain_r)

    audit_r = receipt("AUDIT", inputs={"manifest": "manifest.sha256.json"}, outputs={"count": manifest["count"]})
    write_receipt(paths.evidence_dir / "receipt_audit.json", audit_r)

    destroy_out = simulate_destroy(paths.out_dir)
    destroy_r = receipt("DESTROY", inputs={"target": "demo-ephemeral-plane"}, outputs=destroy_out)
    write_receipt(paths.evidence_dir / "receipt_destroy.json", destroy_r)

    _print_summary(tf_findings, sls_findings, base_rs, overall_gate, paths.out_dir)

def _print_summary(tf_findings, sls_findings, base_rs, gate_status: str, out_dir: Path) -> None:
    t = Table(title="DSPM + DevSecOps Pipeline Summary (v1.1)")
    t.add_column("Category")
    t.add_column("Count", justify="right")
    t.add_column("Notes")

    t.add_row("Terraform findings", str(len(tf_findings)), "IaC posture + network/iam/serverless patterns")
    t.add_row("Serverless findings", str(len(sls_findings)), "Triggers, env leakage, VPC attachment, logging")
    t.add_row("Base Risk (0-100)", str(base_rs.normalized_0_100), "From IaC findings (demo)")
    t.add_row("Policy Gate", gate_status, "Policy DSL evaluated against normalized assets")
    t.add_row("Artifacts", "-", f"Wrote outputs to {out_dir.as_posix()}")
    console.print(t)
