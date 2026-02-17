from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass(frozen=True)
class PolicyDecision:
    name: str
    action: str  # pass|warn|fail_pipeline
    severity: str
    matched: bool
    reason: str

def _match_condition(cond: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    # Supported keys: classification, exposure, cross_tenant, provider, canonical_type, min_risk
    for k, v in cond.items():
        if k == "min_risk":
            if float(ctx.get("risk_0_100", 0)) < float(v):
                return False
        else:
            if ctx.get(k) != v:
                return False
    return True

def evaluate_policies(policies: List[Dict[str, Any]], ctx: Dict[str, Any]) -> List[PolicyDecision]:
    out: List[PolicyDecision] = []
    for p in policies:
        name = p.get("name", "unnamed")
        cond = p.get("condition", {}) or {}
        matched = _match_condition(cond, ctx)
        out.append(
            PolicyDecision(
                name=name,
                action=p.get("action", "pass"),
                severity=p.get("severity", "INFO"),
                matched=matched,
                reason=p.get("reason", "") if matched else "no_match",
            )
        )
    return out

def gate(decisions: List[PolicyDecision]) -> Dict[str, Any]:
    # If any matched fail_pipeline => fail. Else if any matched warn => warn. Else pass.
    matched = [d for d in decisions if d.matched]
    if any(d.action == "fail_pipeline" for d in matched):
        status = "FAIL"
    elif any(d.action == "warn" for d in matched):
        status = "WARN"
    else:
        status = "PASS"
    return {
        "status": status,
        "matched": [d.__dict__ for d in matched],
        "total_rules": len(decisions),
        "matched_rules": len(matched),
    }
