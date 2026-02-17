from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from dspm_devsecops.classification.pii import CLASS_MULTIPLIER

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10,
}

@dataclass(frozen=True)
class RiskScore:
    total: int
    breakdown: Dict[str, int]
    normalized_0_100: int

def score_findings(terraform_findings: List[Any], serverless_findings: List[Any]) -> RiskScore:
    breakdown: Dict[str, int] = {
        "terraform": sum(SEVERITY_WEIGHT.get(getattr(f, "severity", "LOW"), 1) for f in terraform_findings),
        "serverless": sum(SEVERITY_WEIGHT.get(getattr(f, "severity", "LOW"), 1) for f in serverless_findings),
    }
    total = breakdown["terraform"] + breakdown["serverless"]
    normalized = min(100, int((total / 60) * 100))  # demo calibration
    return RiskScore(total=total, breakdown=breakdown, normalized_0_100=normalized)

def adjust_risk(
    base_risk_0_100: int,
    classification: str,
    cross_tenant: bool,
    provider: str,
    canonical_type: str,
) -> int:
    """v1.1: context-aware risk normalization.

    - Data classification multiplier
    - Cross-tenant penalty
    - Lightweight provider/canonical-type nudges (demo)
    """
    mult = float(CLASS_MULTIPLIER.get(classification, 1.0))
    r = int(min(100, round(base_risk_0_100 * mult)))

    if cross_tenant:
        r = min(100, r + 12)

    # Demo nudges for high-risk surfaces
    if canonical_type in {"event_bus", "api_gateway"}:
        r = min(100, r + 5)

    # Provider is used only for labeling here (kept for future).
    return int(r)
