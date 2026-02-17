from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    severity: str
    control: str

DEFAULT_POLICY: List[PolicyRule] = [
    PolicyRule(
        id="DSPM-IAC-001",
        description="Block wildcard invoke permissions for serverless",
        severity="CRITICAL",
        control="least-privilege-invoke",
    ),
    PolicyRule(
        id="DSPM-IAC-002",
        description="Avoid public storage access; enforce public access blocks",
        severity="HIGH",
        control="data-exposure-prevention",
    ),
    PolicyRule(
        id="DSPM-IAC-003",
        description="Model trigger-to-function edges; enforce trigger allowlists",
        severity="MEDIUM",
        control="event-surface-governance",
    ),
]
