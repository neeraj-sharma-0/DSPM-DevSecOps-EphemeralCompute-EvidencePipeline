from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

@dataclass(frozen=True)
class TenantModel:
    tenants: List[str]
    asset_tenant: Dict[str, str]
    principal_tenant: Dict[str, str]

def infer_cross_tenant(asset_tenant: str, principal_tenant: str) -> bool:
    return asset_tenant != principal_tenant
