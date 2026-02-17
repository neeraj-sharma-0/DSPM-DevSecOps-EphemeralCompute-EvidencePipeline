from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml

@dataclass(frozen=True)
class ServerlessFinding:
    file: str
    function: str
    severity: str
    message: str
    evidence: Dict[str, Any]

def scan_serverless_yaml(yaml_path: Path) -> List[ServerlessFinding]:
    doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8", errors="ignore")) or {}
    findings: List[ServerlessFinding] = []
    functions = (doc.get("functions") or {})

    provider = doc.get("provider") or {}
    logs = provider.get("logs") or {}
    vpc = provider.get("vpc")

    for fn_name, fn in functions.items():
        events = fn.get("events") or []
        env = fn.get("environment") or {}
        # Trigger surface checks
        for ev in events:
            if "http" in ev or "httpApi" in ev:
                findings.append(ServerlessFinding(
                    file=yaml_path.as_posix(),
                    function=fn_name,
                    severity="HIGH",
                    message="HTTP-triggered function: treat as public invocation surface unless tightly authz-gated",
                    evidence={"event": ev},
                ))
            if "s3" in ev or "sqs" in ev or "eventBridge" in ev:
                findings.append(ServerlessFinding(
                    file=yaml_path.as_posix(),
                    function=fn_name,
                    severity="MEDIUM",
                    message="Event-triggered function: ensure least-privilege + event source allowlist",
                    evidence={"event": ev},
                ))

        # Env leakage hint
        if any(k.lower() in {"api_key", "token", "secret"} for k in env.keys()):
            findings.append(ServerlessFinding(
                file=yaml_path.as_posix(),
                function=fn_name,
                severity="HIGH",
                message="Potential secret-like keys in function environment (use secrets manager + runtime fetch)",
                evidence={"environment_keys": list(env.keys())},
            ))

        # Logging / retention hint
        if not logs:
            findings.append(ServerlessFinding(
                file=yaml_path.as_posix(),
                function=fn_name,
                severity="LOW",
                message="Provider logging not explicitly configured; ensure retention + redaction policy",
                evidence={"provider_logs": logs},
            ))

        # VPC attachment signal
        if not (fn.get("vpc") or vpc):
            findings.append(ServerlessFinding(
                file=yaml_path.as_posix(),
                function=fn_name,
                severity="MEDIUM",
                message="Function not VPC-attached: egress is less CIDR-bounded (model via identity + trigger graph)",
                evidence={},
            ))

    return findings
