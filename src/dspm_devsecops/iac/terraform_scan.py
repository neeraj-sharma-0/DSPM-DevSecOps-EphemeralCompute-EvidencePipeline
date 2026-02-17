from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

# NOTE: This is intentionally lightweight (no full HCL parser) to keep the demo runnable everywhere.
# It looks for "risk-relevant patterns" commonly present in Terraform.

@dataclass(frozen=True)
class TerraformFinding:
    file: str
    resource_type: str
    name: str
    severity: str
    message: str
    evidence: Dict[str, Any]

_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.IGNORECASE)
_ATTR_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$', re.IGNORECASE)

def scan_terraform_dir(tf_dir: Path) -> List[TerraformFinding]:
    findings: List[TerraformFinding] = []
    for fp in sorted(tf_dir.rglob("*.tf")):
        findings.extend(_scan_tf_file(fp))
    return findings

def _scan_tf_file(fp: Path) -> List[TerraformFinding]:
    text = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
    findings: List[TerraformFinding] = []

    cur_res = None
    attrs: Dict[str, str] = {}

    for line in text:
        m = _RESOURCE_RE.search(line)
        if m:
            # flush any previous resource
            if cur_res:
                findings.extend(_analyze_resource(fp, cur_res[0], cur_res[1], attrs))
            cur_res = (m.group(1), m.group(2))
            attrs = {}
            continue

        if cur_res:
            if "}" in line:
                # end resource
                findings.extend(_analyze_resource(fp, cur_res[0], cur_res[1], attrs))
                cur_res = None
                attrs = {}
                continue

            am = _ATTR_RE.match(line)
            if am:
                attrs[am.group(1)] = am.group(2).strip()

    # flush last
    if cur_res:
        findings.extend(_analyze_resource(fp, cur_res[0], cur_res[1], attrs))

    return findings

def _analyze_resource(fp: Path, rtype: str, name: str, attrs: Dict[str, str]) -> List[TerraformFinding]:
    out: List[TerraformFinding] = []
    f = fp.as_posix()

    # Example risk patterns
    if rtype in {"aws_s3_bucket_public_access_block", "aws_s3_bucket_acl"}:
        if "public" in " ".join(attrs.values()).lower():
            out.append(TerraformFinding(
                file=f, resource_type=rtype, name=name, severity="HIGH",
                message="Potential public S3 exposure pattern detected",
                evidence={"attrs": attrs},
            ))

    if rtype in {"aws_lambda_function", "aws_lambda_permission"}:
        # Look for broad invoke permissions or missing VPC attachment
        if rtype == "aws_lambda_permission":
            principal = attrs.get("principal", "")
            if "*" in principal.replace('"', ''):
                out.append(TerraformFinding(
                    file=f, resource_type=rtype, name=name, severity="CRITICAL",
                    message="Lambda invoke permission appears wildcarded (principal='*')",
                    evidence={"attrs": attrs},
                ))
        if rtype == "aws_lambda_function":
            if "vpc_config" not in " ".join(attrs.keys()).lower():
                out.append(TerraformFinding(
                    file=f, resource_type=rtype, name=name, severity="MEDIUM",
                    message="Lambda function appears not VPC-attached (ephemeral egress harder to bound)",
                    evidence={"attrs": attrs},
                ))

    if rtype in {"aws_iam_policy", "aws_iam_role_policy"}:
        blob = " ".join(attrs.values()).lower()
        if "action" in blob and ("*" in blob or "admin" in blob):
            out.append(TerraformFinding(
                file=f, resource_type=rtype, name=name, severity="HIGH",
                message="IAM policy may be overly broad (wildcards/admin-like patterns)",
                evidence={"attrs": attrs},
            ))

    # Generic network egress hint
    if rtype in {"aws_security_group", "aws_security_group_rule"}:
        blob = " ".join(attrs.values()).lower()
        if "0.0.0.0/0" in blob and ("egress" in blob or "from_port" in blob):
            out.append(TerraformFinding(
                file=f, resource_type=rtype, name=name, severity="HIGH",
                message="Security group rule may allow broad internet egress/ingress",
                evidence={"attrs": attrs},
            ))

    return out
