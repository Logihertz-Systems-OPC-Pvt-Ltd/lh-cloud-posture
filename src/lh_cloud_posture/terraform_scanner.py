# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        src.lh_cloud_posture.terraform_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Terraform Infrastructure-as-Code static analysis scanner for lh-cloud-posture.

Inspects Terraform configurations (.tf, .tf.json) for public storage exposure,
wildcard IAM policies, unrestricted security group ingress, unencrypted resources,
disabled logging, and hardcoded secrets.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lh_cloud_posture.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

SENSITIVE_PORTS = {22, 23, 2375, 2376, 3389, 5432, 3306, 1433, 27017, 6379, 9200}

SECRET_KEY_REGEX = re.compile(
    r"(?i)(?:secret|token|password|passwd|api_?key|auth_?token|private_?key|access_?key|credential)"
)
PLACEHOLDER_REGEX = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z0-9_]+|\"\"|''|<[^>]+>|dummy|placeholder|changeme|test|default|none|null)?$",
    re.IGNORECASE,
)
PRIVATE_KEY_REGEX = re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s+)?PRIVATE KEY-----")
AWS_KEY_REGEX = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GITHUB_TOKEN_REGEX = re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{30,})\b")
SLACK_TOKEN_REGEX = re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,})\b")


class TerraformScanner:
    """Scanner for analyzing Terraform HCL (.tf) and JSON (.tf.json) files."""

    def __init__(self, content: str, target_path: str = "main.tf") -> None:
        """Initialize TerraformScanner.

        Args:
            content: Raw file content.
            target_path: Path or filename for reporting.
        """
        self.content = content
        self.target_path = target_path
        self.lines = content.splitlines()

    def _find_line(self, pattern: str, start_line: int = 1) -> int:
        """Find the 1-based line number matching a regex pattern."""
        regex = re.compile(pattern)
        for idx in range(start_line - 1, len(self.lines)):
            if regex.search(self.lines[idx]):
                return idx + 1
        return start_line

    def _extract_blocks(self, pattern: str) -> list[tuple[str, str, int]]:
        """Extract matching resource blocks and their full bodies with balanced braces."""
        results: list[tuple[str, str, int]] = []
        for m in re.finditer(pattern, self.content):
            res_name = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else "inline")
            open_brace_idx = self.content.find("{", m.start())
            if open_brace_idx == -1:
                continue
            depth = 1
            idx = open_brace_idx + 1
            while idx < len(self.content) and depth > 0:
                char = self.content[idx]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                idx += 1
            body = self.content[open_brace_idx + 1 : idx - 1]
            line = self.content[: m.start()].count("\n") + 1
            results.append((res_name, body, line))
        return results

    def _check_sg_ingress_body(
        self,
        res_name: str,
        body: str,
        line_num: int,
        findings: list[Finding],
    ) -> None:
        """Evaluate an ingress block or security group rule body for unrestricted access."""
        has_open_cidr = bool(
            re.search(r'cidr_blocks\s*=\s*\[[^\]]*["\']0\.0\.0\.0/0["\'][^\]]*\]', body)
            or re.search(r'ipv6_cidr_blocks\s*=\s*\[[^\]]*["\']::/0["\'][^\]]*\]', body)
        )
        if not has_open_cidr:
            return

        port_match = re.search(r"(?:from_port|to_port)\s*=\s*([0-9]+)", body)
        port_val = int(port_match.group(1)) if port_match else 0
        proto_match = re.search(r'protocol\s*=\s*["\']([^"\']+)["\']', body)
        proto = proto_match.group(1) if proto_match else ""

        if port_val in SENSITIVE_PORTS or port_val == 0 or proto in ("-1", "all"):
            findings.append(
                create_finding(
                    rule_id="LH-CLOUD-003",
                    target=self.target_path,
                    line_number=line_num,
                    resource=f"aws_security_group.{res_name}",
                    message=(
                        f"Security Group rule exposes sensitive/broad port ({port_val}) to "
                        "unrestricted internet ingress (0.0.0.0/0 or ::/0)."
                    ),
                    details={"port": port_val, "protocol": proto},
                )
            )

    def scan(self) -> ScanTargetResult:
        """Execute all Terraform cloud posture audit rules.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        findings: list[Finding] = []

        if self.target_path.endswith(".json") or self.content.strip().startswith("{"):
            try:
                data = json.loads(self.content)
                self._scan_json_terraform(data, findings)
                return ScanTargetResult(
                    target=self.target_path,
                    target_type=TargetType.TERRAFORM,
                    findings=findings,
                )
            except Exception as e:
                return ScanTargetResult(
                    target=self.target_path,
                    target_type=TargetType.TERRAFORM,
                    findings=[],
                    error_message=f"Failed to parse Terraform JSON: {e}",
                )

        self._scan_hcl_terraform(findings)
        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.TERRAFORM,
            findings=findings,
        )

    def _scan_hcl_terraform(self, findings: list[Finding]) -> None:
        """Analyze native HCL (.tf) content for security violations."""
        for i, line in enumerate(self.lines):
            line_num = i + 1
            if re.search(r'acl\s*=\s*["\'](public-read|public-read-write|website)["\']', line):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-001",
                        target=self.target_path,
                        line_number=line_num,
                        resource="aws_s3_bucket",
                        message="Storage bucket configured with public ACL granting public access.",
                        details={"line": line.strip()},
                    )
                )

            if re.search(
                r"(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false",
                line,
            ):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-001",
                        target=self.target_path,
                        line_number=line_num,
                        resource="aws_s3_bucket_public_access_block",
                        message="S3 Public Access Block setting set to false, exposing storage.",
                        details={"setting": line.strip()},
                    )
                )

        iam_blocks = self._extract_blocks(
            r'resource\s+["\']aws_iam_(?:policy|role_policy|group_policy|user_policy)["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in iam_blocks:
            act_pattern = r'["\']?Action["\']?\s*[:=]\s*(?:\[\s*["\']\*["\']\s*\]|["\']\*["\'])'
            has_star_action = bool(
                re.search(act_pattern, body, re.I)
                or re.search(r'actions\s*=\s*\[\s*["\']\*["\']\s*\]', body, re.I)
            )
            res_pattern = r'["\']?Resource["\']?\s*[:=]\s*(?:\[\s*["\']\*["\']\s*\]|["\']\*["\'])'
            has_star_res = bool(
                re.search(res_pattern, body, re.I)
                or re.search(r'resources\s*=\s*\[\s*["\']\*["\']\s*\]', body, re.I)
            )
            if has_star_action and has_star_res:
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-002",
                        target=self.target_path,
                        line_number=line_num,
                        resource=f"aws_iam_policy.{res_name}",
                        message=f"IAM policy '{res_name}' grants wildcard Action and Resource.",
                        details={"resource": res_name},
                    )
                )

        sg_rule_blocks = self._extract_blocks(
            r'resource\s+["\']aws_security_group_rule["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in sg_rule_blocks:
            self._check_sg_ingress_body(res_name, body, line_num, findings)

        sg_blocks = self._extract_blocks(
            r'resource\s+["\']aws_security_group["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in sg_blocks:
            ingress_matches = list(re.finditer(r"ingress\s*\{([^}]+)\}", body))
            if ingress_matches:
                for im in ingress_matches:
                    self._check_sg_ingress_body(res_name, im.group(1), line_num, findings)
            else:
                self._check_sg_ingress_body(res_name, body, line_num, findings)

        ebs_blocks = self._extract_blocks(
            r'resource\s+["\']aws_ebs_volume["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in ebs_blocks:
            if "encrypted = true" not in body.replace(" ", ""):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-004",
                        target=self.target_path,
                        line_number=line_num,
                        resource=f"aws_ebs_volume.{res_name}",
                        message=f"EBS volume '{res_name}' does not have encrypted set to true.",
                        details={"resource": res_name},
                    )
                )

        rds_blocks = self._extract_blocks(
            r'resource\s+["\']aws_db_instance["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in rds_blocks:
            if "storage_encrypted = true" not in body.replace(" ", ""):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-004",
                        target=self.target_path,
                        line_number=line_num,
                        resource=f"aws_db_instance.{res_name}",
                        message=f"RDS '{res_name}' does not have storage_encrypted enabled.",
                        details={"resource": res_name},
                    )
                )

        trail_blocks = self._extract_blocks(
            r'resource\s+["\']aws_cloudtrail["\']\s+["\']([^"\']+)["\']'
        )
        for res_name, body, line_num in trail_blocks:
            has_multi = "is_multi_region_trail=true" in body.replace(" ", "")
            enable_log = "enable_logging=false" in body.replace(" ", "")
            if not has_multi or enable_log:
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-005",
                        target=self.target_path,
                        line_number=line_num,
                        resource=f"aws_cloudtrail.{res_name}",
                        message=f"CloudTrail '{res_name}' has multi-region logging disabled.",
                        details={"resource": res_name},
                    )
                )

        current_var: str | None = None
        for i, line in enumerate(self.lines):
            line_num = i + 1
            var_match = re.search(r'variable\s+["\']([^"\']+)["\']', line)
            if var_match:
                current_var = var_match.group(1)
            elif "}" in line:
                current_var = None

            found_token = False
            for regex, name in (
                (PRIVATE_KEY_REGEX, "Private Key"),
                (AWS_KEY_REGEX, "AWS Access Key"),
                (GITHUB_TOKEN_REGEX, "GitHub Token"),
                (SLACK_TOKEN_REGEX, "Slack Token"),
            ):
                if regex.search(line):
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-010",
                            target=self.target_path,
                            line_number=line_num,
                            message=f"Hardcoded {name} pattern detected in Terraform definition.",
                            details={"line": line.strip(), "secret_type": name},
                        )
                    )
                    found_token = True
                    break

            if found_token:
                continue

            match = re.search(r'([A-Za-z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', line)
            if match:
                k, v = match.group(1), match.group(2).strip()
                if not v or PLACEHOLDER_REGEX.match(v):
                    continue
                k_check = current_var if k == "default" and current_var else k
                if SECRET_KEY_REGEX.search(k_check):
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-010",
                            target=self.target_path,
                            line_number=line_num,
                            message=f"Hardcoded credential assigned to '{k_check}' in Terraform.",
                            details={"key": k_check},
                        )
                    )

    def _scan_json_terraform(self, data: dict[str, Any], findings: list[Finding]) -> None:
        """Analyze Terraform JSON (.tf.json) structure for security violations."""
        resources = data.get("resource", {})
        if isinstance(resources, list):
            merged: dict[str, Any] = {}
            for item in resources:
                if isinstance(item, dict):
                    merged.update(item)
            resources = merged

        if not isinstance(resources, dict):
            return

        s3_buckets = resources.get("aws_s3_bucket", {})
        if isinstance(s3_buckets, dict):
            for name, cfg in s3_buckets.items():
                if isinstance(cfg, dict) and cfg.get("acl") in (
                    "public-read",
                    "public-read-write",
                    "website",
                ):
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-001",
                            target=self.target_path,
                            resource=f"aws_s3_bucket.{name}",
                            message=f"S3 bucket '{name}' has public ACL '{cfg.get('acl')}'.",
                            details={"resource": name},
                        )
                    )

        iam_policies = resources.get("aws_iam_policy", {})
        if isinstance(iam_policies, dict):
            for name, cfg in iam_policies.items():
                policy_doc = cfg.get("policy", {})
                if isinstance(policy_doc, str):
                    try:
                        policy_doc = json.loads(policy_doc)
                    except Exception:
                        policy_doc = {}
                if isinstance(policy_doc, dict):
                    stmts = policy_doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for stmt in stmts:
                        if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
                            act = stmt.get("Action", [])
                            res = stmt.get("Resource", [])
                            act_star = act == "*" or act == ["*"]
                            res_star = res == "*" or res == ["*"]
                            if act_star and res_star:
                                findings.append(
                                    create_finding(
                                        rule_id="LH-CLOUD-002",
                                        target=self.target_path,
                                        resource=f"aws_iam_policy.{name}",
                                        message=(
                                            f"IAM policy '{name}' has wildcard Action and Resource."
                                        ),
                                        details={"policy": name},
                                    )
                                )

        ebs_volumes = resources.get("aws_ebs_volume", {})
        if isinstance(ebs_volumes, dict):
            for name, cfg in ebs_volumes.items():
                if isinstance(cfg, dict) and cfg.get("encrypted") is not True:
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-004",
                            target=self.target_path,
                            resource=f"aws_ebs_volume.{name}",
                            message=f"EBS volume '{name}' does not have encryption enabled.",
                            details={"resource": name},
                        )
                    )


def scan_terraform(path: Path | str) -> ScanTargetResult:
    """Read and scan a Terraform file.

    Args:
        path: Path to .tf or .tf.json file.

    Returns:
        ScanTargetResult with audit findings.
    """
    file_path = Path(path)
    if not file_path.exists():
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.TERRAFORM,
            findings=[],
            error_message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.TERRAFORM,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = TerraformScanner(content=content, target_path=str(file_path))
    return scanner.scan()
