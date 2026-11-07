# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        src.lh_cloud_posture.cloudformation_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""AWS CloudFormation template static analysis scanner for lh-cloud-posture.

Inspects CloudFormation templates (YAML and JSON) for public S3 buckets,
wildcard IAM policies, open security group ingress, unencrypted storage,
disabled CloudTrail logging, and hardcoded secrets in parameters.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

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


class CloudFormationScanner:
    """Scanner for analyzing AWS CloudFormation templates."""

    def __init__(self, content: str, target_path: str = "template.yaml") -> None:
        """Initialize CloudFormationScanner.

        Args:
            content: Raw YAML or JSON template content.
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

    def scan(self) -> ScanTargetResult:
        """Execute all CloudFormation posture audit rules.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        data: Any = None
        if self.target_path.endswith(".json") or self.content.strip().startswith("{"):
            try:
                data = json.loads(self.content)
            except Exception:
                data = None

        if data is None:
            try:
                data = yaml.safe_load(self.content)
            except Exception as e:
                return ScanTargetResult(
                    target=self.target_path,
                    target_type=TargetType.CLOUDFORMATION,
                    findings=[],
                    error_message=f"Failed to parse CloudFormation template: {e}",
                )

        if not isinstance(data, dict):
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.CLOUDFORMATION,
                findings=[],
                error_message="Template root is not a valid dictionary structure.",
            )

        findings: list[Finding] = []
        self._check_parameters(data.get("Parameters", {}), findings)

        resources = data.get("Resources", {})
        if isinstance(resources, dict):
            for res_id, res_cfg in resources.items():
                if isinstance(res_cfg, dict):
                    self._check_resource(res_id, res_cfg, findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.CLOUDFORMATION,
            findings=findings,
        )

    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-010 (CRITICAL):
    #     Hardcoded Secrets or Plaintext Passwords in IaC Definitions
    # ---
    # Evaluates security posture against hardcoded secrets or plaintext passwords in
    # iac definitions.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------

    def _check_parameters(self, params: Any, findings: list[Finding]) -> None:
        """Audit CloudFormation Parameters for hardcoded secrets (LH-CLOUD-010)."""
        if not isinstance(params, dict):
            return

        for p_name, p_cfg in params.items():
            if not isinstance(p_cfg, dict):
                continue
            default_val = str(p_cfg.get("Default", "")).strip()
            if not default_val or PLACEHOLDER_REGEX.match(default_val):
                continue

            line = self._find_line(rf"[\"']?{re.escape(p_name)}[\"']?\s*:")

            found_token = False
            for regex, name in (
                (PRIVATE_KEY_REGEX, "Private Key"),
                (AWS_KEY_REGEX, "AWS Access Key"),
                (GITHUB_TOKEN_REGEX, "GitHub Token"),
                (SLACK_TOKEN_REGEX, "Slack Token"),
            ):
                if regex.search(default_val):
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-010",
                            target=self.target_path,
                            line_number=line,
                            resource=f"Parameter/{p_name}",
                            message=f"CloudFormation parameter '{p_name}' has default {name}.",
                            details={"parameter": p_name, "secret_type": name},
                        )
                    )
                    found_token = True
                    break

            if found_token:
                continue

            if SECRET_KEY_REGEX.search(p_name):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-010",
                        target=self.target_path,
                        line_number=line,
                        resource=f"Parameter/{p_name}",
                        message=f"Parameter '{p_name}' has hardcoded default password/secret.",
                        details={"parameter": p_name},
                    )
                )

    def _check_resource(
        self,
        res_id: str,
        res_cfg: dict[str, Any],
        findings: list[Finding],
    ) -> None:
        """Evaluate resource definitions against cloud security rules."""
        res_type = res_cfg.get("Type", "")
        props = res_cfg.get("Properties", {})
        if not isinstance(props, dict):
            props = {}

        line = self._find_line(rf"[\"']?{re.escape(res_id)}[\"']?\s*:")

        # Rule 1: LH-CLOUD-001 - Public S3 Buckets
        if res_type == "AWS::S3::Bucket":
            acl = props.get("AccessControl")
            if acl in ("PublicRead", "PublicReadWrite"):
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-001",
                        target=self.target_path,
                        line_number=line,
                        resource=f"AWS::S3::Bucket/{res_id}",
                        message=f"S3 bucket '{res_id}' has public AccessControl '{acl}'.",
                        details={"resource": res_id, "AccessControl": acl},
                    )
                )

            pab = props.get("PublicAccessBlockConfiguration")
            if isinstance(pab, dict):
                for flag in (
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                ):
                    if pab.get(flag) is False:
                        findings.append(
                            create_finding(
                                rule_id="LH-CLOUD-001",
                                target=self.target_path,
                                line_number=line,
                                resource=f"AWS::S3::Bucket/{res_id}",
                                message=f"S3 bucket '{res_id}' sets '{flag}: false'.",
                                details={"resource": res_id, "setting": f"{flag}: false"},
                            )
                        )

        # Rule 2: LH-CLOUD-002 - IAM Policies
        if res_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            policy_doc = props.get("PolicyDocument")
            if not policy_doc and "Policies" in props:
                policies_list = props.get("Policies", [])
                if isinstance(policies_list, list) and policies_list:
                    policy_doc = policies_list[0].get("PolicyDocument")

            if isinstance(policy_doc, dict):
                stmts = policy_doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                if isinstance(stmts, list):
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
                                        line_number=line,
                                        resource=f"{res_type}/{res_id}",
                                        message=f"IAM policy in '{res_id}' grants wildcard access.",
                                        details={"resource": res_id},
                                    )
                                )

        # Rule 3: LH-CLOUD-003 - Open Security Group Ingress
        if res_type == "AWS::EC2::SecurityGroup":
            ingress_list = props.get("SecurityGroupIngress", [])
            if isinstance(ingress_list, dict):
                ingress_list = [ingress_list]
            if isinstance(ingress_list, list):
                for rule in ingress_list:
                    if not isinstance(rule, dict):
                        continue
                    cidr = rule.get("CidrIp") or rule.get("CidrIpv6")
                    if cidr in ("0.0.0.0/0", "::/0"):
                        from_p = rule.get("FromPort", 0)
                        proto = str(rule.get("IpProtocol", ""))

                        if from_p in SENSITIVE_PORTS or from_p == 0 or proto in ("-1", "all"):
                            findings.append(
                                create_finding(
                                    rule_id="LH-CLOUD-003",
                                    target=self.target_path,
                                    line_number=line,
                                    resource=f"AWS::EC2::SecurityGroup/{res_id}",
                                    message=(
                                        f"Security Group '{res_id}' allows ingress from {cidr} "
                                        f"on port {from_p} (protocol: {proto})."
                                    ),
                                    details={"resource": res_id, "cidr": cidr, "port": from_p},
                                )
                            )

        # Rule 4: LH-CLOUD-004 - Unencrypted EBS Volume & RDS
        if res_type == "AWS::EC2::Volume":
            if props.get("Encrypted") is not True:
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-004",
                        target=self.target_path,
                        line_number=line,
                        resource=f"AWS::EC2::Volume/{res_id}",
                        message=f"EBS Volume '{res_id}' does not have encryption enabled.",
                        details={"resource": res_id},
                    )
                )

        if res_type == "AWS::RDS::DBInstance":
            if props.get("StorageEncrypted") is not True:
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-004",
                        target=self.target_path,
                        line_number=line,
                        resource=f"AWS::RDS::DBInstance/{res_id}",
                        message=f"RDS instance '{res_id}' has unencrypted storage.",
                        details={"resource": res_id},
                    )
                )

        # Rule 5: LH-CLOUD-005 - CloudTrail Logging
        if res_type == "AWS::CloudTrail::Trail":
            is_multi = props.get("IsMultiRegionTrail")
            logging = props.get("EnableLogging")
            if is_multi is not True or logging is False:
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-005",
                        target=self.target_path,
                        line_number=line,
                        resource=f"AWS::CloudTrail::Trail/{res_id}",
                        message=f"CloudTrail '{res_id}' has logging disabled.",
                        details={"resource": res_id},
                    )
                )


def scan_cloudformation(path: Path | str) -> ScanTargetResult:
    """Read and scan an AWS CloudFormation template file.

    Args:
        path: Path to YAML or JSON template.

    Returns:
        ScanTargetResult with audit findings.
    """
    file_path = Path(path)
    if not file_path.exists():
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.CLOUDFORMATION,
            findings=[],
            error_message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.CLOUDFORMATION,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = CloudFormationScanner(content=content, target_path=str(file_path))
    return scanner.scan()
