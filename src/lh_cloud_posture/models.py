# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        src.lh_cloud_posture.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-cloud-posture.

Provides structured types for cloud IaC targets, security findings, severity levels,
detection rules registry, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity levels for audit findings, ordered from highest to lowest."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level_rank(self) -> int:
        """Numeric rank for severity comparison (higher means more severe)."""
        ranks = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity is greater than or equal to threshold."""
        return self.level_rank >= threshold.level_rank


class FindingCategory(StrEnum):
    """Categorization of cloud security posture findings."""

    STORAGE_EXPOSURE = "STORAGE_EXPOSURE"
    IAM_RBAC = "IAM_RBAC"
    NETWORK_INGRESS = "NETWORK_INGRESS"
    DATA_ENCRYPTION = "DATA_ENCRYPTION"
    AUDIT_LOGGING = "AUDIT_LOGGING"
    WORKLOAD_ISOLATION = "WORKLOAD_ISOLATION"
    RESOURCE_MANAGEMENT = "RESOURCE_MANAGEMENT"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"  # nosec B105


class TargetType(StrEnum):
    """Type of Infrastructure-as-Code artifact analyzed."""

    TERRAFORM = "TERRAFORM"
    KUBERNETES = "KUBERNETES"
    CLOUDFORMATION = "CLOUDFORMATION"


@dataclass(frozen=True)
class RuleDefinition:
    """Specification of an audit detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    remediation: str
    target_types: list[TargetType]

    def to_dict(self) -> dict[str, Any]:
        """Convert rule definition to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "remediation": self.remediation,
            "target_types": [t.value for t in self.target_types],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-CLOUD-001": RuleDefinition(
        rule_id="LH-CLOUD-001",
        title="Publicly accessible storage bucket or public ACL",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.STORAGE_EXPOSURE,
        description=(
            "Cloud storage bucket configured with public ACL (public-read/public-read-write) "
            "or public access block settings disabled."
        ),
        remediation=(
            "Enforce private ACL on storage buckets and enable all S3 public access block "
            "settings (block_public_acls, block_public_policy, ignore_public_acls)."
        ),
        target_types=[TargetType.TERRAFORM, TargetType.CLOUDFORMATION],
    ),
    "LH-CLOUD-002": RuleDefinition(
        rule_id="LH-CLOUD-002",
        title="Overly permissive IAM policy with wildcard Action ('*') or Resource ('*')",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.IAM_RBAC,
        description=(
            "IAM policy statement grants full administrative access with wildcard Action ('*') "
            "or wildcard Resource ('*')."
        ),
        remediation=(
            "Apply principle of least privilege. Grant only specific actions on scoped ARNs "
            "rather than broad wildcards."
        ),
        target_types=[TargetType.TERRAFORM, TargetType.CLOUDFORMATION],
    ),
    "LH-CLOUD-003": RuleDefinition(
        rule_id="LH-CLOUD-003",
        title="Unrestricted ingress (0.0.0.0/0 or ::/0) in Security Groups or Network ACLs",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.NETWORK_INGRESS,
        description=(
            "Security Group or Network ACL rule allows unrestricted inbound traffic from "
            "0.0.0.0/0 or ::/0 on sensitive administrative or database ports."
        ),
        remediation=(
            "Restrict ingress CIDR ranges to trusted IP addresses or internal security groups. "
            "Avoid exposing ports 22, 3389, and databases to 0.0.0.0/0."
        ),
        target_types=[TargetType.TERRAFORM, TargetType.CLOUDFORMATION],
    ),
    "LH-CLOUD-004": RuleDefinition(
        rule_id="LH-CLOUD-004",
        title="Unencrypted cloud storage, EBS volumes, or RDS database instances",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.DATA_ENCRYPTION,
        description=(
            "Cloud resource created with encryption disabled (encrypted = false, "
            "storage_encrypted = false) or lacking KMS/SSE encryption specification."
        ),
        remediation=(
            "Enable encryption at rest using AWS KMS or provider-managed keys (SSE-S3 / AES256) "
            "for all storage and databases."
        ),
        target_types=[TargetType.TERRAFORM, TargetType.CLOUDFORMATION],
    ),
    "LH-CLOUD-005": RuleDefinition(
        rule_id="LH-CLOUD-005",
        title="Disabled audit logging, CloudTrail multi-region disabled, or missing VPC flow logs",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.AUDIT_LOGGING,
        description=(
            "Security audit logging disabled or partially configured (CloudTrail multi-region "
            "logging disabled, logging disabled, or VPC lacking flow logs)."
        ),
        remediation=(
            "Enable multi-region logging for CloudTrail trails and configure VPC flow logs to "
            "capture network traffic metadata."
        ),
        target_types=[TargetType.TERRAFORM, TargetType.CLOUDFORMATION],
    ),
    "LH-CLOUD-006": RuleDefinition(
        rule_id="LH-CLOUD-006",
        title="Kubernetes Pod/Deployment with privileged: true, hostNetwork, hostPID, or hostPath",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.WORKLOAD_ISOLATION,
        description=(
            "Kubernetes container or pod shares host namespaces (hostNetwork, hostPID, hostIPC), "
            "runs in privileged mode, or mounts hostPath volumes."
        ),
        remediation=(
            "Remove privileged flags, disable host namespace sharing, and replace hostPath "
            "volumes with persistent volume claims or configMaps."
        ),
        target_types=[TargetType.KUBERNETES],
    ),
    "LH-CLOUD-007": RuleDefinition(
        rule_id="LH-CLOUD-007",
        title="Kubernetes container spec missing CPU/memory resource limits or requests",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.RESOURCE_MANAGEMENT,
        description=(
            "Container specification does not declare resource requests or limits for CPU and "
            "memory, risking resource starvation and node instability."
        ),
        remediation=(
            "Define explicit resources.requests and resources.limits for CPU and memory in every "
            "container spec."
        ),
        target_types=[TargetType.KUBERNETES],
    ),
    "LH-CLOUD-008": RuleDefinition(
        rule_id="LH-CLOUD-008",
        title=(
            "Kubernetes RBAC ClusterRole or Role granting wildcard verbs/resources or cluster-admin"
        ),
        severity=FindingSeverity.HIGH,
        category=FindingCategory.IAM_RBAC,
        description=(
            "Kubernetes RBAC role specifies wildcard verbs ('*') or resources ('*'), or binding "
            "attaches non-system identities directly to cluster-admin."
        ),
        remediation=(
            "Scope RBAC permissions to explicit API groups, resources, and verbs. Avoid assigning "
            "cluster-admin to standard application workloads."
        ),
        target_types=[TargetType.KUBERNETES],
    ),
    "LH-CLOUD-009": RuleDefinition(
        rule_id="LH-CLOUD-009",
        title=(
            "Kubernetes Pod/ServiceAccount with automountServiceAccountToken "
            "not explicitly disabled"
        ),
        severity=FindingSeverity.LOW,
        category=FindingCategory.WORKLOAD_ISOLATION,
        description=(
            "Pod or ServiceAccount leaves automountServiceAccountToken enabled or omitted, "
            "mounting Kubernetes API credentials by default."
        ),
        remediation=(
            "Set automountServiceAccountToken: false on Pod or ServiceAccount manifests unless "
            "in-cluster API access is explicitly required."
        ),
        target_types=[TargetType.KUBERNETES],
    ),
    "LH-CLOUD-010": RuleDefinition(
        rule_id="LH-CLOUD-010",
        title="Hardcoded secrets, API keys, or plaintext passwords in IaC definitions",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.SECRET_EXPOSURE,
        description=(
            "Sensitive credentials, tokens, or plaintext passwords hardcoded in Kubernetes "
            "ConfigMaps, Terraform default variables, or CloudFormation parameters."
        ),
        remediation=(
            "Remove hardcoded credentials. Store secrets in AWS Secrets Manager, HashiCorp Vault, "
            "or Kubernetes Secret stores via external CSI drivers."
        ),
        target_types=[
            TargetType.TERRAFORM,
            TargetType.KUBERNETES,
            TargetType.CLOUDFORMATION,
        ],
    ),
}


@dataclass(frozen=True)
class Finding:
    """Represents an individual cloud security posture finding.

    Attributes:
        rule_id: Unique rule identifier (e.g. LH-CLOUD-001).
        title: Short title summarizing the issue.
        category: Category of the finding.
        severity: Severity level.
        target: Affected target artifact (file path or resource name).
        message: Detailed explanation of the finding.
        line_number: Line number where issue occurred, if applicable.
        resource: Affected cloud or Kubernetes resource identifier.
        details: Additional context or technical parameters.
    """

    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    target: str
    message: str
    line_number: int | None = None
    resource: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "line_number": self.line_number,
            "resource": self.resource,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanTargetResult:
    """Audit result for a single IaC file or artifact.

    Attributes:
        target: Target path or identifier.
        target_type: Type of IaC artifact analyzed.
        findings: List of security findings.
        error_message: Error string if scan failed.
    """

    target: str
    target_type: TargetType
    findings: list[Finding] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert scan target result to dictionary representation."""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class AuditReport:
    """Top-level report containing all audit results and execution parameters.

    Attributes:
        report_type: Type of audit (cloud_posture).
        generated_at: Timestamp when report was produced (UTC).
        parameters: Scan parameters used during execution.
        results: List of scan target results.
        summary: Aggregated summary statistics.
    """

    report_type: str = "cloud_posture"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Calculate and store summary statistics."""
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0

        all_findings: list[Finding] = []
        for r in self.results:
            all_findings.extend(r.findings)

        for f in all_findings:
            if f.severity == FindingSeverity.CRITICAL:
                critical_count += 1
            elif f.severity == FindingSeverity.HIGH:
                high_count += 1
            elif f.severity == FindingSeverity.MEDIUM:
                medium_count += 1
            elif f.severity == FindingSeverity.LOW:
                low_count += 1
            elif f.severity == FindingSeverity.INFO:
                info_count += 1

        self.summary = {
            "total_targets": len(self.results),
            "total_findings": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        }

    def filter_min_severity(self, min_severity: FindingSeverity | None) -> None:
        """Filter out findings with severity lower than min_severity."""
        if min_severity is None:
            return
        for r in self.results:
            r.findings = [f for f in r.findings if f.severity.meets_threshold(min_severity)]
        self.compute_summary()

    def has_failures(self, fail_on: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the fail_on threshold."""
        if fail_on is None:
            return False
        for r in self.results:
            if r.error_message:
                return True
            for f in r.findings:
                if f.severity.meets_threshold(fail_on):
                    return True
        return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }


def create_finding(
    rule_id: str,
    target: str,
    message: str,
    line_number: int | None = None,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
) -> Finding:
    """Helper to construct a Finding with metadata populated from RULES_REGISTRY."""
    rule_def = RULES_REGISTRY.get(rule_id)
    if rule_def:
        title = rule_def.title
        category = rule_def.category
        severity = rule_def.severity
    else:
        title = rule_id
        category = FindingCategory.STORAGE_EXPOSURE
        severity = FindingSeverity.MEDIUM

    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        target=target,
        message=message,
        line_number=line_number,
        resource=resource,
        details=details or {},
    )
