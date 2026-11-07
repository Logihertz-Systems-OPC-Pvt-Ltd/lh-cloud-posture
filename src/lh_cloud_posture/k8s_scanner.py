# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        src.lh_cloud_posture.k8s_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Kubernetes manifest static analysis scanner for lh-cloud-posture.

Inspects Kubernetes YAML and JSON manifests for privileged workloads, host namespaces,
missing resource requests/limits, wildcard RBAC roles, automounted tokens, and plaintext secrets.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Any

import yaml

from lh_cloud_posture.models import (
    Finding,
    ScanTargetResult,
    TargetType,
    create_finding,
)

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "DaemonSet",
    "StatefulSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}

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


class KubernetesScanner:
    """Scanner for analyzing Kubernetes manifest files (.yaml, .yml, .json)."""

    def __init__(self, content: str, target_path: str = "manifest.yaml") -> None:
        """Initialize KubernetesScanner.

        Args:
            content: Raw YAML/JSON manifest content.
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
        """Execute all Kubernetes posture audit rules.

        Returns:
            ScanTargetResult containing all detected findings.
        """
        try:
            docs = list(yaml.safe_load_all(self.content))
        except yaml.YAMLError:
            try:
                docs = list(yaml.safe_load_all(textwrap.dedent(self.content)))
            except Exception as e:
                return ScanTargetResult(
                    target=self.target_path,
                    target_type=TargetType.KUBERNETES,
                    findings=[],
                    error_message=f"YAML parsing error: {e}",
                )
        except Exception as e:
            return ScanTargetResult(
                target=self.target_path,
                target_type=TargetType.KUBERNETES,
                findings=[],
                error_message=f"YAML parsing error: {e}",
            )

        findings: list[Finding] = []

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed") if isinstance(metadata, dict) else "unnamed"
            resource_id = f"{kind}/{name}"

            if kind in WORKLOAD_KINDS:
                self._check_workload(doc, resource_id, findings)
            elif kind in ("ClusterRole", "Role"):
                self._check_rbac_role(doc, resource_id, findings)
            elif kind in ("ClusterRoleBinding", "RoleBinding"):
                self._check_rbac_binding(doc, resource_id, findings)
            elif kind == "ServiceAccount":
                self._check_service_account(doc, resource_id, findings)
            elif kind == "ConfigMap":
                self._check_config_map(doc, resource_id, findings)

        return ScanTargetResult(
            target=self.target_path,
            target_type=TargetType.KUBERNETES,
            findings=findings,
        )

    def _extract_pod_spec(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Extract the pod spec from either Pod or Controller workload."""
        kind = doc.get("kind", "")
        spec = doc.get("spec", {})
        if not isinstance(spec, dict):
            return {}

        if kind == "Pod":
            return spec
        if kind == "CronJob":
            job_spec = spec.get("jobTemplate", {}).get("spec", {})
            if isinstance(job_spec, dict):
                template_spec = job_spec.get("template", {}).get("spec", {})
                return template_spec if isinstance(template_spec, dict) else {}
            return {}

        template = spec.get("template", {})
        return template.get("spec", {}) if isinstance(template, dict) else {}

    def _check_workload(
        self,
        doc: dict[str, Any],
        resource_id: str,
        findings: list[Finding],
    ) -> None:
        """Audit Pod or workload controller specifications."""
        pod_spec = self._extract_pod_spec(doc)
        if not pod_spec or not isinstance(pod_spec, dict):
            return

        res_name = resource_id.split("/")[-1]
        line_base = self._find_line(rf"name\s*:\s*[\"']?{re.escape(res_name)}[\"']?")

        for ns in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(ns) is True:
                line = self._find_line(rf"{ns}\s*:\s*true", line_base)
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-006",
                        target=self.target_path,
                        line_number=line,
                        resource=resource_id,
                        message=f"{resource_id} specifies '{ns}: true', sharing host namespaces.",
                        details={"setting": f"{ns}: true"},
                    )
                )

        volumes = pod_spec.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                if isinstance(vol, dict) and "hostPath" in vol:
                    path_val = vol.get("hostPath", {}).get("path", "")
                    line = self._find_line(r"hostPath\s*:", line_base)
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-006",
                            target=self.target_path,
                            line_number=line,
                            resource=resource_id,
                            message=f"{resource_id} mounts host filesystem volume via hostPath.",
                            details={"hostPath": path_val},
                        )
                    )

        containers = pod_spec.get("containers", [])
        if not isinstance(containers, list):
            containers = []

        init_containers = pod_spec.get("initContainers", [])
        if isinstance(init_containers, list):
            containers = list(containers) + list(init_containers)

        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "unnamed")

            sec_ctx = c.get("securityContext", {})
            if isinstance(sec_ctx, dict) and sec_ctx.get("privileged") is True:
                line = self._find_line(r"privileged\s*:\s*true", line_base)
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-006",
                        target=self.target_path,
                        line_number=line,
                        resource=f"{resource_id}/container:{c_name}",
                        message=f"Container '{c_name}' in {resource_id} has privileged: true.",
                        details={"container": c_name},
                    )
                )

            resources = c.get("resources", {})
            has_res = isinstance(resources, dict) and resources
            limits = resources.get("limits", {}) if has_res else {}
            res_requests = resources.get("requests", {}) if has_res else {}

            missing_limits = not (
                isinstance(limits, dict) and limits.get("cpu") and limits.get("memory")
            )
            missing_requests = not (
                isinstance(res_requests, dict)
                and res_requests.get("cpu")
                and res_requests.get("memory")
            )

            if missing_limits or missing_requests:
                line = self._find_line(rf"name\s*:\s*[\"']?{re.escape(c_name)}[\"']?", line_base)
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-007",
                        target=self.target_path,
                        line_number=line,
                        resource=f"{resource_id}/container:{c_name}",
                        message=(
                            f"Container '{c_name}' in {resource_id} "
                            "missing CPU/memory limits or requests."
                        ),
                        details={
                            "container": c_name,
                            "missing_limits": missing_limits,
                            "missing_requests": missing_requests,
                        },
                    )
                )

        automount = pod_spec.get("automountServiceAccountToken")
        if automount is not False:
            line = (
                self._find_line(r"automountServiceAccountToken\s*:\s*true", line_base) or line_base
            )
            findings.append(
                create_finding(
                    rule_id="LH-CLOUD-009",
                    target=self.target_path,
                    line_number=line,
                    resource=resource_id,
                    message=f"{resource_id} does not set 'automountServiceAccountToken: false'.",
                    details={"automountServiceAccountToken": automount},
                )
            )

    def _check_rbac_role(
        self,
        doc: dict[str, Any],
        resource_id: str,
        findings: list[Finding],
    ) -> None:
        """Check RBAC Role or ClusterRole for wildcard permissions (LH-CLOUD-008)."""
        rules = doc.get("rules", [])
        if not isinstance(rules, list):
            return

        res_name = resource_id.split("/")[-1]
        line_base = self._find_line(rf"name\s*:\s*[\"']?{re.escape(res_name)}[\"']?")

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])

            has_star_verbs = "*" in verbs if isinstance(verbs, list) else verbs == "*"
            has_star_resources = (
                "*" in resources if isinstance(resources, list) else resources == "*"
            )

            if has_star_verbs or has_star_resources:
                line = self._find_line(r'-\s*["\']?\*["\']?', line_base)
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-008",
                        target=self.target_path,
                        line_number=line,
                        resource=resource_id,
                        message=(
                            f"{resource_id} grants wildcard RBAC access (verbs: {verbs}, "
                            f"resources: {resources})."
                        ),
                        details={"verbs": verbs, "resources": resources},
                    )
                )

    def _check_rbac_binding(
        self,
        doc: dict[str, Any],
        resource_id: str,
        findings: list[Finding],
    ) -> None:
        """Check RoleBinding or ClusterRoleBinding for cluster-admin attachment (LH-CLOUD-008)."""
        role_ref = doc.get("roleRef", {})
        if isinstance(role_ref, dict) and role_ref.get("name") == "cluster-admin":
            res_name = resource_id.split("/")[-1]
            line = self._find_line(r"name\s*:\s*[\"']?cluster-admin[\"']?")
            findings.append(
                create_finding(
                    rule_id="LH-CLOUD-008",
                    target=self.target_path,
                    line_number=line,
                    resource=resource_id,
                    message=f"{resource_id} binds subjects directly to the 'cluster-admin' role.",
                    details={"roleRef": "cluster-admin", "binding": res_name},
                )
            )

    def _check_service_account(
        self,
        doc: dict[str, Any],
        resource_id: str,
        findings: list[Finding],
    ) -> None:
        """Check ServiceAccount for automountServiceAccountToken (LH-CLOUD-009)."""
        automount = doc.get("automountServiceAccountToken")
        if automount is not False:
            res_name = resource_id.split("/")[-1]
            line_base = self._find_line(rf"name\s*:\s*[\"']?{re.escape(res_name)}[\"']?")
            findings.append(
                create_finding(
                    rule_id="LH-CLOUD-009",
                    target=self.target_path,
                    line_number=line_base,
                    resource=resource_id,
                    message=f"{resource_id} does not disable automountServiceAccountToken.",
                    details={"automountServiceAccountToken": automount},
                )
            )

    def _check_config_map(
        self,
        doc: dict[str, Any],
        resource_id: str,
        findings: list[Finding],
    ) -> None:
        """Check ConfigMap data for hardcoded secrets or credentials (LH-CLOUD-010)."""
        data = doc.get("data", {})
        if not isinstance(data, dict):
            return

        res_name = resource_id.split("/")[-1]
        line_base = self._find_line(rf"name\s*:\s*[\"']?{re.escape(res_name)}[\"']?")

        for k, v in data.items():
            val_str = str(v).strip()
            if not val_str or PLACEHOLDER_REGEX.match(val_str):
                continue

            found_token = False
            for regex, name in (
                (PRIVATE_KEY_REGEX, "Private Key"),
                (AWS_KEY_REGEX, "AWS Access Key"),
                (GITHUB_TOKEN_REGEX, "GitHub Token"),
                (SLACK_TOKEN_REGEX, "Slack Token"),
            ):
                if regex.search(val_str):
                    line = self._find_line(re.escape(k), line_base)
                    findings.append(
                        create_finding(
                            rule_id="LH-CLOUD-010",
                            target=self.target_path,
                            line_number=line,
                            resource=f"{resource_id}:{k}",
                            message=f"{resource_id} contains hardcoded {name} in key '{k}'.",
                            details={"key": k, "secret_type": name},
                        )
                    )
                    found_token = True
                    break

            if found_token:
                continue

            if SECRET_KEY_REGEX.search(k):
                line = self._find_line(re.escape(k), line_base)
                findings.append(
                    create_finding(
                        rule_id="LH-CLOUD-010",
                        target=self.target_path,
                        line_number=line,
                        resource=f"{resource_id}:{k}",
                        message=f"{resource_id} stores potential credential in key '{k}'.",
                        details={"key": k},
                    )
                )


def scan_kubernetes(path: Path | str) -> ScanTargetResult:
    """Read and scan a Kubernetes manifest file.

    Args:
        path: Path to YAML or JSON manifest.

    Returns:
        ScanTargetResult with audit findings.
    """
    file_path = Path(path)
    if not file_path.exists():
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.KUBERNETES,
            findings=[],
            error_message=f"File not found: {file_path}",
        )

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return ScanTargetResult(
            target=str(file_path),
            target_type=TargetType.KUBERNETES,
            findings=[],
            error_message=f"Failed to read file: {e}",
        )

    scanner = KubernetesScanner(content=content, target_path=str(file_path))
    return scanner.scan()
