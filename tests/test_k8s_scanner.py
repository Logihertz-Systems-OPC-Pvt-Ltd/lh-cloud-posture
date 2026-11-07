# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.test_k8s_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for KubernetesScanner."""

from __future__ import annotations

from pathlib import Path

from lh_cloud_posture.k8s_scanner import KubernetesScanner, scan_kubernetes
from lh_cloud_posture.models import FindingSeverity

# --------------------------------------------------------------------------
# --- Rule LH-CLOUD-006 (CRITICAL):
#     Privileged Kubernetes Pod/Deployment Execution
# ---
# Evaluates security posture against privileged kubernetes pod/deployment
# execution.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_k8s_privileged_and_host_namespaces() -> None:
    """Test LH-CLOUD-006: Privileged containers, hostNetwork, hostPID, and hostPath."""
    manifest = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: insecure-deploy
    spec:
      template:
        spec:
          hostNetwork: true
          hostPID: true
          volumes:
            - name: host-root
              hostPath:
                path: /
          containers:
            - name: privileged-container
              image: alpine:3.19
              securityContext:
                privileged: true
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    rule_006 = [f for f in res.findings if f.rule_id == "LH-CLOUD-006"]
    assert len(rule_006) == 4
    for f in rule_006:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-007 (MEDIUM):
    #     Kubernetes Container Spec Missing Resource Limits
    # ---
    # Evaluates security posture against kubernetes container spec missing resource
    # limits.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_k8s_missing_resource_limits_and_requests() -> None:
    """Test LH-CLOUD-007: Container missing CPU/memory limits or requests."""
    manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: unconstrained-pod
    spec:
      containers:
        - name: app
          image: nginx:1.25
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    rule_007 = [f for f in res.findings if f.rule_id == "LH-CLOUD-007"]
    assert len(rule_007) == 1
    assert rule_007[0].severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-008 (HIGH):
    #     Kubernetes RBAC Role Granting Wildcard Verbs or cluster-admin
    # ---
    # Evaluates security posture against kubernetes rbac role granting wildcard
    # verbs or cluster-admin.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_k8s_rbac_wildcards_and_cluster_admin() -> None:
    """Test LH-CLOUD-008: ClusterRole wildcard verbs/resources and cluster-admin binding."""
    manifest = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: wildcard-admin
    rules:
      - apiGroups: ["*"]
        resources: ["*"]
        verbs: ["*"]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: user-admin-binding
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: cluster-admin
    subjects:
      - kind: ServiceAccount
        name: app-runner
        namespace: default
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    rule_008 = [f for f in res.findings if f.rule_id == "LH-CLOUD-008"]
    assert len(rule_008) == 2
    for f in rule_008:
        assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-009 (LOW):
    #     Kubernetes Pod with automountServiceAccountToken Enabled
    # ---
    # Evaluates security posture against kubernetes pod with
    # automountserviceaccounttoken enabled.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_k8s_automount_token() -> None:
    """Test LH-CLOUD-009: automountServiceAccountToken not explicitly false."""
    manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: default-token-pod
    spec:
      containers:
        - name: web
          image: nginx:1.25
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    rule_009 = [f for f in res.findings if f.rule_id == "LH-CLOUD-009"]
    assert len(rule_009) == 1
    assert rule_009[0].severity == FindingSeverity.LOW
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


def test_k8s_configmap_secrets() -> None:
    """Test LH-CLOUD-010: Hardcoded secrets in ConfigMap."""
    manifest = """
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: app-config
    data:
      DB_PASSWORD: "HardcodedPlainTextPassword123!"
      GITHUB_TOKEN: "ghp_123456789012345678901234567890123456"
      SAFE_CONFIG: "true"
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    rule_010 = [f for f in res.findings if f.rule_id == "LH-CLOUD-010"]
    assert len(rule_010) >= 2
    for f in rule_010:
        assert f.severity == FindingSeverity.CRITICAL


def test_k8s_clean_pod_manifest() -> None:
    """Test clean, fully secured Kubernetes pod manifest."""
    manifest = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: secure-pod
    spec:
      automountServiceAccountToken: false
      containers:
        - name: app
          image: cgr.dev/chainguard/static:latest
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "64Mi"
          securityContext:
            privileged: false
    """
    scanner = KubernetesScanner(manifest)
    res = scanner.scan()
    assert len(res.findings) == 0


def test_k8s_error_handling(tmp_path: Path) -> None:
    """Test error handling for missing and invalid YAML."""
    res_missing = scan_kubernetes(tmp_path / "missing.yaml")
    assert res_missing.error_message is not None

    invalid_yaml = tmp_path / "bad.yaml"
    invalid_yaml.write_text(": invalid: yaml - *")
    res_bad = scan_kubernetes(invalid_yaml)
    assert res_bad.error_message is not None
