# Security Rules Reference: lh-cloud-posture

An enterprise cloud infrastructure security posture & iac auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-cloud-posture`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-CLOUD-001` | `CRITICAL` | Storage Exposure | Publicly Accessible Storage Bucket or Public ACL |
| `LH-CLOUD-002` | `CRITICAL` | IAM/RBAC | Overly Permissive IAM Policy with Wildcard Action or Resource |
| `LH-CLOUD-003` | `HIGH` | Network Ingress | Unrestricted Ingress in Security Groups or Network ACLs |
| `LH-CLOUD-004` | `HIGH` | Data Encryption | Unencrypted Cloud Storage, EBS Volumes, or Database Instances |
| `LH-CLOUD-005` | `MEDIUM` | Audit Logging | Disabled Audit Logging or Single-Region CloudTrail |
| `LH-CLOUD-006` | `CRITICAL` | Workload Isolation | Privileged Kubernetes Pod/Deployment Execution |
| `LH-CLOUD-007` | `MEDIUM` | Resource Management | Kubernetes Container Spec Missing Resource Limits |
| `LH-CLOUD-008` | `HIGH` | IAM/RBAC | Kubernetes RBAC Role Granting Wildcard Verbs or cluster-admin |
| `LH-CLOUD-009` | `LOW` | Workload Isolation | Kubernetes Pod with automountServiceAccountToken Enabled |
| `LH-CLOUD-010` | `CRITICAL` | Secret Exposure | Hardcoded Secrets or Plaintext Passwords in IaC Definitions |

---

## Granular Rule Specifications

### `LH-CLOUD-001`: Publicly Accessible Storage Bucket or Public ACL

- **Severity**: `CRITICAL`
- **Category**: `Storage Exposure`
- **Description**: Cloud storage bucket configured with public ACL or public access block settings disabled.
- **Remediation**: Enforce private ACLs on storage buckets and enable all public access block controls.

---

### `LH-CLOUD-002`: Overly Permissive IAM Policy with Wildcard Action or Resource

- **Severity**: `CRITICAL`
- **Category**: `IAM/RBAC`
- **Description**: IAM policy statement grants administrative privileges with wildcard Action ('*') or Resource ('*').
- **Remediation**: Apply least privilege by scoping Action to specific API verbs and Resource to exact ARNs.

---

### `LH-CLOUD-003`: Unrestricted Ingress in Security Groups or Network ACLs

- **Severity**: `HIGH`
- **Category**: `Network Ingress`
- **Description**: Security Group or Network ACL allows inbound traffic from 0.0.0.0/0 on sensitive ports.
- **Remediation**: Restrict ingress rules to authorized corporate CIDR blocks or internal security groups.

---

### `LH-CLOUD-004`: Unencrypted Cloud Storage, EBS Volumes, or Database Instances

- **Severity**: `HIGH`
- **Category**: `Data Encryption`
- **Description**: EBS volumes, S3 buckets, or RDS databases configured without KMS encryption at rest.
- **Remediation**: Enable default encryption using AWS KMS or customer-managed KMS keys.

---

### `LH-CLOUD-005`: Disabled Audit Logging or Single-Region CloudTrail

- **Severity**: `MEDIUM`
- **Category**: `Audit Logging`
- **Description**: CloudTrail logging disabled, single-region only, or missing VPC flow log definitions.
- **Remediation**: Enable multi-region CloudTrail with log validation and activate VPC flow logs.

---

### `LH-CLOUD-006`: Privileged Kubernetes Pod/Deployment Execution

- **Severity**: `CRITICAL`
- **Category**: `Workload Isolation`
- **Description**: Kubernetes workload configured with privileged: true, hostNetwork, hostPID, or hostPath.
- **Remediation**: Remove privileged flags, isolate host namespaces, and replace hostPath with persistent volumes.

---

### `LH-CLOUD-007`: Kubernetes Container Spec Missing Resource Limits

- **Severity**: `MEDIUM`
- **Category**: `Resource Management`
- **Description**: Container spec lacks CPU or memory limits and requests, risking node exhaustion.
- **Remediation**: Define explicit CPU and memory requests and limits for all containers in pod spec.

---

### `LH-CLOUD-008`: Kubernetes RBAC Role Granting Wildcard Verbs or cluster-admin

- **Severity**: `HIGH`
- **Category**: `IAM/RBAC`
- **Description**: ClusterRole or Role grants wildcard ('*') verbs or binds to cluster-admin.
- **Remediation**: Scope RBAC permissions strictly to specific resources and required API verbs.

---

### `LH-CLOUD-009`: Kubernetes Pod with automountServiceAccountToken Enabled

- **Severity**: `LOW`
- **Category**: `Workload Isolation`
- **Description**: ServiceAccount token automatically mounted in pod that does not require Kubernetes API access.
- **Remediation**: Set automountServiceAccountToken: false on ServiceAccounts and Pod specifications.

---

### `LH-CLOUD-010`: Hardcoded Secrets or Plaintext Passwords in IaC Definitions

- **Severity**: `CRITICAL`
- **Category**: `Secret Exposure`
- **Description**: Plaintext passwords, API keys, or private certificates embedded in IaC defaults.
- **Remediation**: Externalize secrets to AWS Secrets Manager, HashiCorp Vault, or sealed secrets.

---
