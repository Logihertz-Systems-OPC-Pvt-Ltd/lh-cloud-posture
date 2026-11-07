# lh-cloud-posture

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-cloud-posture/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-cloud-posture/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise cloud infrastructure & iac security (cspm) developed by **Logihertz Systems (OPC) Private Limited**.

Audits Terraform HCL/JSON plans, Kubernetes workload manifests, and AWS CloudFormation templates for public storage buckets, wildcard IAM privileges, unencrypted volumes, and exposed security groups.

---

## Key Features

- **Multi-IaC Static Auditing**: Parses HCL/Terraform, Kubernetes resource manifests, and CloudFormation templates without cloud credentials.
- **Cloud Storage & Data Encryption**: Detects public S3 buckets, unencrypted EBS volumes, and unencrypted RDS instances.
- **IAM & RBAC Privilege Analysis**: Flags wildcard `Action: *` or `Resource: *` policies, and over-privileged Kubernetes `ClusterRole` bindings.
- **Container & Workload Hardening**: Detects privileged containers, `hostNetwork`, `hostPID`, and `hostPath` volume mounts in pod specs.
- **Secret Hygiene**: Detects hardcoded passwords, tokens, and private keys embedded in IaC variable defaults or ConfigMaps.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-CLOUD-001` | `CRITICAL` | Publicly accessible storage bucket or public ACL in Terraform/CloudFormation |
| `LH-CLOUD-002` | `CRITICAL` | Overly permissive IAM policy with wildcard Action ('*') or Resource ('*') |
| `LH-CLOUD-003` | `HIGH` | Unrestricted ingress (0.0.0.0/0 or ::/0) in Security Groups or Network ACLs |
| `LH-CLOUD-004` | `HIGH` | Unencrypted cloud storage, EBS volumes, or RDS database instances |
| `LH-CLOUD-005` | `MEDIUM` | Disabled audit logging, CloudTrail multi-region disabled, or missing flow logs |
| `LH-CLOUD-006` | `CRITICAL` | Kubernetes Pod/Deployment running with privileged: true, hostNetwork, hostPID, or hostPath |
| `LH-CLOUD-007` | `MEDIUM` | Kubernetes container spec missing CPU/memory resource limits or requests |
| `LH-CLOUD-008` | `HIGH` | Kubernetes RBAC ClusterRole or Role granting wildcard verbs/resources or cluster-admin |
| `LH-CLOUD-009` | `LOW` | Kubernetes Pod/ServiceAccount with automountServiceAccountToken not explicitly disabled |
| `LH-CLOUD-010` | `CRITICAL` | Hardcoded secrets, API keys, or plaintext passwords in IaC definitions |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-cloud-posture.git
cd lh-cloud-posture

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-cloud` (also accessible via `lh-cloud`, `lh-cloud-posture`).

```bash
# Scan a Terraform configuration directory
lh-cloud scan ./infra/terraform/

# Scan a Kubernetes deployment manifest
lh-cloud scan deploy.yaml --format json

# Export findings to OASIS SARIF v2.1.0
lh-cloud scan ./k8s/ --format sarif --output cloud-findings.sarif

# Filter findings by minimum severity
lh-cloud scan ./infra/ --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
