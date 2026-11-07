# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from lh_cloud_posture.exporters import (
    _get_severity_badge,
    _severity_to_sarif_level,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_cloud_posture.models import (
    RULES_REGISTRY,
    AuditReport,
    Finding,
    FindingCategory,
    FindingSeverity,
    ScanTargetResult,
    TargetType,
)


def _sample_report() -> AuditReport:
    """Create a sample AuditReport with findings."""
    f1 = Finding(
        rule_id="LH-CLOUD-001",
        title="Public bucket",
        category=FindingCategory.STORAGE_EXPOSURE,
        severity=FindingSeverity.CRITICAL,
        target="main.tf",
        line_number=10,
        resource="aws_s3_bucket.public",
        message="Public bucket ACL configured.",
    )
    f2 = Finding(
        rule_id="LH-CLOUD-003",
        title="Unrestricted ingress",
        category=FindingCategory.NETWORK_INGRESS,
        severity=FindingSeverity.HIGH,
        target="main.tf",
        line_number=25,
        resource="aws_security_group.ssh",
        message="Port 22 open to 0.0.0.0/0.",
    )
    f3 = Finding(
        rule_id="LH-CLOUD-009",
        title="automountServiceAccountToken not disabled",
        category=FindingCategory.WORKLOAD_ISOLATION,
        severity=FindingSeverity.LOW,
        target="pod.yaml",
        line_number=5,
        resource="Pod/app",
        message="Token automount enabled.",
    )
    res = ScanTargetResult(
        target="main.tf",
        target_type=TargetType.TERRAFORM,
        findings=[f1, f2, f3],
    )
    report = AuditReport(
        report_type="cloud_posture",
        generated_at=datetime.now(UTC),
        parameters={"format": "table", "min_severity": "LOW"},
        results=[res],
    )
    report.compute_summary()
    return report


def test_export_json() -> None:
    """Test JSON export serialization and structure."""
    report = _sample_report()
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "cloud_posture"
    assert "summary" in data
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert data["summary"]["low"] == 1
    assert len(data["results"]) == 1


def test_export_sarif() -> None:
    """Test OASIS SARIF v2.1.0 output."""
    report = _sample_report()
    sarif_str = export_sarif(report)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-cloud-posture"
    assert len(run["results"]) == 3


def test_render_table_report() -> None:
    """Test Rich terminal table rendering."""
    report = _sample_report()
    rendered = render_table_report(report)

    assert "lh-cloud-posture" in rendered
    assert "Audit Executive Summary" in rendered
    assert "LH-CLOUD-001" in rendered
    assert "CRITICAL" in rendered


def test_render_table_clean_report() -> None:
    """Test Rich table rendering with no findings."""
    res = ScanTargetResult(
        target="clean.tf",
        target_type=TargetType.TERRAFORM,
        findings=[],
    )
    report = AuditReport(
        report_type="cloud_posture",
        generated_at=datetime.now(UTC),
        parameters={},
        results=[res],
    )
    rendered = render_table_report(report)
    assert "Clean Audit" in rendered


def test_rule_definition_and_badges() -> None:
    """Test rule serialization and badge levels."""
    rule = RULES_REGISTRY["LH-CLOUD-001"]
    assert rule.to_dict()["rule_id"] == "LH-CLOUD-001"

    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"
    assert _severity_to_sarif_level(FindingSeverity.INFO) == "note"

    badge = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in str(badge)
