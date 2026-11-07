# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the CLI interface using Typer CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_cloud_posture.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Test CLI top-level and subcommand help commands."""
    res = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Enterprise cloud security posture analyzer" in res.stdout

    res_scan = runner.invoke(app, ["scan", "--help"], env=CLI_ENV)
    assert res_scan.exit_code == 0
    assert "--format" in res_scan.stdout
    assert "--min-severity" in res_scan.stdout
    assert "--fail-on" in res_scan.stdout

    res_rules = runner.invoke(app, ["rules", "--help"], env=CLI_ENV)
    assert res_rules.exit_code == 0
    assert "List all supported LH-CLOUD security posture detection rules" in res_rules.stdout


def test_cli_rules_list() -> None:
    """Test listing all 10 LH-CLOUD detection rules."""
    res = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert res.exit_code == 0
    for i in range(1, 11):
        rule_id = f"LH-CLOUD-{i:03d}"
        assert rule_id in res.stdout


def test_cli_scan_clean_terraform(tmp_path: Path) -> None:
    """Test scanning a secure Terraform file produces exit code 0."""
    clean_tf = tmp_path / "main.tf"
    clean_tf.write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "private-bucket"\n  acl    = "private"\n}\n'
    )

    res = runner.invoke(app, ["scan", str(clean_tf)], env=CLI_ENV)
    assert res.exit_code == 0
    assert "Clean Audit" in res.stdout


def test_cli_scan_violations_terraform(tmp_path: Path) -> None:
    """Test scanning a vulnerable Terraform file produces exit code 1 with default fail-on HIGH."""
    vuln_tf = tmp_path / "main.tf"
    vuln_tf.write_text(
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "public-bucket"\n'
        '  acl    = "public-read"\n'
        "}\n"
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n"
        "    from_port   = 22\n"
        "    to_port     = 22\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )

    res = runner.invoke(app, ["scan", str(vuln_tf)], env=CLI_ENV)
    assert res.exit_code == 1
    assert "LH-CLOUD-001" in res.stdout
    assert "LH-CLOUD-003" in res.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    """Test CLI output in JSON format."""
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "test-bucket"\n}\n')

    res = runner.invoke(app, ["scan", str(tf), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["report_type"] == "cloud_posture"
    assert "summary" in data


def test_cli_scan_sarif_output(tmp_path: Path) -> None:
    """Test CLI output in SARIF format."""
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')

    res = runner.invoke(
        app,
        ["scan", str(tf), "--format", "sarif", "--fail-on", "CRITICAL"],
        env=CLI_ENV,
    )
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


def test_cli_scan_output_file(tmp_path: Path) -> None:
    """Test writing scan results to an output file."""
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "test-bucket"\n}\n')
    out_file = tmp_path / "report.json"

    res = runner.invoke(
        app,
        ["scan", str(tf), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["report_type"] == "cloud_posture"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Test --fail-on threshold logic."""
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_cloudtrail" "trail" {\n'
        '  name                  = "trail"\n'
        "  is_multi_region_trail = false\n"
        "}\n"
    )

    # Fail on HIGH: should pass (exit 0) because finding is MEDIUM (LH-CLOUD-005)
    res_high = runner.invoke(
        app,
        ["scan", str(tf), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert res_high.exit_code == 0

    # Fail on MEDIUM: should fail (exit 1)
    res_med = runner.invoke(
        app,
        ["scan", str(tf), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert res_med.exit_code == 1


def test_cli_scan_min_severity_filter(tmp_path: Path) -> None:
    """Test --min-severity filtering."""
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_cloudtrail" "trail" {\n'
        '  name                  = "trail"\n'
        "  is_multi_region_trail = false\n"
        "}\n"
    )

    # Filter min-severity HIGH: MEDIUM is filtered out -> 0 findings
    res = runner.invoke(
        app,
        ["scan", str(tf), "--min-severity", "HIGH", "--format", "json"],
        env=CLI_ENV,
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["summary"]["total_findings"] == 0


def test_cli_scan_directory(tmp_path: Path) -> None:
    """Test scanning a directory with Terraform, Kubernetes, and CloudFormation."""
    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" { bucket = "clean" }\n')

    k8s = tmp_path / "deploy.yaml"
    k8s.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: pod\n"
        "spec:\n"
        "  automountServiceAccountToken: false\n"
        "  containers:\n"
        "    - name: c\n"
        "      image: static\n"
        "      resources:\n"
        "        limits: { cpu: 1, memory: 1Gi }\n"
        "        requests: { cpu: 1, memory: 1Gi }\n"
    )

    cfn = tmp_path / "template.template"
    cfn.write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B: { Type: "AWS::S3::Bucket" }\n'
    )

    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"], env=CLI_ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert len(data["results"]) >= 3


def test_cli_scan_nonexistent_target() -> None:
    """Test error handling when target path does not exist."""
    res = runner.invoke(app, ["scan", "/nonexistent/path/target"], env=CLI_ENV)
    assert res.exit_code == 2
    assert "does not exist" in res.stdout
