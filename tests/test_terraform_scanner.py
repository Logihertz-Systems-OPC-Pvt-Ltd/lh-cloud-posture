# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.test_terraform_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for TerraformScanner."""

from __future__ import annotations

import json
from pathlib import Path

from lh_cloud_posture.models import FindingSeverity
from lh_cloud_posture.terraform_scanner import TerraformScanner, scan_terraform

# --------------------------------------------------------------------------
# --- Rule LH-CLOUD-001 (CRITICAL):
#     Publicly Accessible Storage Bucket or Public ACL
# ---
# Evaluates security posture against publicly accessible storage bucket or
# public acl.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_terraform_public_s3_and_pab(tmp_path: Path) -> None:
    """Test LH-CLOUD-001: Public S3 bucket ACL and disabled public access block."""
    tf_content = """
    resource "aws_s3_bucket" "open_bucket" {
      bucket = "public-assets"
      acl    = "public-read"
    }

    resource "aws_s3_bucket_public_access_block" "open_pab" {
      bucket            = aws_s3_bucket.open_bucket.id
      block_public_acls = false
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_001 = [f for f in res.findings if f.rule_id == "LH-CLOUD-001"]
    assert len(rule_001) == 2
    for f in rule_001:
        assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-002 (CRITICAL):
    #     Overly Permissive IAM Policy with Wildcard Action or Resource
    # ---
    # Evaluates security posture against overly permissive iam policy with wildcard
    # action or resource.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_terraform_wildcard_iam_policy() -> None:
    """Test LH-CLOUD-002: Overly permissive IAM policy with wildcard Action and Resource."""
    tf_content = """
    resource "aws_iam_policy" "wildcard_policy" {
      name = "super-admin"
      policy = jsonencode({
        Statement = [
          {
            Effect   = "Allow"
            Action   = ["*"]
            Resource = ["*"]
          }
        ]
      })
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_002 = [f for f in res.findings if f.rule_id == "LH-CLOUD-002"]
    assert len(rule_002) == 1
    assert rule_002[0].severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-003 (HIGH):
    #     Unrestricted Ingress in Security Groups or Network ACLs
    # ---
    # Evaluates security posture against unrestricted ingress in security groups or
    # network acls.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_terraform_unrestricted_ingress() -> None:
    """Test LH-CLOUD-003: Unrestricted security group ingress on port 22."""
    tf_content = """
    resource "aws_security_group" "ssh_sg" {
      name = "allow_all_ssh"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_003 = [f for f in res.findings if f.rule_id == "LH-CLOUD-003"]
    assert len(rule_003) == 1
    assert rule_003[0].severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-004 (HIGH):
    #     Unencrypted Cloud Storage, EBS Volumes, or Database Instances
    # ---
    # Evaluates security posture against unencrypted cloud storage, ebs volumes, or
    # database instances.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_terraform_unencrypted_storage() -> None:
    """Test LH-CLOUD-004: Unencrypted EBS volume and RDS database instance."""
    tf_content = """
    resource "aws_ebs_volume" "data_vol" {
      availability_zone = "us-east-1a"
      size              = 100
      encrypted         = false
    }

    resource "aws_db_instance" "prod_db" {
      instance_class    = "db.t3.micro"
      engine            = "postgres"
      storage_encrypted = false
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_004 = [f for f in res.findings if f.rule_id == "LH-CLOUD-004"]
    assert len(rule_004) == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-CLOUD-005 (MEDIUM):
    #     Disabled Audit Logging or Single-Region CloudTrail
    # ---
    # Evaluates security posture against disabled audit logging or single-region
    # cloudtrail.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_terraform_cloudtrail_logging() -> None:
    """Test LH-CLOUD-005: CloudTrail multi-region disabled or logging turned off."""
    tf_content = """
    resource "aws_cloudtrail" "trail_bad" {
      name                  = "audit-trail"
      s3_bucket_name        = "trail-bucket"
      is_multi_region_trail = false
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_005 = [f for f in res.findings if f.rule_id == "LH-CLOUD-005"]
    assert len(rule_005) == 1
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


def test_terraform_hardcoded_secrets() -> None:
    """Test LH-CLOUD-010: Hardcoded secrets in variables and credentials."""
    tf_content = """
    variable "db_password" {
      default = "SuperSecretPassword123!"
    }

    variable "aws_key" {
      default = "AKIAIOSFODNN7EXAMPLE"
    }

    variable "safe_var" {
      default = ""
    }
    """
    scanner = TerraformScanner(tf_content)
    res = scanner.scan()
    rule_010 = [f for f in res.findings if f.rule_id == "LH-CLOUD-010"]
    assert len(rule_010) >= 2


def test_terraform_json_scanning(tmp_path: Path) -> None:
    """Test scanning Terraform JSON (.tf.json) format."""
    tf_data = {
        "resource": {
            "aws_s3_bucket": {
                "public_bucket": {
                    "acl": "public-read",
                }
            },
            "aws_ebs_volume": {
                "unencrypted_vol": {
                    "encrypted": False,
                }
            },
        }
    }
    json_path = tmp_path / "main.tf.json"
    json_path.write_text(json.dumps(tf_data))

    res = scan_terraform(json_path)
    rule_ids = {f.rule_id for f in res.findings}
    assert "LH-CLOUD-001" in rule_ids
    assert "LH-CLOUD-004" in rule_ids


def test_terraform_error_handling(tmp_path: Path) -> None:
    """Test error handling for nonexistent and invalid files."""
    res_missing = scan_terraform(tmp_path / "nonexistent.tf")
    assert res_missing.error_message is not None

    invalid_json = tmp_path / "bad.tf.json"
    invalid_json.write_text("{broken json")
    res_bad = scan_terraform(invalid_json)
    assert res_bad.error_message is not None
