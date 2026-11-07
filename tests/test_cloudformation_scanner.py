# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.test_cloudformation_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for CloudFormationScanner."""

from __future__ import annotations

import json
from pathlib import Path

from lh_cloud_posture.cloudformation_scanner import (
    CloudFormationScanner,
    scan_cloudformation,
)
from lh_cloud_posture.models import FindingSeverity

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


def test_cfn_public_s3_bucket() -> None:
    """Test LH-CLOUD-001: CloudFormation S3 bucket with PublicRead ACL."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      PublicBucket:
        Type: "AWS::S3::Bucket"
        Properties:
          AccessControl: "PublicRead"
          PublicAccessBlockConfiguration:
            BlockPublicAcls: false
    """
    scanner = CloudFormationScanner(template)
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


def test_cfn_wildcard_iam_policy() -> None:
    """Test LH-CLOUD-002: CloudFormation IAM policy with wildcard Action and Resource."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      AdminRole:
        Type: "AWS::IAM::Role"
        Properties:
          Policies:
            - PolicyName: "RootPolicy"
              PolicyDocument:
                Statement:
                  - Effect: "Allow"
                    Action: "*"
                    Resource: "*"
    """
    scanner = CloudFormationScanner(template)
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


def test_cfn_open_security_group_ingress() -> None:
    """Test LH-CLOUD-003: Open ingress on port 22 from 0.0.0.0/0."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      InsecureSG:
        Type: "AWS::EC2::SecurityGroup"
        Properties:
          GroupDescription: "Allow SSH"
          SecurityGroupIngress:
            - IpProtocol: "tcp"
              FromPort: 22
              ToPort: 22
              CidrIp: "0.0.0.0/0"
    """
    scanner = CloudFormationScanner(template)
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


def test_cfn_unencrypted_ebs_and_rds() -> None:
    """Test LH-CLOUD-004: Unencrypted EBS volume and RDS DB instance."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      PlainVolume:
        Type: "AWS::EC2::Volume"
        Properties:
          Size: 100
          Encrypted: false
      PlainDatabase:
        Type: "AWS::RDS::DBInstance"
        Properties:
          DBInstanceClass: "db.t3.micro"
          StorageEncrypted: false
    """
    scanner = CloudFormationScanner(template)
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


def test_cfn_cloudtrail_logging() -> None:
    """Test LH-CLOUD-005: CloudTrail without multi-region logging."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      AuditTrail:
        Type: "AWS::CloudTrail::Trail"
        Properties:
          IsMultiRegionTrail: false
          EnableLogging: false
    """
    scanner = CloudFormationScanner(template)
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


def test_cfn_hardcoded_parameters() -> None:
    """Test LH-CLOUD-010: Hardcoded password in CloudFormation parameter default."""
    template = """
    AWSTemplateFormatVersion: "2010-09-09"
    Parameters:
      DbPassword:
        Type: "String"
        Default: "SuperSecretAdminPass123!"
      ApiKey:
        Type: "String"
        Default: "AKIAIOSFODNN7EXAMPLE"
    Resources: {}
    """
    scanner = CloudFormationScanner(template)
    res = scanner.scan()
    rule_010 = [f for f in res.findings if f.rule_id == "LH-CLOUD-010"]
    assert len(rule_010) >= 2


def test_cfn_json_template(tmp_path: Path) -> None:
    """Test scanning a CloudFormation JSON template."""
    cfn_json = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "AccessControl": "PublicRead",
                },
            }
        },
    }
    file_path = tmp_path / "template.json"
    file_path.write_text(json.dumps(cfn_json))

    res = scan_cloudformation(file_path)
    assert any(f.rule_id == "LH-CLOUD-001" for f in res.findings)


def test_cfn_error_handling(tmp_path: Path) -> None:
    """Test error handling for missing and invalid template files."""
    res_missing = scan_cloudformation(tmp_path / "nonexistent.yaml")
    assert res_missing.error_message is not None

    invalid_file = tmp_path / "bad.yaml"
    invalid_file.write_text(": invalid * yaml")
    res_bad = scan_cloudformation(invalid_file)
    assert res_bad.error_message is not None
