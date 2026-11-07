# ==============================================================================
# Product:       lh-cloud-posture (lh-cloud)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-cloud-posture."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_clean_terraform() -> str:
    """Return a hardened, compliant Terraform HCL string."""
    return """
    resource "aws_s3_bucket" "secure_bucket" {
      bucket = "my-secure-company-bucket"
      acl    = "private"
    }

    resource "aws_s3_bucket_public_access_block" "secure_pab" {
      bucket                  = aws_s3_bucket.secure_bucket.id
      block_public_acls       = true
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true
    }

    resource "aws_ebs_volume" "secure_ebs" {
      availability_zone = "us-east-1a"
      size              = 40
      encrypted         = true
    }
    """


@pytest.fixture
def sample_vulnerable_terraform() -> str:
    """Return a Terraform HCL string with multiple cloud misconfigurations."""
    return """
    resource "aws_s3_bucket" "public_bucket" {
      bucket = "data-lake-public"
      acl    = "public-read"
    }

    resource "aws_iam_policy" "admin_access" {
      name   = "overly-permissive-policy"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Effect   = "Allow"
            Action   = "*"
            Resource = "*"
          }
        ]
      })
    }

    resource "aws_security_group" "open_ssh" {
      name = "open-ssh-sg"
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }

    resource "aws_ebs_volume" "unencrypted_vol" {
      availability_zone = "us-east-1a"
      size              = 20
      encrypted         = false
    }
    """


@pytest.fixture
def sample_k8s_manifest() -> str:
    """Return a Kubernetes manifest with security misconfigurations."""
    return """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: privileged-app
    spec:
      replicas: 1
      template:
        spec:
          hostNetwork: true
          containers:
            - name: worker
              image: alpine:3.19
              securityContext:
                privileged: true
    """
