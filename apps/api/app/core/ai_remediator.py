from typing import Dict, Any

class AIRemediator:
    KNOWLEDGE_BASE = {
        'CKV_AWS_24': {
            'root_cause': 'Security group allows ingress on port 22 (SSH) from 0.0.0.0/0, exposing instances to brute-force attacks.',
            'patch': '''# Restrict SSH access to trusted CIDR or VPN
ingress {
  description = "SSH from bastion host only"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
}'''
        },
        'CKV2_AWS_6': {
            'root_cause': 'S3 bucket lacks an explicit public access block configuration, leaving data vulnerable to public exposure.',
            'patch': '''resource "aws_s3_bucket_public_access_block" "pab" {
  bucket = aws_s3_bucket.test_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}'''
        },
        'CKV_AWS_145': {
            'root_cause': 'S3 bucket objects are not encrypted at rest with AWS KMS managed customer keys (SSE-KMS).',
            'patch': '''resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.test_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}'''
        },
        'CKV_AWS_21': {
            'root_cause': 'Object versioning is disabled on the S3 bucket, preventing recovery from accidental overwrites or deletes.',
            'patch': '''resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.test_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}'''
        }
    }

    @classmethod
    def generate_remediation(cls, rule_id: str, title: str, resource_name: str) -> Dict[str, str]:
        if rule_id in cls.KNOWLEDGE_BASE:
            return cls.KNOWLEDGE_BASE[rule_id]
        return {
            'root_cause': f'Resource {resource_name} violates CIS compliance check: {title}.',
            'patch': f'# Remediation: Apply least-privilege security controls conforming to {rule_id}.'
        }
