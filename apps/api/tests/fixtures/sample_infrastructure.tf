resource "aws_s3_bucket" "audit_test_bucket" {
  bucket = "ci-security-gate-test-bucket"
}

resource "aws_s3_bucket_public_access_block" "audit_test_pab" {
  bucket = aws_s3_bucket.audit_test_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "ci_firewall" {
  name        = "ci-hardened-sg"
  description = "Hardened security group for CI testing"

  ingress {
    description = "SSH internal bastion"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
