resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "pr-bot-test-bucket-cloudsec"
}

resource "aws_security_group" "open_ssh" {
  name = "pr-bot-open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
