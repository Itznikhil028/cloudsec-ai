resource "aws_s3_bucket" "unlabeled_data_lake" {
  bucket = "prod-compliant-lake-2026"

  tags = {
    Environment = "production"
    Owner       = "security-core"
  }
}

resource "aws_instance" "rogue_compute" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  tags = {
    Environment = "production"
    Owner       = "security-core"
  }
}
