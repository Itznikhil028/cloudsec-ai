resource "aws_s3_bucket" "unlabeled_data_lake" {
  bucket = "prod-unlabeled-lake-2026"
}

resource "aws_instance" "rogue_compute" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "p4d.24xlarge"
}
