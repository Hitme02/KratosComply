resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  # Insecure ACL (violation)
  acl = "public-read"
}

resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
  acl    = "private"  # OK
}
