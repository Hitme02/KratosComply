resource "aws_s3_bucket" "demo" {
  bucket = "kratos-demo"
  acl    = "public-read"
}
