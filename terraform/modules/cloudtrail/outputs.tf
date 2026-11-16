output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "log_bucket" {
  value = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}
