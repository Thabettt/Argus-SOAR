# Remote state in the bucket created by terraform/bootstrap.
# Bucket, key and region come from backend.hcl (partial configuration):
#
#   terraform init -backend-config=backend.hcl
#
# use_lockfile enables native S3 state locking (no DynamoDB lock table needed).
terraform {
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}
