# One customer-managed key per data classification boundary:
#   cloudtrail - CloudTrail log files
#   evidence   - evidence bucket and the VPC Flow Logs group
#   ssm        - SecureString parameters (simulation credentials, webhook URL)
#
# Each key policy keeps the standard "delegate to IAM" statement, so IAM policies on
# the Argus roles grant the actual kms:* permissions; service principals get only what
# they need, scoped with aws:SourceArn / encryption context to prevent confused deputies.

locals {
  root_arn = "arn:${var.partition}:iam::${var.account_id}:root"

  delegate_to_iam = {
    Sid       = "EnableIAMPolicies"
    Effect    = "Allow"
    Principal = { AWS = local.root_arn }
    Action    = "kms:*"
    Resource  = "*"
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "${var.prefix}: CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.delegate_to_iam,
      {
        Sid       = "CloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = var.trail_arn }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${var.partition}:cloudtrail:*:${var.account_id}:trail/*"
          }
        }
      },
      {
        Sid       = "CloudTrailDescribe"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceArn" = var.trail_arn } }
      },
    ]
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.prefix}-cloudtrail-key"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

resource "aws_kms_key" "evidence" {
  description             = "${var.prefix}: incident evidence and flow logs"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.delegate_to_iam,
      {
        Sid       = "CloudWatchLogsFlowLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:/${var.prefix}/*"
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${var.prefix}-evidence-key"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_kms_key" "ssm" {
  description             = "${var.prefix}: SSM SecureString parameters"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.delegate_to_iam]
  })
}

resource "aws_kms_alias" "ssm" {
  name          = "alias/${var.prefix}-ssm-key"
  target_key_id = aws_kms_key.ssm.key_id
}
