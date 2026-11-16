# VPC Flow Logs for Argus's own forensics (GuardDuty reads flow data independently).
# Records arrive ~10 minutes late, so they are queried by CollectLateEvidence.

variable "prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "retention_days" {
  type    = number
  default = 30
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/${var.prefix}/vpc-flow-logs"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "deliver" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
  statement {
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "deliver-flow-logs"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.deliver.json
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = var.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  tags                     = { Name = "${var.prefix}-flow-logs" }
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.flow_logs.name
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.flow_logs.arn
}
