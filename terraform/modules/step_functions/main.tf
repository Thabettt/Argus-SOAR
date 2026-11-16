# One Standard state machine per playbook, all rendered from playbook.asl.json.tftpl.
# Standard (not Express): the 15-minute Wait, exactly-once steps and the console
# execution history (the per-incident audit trail) all need it.

locals {
  playbooks = {
    iam = "iam-playbook"
    ec2 = "ec2-playbook"
    s3  = "s3-playbook"
  }

  lambda_retry = jsonencode({
    ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException",
    "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 2
    BackoffRate     = 2
    MaxAttempts     = 3
  })

  catch_to_failed = jsonencode({
    ErrorEquals = ["States.ALL"]
    ResultPath  = "$.error"
    Next        = "MarkFailed"
  })
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.prefix}-step-functions"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "sfn" {
  name = "orchestrate"
  role = aws_iam_role.sfn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = concat(values(var.function_arns), [for a in values(var.function_arns) : "${a}:*"])
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
        Resource = var.incidents_table_arn
      },
      {
        # Required by Step Functions to deliver execution logs to CloudWatch Logs.
        Effect = "Allow"
        Action = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
        "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${var.prefix}-playbooks"
  retention_in_days = 30
}

resource "aws_sfn_state_machine" "playbook" {
  for_each = local.playbooks
  name     = "${var.prefix}-${each.value}"
  type     = "STANDARD"
  role_arn = aws_iam_role.sfn.arn

  definition = templatefile("${path.module}/playbook.asl.json.tftpl", {
    playbook                   = each.key
    validator_arn              = var.function_arns["validator"]
    forensics_arn              = var.function_arns["forensics"]
    playbook_arn               = var.function_arns[each.value]
    package_arn                = var.function_arns["package-evidence"]
    finalize_arn               = var.function_arns["finalize"]
    notifier_arn               = var.function_arns["notifier"]
    late_evidence_arn          = var.function_arns["late-evidence"]
    table_name                 = var.incidents_table
    late_evidence_wait_seconds = var.late_evidence_wait_seconds
    lambda_retry               = local.lambda_retry
    catch_to_failed            = local.catch_to_failed
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  depends_on = [aws_iam_role_policy.sfn]
}
