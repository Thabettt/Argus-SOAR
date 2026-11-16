# One rule per playbook on the default bus, matching Security Hub "Findings - Imported".
# Each rule: GuardDuty only, finding type by wildcard on ASFF Types, its OWN severity
# threshold, Workflow NEW + RecordState ACTIVE (so updates - including Argus's own
# RESOLVED update - never re-trigger), and scoped to the exact simulation resources.
#
# Verify the Types strings and the IAM principal field against real captured events
# (build plan Phase 3) before trusting these patterns.

locals {
  base = {
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
  }

  common_finding = {
    ProductName = ["GuardDuty"]
    Workflow    = { Status = ["NEW"] }
    RecordState = ["ACTIVE"]
  }

  severities_from = {
    LOW    = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    MEDIUM = ["MEDIUM", "HIGH", "CRITICAL"]
    HIGH   = ["HIGH", "CRITICAL"]
  }

  rules = {
    iam = {
      description   = "IAM credential compromise from a threat-list IP"
      state_machine = "iam"
      types         = "*UnauthorizedAccess:IAMUser-MaliciousIPCaller*"
      min_severity  = "MEDIUM"
      scope = {
        Resources = { Details = { AwsIamAccessKey = { PrincipalName = [{ prefix = "${var.prefix}-sim-" }] } } }
      }
    }
    ec2 = {
      description   = "EC2 crypto-mining (BitcoinTool) on the simulation instance"
      state_machine = "ec2"
      types         = "*CryptoCurrency:EC2-BitcoinTool*"
      min_severity  = "HIGH"
      scope         = { Resources = { Id = [var.sim_instance_arn] } }
    }
    s3 = {
      description   = "S3 discovery/exfiltration from a threat-list IP on the simulation bucket"
      state_machine = "s3"
      types         = "*Discovery:S3-MaliciousIPCaller*"
      min_severity  = "HIGH"
      scope         = { Resources = { Id = [var.sim_bucket_arn] } }
    }
    s3-policy = {
      # LOW is accepted only because the scope is one exact bucket ARN.
      description   = "Block Public Access disabled on the simulation bucket"
      state_machine = "s3"
      types         = "*Policy:S3-BucketBlockPublicAccessDisabled*"
      min_severity  = "LOW"
      scope         = { Resources = { Id = [var.sim_bucket_arn] } }
    }
  }

  input_paths = {
    event_id        = "$.id"
    event_received  = "$.time"
    finding_id      = "$.detail.findings[0].Id"
    product_arn     = "$.detail.findings[0].ProductArn"
    finding_type    = "$.detail.findings[0].Types[0]"
    severity        = "$.detail.findings[0].Severity.Label"
    finding_created = "$.detail.findings[0].CreatedAt"
    account         = "$.detail.findings[0].AwsAccountId"
    region          = "$.detail.findings[0].Region"
    resources       = "$.detail.findings[0].Resources"
  }

  # Unquoted placeholders: EventBridge inserts strings with quotes and objects/arrays as JSON.
  input_template = <<-EOT
    {"finding_id": <finding_id>, "product_arn": <product_arn>, "event_id": <event_id>, "event_received": <event_received>, "finding_type": <finding_type>, "severity": <severity>, "finding_created": <finding_created>, "account": <account>, "region": <region>, "resources": <resources>}
  EOT
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "events" {
  name               = "${var.prefix}-eventbridge"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy" "events" {
  name = "start-playbooks"
  role = aws_iam_role.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = values(var.state_machine_arns)
    }]
  })
}

resource "aws_cloudwatch_event_rule" "playbook" {
  for_each    = local.rules
  name        = "${var.prefix}-${each.key}"
  description = each.value.description

  event_pattern = jsonencode(merge(local.base, {
    detail = {
      findings = merge(local.common_finding, each.value.scope, {
        Types    = [{ wildcard = each.value.types }]
        Severity = { Label = local.severities_from[each.value.min_severity] }
      })
    }
  }))
}

resource "aws_cloudwatch_event_target" "playbook" {
  for_each = local.rules
  rule     = aws_cloudwatch_event_rule.playbook[each.key].name
  arn      = var.state_machine_arns[each.value.state_machine]
  role_arn = aws_iam_role.events.arn

  input_transformer {
    input_paths    = local.input_paths
    input_template = trimspace(local.input_template)
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}

output "rule_names" {
  value = [for r in aws_cloudwatch_event_rule.playbook : r.name]
}
