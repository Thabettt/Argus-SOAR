# Rules on the default bus, matching Security Hub "Findings - Imported".
# GuardDuty rules: finding type by wildcard on ASFF Types, its OWN severity
# threshold, RecordState ACTIVE and any workflow status but SUPPRESSED, and scoped to
# the exact simulation resources.
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
    # Anything but SUPPRESSED (a human said "ignore this"). RESOLVED findings stay in, so a
    # recurrence after recovery triggers again: GuardDuty updates the same finding (new
    # UpdatedAt) instead of creating one. Argus's own RESOLVED update keeps the same
    # UpdatedAt, so it is de-duplicated by the per-occurrence key.
    Workflow    = { Status = [{ "anything-but" = ["SUPPRESSED"] }] }
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

  guardduty_patterns = {
    for k, r in local.rules : k => merge(local.common_finding, r.scope, {
      Types    = [{ wildcard = r.types }]
      Severity = { Label = local.severities_from[r.min_severity] }
    })
  }

  # AWS Config's state-based signal. In the live test it flagged the public bucket in
  # ~45 s, while GuardDuty's update reached Argus ~10 min later; routing it closes the
  # exposure window. Only FAILED evaluations of the Argus rule on the simulation bucket.
  config_patterns = {
    s3-config = merge(local.common_finding, {
      ProductName = ["Config"]
      Title       = ["${var.prefix}-s3-bucket-public-read-prohibited"]
      Compliance  = { Status = ["FAILED"] }
      Resources   = { Id = [var.sim_bucket_arn] }
    })
  }

  patterns = merge(local.guardduty_patterns, local.config_patterns)

  rule_target = merge({ for k, r in local.rules : k => r.state_machine }, { s3-config = "s3" })
  rule_description = merge({ for k, r in local.rules : k => r.description },
  { s3-config = "AWS Config: the simulation bucket allows public reads" })

  input_paths = {
    event_id        = "$.id"
    event_received  = "$.time"
    finding_id      = "$.detail.findings[0].Id"
    product_arn     = "$.detail.findings[0].ProductArn"
    finding_type    = "$.detail.findings[0].Types[0]"
    severity        = "$.detail.findings[0].Severity.Label"
    finding_created = "$.detail.findings[0].CreatedAt"
    finding_updated = "$.detail.findings[0].UpdatedAt"
    account         = "$.detail.findings[0].AwsAccountId"
    region          = "$.detail.findings[0].Region"
    resources       = "$.detail.findings[0].Resources"
  }

  # Unquoted placeholders: EventBridge inserts strings with quotes and objects/arrays as JSON.
  input_template = <<-EOT
    {"finding_id": <finding_id>, "product_arn": <product_arn>, "event_id": <event_id>, "event_received": <event_received>, "finding_type": <finding_type>, "severity": <severity>, "finding_created": <finding_created>, "finding_updated": <finding_updated>, "account": <account>, "region": <region>, "resources": <resources>}
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
  for_each    = local.patterns
  name        = "${var.prefix}-${each.key}"
  description = local.rule_description[each.key]

  event_pattern = jsonencode(merge(local.base, { detail = { findings = each.value } }))
}

resource "aws_cloudwatch_event_target" "playbook" {
  for_each = local.patterns
  rule     = aws_cloudwatch_event_rule.playbook[each.key].name
  arn      = var.state_machine_arns[local.rule_target[each.key]]
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
