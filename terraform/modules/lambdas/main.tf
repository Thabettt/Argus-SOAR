# Packages and deploys the Argus functions. Shared code (lambdas/shared/python/argus_shared)
# is a Lambda layer; each function zip contains only its handler.

locals {
  lambdas_root = "${path.root}/../lambdas"
  build_dir    = "${path.root}/../build"

  common_env = {
    SIM_NAME_PREFIX = "${var.prefix}-sim-"
  }

  evidence_env = {
    EVIDENCE_BUCKET      = var.evidence_bucket
    EVIDENCE_KMS_KEY_ARN = var.evidence_key_arn
  }

  functions = {
    validator = {
      dir     = "validator"
      timeout = 15
      env     = { SIM_INSTANCE_IDS = join(",", var.sim_instance_ids) }
    }
    forensics = {
      dir     = "forensics"
      timeout = 120
      env     = merge(local.evidence_env, { FORENSICS_ROLE_ARN = var.forensics_role_arn, LOOKBACK_MINUTES = "60" })
    }
    late-evidence = {
      dir     = "late_evidence"
      timeout = 300
      env = merge(local.evidence_env, {
        FORENSICS_ROLE_ARN    = var.forensics_role_arn
        FLOW_LOG_GROUP        = var.flow_log_group_name
        ATHENA_WORKGROUP      = var.athena_workgroup
        ATHENA_DATABASE       = var.athena_database
        ATHENA_TABLE          = var.athena_table
        WINDOW_BEFORE_MINUTES = "120"
      })
    }
    iam-playbook = {
      dir     = "playbooks/iam_breach"
      timeout = 60
      env     = { REMEDIATION_ROLE_ARN = var.remediation_role_arn }
    }
    ec2-playbook = {
      dir     = "playbooks/ec2_mining"
      timeout = 60
      env = {
        REMEDIATION_ROLE_ARN = var.remediation_role_arn
        UNTRACK_SG_ID        = var.untrack_sg_id
        ISOLATE_SG_ID        = var.isolate_sg_id
      }
    }
    s3-playbook = {
      dir     = "playbooks/s3_exfil"
      timeout = 60
      env = {
        REMEDIATION_ROLE_ARN             = var.remediation_role_arn
        QUARANTINE_EXEMPT_PRINCIPAL_ARNS = join(",", var.quarantine_exempt_principal_arns)
        IAM_STATE_MACHINE_ARN            = var.iam_state_machine_arn
      }
    }
    package-evidence = {
      dir     = "package_evidence"
      timeout = 45
      env     = local.evidence_env
    }
    finalize = {
      dir     = "finalize"
      timeout = 20
      env     = { INCIDENTS_TABLE = var.incidents_table }
    }
    notifier = {
      dir     = "notifier"
      timeout = 20
      env = merge(local.evidence_env, {
        WEBHOOK_PARAM           = var.webhook_parameter_name
        SNS_TOPIC_ARN           = var.sns_topic_arn
        ESCALATION_MIN_SEVERITY = var.escalation_min_severity
      })
    }
  }
}

data "archive_file" "layer" {
  type        = "zip"
  source_dir  = "${local.lambdas_root}/shared"
  output_path = "${local.build_dir}/argus-shared-layer.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_lambda_layer_version" "shared" {
  layer_name          = "${var.prefix}-shared"
  filename            = data.archive_file.layer.output_path
  source_code_hash    = data.archive_file.layer.output_base64sha256
  compatible_runtimes = [var.runtime]
  description         = "Argus shared code: envelope, phase recorder, AWS helpers"
}

data "archive_file" "function" {
  for_each    = local.functions
  type        = "zip"
  source_dir  = "${local.lambdas_root}/${each.value.dir}"
  output_path = "${local.build_dir}/${var.prefix}-${each.key}.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_cloudwatch_log_group" "function" {
  for_each          = local.functions
  name              = "/aws/lambda/${var.prefix}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "this" {
  for_each         = local.functions
  function_name    = "${var.prefix}-${each.key}"
  role             = var.role_arns[each.key]
  runtime          = var.runtime
  architectures    = ["arm64"]
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.function[each.key].output_path
  source_code_hash = data.archive_file.function[each.key].output_base64sha256
  layers           = [aws_lambda_layer_version.shared.arn]
  timeout          = each.value.timeout
  memory_size      = 256

  environment {
    variables = merge(local.common_env, each.value.env)
  }

  depends_on = [aws_cloudwatch_log_group.function]
}
