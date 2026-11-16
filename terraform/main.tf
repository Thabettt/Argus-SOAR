# Argus root module. Logical "accounts" are kept apart by naming and tags:
#   security side - detection, evidence, orchestration
#   app side      - VPC, attack targets, quarantine groups, remediation roles

locals {
  trail_name = "${local.prefix}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

# ------------------------------------------------------------ foundation

module "kms" {
  source     = "./modules/kms"
  prefix     = local.prefix
  account_id = local.account_id
  region     = local.region
  partition  = local.partition
  trail_arn  = local.trail_arn
}

module "vpc" {
  source     = "./modules/vpc"
  prefix     = local.prefix
  cidr_block = var.vpc_cidr
}

module "vpc_flow_logs" {
  source      = "./modules/vpc_flow_logs"
  prefix      = local.prefix
  vpc_id      = module.vpc.vpc_id
  kms_key_arn = module.kms.evidence_key_arn
}

module "quarantine_sg" {
  source = "./modules/quarantine_sg"
  prefix = local.prefix
  vpc_id = module.vpc.vpc_id
}

# ------------------------------------------------------------ detection

data "aws_regions" "enabled" {}

locals {
  # Named up front: CloudTrail's data-event selector needs it before the bucket exists.
  sim_data_bucket = "${local.prefix}-sim-data-${local.account_id}-${local.region}"
}

module "guardduty" {
  source               = "./modules/guardduty"
  prefix               = local.prefix
  account_id           = local.account_id
  region               = local.region
  create_detector      = var.create_guardduty_detector
  existing_detector_id = var.existing_guardduty_detector_id
  threat_list_ips      = var.threat_list_ips
}

module "cloudtrail" {
  source              = "./modules/cloudtrail"
  prefix              = local.prefix
  account_id          = local.account_id
  region              = local.region
  trail_name          = local.trail_name
  trail_arn           = local.trail_arn
  kms_key_arn         = module.kms.cloudtrail_key_arn
  sim_data_bucket_arn = "arn:${local.partition}:s3:::${local.sim_data_bucket}"
}

module "athena" {
  source             = "./modules/athena"
  prefix             = local.prefix
  account_id         = local.account_id
  region             = local.region
  cloudtrail_bucket  = module.cloudtrail.log_bucket
  kms_key_arn        = module.kms.cloudtrail_key_arn
  projection_regions = sort(data.aws_regions.enabled.names)
}

module "config" {
  source          = "./modules/config"
  prefix          = local.prefix
  account_id      = local.account_id
  region          = local.region
  partition       = local.partition
  create_recorder = var.create_config_recorder
}

module "security_hub" {
  source = "./modules/security_hub"
  enable = var.enable_security_hub
}

# ------------------------------------------------------------ storage, alerts, cost

module "evidence_bucket" {
  source      = "./modules/evidence_bucket"
  prefix      = local.prefix
  account_id  = local.account_id
  region      = local.region
  kms_key_arn = module.kms.evidence_key_arn
  lock_mode   = var.evidence_lock_mode
  lock_days   = var.evidence_lock_days
}

module "dynamodb" {
  source = "./modules/dynamodb"
  prefix = local.prefix
}

module "sns" {
  source      = "./modules/sns"
  prefix      = local.prefix
  alert_email = var.alert_email
}

module "budget" {
  source      = "./modules/budget"
  prefix      = local.prefix
  limit_usd   = var.monthly_budget_usd
  alert_email = var.alert_email
}

# ------------------------------------------------------------ app side: attack targets

module "attack_targets" {
  source           = "./modules/attack_targets"
  prefix           = local.prefix
  account_id       = local.account_id
  region           = local.region
  partition        = local.partition
  managed_tags     = local.managed_tags
  vpc_id           = module.vpc.vpc_id
  public_subnet_id = module.vpc.public_subnet_id
  instance_type    = var.sim_instance_type
  operator_cidr    = var.operator_cidr
  sim_data_bucket  = local.sim_data_bucket
  ssm_kms_key_arn  = module.kms.ssm_key_arn
}

# ------------------------------------------------------------ orchestration

locals {
  state_machine_arn_prefix = "arn:${local.partition}:states:${local.region}:${local.account_id}:stateMachine:${local.prefix}"
  iam_state_machine_arn    = "${local.state_machine_arn_prefix}-iam-playbook"

  # The identity running Terraform must stay exempt from the S3 quarantine policy, or
  # terraform can no longer manage/destroy a quarantined bucket. aws:PrincipalArn is the
  # role ARN (possibly with a path, e.g. SSO roles), so match any path.
  caller_arn   = data.aws_caller_identity.current.arn
  assumed_role = regexall("^arn:[^:]+:sts::[0-9]+:assumed-role/([^/]+)/", local.caller_arn)
  deployer_arn = length(local.assumed_role) > 0 ? "arn:${local.partition}:iam::${local.account_id}:role/*${local.assumed_role[0][0]}" : local.caller_arn
  quarantine_exempt = distinct(concat(
    [module.lambda_roles.remediation_role_arn, module.lambda_roles.auditor_role_arn, local.deployer_arn],
    var.extra_quarantine_exempt_arns,
  ))
}

# Webhook URL placeholder. Set the real Discord webhook URL outside Terraform so the
# secret never lands in .tfvars or state:
#   aws ssm put-parameter --name /argus/notifier/webhook-url --type SecureString \
#     --key-id alias/argus-ssm-key --overwrite --value 'https://discord.com/api/webhooks/...'
resource "aws_ssm_parameter" "webhook" {
  name        = "/${local.prefix}/notifier/webhook-url"
  type        = "SecureString"
  key_id      = module.kms.ssm_key_arn
  value       = "disabled"
  description = "Discord webhook URL for Argus alerts ('disabled' skips the webhook)"

  lifecycle {
    # The URL is stored by hand (aws ssm put-parameter). Ignoring key_id too: an update
    # would re-put the parameter with the "disabled" placeholder and switch alerts off.
    ignore_changes = [value, key_id]
  }
}

module "lambda_roles" {
  source                    = "./modules/lambda_roles"
  prefix                    = local.prefix
  account_id                = local.account_id
  region                    = local.region
  partition                 = local.partition
  evidence_bucket_arn       = module.evidence_bucket.bucket_arn
  evidence_key_arn          = module.kms.evidence_key_arn
  ssm_key_arn               = module.kms.ssm_key_arn
  cloudtrail_key_arn        = module.kms.cloudtrail_key_arn
  cloudtrail_bucket_arn     = module.cloudtrail.log_bucket_arn
  athena_workgroup_arn      = module.athena.workgroup_arn
  athena_results_bucket_arn = module.athena.results_bucket_arn
  athena_database           = module.athena.database
  flow_log_group_arn        = module.vpc_flow_logs.log_group_arn
  incidents_table_arn       = module.dynamodb.table_arn
  sns_topic_arn             = module.sns.topic_arn
  webhook_parameter_arn     = aws_ssm_parameter.webhook.arn
  isolate_nacl_id           = module.quarantine_sg.isolate_nacl_id
  vpc_id                    = module.vpc.vpc_id
  isolate_sg_arn            = module.quarantine_sg.isolate_sg_arn
  iam_state_machine_arn     = local.iam_state_machine_arn
}

module "lambdas" {
  source                           = "./modules/lambdas"
  prefix                           = local.prefix
  role_arns                        = module.lambda_roles.lambda_role_arns
  evidence_bucket                  = module.evidence_bucket.bucket
  evidence_key_arn                 = module.kms.evidence_key_arn
  forensics_role_arn               = module.lambda_roles.forensics_role_arn
  remediation_role_arn             = module.lambda_roles.remediation_role_arn
  sim_instance_ids                 = [module.attack_targets.instance_id]
  isolate_nacl_id                  = module.quarantine_sg.isolate_nacl_id
  isolate_sg_id                    = module.quarantine_sg.isolate_sg_id
  quarantine_exempt_principal_arns = local.quarantine_exempt
  iam_state_machine_arn            = local.iam_state_machine_arn
  incidents_table                  = module.dynamodb.table_name
  webhook_parameter_name           = aws_ssm_parameter.webhook.name
  sns_topic_arn                    = module.sns.topic_arn
  escalation_min_severity          = var.escalation_min_severity
  flow_log_group_name              = module.vpc_flow_logs.log_group_name
  athena_workgroup                 = module.athena.workgroup
  athena_database                  = module.athena.database
  athena_table                     = module.athena.table
}

module "step_functions" {
  source                     = "./modules/step_functions"
  prefix                     = local.prefix
  account_id                 = local.account_id
  function_arns              = module.lambdas.function_arns
  incidents_table            = module.dynamodb.table_name
  incidents_table_arn        = module.dynamodb.table_arn
  late_evidence_wait_seconds = var.late_evidence_wait_seconds
}

module "eventbridge" {
  source             = "./modules/eventbridge"
  prefix             = local.prefix
  account_id         = local.account_id
  state_machine_arns = module.step_functions.state_machine_arns
  sim_instance_arn   = module.attack_targets.instance_arn
  sim_bucket_arn     = module.attack_targets.data_bucket_arn
}
