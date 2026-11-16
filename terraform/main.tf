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
