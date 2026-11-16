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
