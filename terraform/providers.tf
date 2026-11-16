provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project    = "argus"
      managed_by = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition
  prefix     = var.name_prefix

  # Every simulation (attack target) resource carries this tag; remediation permissions
  # are conditioned on it.
  managed_tags = { "argus:managed" = "true" }
}
