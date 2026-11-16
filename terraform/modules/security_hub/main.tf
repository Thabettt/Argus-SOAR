# Security Hub (CSPM): aggregates GuardDuty and Config findings into ASFF and emits the
# "Security Hub Findings - Imported" events Argus routes on. GuardDuty and Config
# integrations are enabled automatically when both services are on.
#
# If Security Hub is already enabled in your account, set enable = false.
# Default standards are off to keep cost down (they run hundreds of control checks).

variable "enable" {
  type    = bool
  default = true
}

resource "aws_securityhub_account" "this" {
  count                     = var.enable ? 1 : 0
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}
