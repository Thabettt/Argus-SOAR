variable "region" {
  description = "AWS region for the whole stack."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "argus"
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

# ------------------------------------------------------------ detection

variable "create_guardduty_detector" {
  description = "false if the account already has a GuardDuty detector in this region."
  type        = bool
  default     = true
}

variable "existing_guardduty_detector_id" {
  description = "Existing detector ID, used when create_guardduty_detector = false."
  type        = string
  default     = ""
}

variable "threat_list_ips" {
  description = "Public IPs GuardDuty treats as malicious - put your VPN/proxy egress IP here."
  type        = list(string)
  default     = []
}

variable "enable_security_hub" {
  description = "false if Security Hub (CSPM) is already enabled in this account and region."
  type        = bool
  default     = true
}

variable "create_config_recorder" {
  description = "false if AWS Config already records in this account and region."
  type        = bool
  default     = true
}

# ------------------------------------------------------------ storage, alerts, cost

variable "alert_email" {
  description = "Email for SNS escalation and the budget alarm (confirm the SNS subscription email). Empty = none."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  type    = number
  default = 20
}

variable "evidence_lock_mode" {
  description = "GOVERNANCE for dev (can be bypassed and torn down); COMPLIANCE only for a demo you accept keeping."
  type        = string
  default     = "GOVERNANCE"
}

variable "evidence_lock_days" {
  type    = number
  default = 1
}

# ------------------------------------------------------------ attack targets

variable "operator_cidr" {
  description = "Optional CIDR allowed to SSH to the simulation instance. Empty = Session Manager only."
  type        = string
  default     = ""
}

variable "sim_instance_type" {
  type    = string
  default = "t3.micro"
}

# ------------------------------------------------------------ orchestration

variable "escalation_min_severity" {
  description = "Incidents at or above this severity also go to SNS email. None of the simulations is CRITICAL; use HIGH to demo escalation."
  type        = string
  default     = "HIGH"
  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.escalation_min_severity)
    error_message = "Must be LOW, MEDIUM, HIGH or CRITICAL."
  }
}

variable "extra_quarantine_exempt_arns" {
  description = "Extra principal ARNs (patterns allowed) exempt from the S3 quarantine policy. The identity running Terraform is added automatically."
  type        = list(string)
  default     = []
}

variable "late_evidence_wait_seconds" {
  description = "Wait before CollectLateEvidence (CloudTrail and Flow Logs arrive 5-15 minutes late)."
  type        = number
  default     = 900
}
