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
