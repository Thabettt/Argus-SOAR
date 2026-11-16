variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "create_detector" {
  description = "false if the account already has a GuardDuty detector in this region."
  type        = bool
  default     = true
}

variable "existing_detector_id" {
  description = "Detector ID to use when create_detector = false."
  type        = string
  default     = ""

  validation {
    condition     = var.existing_detector_id == "" || can(regex("^[0-9a-f]{32}$", var.existing_detector_id))
    error_message = "existing_detector_id must be a 32-character GuardDuty detector ID."
  }
}

variable "threat_list_ips" {
  description = "Public IPs (e.g. your VPN egress IP) that GuardDuty should treat as malicious."
  type        = list(string)
  default     = []
}
