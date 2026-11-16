variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "partition" {
  type = string
}

variable "trail_arn" {
  description = "ARN of the Argus trail (built from its name, so there is no dependency cycle)."
  type        = string
}

variable "deletion_window_days" {
  type    = number
  default = 7
}
