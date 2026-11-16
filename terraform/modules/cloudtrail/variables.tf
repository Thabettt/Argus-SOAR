variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "trail_name" {
  type = string
}

variable "trail_arn" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "sim_data_bucket_arn" {
  description = "Only this bucket's object-level (data) events are logged."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 90
}
