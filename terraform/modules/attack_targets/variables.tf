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

variable "managed_tags" {
  type = map(string)
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "operator_cidr" {
  description = "Optional CIDR allowed to SSH to the simulation instance (e.g. 203.0.113.7/32). Empty = no SSH."
  type        = string
  default     = ""
}

variable "sim_data_bucket" {
  type = string
}

variable "ssm_kms_key_arn" {
  type = string
}
