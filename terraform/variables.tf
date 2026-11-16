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
