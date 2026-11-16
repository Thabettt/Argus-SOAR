variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "state_machine_arns" {
  description = "Map of playbook key (iam, ec2, s3) to state machine ARN."
  type        = map(string)
}

variable "sim_instance_arn" {
  type = string
}

variable "sim_bucket_arn" {
  type = string
}
