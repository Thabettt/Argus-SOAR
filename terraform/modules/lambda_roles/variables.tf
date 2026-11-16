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

variable "evidence_bucket_arn" {
  type = string
}

variable "evidence_key_arn" {
  type = string
}

variable "ssm_key_arn" {
  type = string
}

variable "cloudtrail_key_arn" {
  type = string
}

variable "cloudtrail_bucket_arn" {
  type = string
}

variable "athena_workgroup_arn" {
  type = string
}

variable "athena_results_bucket_arn" {
  type = string
}

variable "athena_database" {
  type = string
}

variable "flow_log_group_arn" {
  type = string
}

variable "incidents_table_arn" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "webhook_parameter_arn" {
  type = string
}

variable "isolate_nacl_id" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "isolate_sg_arn" {
  type = string
}

variable "iam_state_machine_arn" {
  type = string
}
