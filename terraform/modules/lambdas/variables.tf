variable "prefix" {
  type = string
}

variable "runtime" {
  type    = string
  default = "python3.12"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "role_arns" {
  description = "Execution role ARN per function key (from lambda_roles)."
  type        = map(string)
}

variable "evidence_bucket" {
  type = string
}

variable "evidence_key_arn" {
  type = string
}

variable "forensics_role_arn" {
  type = string
}

variable "remediation_role_arn" {
  type = string
}

variable "sim_instance_ids" {
  type = list(string)
}

variable "isolate_nacl_id" {
  type = string
}

variable "isolate_sg_id" {
  type = string
}

variable "quarantine_exempt_principal_arns" {
  type = list(string)
}

variable "iam_state_machine_arn" {
  type = string
}

variable "incidents_table" {
  type = string
}

variable "webhook_parameter_name" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "escalation_min_severity" {
  type = string
}

variable "flow_log_group_name" {
  type = string
}

variable "athena_workgroup" {
  type = string
}

variable "athena_database" {
  type = string
}

variable "athena_table" {
  type = string
}
