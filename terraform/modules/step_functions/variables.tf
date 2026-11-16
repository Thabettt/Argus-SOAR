variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "function_arns" {
  type = map(string)
}

variable "incidents_table" {
  type = string
}

variable "incidents_table_arn" {
  type = string
}

variable "late_evidence_wait_seconds" {
  type    = number
  default = 900
}
