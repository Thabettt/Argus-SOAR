# Escalation topic: severe incidents (>= escalation threshold) and every failure.
# The email subscription must be confirmed from the inbox before it delivers.

variable "prefix" {
  type = string
}

variable "alert_email" {
  type    = string
  default = ""
}

resource "aws_sns_topic" "escalation" {
  name              = "${var.prefix}-escalation"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.escalation.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

output "topic_arn" {
  value = aws_sns_topic.escalation.arn
}
