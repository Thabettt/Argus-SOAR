# Incident table. Partition key = Security Hub finding ID, the idempotency key.
# RecordIncident writes it with attribute_not_exists(finding_id) in one atomic call.

variable "prefix" {
  type = string
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}

output "table_name" {
  value = aws_dynamodb_table.incidents.name
}

output "table_arn" {
  value = aws_dynamodb_table.incidents.arn
}
