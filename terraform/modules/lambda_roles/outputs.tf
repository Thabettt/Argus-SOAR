output "lambda_role_arns" {
  description = "Execution role ARN per function key."
  value       = { for k, r in aws_iam_role.lambda : k => r.arn }
}

output "forensics_role_arn" {
  value = aws_iam_role.forensics.arn
}

output "remediation_role_arn" {
  value = aws_iam_role.remediation.arn
}

output "auditor_role_arn" {
  value = aws_iam_role.auditor.arn
}
