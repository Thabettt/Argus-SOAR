output "function_arns" {
  value = { for k, f in aws_lambda_function.this : k => f.arn }
}
