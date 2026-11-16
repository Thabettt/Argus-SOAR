output "cloudtrail_key_arn" {
  value = aws_kms_key.cloudtrail.arn
}

output "evidence_key_arn" {
  value = aws_kms_key.evidence.arn
}

output "ssm_key_arn" {
  value = aws_kms_key.ssm.arn
}
