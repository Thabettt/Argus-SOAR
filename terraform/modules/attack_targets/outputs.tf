output "instance_id" {
  value = aws_instance.miner.id
}

output "instance_arn" {
  value = aws_instance.miner.arn
}

output "instance_role_arn" {
  value = aws_iam_role.instance.arn
}

output "backdoor_user_name" {
  value = aws_iam_user.backdoor.name
}

output "exfil_user_name" {
  value = aws_iam_user.exfil.name
}

output "data_bucket" {
  value = aws_s3_bucket.data.id
}

output "data_bucket_arn" {
  value = aws_s3_bucket.data.arn
}

output "backdoor_key_parameter" {
  value = aws_ssm_parameter.backdoor_key.name
}

output "exfil_key_parameter" {
  value = aws_ssm_parameter.exfil_key.name
}

output "instance_sg_id" {
  value = aws_security_group.instance.id
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.instance.name
}

output "instance_role_name" {
  value = aws_iam_role.instance.name
}

output "app_role_arn" {
  value = aws_iam_role.app.arn
}
