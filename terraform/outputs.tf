output "region" {
  value = local.region
}

output "evidence_bucket" {
  value = module.evidence_bucket.bucket
}

output "incidents_table" {
  value = module.dynamodb.table_name
}

output "state_machine_arns" {
  value = module.step_functions.state_machine_arns
}

output "guardduty_detector_id" {
  value = module.guardduty.detector_id
}

output "sim_instance_id" {
  value = module.attack_targets.instance_id
}

output "sim_data_bucket" {
  value = module.attack_targets.data_bucket
}

output "sim_backdoor_key_parameter" {
  value = module.attack_targets.backdoor_key_parameter
}

output "sim_exfil_key_parameter" {
  value = module.attack_targets.exfil_key_parameter
}

output "webhook_parameter" {
  value = aws_ssm_parameter.webhook.name
}

output "quarantine_exempt_principals" {
  value = local.quarantine_exempt
}

output "auditor_role_arn" {
  value = module.lambda_roles.auditor_role_arn
}

# Used by attack_simulations/reset_simulation.py
output "sim_backdoor_user" {
  value = module.attack_targets.backdoor_user_name
}

output "sim_exfil_user" {
  value = module.attack_targets.exfil_user_name
}

output "sim_instance_sg_id" {
  value = module.attack_targets.instance_sg_id
}

output "sim_instance_profile" {
  value = module.attack_targets.instance_profile_name
}

output "sim_instance_role_name" {
  value = module.attack_targets.instance_role_name
}
