output "state_machine_arns" {
  value = { for k, sm in aws_sfn_state_machine.playbook : k => sm.arn }
}
