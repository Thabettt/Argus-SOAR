# Pre-provisioned isolation controls (NIST "Preparation": ready before any incident).
#
# isolate SG   - no rules. Blocks every NEW connection to or from the instance. It does
#                NOT end connections that already exist: security groups are stateful, and
#                a flow that was tracked when it started stays allowed. (Verified live: a
#                Session Manager session kept streaming after a direct swap AND after the
#                "allow-all first, then isolate" untrack trick.)
# isolate NACL - no rules, so the implicit deny applies. NACLs are stateless, so attaching
#                it to a subnet cuts existing connections within seconds (verified live).
#                It applies to the whole subnet, so the playbook only uses it on subnets
#                tagged argus:dedicated-subnet=true.

variable "prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

# No ingress or egress blocks: Terraform removes AWS's default allow-all egress rule.
resource "aws_security_group" "isolate" {
  name                   = "${var.prefix}-quarantine-isolate"
  description            = "Argus step 2: no rules - total network isolation." # unchanged: editing it forces replacement
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true
  tags                   = { Name = "${var.prefix}-quarantine-isolate" }
}

# No rule blocks: only the implicit "deny all" entries, inbound and outbound.
resource "aws_network_acl" "isolate" {
  vpc_id = var.vpc_id
  tags   = { Name = "${var.prefix}-quarantine-nacl" }
}

output "isolate_sg_id" {
  value = aws_security_group.isolate.id
}

output "isolate_sg_arn" {
  value = aws_security_group.isolate.arn
}

output "isolate_nacl_id" {
  value = aws_network_acl.isolate.id
}
