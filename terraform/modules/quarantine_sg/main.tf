# Pre-provisioned isolation groups (NIST "Preparation": ready before any incident).
#
# Changing security groups does not cut connections that are already tracked. The EC2
# playbook therefore swaps each network interface to "untrack" first - all traffic
# allowed in and out, so existing flows become untracked - and then to "isolate"
# (no rules), which drops them.

variable "prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

resource "aws_security_group" "untrack" {
  name                   = "${var.prefix}-quarantine-untrack"
  description            = "Argus step 1: allow-all so existing flows become untracked. Used for milliseconds."
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  ingress {
    description      = "all traffic (makes flows untracked)"
    protocol         = "-1"
    from_port        = 0
    to_port          = 0
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description      = "all traffic (makes flows untracked)"
    protocol         = "-1"
    from_port        = 0
    to_port          = 0
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = { Name = "${var.prefix}-quarantine-untrack" }
}

# No ingress or egress blocks: Terraform removes AWS's default allow-all egress rule.
resource "aws_security_group" "isolate" {
  name                   = "${var.prefix}-quarantine-isolate"
  description            = "Argus step 2: no rules - total network isolation."
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true
  tags                   = { Name = "${var.prefix}-quarantine-isolate" }
}

output "untrack_sg_id" {
  value = aws_security_group.untrack.id
}

output "untrack_sg_arn" {
  value = aws_security_group.untrack.arn
}

output "isolate_sg_id" {
  value = aws_security_group.isolate.id
}

output "isolate_sg_arn" {
  value = aws_security_group.isolate.arn
}
