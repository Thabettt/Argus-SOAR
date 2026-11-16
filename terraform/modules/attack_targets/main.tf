# Deliberately weak simulation resources. Everything here is tagged argus:managed=true
# and named argus-sim-*: Argus's routing rules, validator and remediation permissions
# only ever act on these.
#
# NOTE: the simulation access keys are stored in SSM SecureString parameters, but
# Terraform state also holds them in plaintext. That's acceptable for throwaway
# simulation users with read-only access to fake data; never do this with real keys.

locals {
  name = "${var.prefix}-sim"
  tags = merge(var.managed_tags, { "argus:role" = "attack-target" })
}

# ================================================================== EC2 (crypto-mining)

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${local.name}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = local.tags
}

# Session Manager access instead of SSH: no inbound port needed.
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${local.name}-instance-profile"
  role = aws_iam_role.instance.name
  tags = local.tags
}

resource "aws_security_group" "instance" {
  name        = "${local.name}-instance"
  description = "Argus simulation instance (SSH only from the operator, if enabled)"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.operator_cidr == "" ? [] : [var.operator_cidr]
    content {
      description = "SSH from the operator only - never 0.0.0.0/0"
      protocol    = "tcp"
      from_port   = 22
      to_port     = 22
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "outbound (Session Manager, package installs, simulated DNS lookups)"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-instance" })
}

resource "aws_instance" "miner" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnet_id
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = true

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  tags        = merge(local.tags, { Name = "${local.name}-miner" })
  volume_tags = local.tags

  lifecycle {
    # Argus changes these during an incident (quarantine groups, profile removal,
    # termination protection, tags, and stopping - which releases the public IP, and
    # associate_public_ip_address would otherwise force a replacement that destroys
    # the quarantined instance). Don't fight it on the next plan.
    ignore_changes = [ami, vpc_security_group_ids, iam_instance_profile, disable_api_termination, tags,
    associate_public_ip_address]
  }
}

# Remediation permissions on network interfaces are conditioned on this tag.
resource "aws_ec2_tag" "primary_eni" {
  resource_id = aws_instance.miner.primary_network_interface_id
  key         = "argus:managed"
  value       = "true"
}

# ================================================================== IAM (credential compromise)

resource "aws_s3_bucket" "decoy" {
  bucket        = "${local.name}-decoy-${var.account_id}-${var.region}"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "decoy" {
  bucket                  = aws_s3_bucket.decoy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "decoy" {
  bucket  = aws_s3_bucket.decoy.id
  key     = "readme.txt"
  content = "Non-sensitive decoy data for the Argus IAM simulation.\n"
}

resource "aws_iam_user" "backdoor" {
  name          = "${local.name}-backdoor"
  force_destroy = true
  tags          = local.tags
}

resource "aws_iam_user_policy" "backdoor" {
  name = "read-decoy-bucket"
  user = aws_iam_user.backdoor.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:ListAllMyBuckets", Resource = "*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.decoy.arn },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.decoy.arn}/*" },
      { Effect = "Allow", Action = ["iam:GetUser"], Resource = aws_iam_user.backdoor.arn },
    ]
  })
}

resource "aws_iam_access_key" "backdoor" {
  user = aws_iam_user.backdoor.name
}

resource "aws_ssm_parameter" "backdoor_key" {
  name   = "/${var.prefix}/sim/backdoor-access-key"
  type   = "SecureString"
  key_id = var.ssm_kms_key_arn
  value = jsonencode({
    access_key_id     = aws_iam_access_key.backdoor.id
    secret_access_key = aws_iam_access_key.backdoor.secret
  })
  description = "Simulated leaked .env file for the Argus IAM scenario"
  tags        = local.tags
}

# ================================================================== S3 (exfiltration)

resource "aws_s3_bucket" "data" {
  bucket        = var.sim_data_bucket
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  lifecycle {
    # The simulation turns this off and Argus turns it back on.
    ignore_changes = all
  }
}

resource "aws_s3_object" "fake_pii" {
  bucket       = aws_s3_bucket.data.id
  key          = "exports/customers.csv"
  content_type = "text/csv"
  content      = <<-CSV
    customer_id,full_name,email,phone,card_last4
    1001,Fake Person One,fake.one@example.invalid,+00-000-0001,0000
    1002,Fake Person Two,fake.two@example.invalid,+00-000-0002,0000
    1003,Fake Person Three,fake.three@example.invalid,+00-000-0003,0000
  CSV
}

resource "aws_s3_object" "fake_creds" {
  bucket       = aws_s3_bucket.data.id
  key          = "config/prod-credentials.env"
  content_type = "text/plain"
  content      = <<-ENV
    # FAKE credentials - Argus simulation data, not valid anywhere
    DB_HOST=db.example.invalid
    DB_USER=fake_admin
    DB_PASSWORD=not-a-real-password
  ENV
}

resource "aws_iam_user" "exfil" {
  name          = "${local.name}-exfil"
  force_destroy = true
  tags          = local.tags
}

resource "aws_iam_user_policy" "exfil" {
  name = "read-sim-data-bucket"
  user = aws_iam_user.exfil.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.data.arn },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.data.arn}/*" },
    ]
  })
}

resource "aws_iam_access_key" "exfil" {
  user = aws_iam_user.exfil.name
}

resource "aws_ssm_parameter" "exfil_key" {
  name   = "/${var.prefix}/sim/exfil-access-key"
  type   = "SecureString"
  key_id = var.ssm_kms_key_arn
  value = jsonencode({
    access_key_id     = aws_iam_access_key.exfil.id
    secret_access_key = aws_iam_access_key.exfil.secret
  })
  description = "Credentials used by the Argus S3 exfiltration simulation"
  tags        = local.tags
}
