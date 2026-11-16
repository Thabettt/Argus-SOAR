# Least privilege, as in spec section 10.
#
# Lambda execution roles hold almost nothing. App-side work goes through two roles
# that only specific Lambda roles may assume:
#   forensics role    - read-only (+ snapshot creation)
#   remediation role  - write actions, limited to resources named <prefix>-sim-* and/or
#                       tagged argus:managed=true, and to the two quarantine groups
# This is the cross-account pattern in one account: moving the app-side roles to
# another account only changes their account ID and trust policies.

locals {
  p          = var.partition
  acct       = var.account_id
  sim        = "${var.prefix}-sim-"
  managed    = { "aws:ResourceTag/argus:managed" = "true" }
  iam_tagged = { "iam:ResourceTag/argus:managed" = "true" }

  functions = ["validator", "forensics", "late-evidence", "iam-playbook", "ec2-playbook",
  "s3-playbook", "package-evidence", "finalize", "notifier"]
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  for_each           = toset(local.functions)
  name               = "${var.prefix}-${each.key}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Logging: own log group only (Terraform creates the groups, so no CreateLogGroup).
resource "aws_iam_role_policy" "logs" {
  for_each = toset(local.functions)
  name     = "logs"
  role     = aws_iam_role.lambda[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:${local.p}:logs:${var.region}:${local.acct}:log-group:/aws/lambda/${var.prefix}-${each.key}:*"
    }]
  })
}

# ================================================================ per-function permissions

locals {
  evidence_write = [
    {
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "${var.evidence_bucket_arn}/*"
    },
    {
      # Without ListBucket, reading a missing key returns 403 instead of 404.
      Effect   = "Allow"
      Action   = "s3:ListBucket"
      Resource = var.evidence_bucket_arn
    },
    {
      Effect   = "Allow"
      Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
      Resource = var.evidence_key_arn
    },
  ]

  assume_forensics = {
    Effect   = "Allow"
    Action   = "sts:AssumeRole"
    Resource = aws_iam_role.forensics.arn
  }

  assume_remediation = {
    Effect   = "Allow"
    Action   = "sts:AssumeRole"
    Resource = aws_iam_role.remediation.arn
  }

  function_statements = {
    forensics = concat([local.assume_forensics], local.evidence_write)

    late-evidence = concat([local.assume_forensics], local.evidence_write, [
      {
        Effect   = "Allow"
        Action   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults"]
        Resource = var.athena_workgroup_arn
      },
      {
        Effect = "Allow"
        Action = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"]
        Resource = [
          "arn:${local.p}:glue:${var.region}:${local.acct}:catalog",
          "arn:${local.p}:glue:${var.region}:${local.acct}:database/${var.athena_database}",
          "arn:${local.p}:glue:${var.region}:${local.acct}:table/${var.athena_database}/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
        Resource = [var.cloudtrail_bucket_arn, "${var.cloudtrail_bucket_arn}/*"]
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation",
        "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = [var.athena_results_bucket_arn, "${var.athena_results_bucket_arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.cloudtrail_key_arn
      },
      {
        Effect   = "Allow"
        Action   = "logs:StartQuery"
        Resource = "${var.flow_log_group_arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = "logs:GetQueryResults"
        Resource = "*"
      },
    ])

    iam-playbook = [local.assume_remediation]
    ec2-playbook = [local.assume_remediation]
    s3-playbook = [local.assume_remediation, {
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = var.iam_state_machine_arn
    }]

    package-evidence = local.evidence_write

    finalize = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:UpdateItem"
        Resource = var.incidents_table_arn
      },
      {
        Effect   = "Allow"
        Action   = "securityhub:BatchUpdateFindings"
        Resource = "*"
      },
    ]

    notifier = [
      {
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = var.webhook_parameter_arn
      },
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.ssm_key_arn
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = var.sns_topic_arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${var.evidence_bucket_arn}/runbooks/*"
      },
      {
        Effect   = "Allow"
        Action   = "kms:GenerateDataKey"
        Resource = var.evidence_key_arn
      },
    ]
  }
}

resource "aws_iam_role_policy" "function" {
  for_each = local.function_statements
  name     = "argus-${each.key}"
  role     = aws_iam_role.lambda[each.key].id
  policy   = jsonencode({ Version = "2012-10-17", Statement = each.value })
}

# ================================================================ app side: forensics role

resource "aws_iam_role" "forensics" {
  name = "${var.prefix}-forensics-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = [for f in ["forensics", "late-evidence"] : aws_iam_role.lambda[f].arn] }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "forensics" {
  name = "read-only-forensics"
  role = aws_iam_role.forensics.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IamRead"
        Effect = "Allow"
        Action = ["iam:GetUser", "iam:GetUserPolicy", "iam:GetLoginProfile", "iam:GetAccessKeyLastUsed",
          "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListAccessKeys",
        "iam:ListGroupsForUser"]
        Resource = "arn:${local.p}:iam::${local.acct}:user/${local.sim}*"
      },
      {
        Sid      = "InstanceProfileRead"
        Effect   = "Allow"
        Action   = "iam:GetInstanceProfile"
        Resource = "arn:${local.p}:iam::${local.acct}:instance-profile/*"
      },
      {
        Sid    = "Ec2Describe"
        Effect = "Allow"
        Action = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
        "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeSubnets", "ec2:DescribeNetworkAcls"]
        Resource = "*"
      },
      {
        Sid       = "SnapshotManagedVolumes"
        Effect    = "Allow"
        Action    = "ec2:CreateSnapshot"
        Resource  = "arn:${local.p}:ec2:${var.region}:${local.acct}:volume/*"
        Condition = { StringEquals = local.managed }
      },
      {
        Sid      = "SnapshotResource"
        Effect   = "Allow"
        Action   = "ec2:CreateSnapshot"
        Resource = "arn:${local.p}:ec2:${var.region}::snapshot/*"
      },
      {
        Sid       = "TagNewSnapshots"
        Effect    = "Allow"
        Action    = "ec2:CreateTags"
        Resource  = "arn:${local.p}:ec2:${var.region}::snapshot/*"
        Condition = { StringEquals = { "ec2:CreateAction" = "CreateSnapshot" } }
      },
      {
        Sid    = "S3ConfigRead"
        Effect = "Allow"
        Action = ["s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketAcl",
          "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:GetBucketVersioning",
        "s3:ListBucketVersions"]
        Resource = "arn:${local.p}:s3:::${local.sim}*"
      },
      {
        Sid      = "CloudTrailLookup"
        Effect   = "Allow"
        Action   = "cloudtrail:LookupEvents"
        Resource = "*"
      },
    ]
  })
}

# ================================================================ app side: remediation role

resource "aws_iam_role" "remediation" {
  name = "${var.prefix}-remediation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = [for f in ["iam-playbook", "ec2-playbook", "s3-playbook"] : aws_iam_role.lambda[f].arn] }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "remediation" {
  name = "scoped-remediation"
  role = aws_iam_role.remediation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ---- IAM playbook: only simulation users that carry the managed tag
      {
        Sid       = "ContainSimUsers"
        Effect    = "Allow"
        Action    = ["iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:DeleteLoginProfile", "iam:TagUser"]
        Resource  = "arn:${local.p}:iam::${local.acct}:user/${local.sim}*"
        Condition = { StringEquals = local.iam_tagged }
      },
      {
        Sid      = "AttachOnlyDenyAll"
        Effect   = "Allow"
        Action   = "iam:AttachUserPolicy"
        Resource = "arn:${local.p}:iam::${local.acct}:user/${local.sim}*"
        Condition = {
          StringEquals = local.iam_tagged
          ArnEquals    = { "iam:PolicyARN" = "arn:${local.p}:iam::aws:policy/AWSDenyAll" }
        }
      },
      {
        Sid      = "ReadRoleTags"
        Effect   = "Allow"
        Action   = "iam:ListRoleTags"
        Resource = "arn:${local.p}:iam::${local.acct}:role/*"
      },
      {
        Sid       = "RevokeManagedRoleSessions"
        Effect    = "Allow"
        Action    = "iam:PutRolePolicy"
        Resource  = "arn:${local.p}:iam::${local.acct}:role/*"
        Condition = { StringEquals = local.iam_tagged }
      },
      # ---- EC2 playbook: managed instances/ENIs, and only the two quarantine groups
      {
        Sid       = "SwapManagedEnis"
        Effect    = "Allow"
        Action    = "ec2:ModifyNetworkInterfaceAttribute"
        Resource  = "arn:${local.p}:ec2:${var.region}:${local.acct}:network-interface/*"
        Condition = { StringEquals = local.managed }
      },
      {
        Sid      = "OnlyQuarantineGroup"
        Effect   = "Allow"
        Action   = "ec2:ModifyNetworkInterfaceAttribute"
        Resource = var.isolate_sg_arn
      },
      {
        # Swapping a subnet's NACL association: limited to NACLs in the Argus VPC. The
        # playbook only does this for subnets tagged argus:dedicated-subnet=true.
        Sid       = "QuarantineDedicatedSubnet"
        Effect    = "Allow"
        Action    = "ec2:ReplaceNetworkAclAssociation"
        Resource  = "arn:${local.p}:ec2:${var.region}:${local.acct}:network-acl/*"
        Condition = { ArnEquals = { "ec2:Vpc" = "arn:${local.p}:ec2:${var.region}:${local.acct}:vpc/${var.vpc_id}" } }
      },
      {
        # ReplaceNetworkAclAssociation is also authorized against the SUBNET (found live:
        # granting only the network-acl resource fails). Only dedicated subnets qualify.
        Sid       = "QuarantineDedicatedSubnetResource"
        Effect    = "Allow"
        Action    = "ec2:ReplaceNetworkAclAssociation"
        Resource  = "arn:${local.p}:ec2:${var.region}:${local.acct}:subnet/*"
        Condition = { StringEquals = { "aws:ResourceTag/argus:dedicated-subnet" = "true" } }
      },
      {
        Sid    = "ContainManagedInstances"
        Effect = "Allow"
        Action = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:DisassociateIamInstanceProfile",
        "ec2:CreateTags"]
        Resource  = "arn:${local.p}:ec2:${var.region}:${local.acct}:instance/*"
        Condition = { StringEquals = local.managed }
      },
      {
        Sid    = "DescribeInstances"
        Effect = "Allow"
        Action = ["ec2:DescribeInstances", "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeSubnets",
        "ec2:DescribeNetworkAcls"]
        Resource = "*"
      },
      # ---- S3 playbook: simulation buckets only (by name)
      {
        Sid    = "ContainSimBuckets"
        Effect = "Allow"
        Action = ["s3:PutBucketPublicAccessBlock", "s3:DeleteBucketPolicy", "s3:PutBucketAcl",
          "s3:PutBucketPolicy", "s3:PutBucketVersioning", "s3:GetBucketTagging", "s3:PutBucketTagging",
        "s3:GetBucketOwnershipControls"]
        Resource = "arn:${local.p}:s3:::${local.sim}*"
      },
    ]
  })
}

# ================================================================ auditor role
# Exempt from the S3 quarantine policy so investigators can read evidence and the
# quarantined bucket. Assumable by principals in this account that are allowed to.

resource "aws_iam_role" "auditor" {
  name = "${var.prefix}-auditor-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.p}:iam::${local.acct}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "auditor" {
  name = "read-evidence"
  role = aws_iam_role.auditor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions",
        "s3:GetBucketPolicy"]
        Resource = [var.evidence_bucket_arn, "${var.evidence_bucket_arn}/*",
        "arn:${local.p}:s3:::${local.sim}*", "arn:${local.p}:s3:::${local.sim}*/*"]
      },
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.evidence_key_arn
      },
    ]
  })
}
