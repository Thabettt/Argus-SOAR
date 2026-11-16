# GuardDuty detector (or an existing one), S3 Protection, and a custom threat list.
#
# Only one detector can exist per account and region. If your account already has
# one, set create_detector = false and pass its ID.

locals {
  detector_id = var.create_detector ? aws_guardduty_detector.this[0].id : var.existing_detector_id
}

resource "aws_guardduty_detector" "this" {
  count  = var.create_detector ? 1 : 0
  enable = true
  # Repeat occurrences of a finding are published every 15 minutes instead of 6 hours.
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = { Name = "${var.prefix}-detector" }
}

# S3 Protection: reads CloudTrail S3 data events. Needed for Discovery:S3/MaliciousIPCaller.Custom.
resource "aws_guardduty_detector_feature" "s3" {
  detector_id = local.detector_id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# ---------------------------------------------------------------- custom threat list
# Calls from these IPs produce the ".Custom" MaliciousIPCaller findings.

resource "aws_s3_bucket" "threat_list" {
  count         = length(var.threat_list_ips) > 0 ? 1 : 0
  bucket        = "${var.prefix}-threatlist-${var.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "threat_list" {
  count                   = length(var.threat_list_ips) > 0 ? 1 : 0
  bucket                  = aws_s3_bucket.threat_list[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "threat_list" {
  count        = length(var.threat_list_ips) > 0 ? 1 : 0
  bucket       = aws_s3_bucket.threat_list[0].id
  key          = "argus-threat-list.txt"
  content      = join("\n", var.threat_list_ips)
  content_type = "text/plain"
}

resource "aws_guardduty_threatintelset" "this" {
  count       = length(var.threat_list_ips) > 0 ? 1 : 0
  detector_id = local.detector_id
  name        = "${var.prefix}-simulation-threat-list"
  format      = "TXT"
  location    = "https://s3.amazonaws.com/${aws_s3_object.threat_list[0].bucket}/${aws_s3_object.threat_list[0].key}"
  activate    = true
}
