# Athena table over the CloudTrail bucket. LookupEvents can't return S3 data events,
# so CollectLateEvidence queries them here. Partition projection avoids crawlers and
# MSCK REPAIR: partitions are computed from the S3 path.

variable "prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "cloudtrail_bucket" {
  type = string
}

variable "kms_key_arn" {
  description = "Key used to encrypt query results (the CloudTrail key: results contain log data)."
  type        = string
}

variable "projection_regions" {
  description = "Regions CloudTrail delivers logs for (multi-region trail)."
  type        = list(string)
}

locals {
  database = replace("${var.prefix}_forensics", "-", "_")
  table    = "cloudtrail_logs"
}

resource "aws_s3_bucket" "results" {
  bucket        = "${var.prefix}-athena-results-${var.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
  }
}

resource "aws_athena_workgroup" "this" {
  name          = "${var.prefix}-forensics"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false
    bytes_scanned_cutoff_per_query     = 1073741824 # 1 GB guardrail

    result_configuration {
      output_location = "s3://${aws_s3_bucket.results.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }
}

resource "aws_glue_catalog_database" "this" {
  name = local.database
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = local.table
  database_name = aws_glue_catalog_database.this.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                             = "TRUE"
    "projection.enabled"                 = "true"
    "projection.region.type"             = "enum"
    "projection.region.values"           = join(",", var.projection_regions)
    "projection.timestamp.type"          = "date"
    "projection.timestamp.format"        = "yyyy/MM/dd"
    "projection.timestamp.range"         = "2026/01/01,NOW"
    "projection.timestamp.interval"      = "1"
    "projection.timestamp.interval.unit" = "DAYS"
    "storage.location.template"          = "s3://${var.cloudtrail_bucket}/AWSLogs/${var.account_id}/CloudTrail/$${region}/$${timestamp}"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "timestamp"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${var.cloudtrail_bucket}/AWSLogs/${var.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }
}

output "workgroup" {
  value = aws_athena_workgroup.this.name
}

output "workgroup_arn" {
  value = aws_athena_workgroup.this.arn
}

output "database" {
  value = aws_glue_catalog_database.this.name
}

output "table" {
  value = aws_glue_catalog_table.cloudtrail.name
}

output "results_bucket_arn" {
  value = aws_s3_bucket.results.arn
}
