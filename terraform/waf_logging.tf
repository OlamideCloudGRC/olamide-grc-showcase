###------------------------------------------------------
# FIREHOSE LOG BUCKET COMPONENTS
# Bucket + related resources for firehose
###------------------------------------------------------

# Create S3 bucket for WAF logs
resource "aws_s3_bucket" "waf_logs" {
  bucket = "${var.waf_log_bucket}-${lower(var.environment)}-${data.aws_caller_identity.current.account_id}"

  # Allow force destroy in non prod environment
  force_destroy = var.environment != "Prod"

  tags = {
    Name = "waf-logs"
  }
}

# Enable bucket versioning
resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Server-side encryption
resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  rule {
    id     = "expire-after-90d"
    status = "Enabled"
    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}

# Bucket policy for waf log bucket
data "aws_iam_policy_document" "waf_logs_bucket_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.waf_logs.arn,
      "${aws_s3_bucket.waf_logs.arn}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Policy attachment
resource "aws_s3_bucket_policy" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  policy = data.aws_iam_policy_document.waf_logs_bucket_policy.json
}


# Assume role policy for AWS Firehose
data "aws_iam_policy_document" "firehose_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Create a role for AWS Firehose
resource "aws_iam_role" "firehose_role" {
  name               = "waf-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume_role.json
  path               = "/portfolio/"
  tags = {
    Project = "GRC-Portfolio"
  }
}

# Create policy  document for AWS Firehose
data "aws_iam_policy_document" "firehose_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartsUploads",
      "s3:PutObject"
    ]
    resources = [
      aws_s3_bucket.waf_logs.arn,
      "${aws_s3_bucket.waf_logs.arn}/*"
    ]

  }
}

# Create policy for AWS Firehose role
resource "aws_iam_role_policy" "firehose_role_policy" {
  name   = "firehose-role-policy"
  role   = aws_iam_role.firehose_role.name
  policy = data.aws_iam_policy_document.firehose_policy.json
}


# AWS WAF Delivery stream
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-delivery-${lower(var.environment)}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn

    buffering_interval = 60 #seconds
    buffering_size     = 5  #MB
    compression_format = "GZIP"

    # Organized folder structure for Athena partitioning
    prefix              = "year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/"

  }
}


# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
  depends_on              = [aws_kinesis_firehose_delivery_stream.waf_logs]

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior    = "DROP"
      requirement = "MEETS_ALL"

      condition {
        action_condition {
          action = "COUNT"
        }
      }
    }
  }
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}

