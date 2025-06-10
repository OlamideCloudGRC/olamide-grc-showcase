###------------------------------------------------------
# TRIGGER BUCKET COMPONENTS
# Bucket + related resources for S3-> Lambda workflow
###------------------------------------------------------

# Create S3 bucket 
resource "aws_s3_bucket" "trigger_bucket" {
  bucket = var.trigger_bucket_name

  # Allow force destroy in non prod envinronment
  force_destroy = var.environment != "Prod"

  tags = merge(
    local.standard_tags,
    {
      Name = var.trigger_bucket_name
    }
  )
}

# Add Public Access Block
resource "aws_s3_bucket_public_access_block" "trigger_bucket" {
  bucket = aws_s3_bucket.trigger_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable bucket versioning for trigger bucket
resource "aws_s3_bucket_versioning" "trigger_bucket" {
  bucket = aws_s3_bucket.trigger_bucket.id
  versioning_configuration {
    status = var.enable_bucket_versioning ? "Enabled" : "Suspended"
  }
}

# Deny unecrypted object uploads
resource "aws_s3_bucket_policy" "trigger_bucket" {
  bucket = aws_s3_bucket.trigger_bucket.id
  policy = jsonencode({
    "Version" : "2012-10-17"
    "Id" : "PutObjPolicy"
    "Statement" : [
      {
        "Sid" : "DenyIncorrectEncryptionHeader",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.trigger_bucket.arn}/*",
        "Condition" : {
          "StringNotEquals" : {
            "s3:x-amz-server-side-encryption" : "aws:kms"
          }
        }
      },
      {
        "Sid" : "DenyUnEncryptedUploads",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.trigger_bucket.arn}/*",
        "Condition" : {
          "Null" : {
            "s3:x-amz-server-side-encryption" : true
          }
        }
      }
    ]
  })

}

# Create KMS Key for S3 encryption
resource "aws_kms_key" "trigger_encryption" {
  description             = " This key is used to encrypt uploaded objects"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
  }
}

# Aliasing the KMS Key
resource "aws_kms_alias" "trigger_encryption" {
  name          = "alias/trigger_bucket_encryption"
  target_key_id = aws_kms_key.trigger_encryption.id
}

# Retrieve the current AWS account ID for use in KMS key policy conditions
data "aws_caller_identity" "current" {}

# KMS Key Policy
resource "aws_kms_key_policy" "key_policy" {
  key_id = aws_kms_key.trigger_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "s3.amazonaws.com"
      },
      Action = [
        "kms:GenerateDataKey",
        "kms:Decrypt"
      ],
      Resource = "*",
      Condition = {
        StringEquals = {
          "aws:SourceAccount" : data.aws_caller_identity.current.account_id
        }
      }

    }]
  })
}

# Enable server side encryption with KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "trigger_bucket" {
  bucket = aws_s3_bucket.trigger_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.trigger_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = var.enable_bucket_key
  }
}

# Add Lifecycle Policy for trigger bucket
resource "aws_s3_bucket_lifecycle_configuration" "trigger_bucket" {
  bucket = aws_s3_bucket.trigger_bucket.id

  rule {
    id     = "auto-archive-old-files"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }

}

###------------------------------------------------------
# LOG BUCKET COMPONENTS
# Log Bucket + related resources for S3-> Lambda workflow
###------------------------------------------------------

# Create log bucket
resource "aws_s3_bucket" "log_bucket" {
  bucket = var.log_bucket

  tags = merge(
    local.standard_tags,
    {
      Name = var.log_bucket
    }
  )
}

# Enable logging for trigger bucket
resource "aws_s3_bucket_logging" "bucket_logging" {
  bucket = aws_s3_bucket.trigger_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "logs/${var.trigger_bucket_name}/"
}


# Add Public Access Block
resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable bucket versioning for log bucket
resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = var.enable_bucket_versioning ? "Enabled" : "Suspended"
  }
}

# Create KMS Key for S3 encryption
resource "aws_kms_key" "log_encryption" {
  description             = "This key is used to encrypt uploaded logs"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
  }
}

# Aliasing the KMS Key
resource "aws_kms_alias" "log_encryption" {
  name          = "alias/log_bucket_encryption"
  target_key_id = aws_kms_key.log_encryption.id
}

# KMS Key Policy
resource "aws_kms_key_policy" "log_key_policy" {
  key_id = aws_kms_key.log_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "s3.amazonaws.com"
      },
      Action = [
        "kms:GenerateDataKey",
        "kms:Decrypt"
      ],
      Resource = "*",
      Condition = {
        StringEquals = {
          "aws:SourceAccount" : data.aws_caller_identity.current.account_id
        }
      }

    }]
  })
}

# Enable server side encryption with KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.log_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = var.enable_bucket_key
  }
}


# Add Lifecycle Policy for log bucket
resource "aws_s3_bucket_lifecycle_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    id     = "auto-archive-log-files"
    status = "Enabled"

    filter {
      prefix = "logs/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }

}


# Write IAM policy for Lambda execution role
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]

    }

  }
}

# Create Lambda execution role
resource "aws_iam_role" "lambda_exec_role" {
  name               = "lambda_exec_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}


# Add permissions for Lambda function
data "aws_iam_policy_document" "lambda_permissions" {
  # S3 Access for trigger bucket only
  statement {
    sid    = "S3ReadAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetBucketLocation",
      "s3:GetBucketTagging"
    ]
    resources = [
      "arn:aws:s3:::${var.trigger_bucket_name}",
      "arn:aws:s3:::${var.trigger_bucket_name}/*"
    ]
  }

  # Permission for Security Hub submission
  statement {
    sid    = "SecurityHubSubmitFindings"
    effect = "Allow"
    actions = [
      "securityhub:BatchImportFindings"
    ]
    resources = ["*"]
  }

  # Permission for KMS key
  statement {
    sid    = "KMSDescribeKey"
    effect = "Allow"
    actions = [
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.trigger_encryption.arn]
  }

  # Permission for CloudWatch Logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}:*"
    ]

  }

  # Add explicit deny
  statement {
    sid    = "ExplicitDeny"
    effect = "Deny"
    actions = [
      "s3:Delete*",
      "s3:Put*",
      "kms:Decrypt"
    ]
    resources = ["*"]
  }
}

# Attach lambda permission to lambda execution role
resource "aws_iam_role_policy" "lambda_policy" {
  name   = "${var.function_name}-policy"
  role   = aws_iam_role.lambda_exec_role.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}


# Create zip archive of lambda handler file
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/s3_encryption_checker.py"
  output_path = "${path.module}/lambda/s3_encryption_checker.zip"
}

# Create Lambda function
resource "aws_lambda_function" "s3_encryption_checker" {
  filename         = data.archive_file.lambda.output_path
  function_name    = var.function_name
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = var.lambda_handler
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = var.runtime
  timeout          = var.timeout
  memory_size      = var.memory_size
  architectures    = ["arm64"]
  ephemeral_storage {
    size = var.ephemeral_storage_size
  }
  reserved_concurrent_executions = var.reserved_concurrent_executions
  environment {
    variables = {
      Environment = var.environment
    }
  }
}


# Enforce tagging on S3 buckets
data "aws_iam_policy_document" "require_s3_tag" {
  # Allow compliant requests
  statement {
    sid       = "AllowS3BucketCreationWithRequiredTags"
    effect    = "Allow"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    # Ensure only allowed values are used for DataClassification
    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:RequestTag/DataClassification"
      values   = ["Confidential", "Internal", "Public"]
    }

    # Ensure only allowed values are used for RetentionPeriod
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/RetentionPeriod"
      values   = ["*yr", "*mo"]
    }

    # Enforce allowed format for Owner tag (e.g., SECURITYTeam, DEVTeam)
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/Owner"
      values   = ["*Team"]
    }
  }


  # Deny non-compliant requests
  statement {
    sid       = "DenyS3BucketCreationWithoutRequiredTags"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    # Deny creation if required tag: DataClassification is missing
    condition {
      test     = "Null"
      variable = "aws:RequestTag/DataClassification"
      values   = ["true"]
    }

    # Deny creation if required tag: RetentionPeriod is missing
    condition {
      test     = "Null"
      variable = "aws:RequestTag/RetentionPeriod"
      values   = ["true"]
    }

    # Deny creation if required tag: Owner is missing
    condition {
      test     = "Null"
      variable = "aws:RequestTag/Owner"
      values   = ["true"]
    }
  }
}


# Define AWS Organization SCP using the IAM policy Document
resource "aws_organizations_policy" "require_s3_tag" {
  name        = "S3_tagging_policy"
  description = "SCP to enforce tagging standards on all new S3 bucket creations"
  content     = data.aws_iam_policy_document.require_s3_tag.json
}

# Attach policy to AWS Organization
data "aws_organizations_organization" "org" {}

resource "aws_organizations_policy_attachment" "s3_tag_policy_attach" {
  policy_id = aws_organizations_policy.require_s3_tag.id
  target_id = data.aws_organizations_organization.org.roots[0].id
}



###------------------------------------------------------
# AWS CONFIG COMPONENTS
# AWS Config rules + related resources 
###------------------------------------------------------

# Assume role policy for AWS Config
data "aws_iam_policy_document" "s3_config_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# Create a role for AWS config
resource "aws_iam_role" "s3_config_role" {
  name               = "s3-config-role"
  assume_role_policy = data.aws_iam_policy_document.s3_config_assume_role.json
}

# Create policy  document for AWS Config
data "aws_iam_policy_document" "s3_config_policy" {
  statement {
    effect = "Allow"
    actions = [
      "config:Put*",
      "config:Get*",
      "config:Describe"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketTagging",
      "s3:ListBucket"
    ]
    resources = ["arn:aws:s3:::*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Environment"
      values   = [var.environment]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.s3_for_config_delivery.arn}/*"]
  }
}

# Create policy for AWS Config role
resource "aws_iam_role_policy" "s3_config_role_policy" {
  name   = "s3-config-role-policy"
  role   = aws_iam_role.s3_config_role.id
  policy = data.aws_iam_policy_document.s3_config_policy.json
}

# Create s3 bucket for AWS Config delivry
resource "aws_s3_bucket" "s3_for_config_delivery" {
  bucket        = "${var.config_delivery_bucket}-${lower(var.environment)}-${data.aws_caller_identity.current.account_id}"
  force_destroy = var.environment != "Prod"

  tags = merge(
    {
      Name               = "config-delivery-${var.environment}"
      Environment        = var.environment
      DataClassification = var.compliance_tags.DataClassification
      RetentionPeriod    = var.compliance_tags.RetentionPeriod
      Owner              = var.compliance_tags.Owner
    }
  )

}

# Create config recorder
resource "aws_config_configuration_recorder" "s3_config_recorder" {
  name     = "s3-config-recorder"
  role_arn = aws_iam_role.s3_config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}


# Create a delivery channel for AWS Config
resource "aws_config_delivery_channel" "s3_config_delivery" {
  name           = "aws-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.s3_for_config_delivery.bucket
  depends_on     = [aws_config_configuration_recorder.s3_config_recorder]
}

# Enable config recording
resource "aws_config_configuration_recorder_status" "recorder_status" {
  name       = aws_config_configuration_recorder.s3_config_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.s3_config_delivery]
}

# Config Rule with custom input parameters
resource "aws_config_config_rule" "s3_bucket_tag_check" {
  name        = "s3-bucket-tagging-check-$(var.environment)"
  description = "Checks if S3 buckets have required tags"
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  input_parameters = jsonencode({
    tag1Key   = "DataClassification",
    tag1Value = var.compliance_tags.DataClassification,
    tag2Key   = "Owner",
    tag2Value = var.compliance_tags.Owner,
    tag3Key   = "Environment",
    tag3Value = var.environment
  })
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  depends_on = [aws_config_configuration_recorder.s3_config_recorder]
}
