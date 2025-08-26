###------------------------------------------------------
# TRIGGER BUCKET COMPONENTS
# Bucket + related resources for S3-> Lambda workflow
###------------------------------------------------------

# Create S3 bucket 
resource "aws_s3_bucket" "trigger_bucket" {
  bucket = "${var.trigger_bucket_name}-${lower(var.environment)}-${data.aws_caller_identity.current.account_id}"

  # Allow force destroy in non prod environment
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



# KMS Key Policy
resource "aws_kms_key_policy" "key_policy" {
  key_id = aws_kms_key.trigger_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ServiceToUseKey"
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

      },
      {
        Sid    = "AllowLambdaDecrypt"
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.lambda_exec_role.arn
        },
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        Resource = "*"

      },
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = [
          "kms:*"
        ],
        Resource = "*"
      },

      # Allow Terraform role to manage key
      {
        Sid    = "AllowTerraformRoleToManageKey"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_exec_role_arn
        }

        Action = [
          "kms:CreateAlias",
          "kms:TagResource",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:PutKeyPolicy",
          "kms:ListResourceTags",
          "kms:TagResource"
        ]
        Resource = "*"

      }
    ]
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
  bucket = "${var.log_bucket}-${lower(var.environment)}"

  # Allow force destroy in non prod environment
  force_destroy = var.environment != "Prod"

  tags = merge(
    local.standard_tags,
    {
      Name = var.log_bucket
    }
  )
}

# Log bucket policy
resource "aws_s3_bucket_policy" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "AWSLogDeliveryWrite",
        Effect : "Allow",
        Principal : {
          Service : "logging.s3.amazonaws.com"
        },
        Action : "s3:PutObject",
        Resource : "${aws_s3_bucket.log_bucket.arn}/logs/*"
      }
    ]
  })
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
    Statement = [
      {
        Sid    = "AllowKeyAdministrationFromAccount"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
            data.aws_caller_identity.current.arn
          ]


        }
        Action = [
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:PutKeyPolicy",
          "kms:ListResourceTags"

        ],
        Resource = "*"
      },

      {
        Sid    = "AllowS3LogDeliveryToEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "${data.aws_caller_identity.current.account_id}"
          }
        }
      },

      {
        Sid    = "AllowAccountToReadRotationStatus"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:GetKeyRotationStatus"
        ]
        Resource = "*"
      },

      # Allow Terraform role to manage key
      {
        Sid    = "AllowTerraformRoleToManageKey"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.terraform_exec_role_name}"
        }

        Action = [
          "kms:CreateAlias",
          "kms:TagResource",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:PutKeyPolicy",
          "kms:ListResourceTags",
          "kms:TagResource"
        ]
        Resource = "*"

      }

    ]
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

###------------------------------------------------------
# AWS LAMBDA COMPONENTS
# AWS Lambda + related resources 
###------------------------------------------------------

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
  path               = "/portfolio/"
  tags = {
    Project = "GRC-Portfolio"
  }
}


# Add permissions for Lambda function
data "aws_iam_policy_document" "lambda_permissions" {
  # S3 Access for trigger bucket only
  statement {
    sid    = "S3ReadAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetBucketLocation",
      "s3:GetBucketTagging",
      "s3:PutObject"
    ]
    resources = [
      aws_s3_bucket.trigger_bucket.arn,
      "${aws_s3_bucket.trigger_bucket.arn}/*"
    ]
  }

  # Permission for Security Hub submission
  statement {
    sid    = "SecurityHubSubmitFindings"
    effect = "Allow"
    actions = [
      "securityhub:DescribeHub",
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

  # Permission to write custom CloudWatch metrics
  statement {
    sid    = "AllowPutMetricData"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
  }

  # Permission to decrypt
  statement {
    sid    = "KMSDecryptAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt"
    ]
    resources = [
      aws_kms_key.trigger_encryption.arn,
      aws_kms_key.log_encryption.arn
    ]
  }

  # Explicitly deny S3 Object deletion and Object PUTS 
  statement {
    sid    = "ExplicitDeny"
    effect = "Deny"
    actions = [
      "s3:Delete*",
      "s3:Put*"
    ]
    resources = [
      aws_kms_key.trigger_encryption.arn,
      aws_kms_key.log_encryption.arn
    ]
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
  source_file = "${path.module}/../lambda/s3_encryption_checker.py"
  output_path = "${path.module}/../lambda/s3_encryption_checker.zip"
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
  environment {
    variables = {
      Environment   = var.environment,
      KMS_KEY_ALIAS = var.trigger_bucket_kms_key_alias
    }
  }
}

# Grant S3 permission to invoke Lambda function when an object is uploaded
resource "aws_lambda_permission" "allow_s3_trigger" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_encryption_checker.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.trigger_bucket.arn
}

# Configure S3 to trigger the Lambda function on object upload events (PutObject)
resource "aws_s3_bucket_notification" "s3_lambda_trigger" {
  bucket = aws_s3_bucket.trigger_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.s3_encryption_checker.arn
    events              = ["s3:ObjectCreated:Put"]
  }

  # Ensure Lambda permission is in place before configuring s3 notification
  depends_on = [aws_lambda_permission.allow_s3_trigger]
}

###------------------------------------------------------
# AWS ORGANIZATION
# AWS Organization + related resources 
###------------------------------------------------------
# Enforce tagging on S3 buckets
data "aws_iam_policy_document" "require_s3_tag" {
  # Deny creation if required tag 'DataClassification' is missing
  statement {
    sid       = "DenyWithoutDataClassificationTags"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/DataClassification"
      values   = ["true"]
    }
  }

  # Deny creation if required tag 'RetentionPeriod' is missing
  statement {
    sid       = "DenyWithoutRetentionPeriod"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/RetentionPeriod"
      values   = ["true"]
    }
  }

  # Deny creation if required tag 'Owner' is missing
  statement {
    sid       = "DenyWithoutOwner"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/Owner"
      values   = ["true"]
    }
  }

  # Deny if DataClassification has invalid value
  statement {
    sid       = "DenyInvalidDataClassificationTag"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "StringNotEqualsIfExists"
      variable = "aws:RequestTag/DataClassification"
      values   = ["Confidential", "Internal", "Public"]
    }
  }

  # Deny if RetentionPeriod doesn't follow expected pattern
  statement {
    sid       = "DenyInvalidRetentionPeriodTag"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "StringNotLike"
      variable = "aws:RequestTag/RetentionPeriod"
      values   = ["*yr", "*mo"]
    }
  }

  # Deny if Owner tag doesn't end with "Team"
  statement {
    sid       = "DenyInvalidOwnerTag"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]

    condition {
      test     = "StringNotLike"
      variable = "aws:RequestTag/Owner"
      values   = ["*Team"]
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
  path               = "/portfolio/"
  tags = {
    Project = "GRC-Portfolio"
  }
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

  statement {
    effect = "Allow"
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLocation"
    ]
    resources = [aws_s3_bucket.s3_for_config_delivery.arn]
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
    local.standard_tags,
    {
      Name               = "config-delivery-${var.environment}"
      Environment        = var.environment
      DataClassification = var.compliance_tags.DataClassification
      RetentionPeriod    = var.compliance_tags.RetentionPeriod
      Owner              = var.compliance_tags.Owner
    }
  )

}

# Create policy for AWS config delivery bucket
data "aws_iam_policy_document" "config_delivery_policy" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.s3_for_config_delivery.arn]
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      format(
        "%s/AWSLogs/%s/Config/*",
        aws_s3_bucket.s3_for_config_delivery.arn,
        data.aws_caller_identity.current.account_id
      )
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "AllowConfigBucketValidation"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]
    resources = [aws_s3_bucket.s3_for_config_delivery.arn]
  }
}


# Attach policy
resource "aws_s3_bucket_policy" "config_delivery" {
  bucket = aws_s3_bucket.s3_for_config_delivery.id
  policy = data.aws_iam_policy_document.config_delivery_policy.json
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
  name        = "s3-bucket-tagging-check-${lower(var.environment)}"
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

###------------------------------------------------------
# AWS CLOUDWATCH COMPONENTS
# AWS Cloudwatch + related resources 
###------------------------------------------------------

# Cloudwatch event rule to trigger daily KMS rotation compliance check
resource "aws_cloudwatch_event_rule" "kms_key_rotation_check_schedule" {
  name                = "KMS-key-rotation-check"
  description         = "Triggers the KMS key rotation compliance check Lambda daily"
  schedule_expression = "rate(1 day)"
}

# Add KMS Lambda function as the event rule target
resource "aws_cloudwatch_event_target" "kms_lamda_target" {
  rule      = aws_cloudwatch_event_rule.kms_key_rotation_check_schedule.name
  target_id = "kms-compliance-lambda"
  arn       = aws_lambda_function.kms_rotation_checker.arn
}

# Grant Eventbridge permission to invoke the  Lambda function
resource "aws_lambda_permission" "allow_cloudwatch_kms" {
  statement_id  = "AllowExecutionFromCloudwatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.kms_rotation_checker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.kms_key_rotation_check_schedule.arn
}



###------------------------------------------------------
# ALB ACCESS LOG BUCKET COMPONENTS
# Log Bucket + related resources for ALB Logs
###------------------------------------------------------

# Create log bucket with region-specific naming for global uniqueness
resource "aws_s3_bucket" "alb_log_bucket" {
  bucket = "${var.alb_log_bucket}-${lower(var.environment)}-${var.region}"

  # Allow force destroy only in non-prod environments
  force_destroy = var.environment != "Prod"

  tags = merge(
    local.standard_tags,
    {
      Name = "${var.alb_log_bucket}-${var.environment}"
      Description : "Stores ALB access logs with encryption and lifecycle management"
    }
  )
}

# Alb Log bucket policy
resource "aws_s3_bucket_policy" "alb_log_bucket" {
  bucket = aws_s3_bucket.alb_log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "AllowELBLogDelivery",
        Effect : "Allow",
        Principal : {
          AWS : data.aws_elb_service_account.current_region.arn
        },
        Action : [
          "s3:PutObject",
          "s3:PutObjectAcl"

        ]
        Resource : "arn:aws:s3:::${aws_s3_bucket.alb_log_bucket.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },

      # Allow ELB Log delivery check
      {
        Sid    = "AllowELBLogDeliveryCheck"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.current_region.arn
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${aws_s3_bucket.alb_log_bucket.bucket}"

      },

      # Deny Insecure transport
      {
        Sid : "DenyInsecureTransport",
        Effect : "Deny",
        Principal : "*",
        Action : "s3:*",
        Resource : [
          "arn:aws:s3:::${aws_s3_bucket.alb_log_bucket.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.alb_log_bucket.bucket}/*"
        ]
        Condition : {
          Bool : { "aws:SecureTransport" : "false" }
        }
      }
    ]
  })
}


# Add Public Access Block
resource "aws_s3_bucket_public_access_block" "alb_log_bucket" {
  bucket = aws_s3_bucket.alb_log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable bucket versioning for alb log bucket
resource "aws_s3_bucket_versioning" "alb_log_bucket" {
  bucket = aws_s3_bucket.alb_log_bucket.id
  versioning_configuration {
    status = var.enable_bucket_versioning ? "Enabled" : "Suspended"
  }

}

