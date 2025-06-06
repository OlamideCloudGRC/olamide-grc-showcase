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

    principals{
      type= "Service"
      identifiers= ["lambda.amazonaws.com"]

    }

  }
 }

 # Create Lambda execution role
 resource "aws_iam_role" "lambda_exec_role" {
   name = "lambda_exec_role"
   assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
 }


# Add permissions for Lambda function
data "aws_iam_policy_document" "lambda_permissions" {
  # S3 Access for trigger bucket only
  statement {
    sid = "S3ReadAccess"
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
    sid = "SecurityHubSubmitFindings"
    effect = "Allow"
    actions = [
      "securityhub:BatchImportFindings"
    ]
    resources = ["*"]
  }

  # Permission for KMS key
  statement {
    sid = "KMSDescribeKey"
    effect = "Allow"
    actions = [
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.trigger_encryption.arn]
  }

  # Permission for CloudWatch Logs
  statement {
    sid = "CloudWatchLogs"
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
}

# Attach lambda permission to lambda execution role
resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.function_name}-policy"
  role = aws_iam_role.lambda_exec_role.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}


# Create zip archive of lambda handler file
data "archive_file" "lambda" {
  type = "zip"
  source_file = "${path.module}/lambda/s3_encryption_checker.py"
  output_path = "${path.module}/lambda/s3_encryption_checker.zip"
}

# Create Lambda function
resource "aws_lambda_function" "s3_encryption_checker" {
  filename = data.archive_file.lambda.output_path
  function_name = var.function_name
  role = aws_iam_role.lambda_exec_role.arn
  handler = var.lambda_handler
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime = var.runtime
  timeout = var.timeout
  memory_size = var.memory_size
  architectures = ["arm64"]
  ephemeral_storage {
    size = var.ephemeral_storage_size
  }
  reserved_concurrent_executions = var.reserved_concurrent_executions
  environment {
    variables = var.environment
  }
}