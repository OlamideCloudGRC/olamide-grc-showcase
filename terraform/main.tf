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

