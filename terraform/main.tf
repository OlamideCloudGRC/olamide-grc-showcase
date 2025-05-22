
# Getting the ami using data source
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-kernel-5.10-hvm-2.0.*"]

  }

}


# Creating an instance
resource "aws_instance" "web" {
  for_each               = toset(var.availability_zones)
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private_subnet[each.key].id
  vpc_security_group_ids = [aws_security_group.web-sg.id]

  tags = {
    Name = "GRC_HW_2_${each.key}"
  }
}

# Create S3 bucket 
resource "aws_s3_bucket" "trigger_bucket" {
  bucket = var.trigger_bucket_name

  tags = {
    Name        = var.trigger_bucket_name
    Environment = var.environment
  }
}

# Enable bucket versioning 
resource "aws_s3_bucket_versioning" "s3_versioning" {
  bucket = aws_s3_bucket.trigger_bucket.id
  versioning_configuration {
    status = var.enable_bucket_versioning ? "Enabled" : "Suspended"
  }
}

# Create KMS Key to Encrypt S3 bucket
resource "aws_kms_key" "grc_kms_key" {
  description             = " This key is used to ecrypt uploaded objects"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Environment = var.environment
  }
}

# Aliasing the KMS Key
resource "aws_kms_alias" "grc_key_alias" {
  name          = "alias/grc-s3-key"
  target_key_id = aws_kms_key.grc_kms_key.id
}

# Enable server side encryption with KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "KMS_SSE" {
  bucket = aws_s3_bucket.trigger_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.grc_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Deny unecrypted object uploads
resource "aws_s3_bucket_policy" "block_unecrypted_upload" {
  bucket = aws_s3_bucket.trigger_bucket.id
  policy = jsonencode({
    "Version" : "2012-10-17"
    "Id" : "PutObjPolicy"
    "statement" : [
      {
        "Sid" : "DenyIncorrectEncryptionHeader",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.trigger_bucket.arn}/*",
        "Condition" : {
          "StringsNotEquals" : {
            "s3:x-amz-server-side-encryption" : "aws:kms"
          }
        }
      },
      {
        "Sid" : "DenyUnEncryptedUploads",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.trigger_bucket.arn}/*"
        "Condition" : {
          "Null" : {
            "s3:x-amz-server-side-encryption" : true
          }
        }
      }
    ]
  })

}


resource "aws_s3_bucket" "" {

}

resource "aws_s3_bucket_logging" "loggingbucket" {

}
