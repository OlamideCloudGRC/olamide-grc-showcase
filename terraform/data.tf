###------------------------------------------------------
# Data Sources 
###------------------------------------------------------

# S3 bucket used for remote Terraform state
data "aws_s3_bucket" "terraform_state" {
  bucket = "grc-terraform-state-us-east-1"
}

# DynamoDB table used for Terraform state locking
data "aws_dynamodb_table" "terraform_lock" {
  name = "terraform-lock-grc-test"
}

# Retrieve the current AWS account ID for use in KMS key policy conditions
data "aws_caller_identity" "current" {}

# Get AWS Availability zones in the current region
data "aws_availability_zones" "current_region" {
  state = "available"
}

# Get alb service account for current region
data "aws_elb_service_account" "current_region" {}

# Get hosted zone
data "aws_route53_zone" "main_zone" {
  name         = "securewitholamide.com"
  private_zone = false
}