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


