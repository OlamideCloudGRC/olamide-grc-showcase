output "trigger_bucket_arn" {
  description = "The arn of the trigger bucket"
  value       = aws_s3_bucket.trigger_bucket.arn
}

output "trigger_bucket_name" {
  description = "The name of the trigger bucket"
  value       = aws_s3_bucket.trigger_bucket.id
}

output "log_bucket_name" {
  description = "The name of the trigger bucket"
  value       = aws_s3_bucket.log_bucket.id
}

output "log_bucket_arn" {
  description = "The arn of the log bucket"
  value       = aws_s3_bucket.log_bucket.arn
}

output "terraform_state_bucket" {
  description = "Name of S3 bucket storing Terraform state"
  value = aws_s3_bucket.terraform_state.id
}

output "terraform_lock_table" {
  description = "Name of DynamoDB table for state locking"
  value = aws_dynamodb_table.terraform_lock.name
}