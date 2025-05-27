output "trigger_bucket_arn" {
    description = "The arn of the trigger bucket"
  value = aws_s3_bucket.trigger_bucket.arn
}

output "trigger_bucket_name" {
  description = "The name of the trigger bucket"
  value = aws_s3_bucket.trigger_bucket.id
}

output "log_bucket_name" {
 description = "The name of the trigger bucket"   
 value = aws_s3_bucket.log_bucket.id
}

output "log_bucket_arn" {
  description = "The arn of the log bucket"
  value = aws_s3_bucket.log_bucket.arn
}