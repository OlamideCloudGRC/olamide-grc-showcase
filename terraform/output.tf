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
  description = "The name of the existing S3 bucket used for storing Terraform state"
  value       = data.aws_s3_bucket.terraform_state.id
}

output "terraform_lock_table" {
  description = "Name of DynamoDB table for state locking"
  value       = data.aws_dynamodb_table.terraform_lock.name
}

output "kms_lambda_checker" {
  description = "Details of the KMS rotation compliance Lambda function "
  value = {
    name = aws_lambda_function.kms_rotation_checker.function_name
    arn  = aws_lambda_function.kms_rotation_checker.arn
    role = aws_iam_role.kms_lambda_exec_role.arn
  }
}

output "kms_event_rule" {
  description = "Name of the cloudwatch rule triggering the KMS Compliance Lambda"
  value       = aws_cloudwatch_event_rule.kms_key_rotation_check_schedule.name
}

output "public_subnets" {
  description = "Map of public subnets by zone ID"
  value       = local.public_subnets
}

output "private_subnets" {
  description = "Map of private subnets by zone ID"
  value       = local.private_subnets
}

output "alb_dns_name" {
  description = "The DNS name of the application Load Balancer"
  value       = aws_lb.app_lb.dns_name
}

output "alb_arn" {
  description = "The ARN of the application Load Balancer"
  value       = aws_lb.app_lb.arn
}

output "alb_zone_id" {
  description = "The hosted zone ID of the load balancer"
  value       = aws_lb.app_lb.zone_id
}

output "alb_target_group_arn" {
  description = "The ARN of the ALB target group"
  value       = aws_lb_target_group.alb_tg.arn
}

output "alb_log_bucket_name" {
  description = "The name of the S3 bucket for ALB logs"
  value       = aws_s3_bucket.alb_log_bucket.bucket
}

output "alb_log_bucket_arn" {
  description = "The ARN of the S3 bucket for ALB logs"
  value       = aws_s3_bucket.alb_log_bucket.arn
}

output "aws_wafv2_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}