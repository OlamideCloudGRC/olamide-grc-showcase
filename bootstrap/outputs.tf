output "terraform_execution_role_arn" {
  description = "ARN of the role for the main stack to assume"
  value       = aws_iam_role.terraform_exec.arn
}