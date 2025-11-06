variable "region" {
  description = "AWS region for bootstrap"
  type        = string
  default     = "us-east-1"
}

variable "iam_user_name" {
  description = "The username of the IAM user that will be assuming the terraform exec role"
  type        = string
  default     = "OlamideGRC1"

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.iam_user_name))
    error_message = "The iam_user_name must be a valid IAM username (1-64 characters, consisting of alphanumeric and these symbols: +=,.@-)."
  }
}

variable "terraform_exec_role_name" {
  description = "Least-priviledge role used to deploy the portfolio main stacke"
  type        = string
  default     = "PortfolioTerraformExecutionRole"
}

variable "environment" {
  description = "Deployment Environment (Case Sensitive)"
  type        = string
  default     = "Test"
  validation {
    condition     = contains(["Dev", "Test", "Prod", "Staging"], var.environment)
    error_message = "Environment must be one of: Dev, Test, Prod, Staging"
  }
}

