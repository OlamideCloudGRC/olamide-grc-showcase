variable "environment" {
  description = "Deployment Environment (Case Sensitive)"
  type        = string
  default     = "Test"
  validation {
    condition     = contains(["Dev", "Test", "Prod", "Staging"], var.environment)
    error_message = "Environment must be one of: Dev, Test, Prod, Staging"
  }
}

variable "compliance_tags" {
  description = <<-EOT
    GRC required tags for audit and compliance
    - DataClassification: Follows ISO 27001 standards
    - RetentionPeriod: Minimum Required retention duration
    - Owner: Team accountable for resource lifecycle
  EOT
  type = object({
    DataClassification = string # Values: "Confidential"or "Internal" or "Public"
    RetentionPeriod    = string # Format: "^[0-9]+(yr|mo)$" (e.g, "1yr", "6mo")
    Owner              = string #Regex: "^[A-Z]+Team$" (eg, "SECURITYTeam")

  })
  validation {
    condition = alltrue([
      contains(["Confidential", "Internal", "Public"], var.compliance_tags.DataClassification),
      can(regex("^[0-9]+(yr|mo)$", var.compliance_tags.RetentionPeriod))
    ])
    error_message = "Invalid compliance tags. See variable description for format"
  }

}

variable "trigger_bucket_name" {
  description = "Name of the S3 bucket that will trigger Lambda functions"
  type        = string
  default     = "grc-encrypted-s3-bucket"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,63}", var.trigger_bucket_name))
    error_message = "Bucketname must be 3-63 characters, lowercase, with hyphen only"
  }
}

variable "enable_bucket_versioning" {
  description = "Enable bucket versioning to preserve/retrieve all object versions. This is required for compliance"
  type        = bool
  default     = true
}

variable "enable_bucket_key" {
  description = "Reduce KMS costs by enabling S3 Buckey Keys (recommended for > 1000 objects/month)"
  type        = bool
  default     = true
}

variable "log_bucket" {
  description = "Prefix for the centralized log bucket"
  type        = string
  default     = "my-encrypted-logs"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,63}$", var.log_bucket))
    error_message = "Log bucket prefix must be 3-63 characters, lowercase and contains only letters, numbers and hyphens."
  }
}

variable "region" {
  description = "AWS region where resources are deployed"
  type        = string
  default     = "us-east-1"
}

variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "s3-encryption-compliance-checker"
}

variable "lambda_handler" {
  description = "Handler entry point in the format: <filename>.<function_name>"
  type        = string
  default     = "s3_encryption_checker.lambda_handler"
}

variable "runtime" {
  description = "Lambda runtime environment"
  type        = string
  default     = "python3.11"
}

variable "timeout" {
  description = "Maximum execution time in seconds for Lambda function"
  type        = number
  default     = 30

}

variable "memory_size" {
  description = "Memory allocated to the Lambda function in MB"
  type        = number
  default     = 128
}

variable "ephemeral_storage_size" {
  description = "Amount of ephemeral storage (MB) available to the Lambda function"
  type        = number
  default     = 512
}


variable "config_delivery_bucket" {
  description = "Name for the s3 bucket used for AWS Config delivery"
  type        = string
  default     = "s3-tagging-config-delivery"
}

variable "terraform_state_bucket_name" {
  description = "Name for the S3 bucket for terraform state"
  default     = "grc-terraform-state"
}

variable "DynamoDB_table_name" {
  description = "Name for DynamoDB table foe Terraform State Lock"
  default     = "terraform-lock-grc"
}

variable "monitored_kms_key" {
  description = "List of KMS key aliases/ARNs to monitor for rotation"
  type        = list(string)
  default = [
    "alias/trigger_bucket_encryption",
    "alias/log_bucket_encryption"
  ]
}

variable "kms_lambda_function_name" {
  description = "Name of the Lambda function for KMS key compliance check"
  type        = string
  default     = "kms-key-compliance-checker"
}

variable "kms_lambda_handler" {
  description = "Handler entry point in the format: <filename>.<function_name> for kms lambda"
  type        = string
  default     = "kms_rotation_checker.lambda_handler"
}


variable "sns_sub_email" {
  description = "Email address to recieve critical GRC compliance alerts"
  type        = string
}

variable "trigger_bucket_kms_key_alias" {
  description = "Alias for KMS key to encrypt uploaded objects"
  type        = string
  default     = "alias/trigger_bucket_encryption"

}

variable "vpc_cidr" {
  description = "Cidr block for the main VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "max_azs" {
  description = "Maximum number of Azs to use (1-6)"
  type        = number
  default     = 2

  validation {
    condition     = var.max_azs >= 1 && var.max_azs <= 6
    error_message = "Max AZs must be between 1 and 6"
  }
}

variable "subnet_bits" {
  description = "Number of additional bits for subnet masking (8 creates /24 from /16)"
  type        = number
  default     = 8
} # This will give us a /24


variable "subnet_stride" {
  description = "Numerical gap between subnet groups per AZ to prevent overlap"
  type        = number
  default     = 16
}


variable "alb_log_bucket" {
  description = "Prefix for the alb log bucket"
  type        = string
  default     = "alb-encrypted-logs"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,63}$", var.alb_log_bucket))
    error_message = "Log bucket prefix must be 3-63 characters, lowercase and contains only letters, numbers and hyphens."
  }
}

variable "health_check_path" {
  description = "Path for ALB health checks"
  type        = string
  default     = "/health"
}

variable "log_transition_to_ia_days" {
  description = "Number of days before transitioning logs to IA storage"
  type        = number
  default     = 30
}

variable "log_transition_to_glacier_days" {
  description = "Number of days before transitioning logs to Glacier"
  type        = number
  default     = 90
}

variable "log_expiration_days" {
  description = "Number of days before expiring logs objects"
  type        = number
  default     = 365
}

variable "log_noncurrent_version_expiration_days" {
  description = "Number of days before expiring non-current versions of log objects"
  type        = number
  default     = 30
}

variable "alb_idle_timeout" {
  description = "The idle timeout value, in seconds for ALB"
  type        = number
  default     = 60
}

variable "terraform_exec_role_arn" {
  description = "Execution role ARN created by bootstrap"
  type        = string
}

variable "terraform_exec_role_name" {
  description = "Least-priviledge role used to deploy the portfolio main stacke"
  type        = string
  default     = "PortfolioTerraformExecutionRole"
}

variable "rate_limit" {
  description = "Rate limit for IP-based blocking"
  type        = number
  default     = 1000
}

variable "blocked_countries" {
  description = "List of country codes to block"
  type        = list(string)
  default     = ["RU"]
}

variable "waf_log_bucket" {
  description = "Prefix for the waf log bucket"
  type        = string
  default     = "waf-logs"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,63}$", var.waf_log_bucket))
    error_message = "Log bucket prefix must be 3-63 characters, lowercase and contains only letters, numbers and hyphens."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "min_size" {
  description = "Minimum number of instances in ASG"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum number of instances in ASG"
  type        = number
  default     = 3
}

variable "incident_response_function_name" {
  description = "Name of the Lambda function for compromised EC2"
  type        = string
  default     = "compromised_ec2_response"
}

variable "incident_response_lambda_handler" {
  description = "Handler entry point in the format: <filename>.<function_name>"
  type        = string
  default     = "compromised_ec2_response.lambda_handler"
}

variable "quarantine_sg_name" {
  description = "Name of the quarantine security group"
  type        = string
  default     = "compromise-response-quarantine-sg"
}