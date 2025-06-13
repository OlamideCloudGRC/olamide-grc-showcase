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
  default     = "my-encrypted-s3-bucket"
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
  description = "Name of the centralized log bucket. Follows naming convention <prefix>-logs-<env>"
  type        = string
  default     = "my-encrypted-logs-test"
  validation {
    condition     = endswith(var.log_bucket, "-logs-${lower(var.environment)}")
    error_message = "Log bucket name must end with '-logs-<env>' (lowercase)."
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

variable "reserved_concurrent_executions" {
  description = "Number of reserved concurrent Lambda executions"
  type        = number
  default     = 10
}

variable "config_delivery_bucket" {
  description = "Name for the s3 bucket used for AWS Config delivery"
  type        = string
  default     = "s3-tagging-config-delivery"
}

variable "terraform_state_bucket_name" {
  description = "Name for the S3 bucket for terraform state"
  default = "grc-terraform-state"
}

variable "DynamoDB_table_name" {
  description = "Name for DynamoDB table foe Terraform State Lock"
  default = "terraform-lock-grc"
}

variable "monitored_kms_key" {
  description = "List of KMS key aliases/ARNs to monitor for rotation"
  type = list(string)
  default = [ 
    "alias/trigger_bucket_encryption",
    "alias/log_bucket_encryption",
    "alias/state_bucket_encryption"
  ]
  validation {
    condition = alltrue([
      for k in var.monitored_kms_key: can(regex("^(alias/|arn:aws:kms)", k))
    ])
    error_message = "Keys must be ARNs or begin with 'alias/'"
  }
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

variable "kms_lambda_source_path" {
  description = "Path to Lambda source Python file"
  type = string
  default = "${path.module}/../lambda/kms_rotation_checker.py"
}

variable "kms_lambda_output_path" {
  description = "Path to output ZIP file for Lambda deployment package"
  type = string
  default = "${path.module}/../lambda/kms_rotation_checker.zip"
}