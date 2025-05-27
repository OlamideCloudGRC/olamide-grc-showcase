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
    RetentionPeriod = string # Format: "^[0-9]+(yr|mo)$" (e.g, "1yr", "6mo")
    Owner = string #Regex: "^[A-Z]+Team$" (eg, "SECURITYTeam")

  })
  validation {
    condition = alltrue([
      contains(["Confidential","Internal", "Public" ], var.compliance_tags.DataClassification),
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
    condition = can(regex("^[a-z0-9-]{3,63}",var.trigger_bucket_name))
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
  type = bool
  default = true
}