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