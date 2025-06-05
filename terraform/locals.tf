locals {
  standard_tags = merge(
    {
      Terraform    = "true"
      LastModified = formatdate("YYYY-MM-DD", timestamp())
      Environment  = var.environment
    },
    var.compliance_tags
  )
}