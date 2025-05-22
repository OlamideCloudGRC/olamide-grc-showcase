
variable "vpc_cidr" {
  description = "CIDR BLOCK for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_name" {
  description = "Name tag for VPC"
  type        = string
  default     = "main"
}

variable "enable_dns_support" {
  description = "Enable DNS Support in VPC"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostname in VPC"
  type        = bool
  default     = true
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "instance_type" {
  description = "Instance type"
  type = string
  default = "t2.micro"
}

variable "trigger_bucket_name" {
  description = "Name of the S3 bucket that will trigger Lambda functions"
  type = string
  default = "my-encrypted-s3-bucket"
}

variable "environment" {
description = "Deployment Environment (eg Dev, Test, Prod)"
type = string
default = "Test"
validation {
  condition = contains(["Dev", "Test", "Prod", "Staging"])
  error_message = "Envinronment must be one of: Dev, Test, Prod, Staging"
}
}

variable "enable_bucket_versioning" {
  description = "Enable bucket versioning on s3 bucket"
  type = bool
  default = true
}