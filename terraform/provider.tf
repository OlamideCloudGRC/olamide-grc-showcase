terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


provider "aws" {
  region = "us-east-1"

  assume_role {
    role_arn     = var.terraform_exec_role_arn
    session_name = "portfolio"
  }

  default_tags {
    tags = {
      Project = "GRC-Portfolio"
    }
  }
}