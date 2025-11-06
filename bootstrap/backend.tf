terraform {
  backend "s3" {
    bucket         = "grc-terraform-state-us-east-1"
    key            = "state/bootstrap/bootstrap.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-lock-grc-test"

  }
}