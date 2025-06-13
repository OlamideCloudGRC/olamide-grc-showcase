
# Define IAM trust policy for Lambda to assume execution role
data "aws_iam_policy_document" "kms_lambda_assume_role" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]

    }

  }
}

# IAM role for Lambda execution
resource "aws_iam_role" "kms_lambda_exec_role" {
  name               = "kms_lambda_exec_role"
  assume_role_policy = data.aws_iam_policy_document.kms_lambda_assume_role.json
}


# IAM policy granting KMS rotation check and logging permissions for Lambda
data "aws_iam_policy_document" "kms_lambda_permissions" {
  # Access to get KMS Key information
  statement {
    sid    = "GetKeyInfo"
    effect = "Allow"
    resources = var.monitored_kms_key
    actions = [
      "kms:GetKeyRotationStatus",
      "kms:ListKeys",
      "kms:DescribeKey"
    ]
    
  }

  # Permission to create logs
  statement {
    sid    = "LogsCreation"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = "arn:aws:logs:*:*:*"
  }

}

# Attach  permissions policy to lambda execution role
resource "aws_iam_role_policy" "kms_lambda_policy" {
  name   = "${var.kms_lambda_function_name}-policy"
  role   = aws_iam_role.kms_lambda_exec_role.id
  policy = data.aws_iam_policy_document.kms_lambda_permissions.json
}


# Archive lambda function code (Python script) into ZIP
data "archive_file" "kms_lambda" {
  type        = "zip"
  source_file = var.kms_lambda_source_path
  output_path = var.kms_lambda_output_path
}

# Create Lambda function for KMS compliance check
resource "aws_lambda_function" "kms_rotation_checker" {
  filename         = data.archive_file.kms_lambda.output_path
  function_name    = var.kms_lambda_function_name
  role             = aws_iam_role.kms_lambda_exec_role.arn
  handler          = var.kms_lambda_handler
  source_code_hash = data.archive_file.kms_lambda.output_base64sha256
  runtime          = var.runtime
  timeout          = var.timeout
  memory_size      = var.memory_size
  architectures    = ["arm64"]
  ephemeral_storage {
    size = var.ephemeral_storage_size
  }
  reserved_concurrent_executions = var.reserved_concurrent_executions
  environment {
    variables = {
      MONITORED_KEYS =jsonencode(var.monitored_kms_key)
    }
  }
}