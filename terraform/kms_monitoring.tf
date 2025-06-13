
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

# SNS Topic for critical Alerts
resource "aws_sns_topic" "critical_alerts" {
  name = "grc-critical-alerts"
}

# Email Subscription to SNS topic
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol = "email"
  endpoint = var.sns_sub_email
}



# Cloudwatch alarm:Trigger on critical s3 encryption findings
resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name = "s3-encryption-critical-findings"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = 1
  metric_name = "CriticalFindings"
  namespace = "GRC/Compliance"
  period = 300
  statistic = "Sum"
  threshold = 1
  alarm_description = "Triggers when critical encryption violations are detected"
  treat_missing_data = "notBreaching"
  dimensions = {
    FunctionName = aws_lambda_function.s3_encryption_checker.function_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

}


# Cloudwatch alarm:Trigger when multiple remediation attempts fail
resource "aws_cloudwatch_metric_alarm" "failed_remediations" {
  alarm_name = "s3-encryption-failed-remediations"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = 1
  metric_name = "FailedRemediations"
  namespace = "GRC/Compliance"
  period = 3600
  statistic = "Sum"
  threshold = 3
  alarm_description = "Triggers when multiple remediation attempts fail"
  treat_missing_data = "notBreaching"
  dimensions = {
    FunctionName = aws_lambda_function.s3_encryption_checker.function_name
  }

  alarm_actions = [aws_sns_topic.critical_alerts.arn]

}