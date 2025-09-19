###
# IAM Role and policies for Message Receiver Lambda
###

data "aws_iam_policy_document" "receiver_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "receiver_role" {
  name               = "${var.bot_name}ReceiverRole"
  assume_role_policy = data.aws_iam_policy_document.receiver_assume_role.json
}

resource "aws_iam_role_policy" "receiver_lambda" {
  name = "InvokeLambda"
  role = aws_iam_role.receiver_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ]
        Resource = [aws_lambda_function.worker_slack.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy" "receiver_cloudwatch" {
  name = "Cloudwatch"
  role = aws_iam_role.receiver_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "logs:CreateLogGroup"
        Resource = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/${var.bot_name}Receiver:*"
        ]
      }
    ]
  })
}

###
# Build receiver lambda
###

data "archive_file" "devopsbot_receiver_lambda" {
  type        = "zip"
  source_file = "../python/receiver.py"
  output_path = "${path.module}/receiver.zip"
}

resource "aws_lambda_function" "devopsbot_receiver" {
  filename      = "${path.module}/receiver.zip"
  function_name = "${var.bot_name}Receiver"
  role          = aws_iam_role.receiver_role.arn
  handler       = "receiver.lambda_handler"
  timeout       = 10
  memory_size   = 128
  runtime       = "python3.12"
  architectures = ["arm64"]

  source_code_hash = data.archive_file.devopsbot_receiver_lambda.output_base64sha256

  environment {
    variables = {
      PROCESSOR_FUNCTION_NAME = aws_lambda_function.worker_slack.function_name
      SLACK_BOT_APP_ID        = var.slack_bot_app_id
    }
  }
}

# Publish alias of new version
resource "aws_lambda_alias" "devopsbot_receiver_alias" {
  name             = "Newest"
  function_name    = aws_lambda_function.devopsbot_receiver.arn
  function_version = aws_lambda_function.devopsbot_receiver.version

  # Add ignore for routing_configuration
  lifecycle {
    ignore_changes = [
      routing_config, # This sometimes has a race condition, so ignore changes to it
    ]
  }
}

# Point lambda function url at new version
resource "aws_lambda_function_url" "receiver_slack_function_url" {
  function_name      = aws_lambda_function.devopsbot_receiver.function_name
  qualifier          = aws_lambda_alias.devopsbot_receiver_alias.name
  authorization_type = "NONE"
}

# Print the URL we can use to trigger the bot
output "receiver_slack_function_url" {
  value = aws_lambda_function_url.receiver_slack_function_url.function_url
}