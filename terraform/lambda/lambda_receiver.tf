###
# IAM Role and policies for Message Receiver Lambda
###

data "aws_iam_policy_document" "Ue1TiDevOpsBotReceiverRole_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "Ue1TiDevOpsBotReceiverRole" {
  name               = "Ue1TiDevOpsBotReceiverRole"
  assume_role_policy = data.aws_iam_policy_document.Ue1TiDevOpsBotReceiverRole_assume_role.json
}

resource "aws_iam_role_policy" "DevOpsBotReceiver_Lambda" {
  name = "InvokeLambda"
  role = aws_iam_role.Ue1TiDevOpsBotReceiverRole.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ]
        Resource = [aws_lambda_function.devopsbot_slack.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy" "DevOpsBotReceiver_Cloudwatch" {
  name = "Cloudwatch"
  role = aws_iam_role.Ue1TiDevOpsBotReceiverRole.id

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
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/DevOpsBotReceiver:*"
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
  source_file = "python/receiver.py"
  output_path = "${path.module}/receiver.zip"
}

resource "aws_lambda_function" "devopsbot_receiver" {
  filename      = "${path.module}/receiver.zip"
  function_name = "DevOpsBotReceiver"
  role          = aws_iam_role.Ue1TiDevOpsBotReceiverRole.arn
  handler       = "receiver.lambda_handler"
  timeout       = 10
  memory_size   = 128
  runtime       = "python3.12"
  architectures = ["arm64"]

  source_code_hash = data.archive_file.devopsbot_receiver_lambda.output_base64sha256

  environment {
    variables = {
      PROCESSOR_FUNCTION_NAME = aws_lambda_function.devopsbot_slack.function_name
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
resource "aws_lambda_function_url" "DevOpsBotReceiver_Slack_Trigger_FunctionUrl" {
  function_name      = aws_lambda_function.devopsbot_receiver.function_name
  qualifier          = aws_lambda_alias.devopsbot_receiver_alias.name
  authorization_type = "NONE"
}

# Print the URL we can use to trigger the bot
output "DevOpsBot_Slack_Trigger_FunctionUrl" {
  value = aws_lambda_function_url.DevOpsBotReceiver_Slack_Trigger_FunctionUrl.function_url
}