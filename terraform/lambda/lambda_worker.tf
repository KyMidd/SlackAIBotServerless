###
# General data sources
###

# Current AWS account id
data "aws_caller_identity" "current" {}

# Region
data "aws_region" "current" {}


###
# IAM Role and policies
###

data "aws_iam_policy_document" "worker_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "worker_role" {
  name               = "${var.bot_name}BotIamRole"
  assume_role_policy = data.aws_iam_policy_document.worker_assume_role.json
}

resource "aws_iam_role_policy" "worker_ReadSecret" {
  name = "ReadSecret"
  role = aws_iam_role.worker_role.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : [
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "secretsmanager:ListSecretVersionIds"
          ],
          "Resource" : [
            aws_secretsmanager_secret.BotSecret.arn
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : "secretsmanager:ListSecrets",
          "Resource" : "*"
        }
      ]
    }
  )
}

resource "aws_iam_role_policy" "worker_Bedrock" {
  name = "Bedrock"
  role = aws_iam_role.worker_role.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        # Grant permission to invoke bedrock models of any type in US regions
        {
          "Effect" : "Allow",
          "Action" : [
            "bedrock:InvokeModel",
            "bedrock:InvokeModelStream",
            "bedrock:InvokeModelWithResponseStream",
          ],
          # Both no longer specify region, since Bedrock wants cross-region access
          "Resource" : [
            "arn:aws:bedrock:us-east-1::foundation-model/*",
            "arn:aws:bedrock:us-east-2::foundation-model/*",
            "arn:aws:bedrock:us-west-1::foundation-model/*",
            "arn:aws:bedrock:us-west-2::foundation-model/*",
            "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-east-2:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-west-1:${data.aws_caller_identity.current.account_id}:inference-profile/*",
            "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:inference-profile/*",
          ]
        },
        # Grant permission to invoke bedrock guardrails of any type in us-west-2 region
        {
          "Effect" : "Allow",
          "Action" : "bedrock:ApplyGuardrail",
          "Resource" : "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:guardrail/*"
        },
        # Grant permissions to use knowledge bases in us-west-2 region
        {
          "Effect" : "Allow",
          "Action" : [
            "bedrock:Retrieve",
            "bedrock:RetrieveAndGenerate",
          ],
          "Resource" : "arn:aws:bedrock:us-west-2:${data.aws_caller_identity.current.account_id}:knowledge-base/*"
        },
      ]
    }
  )
}

resource "aws_iam_role_policy" "worker_cloudwatch" {
  name = "Cloudwatch"
  role = aws_iam_role.worker_role.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Action" : "logs:CreateLogGroup",
          "Resource" : "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.id}:*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : [
            "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/${var.bot_name}:*"
          ]
        }
      ]
    }
  )
}


###
# Create lambda layers
###

# Source files created by the following commands:

# Source files created by the following commands:
/*
# Create new python 3.12 venv
mkdir venv_old
mv pyvenv.cfg venv_old
mv bin venv_old
mv include venv_old
mv lib venv_old
# Deactivate old venv
deactivate
# Create new python 3.12 venv
python3.12 -m venv .
# Activate new env
source ./bin/activate
# Remove old files and create new ones
rm -rf lambda/slack_bolt
mkdir -p lambda/slack_bolt/python/lib/python3.12/site-packages/
pip3 install slack_bolt -t lambda/slack_bolt/python/lib/python3.12/site-packages/. --no-cache-dir 
*/

# Committing the zip file directly, rather than creating it, so don't have to commit huge number of files
# data "archive_file" "slack_bolt" {
#   type        = "zip"
#   source_dir  = "${path.module}/slack_bolt"
#   output_path = "${path.module}/slack_bolt_layer.zip"
# }
resource "aws_lambda_layer_version" "slack_bolt" {
  layer_name       = "SlackBolt"
  filename         = "${path.module}/slack_bolt_layer.zip"
  source_code_hash = filesha256("${path.module}/slack_bolt_layer.zip")

  compatible_runtimes      = ["python3.12"]
  compatible_architectures = ["arm64"]
}

# Create requests layer
/*
mkdir -p lambda/requests/python/lib/python3.12/site-packages/
pip3 install requests -t lambda/requests/python/lib/python3.12/site-packages/. --no-cache-dir 
*/
# data "archive_file" "requests_layer" {
#   type        = "zip"
#   source_dir  = "${path.module}/requests"
#   output_path = "${path.module}/requests_layer.zip"
# }
resource "aws_lambda_layer_version" "requests" {
  layer_name       = "Requests"
  filename         = "${path.module}/requests_layer.zip"
  source_code_hash = filesha256("${path.module}/requests_layer.zip")

  compatible_runtimes      = ["python3.12"]
  compatible_architectures = ["arm64"]
}


###
# Build lambda
###

# Zip up python lambda code
data "archive_file" "worker_slack_trigger_lambda" {
  type        = "zip"
  source_file = "../python/worker.py"
  output_path = "${path.module}/worker.zip"
}

# Build lambda function
resource "aws_lambda_function" "worker_slack" {
  filename      = "${path.module}/worker.zip"
  function_name = var.bot_name
  role          = aws_iam_role.worker_role.arn
  handler       = "worker.lambda_handler"
  timeout       = 30
  memory_size   = 1024
  runtime       = "python3.12"
  architectures = ["arm64"]
  publish       = true

  # Layers are packaged code for lambda
  layers = [
    # This layer permits us to ingest secrets from Secrets Manager
    # It's hosted by AWS, so we can just reference the ARN directly
    "arn:aws:lambda:us-east-1:177933569100:layer:AWS-Parameters-and-Secrets-Lambda-Extension-Arm64:12",

    # Slack bolt layer to support slack app
    aws_lambda_layer_version.slack_bolt.arn,

    # Requests layer to support HTTP calls
    aws_lambda_layer_version.requests.arn,
  ]

  source_code_hash = data.archive_file.worker_slack_trigger_lambda.output_base64sha256

  environment {
    variables = {
      BOT_SECRET_NAME  = local.bot_secrets_manager_secret_name
      BOT_NAME         = var.bot_name
      MODEL_NAME       = var.model_name
      SLACK_BOT_APP_ID = var.slack_bot_app_id
    }
  }
}
