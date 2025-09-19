# Define Terraform provider
terraform {
  required_version = "~> 1.7"

  required_providers {
    aws = {
      version = "~> 5.77"
      source  = "hashicorp/aws"
    }
  }
}

# Download AWS provider
provider "aws" {
  region = "us-east-1"
}

# Provider in AI region
provider "aws" {
  alias  = "west2"
  region = "us-west-2"
}

# Build lambda
module "lambda_resources" {
  source = "./lambda"

  slack_bot_app_id     = var.slack_bot_app_id
  slack_bot_token      = var.slack_bot_token
  slack_signing_secret = var.slack_signing_secret
  bot_name             = var.bot_name
  model_name           = var.model_name

  # Pass providers
  providers = {
    aws       = aws
    aws.west2 = aws.west2
  }
}

output "bot_receiver_lambda_public_url" {
  value = module.lambda_resources.receiver_slack_function_url
}