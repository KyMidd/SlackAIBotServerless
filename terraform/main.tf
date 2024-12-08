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
module "devopsbot_lambda" {
  source = "./lambda"

  # Pass providers
  providers = {
    aws       = aws
    aws.west2 = aws.west2
  }
}

