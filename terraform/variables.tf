variable "bot_name" {
  description = "The name of the bot"
  type        = string
}

variable "model_name" {
  description = "Model inference profile - usually (region)+(model name), like: us.anthropic.claude-sonnet-4-20250514-v1:0"
  type        = string
  default     = "us.anthropic.claude-sonnet-4-20250514-v1:0"
}

variable "slack_bot_app_id" {
  description = "The Slack Bot App ID (not token) used to identify the bot's own messages"
  type        = string
  sensitive   = true
}

# From the Slack installation
variable "slack_bot_token" {
  description = "The Slack Bot OAuth Token"
  type        = string
  sensitive   = true
}
variable "slack_signing_secret" {
  description = "The Slack Signing Secret"
  type        = string
  sensitive   = true
}