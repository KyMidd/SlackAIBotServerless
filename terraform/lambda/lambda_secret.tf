# Create terraform secrets manager secret
resource "aws_secretsmanager_secret" "BotSecret" {
  name = local.bot_secrets_manager_secret_name
}

resource "aws_secretsmanager_secret_version" "BotSecretVersion" {
  secret_id = aws_secretsmanager_secret.BotSecret.id
  secret_string = jsonencode({
    SLACK_BOT_TOKEN      = var.slack_bot_token
    SLACK_SIGNING_SECRET = var.slack_signing_secret
  })
}