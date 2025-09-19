locals {
  bot_secrets_manager_secret_name = upper("${var.bot_name}_SECRETS_JSON")
}