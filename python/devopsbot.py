# This is the full devopsbot.py file, which is the main file for the DevOps Bot. 
# This file is responsible for handling all incoming messages and events from Slack, and then responding to them using the AI model. 
# The file contains functions to handle messages, check for duplicate events, and initialize the Slack app with the bot token and socket mode handler.
#  The file also contains the main handler function for AWS Lambda, which is used to handle incoming events from Slack. 
# The file also contains a main function that runs the app in local development mode, which is used for testing and debugging the bot locally.
# Author: Kyler Middleton
# Blog about this file: https://www.letsdodevops.com/p/lets-do-devops-building-an-azure


# Global imports
import os
import logging
import boto3
import json

# Slack app imports
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler # Required for socket mode, used in local development
from slack_bolt.adapter.aws_lambda import SlackRequestHandler


###
# Constants
###

# Specify model ID and temperature
model_id = 'anthropic.claude-3-5-sonnet-20241022-v2:0'
anthropic_version = "bedrock-2023-05-31"
temperature = 0.2
guardrailIdentifier = "xxxxxxxxxx"
guardrailVersion = "DRAFT"

# Enable logging
#logging.basicConfig(level=logging.DEBUG)

# Specify the AWS region for the AI model
model_region_name = "us-west-2"

# Model guidance, shimmed into each conversation as instructions for the model
model_guidance = """Assistant is a large language model trained to provide the best possible experience for developers and operations teams.
Assistant is designed to provide accurate and helpful responses to a wide range of questions. 
Assistant answers should be short and to the point.
Assistant uses Markdown formatting. When using Markdown, Assistant always follows best practices for clarity and consistency. 
Assistant always uses a single space after hash symbols for headers (e.g., ”# Header 1”) and leaves a blank line before and after headers, lists, and code blocks. 
For emphasis, Assistant uses asterisks or underscores consistently (e.g., italic or bold). 
When creating lists, Assistant aligns items properly and uses a single space after the list marker. For nested bullets in bullet point lists, Assistant uses two spaces before the asterisk (*) or hyphen (-) for each level of nesting. 
For nested bullets in numbered lists, Assistant uses three spaces before the number and period (e.g., “1.”) for each level of nesting.
"""


###
# Functions
###

# Get GitHubPAT secret from AWS Secrets Manager that we'll use to start the githubcop workflow
def get_secret(secret_name, region_name):
  
  # Create a Secrets Manager client
  session = boto3.session.Session()
  client = session.client(
    service_name='secretsmanager',
    region_name=region_name
  )

  try:
    get_secret_value_response = client.get_secret_value(
      SecretId=secret_name
    )
  except ClientError as e:
    # For a list of exceptions thrown, see
    # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    print("Had an error attempting to get secret from AWS Secrets Manager:", e)
    raise e

  # Decrypts secret using the associated KMS key.
  secret = get_secret_value_response['SecretString']

  # Print happy joy joy
  print("🚀 Successfully got secret", secret_name, "from AWS Secrets Manager")
  
  # Return the secret
  return secret

# Create a Bedrock client
def create_bedrock_client(region_name):
    return boto3.client(
        'bedrock-runtime',
        region_name=region_name
    )

# Initializes the slack app with the bot token and socket mode handler
def create_app(token, signing_secret):
    return App(
        process_before_response=True, # Required for AWS Lambda
        token=token,
        signing_secret=signing_secret,
    )

# Function to handle ai request input and response
def ai_request(bedrock_client, messages):
  response = bedrock_client.invoke_model(
    modelId=model_id,
    guardrailIdentifier=guardrailIdentifier,
    guardrailVersion=guardrailVersion,
    body=json.dumps(
      {
        "anthropic_version": anthropic_version,
        "max_tokens": 1024,
        "temperature": temperature,
        "system": model_guidance,
        "messages": messages,
      }
    ),
  ) 
  return response

# Check for duplicate events
def local_check_for_duplicate_event(req):
    
    # Isolate headers
    headers = req.headers

    # Check headers, if x-slack-retry-num is present, this is a re-send
    # Really we should be doing async lambda model, but for now detecting resends and exiting
    if "x-slack-retry-num" in headers:
      print("Detected a re-send, exiting")
      logging.info("Detected a re-send, exiting")
      return True
    
# Common function to handle both DMs and app mentions
def handle_message_event(client, body, say, bedrock_client, app):
    
    # If bot_id is in event, this is a message from the bot, ignore
    if "bot_id" in body['event']:
      print("Detected a duplicate event, discarding")
      logging.info("Detected a duplicate event, discarding")
      return

    user_id = body['event']['user']
    prompt = body['event']['text']

    # Initialize conversation context
    conversation = []

    # Check to see if we're in a thread
    # If yes, read previous messages in the thread, append to conversation context for AI response
    if "thread_ts" in body['event']:
        # Get the messages in the thread
        thread_ts = body["event"]["thread_ts"]
        messages = app.client.conversations_replies(channel=body["event"]["channel"], ts=thread_ts)
        for message in messages["messages"]:
           # Check if message came from the bot
            if "bot_id" in message:
              conversation.append({
                "role": "assistant",
                "content": [{
                  "type": "text",
                  "text": message["text"],
              }]})
            # If not, the message came from a user
            else:
              conversation.append({
                "role": "user",
                "content": [{
                  "type": "text",
                  "text": message["text"],
              }]})
    
    # Append user message to conversation
    conversation.append({
        "role": "user",
        "content": [{
            "type": "text",
            "text": prompt
      }]})

    # Call the AI model with the conversation
    response = ai_request(bedrock_client, conversation)

    # Filter response
    response_body = response['body'].read().decode('utf-8')
    response_json = json.loads(response_body)
    response_text = response_json.get("content", [{}])[0].get("text", "")

    # Determine the thread timestamp
    thread_ts = body['event'].get('thread_ts', body['event']['ts'])

    # Return response in the thread
    say(
      #text=f"Oh hi <@{user_id}>!\n\n{response_text}",
      text=f"{response_text}",
      thread_ts=thread_ts
    )

# Isolate the event body from the event package
def isolate_event_body(event):
    # Dump the event to a string, then load it as a dict
    event_string = json.dumps(event, indent=2)
    event_dict = json.loads(event_string)
    
    # Isolate the event body from event package
    event_body = event_dict['body']
    body = json.loads(event_body)
    
    # Return the event
    return body

# Define handler function for AWS Lambda
def lambda_handler(event, context):
    
    print("🚀 Lambda execution starting")

    # Isolate body
    event_body = isolate_event_body(event)

    # Detect if this is a re-send
    # Note this is a dumb workaround. Really the solution is to use an async lambda model so we can 1) kick off another lambda to do the work, and 2) return a response to Slack immediately within 3 second window Slack permits
    if "x-slack-retry-num" in event['headers']:
        print("🚀 Detected a re-send, exiting")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Detected a re-send, exiting"
            }),
        }
    
    # Check if challenge, return the challenge to verify the endpoint
    if "challenge" in event_body:
        return {
            "statusCode": 200,
            "body": json.dumps({
                "challenge": event_body["challenge"]
            }),
        }

    # Print the event
    print(event)

    # Fetch secret package
    secrets = get_secret("SLACKBOT_SECRETS_JSON", "us-east-1")

    # Disambiguate the secrets with json lookups
    secrets_json = json.loads(secrets)
    token = secrets_json["SLACK_BOT_TOKEN"]
    signing_secret = secrets_json["SLACK_SIGNING_SECRET"]

    # Register the Slack handler
    print("🚀 Registering the Slack handler")
    app = create_app(token, signing_secret)

    # Register the AWS Bedrock AI client
    print("🚀 Registering the AWS Bedrock client")
    bedrock_client = create_bedrock_client(model_region_name)

    # Respond to DMs
    @app.message()
    def message_hello(client, body, say):
        handle_message_event(client, event_body, say, bedrock_client, app)

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say):
        handle_message_event(client, event_body, say, bedrock_client, app)

    # Initialize the handler
    print("🚀 Initializing the handler")
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)

## Main function
if __name__ == "__main__":
    
    # Run in local development mode
    print("🚀 Local server starting starting")

    # Fetch secret package
    secrets = get_secret("SLACKBOT_SECRETS_JSON", "us-east-1")

    # Disambiguate the secrets with json lookups
    secrets_json = json.loads(secrets)
    token = secrets_json["SLACK_BOT_TOKEN"]
    signing_secret = secrets_json["SLACK_SIGNING_SECRET"]

    # Register the Slack handler
    print("🚀 Registering the Slack handler")
    app = create_app(token, signing_secret)
    
    # Register the AWS Bedrock AI client
    print("🚀 Registering the AWS Bedrock client")
    bedrock_client = create_bedrock_client(model_region_name)

    # Respond to DMs
    @app.message()
    def message_hello(client, body, say, payload, req):
      # Check for duplicate message
      if local_check_for_duplicate_event(req) == True:
        return

      # Handle request
      handle_message_event(client, body, say, bedrock_client, app)

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say, req):
      # Check for duplicate message
      if local_check_for_duplicate_event(req) == True:
        return

      # Handle request
      handle_message_event(client, body, say, bedrock_client, app)

    # Start the app in websocket mode for local development
    # Will require a separate terminal to run ngrok, e.g.: ngrok http http://localhost:3000
    print("🚀 Starting the app")
    app.start(port=int(os.environ.get("PORT", 3000)),)