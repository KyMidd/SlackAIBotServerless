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
import base64
import requests

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
bot_secret_name = "DEVOPSBOT_SECRETS_JSON"
enable_guardrails = False # Won't use guardrails if False
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
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        print("Had an error attempting to get secret from AWS Secrets Manager:", e)
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response["SecretString"]

    # Print happy joy joy
    print("🚀 Successfully got secret", secret_name, "from AWS Secrets Manager")

    # Return the secret
    return secret


# Create a Bedrock client
def create_bedrock_client(region_name):
    return boto3.client("bedrock-runtime", region_name=region_name)


# Initializes the slack app with the bot token and socket mode handler
def create_app(token, signing_secret):
    return App(
        process_before_response=True,  # Required for AWS Lambda
        token=token,
        signing_secret=signing_secret,
    )


# Function to handle ai request input and response
def ai_request(bedrock_client, messages):
    # If enable_guardrails is set to True, include guardrailIdentifier and guardrailVersion in the request
    if enable_guardrails:
        response = bedrock_client.invoke_model(
            modelId=model_id,
            guardrailIdentifier=guardrailIdentifier,
            guardrailVersion=guardrailVersion,
            body=json.dumps(
                {
                    "anthropic_version": anthropic_version,
                    # "betas": ["pdfs-2024-09-25"], # This is not yet supported, https://docs.anthropic.com/en/docs/build-with-claude/pdf-support#supported-platforms-and-models
                    "max_tokens": 1024,
                    "messages": messages,
                    "temperature": temperature,
                    "system": model_guidance,
                }
            ),
        )
    # If enable_guardrails is set to False, do not include guardrailIdentifier and guardrailVersion in the request
    else:
        response = bedrock_client.invoke_model(
            modelId=model_id,
            body=json.dumps(
                {
                    "anthropic_version": anthropic_version,
                    # "betas": ["pdfs-2024-09-25"], # This is not yet supported, https://docs.anthropic.com/en/docs/build-with-claude/pdf-support#supported-platforms-and-models
                    "max_tokens": 1024,
                    "messages": messages,
                    "temperature": temperature,
                    "system": model_guidance,
                }
            ),
        )
    return response


# Check for duplicate events
def check_for_duplicate_event(headers, payload):

    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Headers:", headers)
        print("🚀 Payload:", payload)

    # Check headers, if x-slack-retry-num is present, this is a re-send
    # Really we should be doing async lambda model, but for now detecting resends and exiting
    if "x-slack-retry-num" in headers:
        print("❌ Detected a re-send, exiting")
        logging.info("❌ Detected a re-send, exiting")
        return True

    # Check if edited message in local development
    if "edited" in payload:
        print("Detected a message edited event, responding with http 200 and exiting")
        return True

    # If bot_id is in event, this is a message from the bot, ignore
    if "bot_id" in payload:
        print("Message from bot detected, discarding")
        logging.info("Detected a duplicate event, discarding")
        return True

    # If body event message subtype is tombstone, this is a message deletion event, ignore
    if (
        "subtype" in payload.get("message", {})
        and payload["message"]["subtype"] == "tombstone"
    ):
        print("Detected a tombstone event, discarding")
        logging.info("Detected a tombstone event, discarding")
        return True


# Function to build the content of a conversation
def build_conversation_content(payload, token):

    # Initialize unsupported file type found canary var
    unsupported_file_type_found = False

    # Initialize the content array
    content = []

    # Identify the user's ID
    user_id = payload["user"]

    # Find the user's information
    user_info = requests.get(
        f"https://slack.com/api/users.info?user={user_id}",
        headers={"Authorization": "Bearer " + token},
    )

    # Identify the user's real name
    user_info_json = user_info.json()
    user_real_name = user_info_json["user"]["real_name"]

    # TODO: Add support for pronouns, if returned in user payload. For now, everyone is nonbinary

    # If text is not empty, and text length is greater than 0, append to content array
    if "text" in payload and len(payload["text"]) > 1:
        # If debug variable is set to true, print the text found in the payload
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Text found in payload: " + payload["text"])

        content.append(
            {
                "type": "text",
                # Combine the user's name with the text to help the model understand who is speaking
                "text": f"{user_real_name} says: {payload['text']}",
            }
        )

    # If the payload contains files, iterate through them
    if "files" in payload:

        # Append the payload files to the content array
        for file in payload["files"]:

            # Check the mime type of the file is a supported file type
            # Commenting out the PDF check until the PDF beta is enabled on bedrock
            # if file["mimetype"] in ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            if file["mimetype"] in [
                "image/png",
                "image/jpeg",
                "image/gif",
                "image/webp",
            ]:
                # File is a supported type
                file_url = file["url_private_download"]

                # Fetch the file and continue
                file_object = requests.get(
                    file_url, headers={"Authorization": "Bearer " + token}
                )

                # Encode the image with base64
                encoded_file = base64.b64encode(file_object.content).decode("utf-8")

                # Identify the mime type of the file, some require different file types when sending to the model
                if file["mimetype"] in [
                    "image/png",
                    "image/jpeg",
                    "image/gif",
                    "image/webp",
                ]:
                    file_type = "image"
                else:
                    file_type = "document"

                # Append the file to the content array
                content.append(
                    {
                        "type": file_type,
                        "source": {
                            "type": "base64",
                            "media_type": file["mimetype"],
                            "data": encoded_file,
                        },
                    }
                )

            # If the mime type is not supported, set unsupported_file_type_found to True
            else:
                print(f"Unsupported file type found: {file['mimetype']}")
                unsupported_file_type_found = True
                continue

    # Return
    return content, unsupported_file_type_found


# Common function to handle both DMs and app mentions
def handle_message_event(client, body, say, bedrock_client, app, token):

    user_id = body["event"]["user"]
    event = body["event"]

    # Determine the thread timestamp
    thread_ts = body["event"].get("thread_ts", body["event"]["ts"])

    # Initialize conversation context
    conversation = []

    # Check to see if we're in a thread
    # If yes, read previous messages in the thread, append to conversation context for AI response
    if "thread_ts" in body["event"]:
        # Get the messages in the thread
        thread_ts = body["event"]["thread_ts"]
        messages = app.client.conversations_replies(
            channel=body["event"]["channel"], ts=thread_ts
        )

        # Iterate through every message in the thread
        for message in messages["messages"]:

            # Build the content array
            thread_conversation_content, unsupported_file_type_found = (
                build_conversation_content(message, token)
            )

            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 Thread conversation content:", thread_conversation_content)

            # Check if the thread conversation content is empty. This happens when a user sends an unsupported doc type only, with no message
            if thread_conversation_content != []:
                # Conversation content is not empty, append to conversation

                # Check if message came from the bot
                # We're assuming the bot only generates text content, which is true of Claude v3.5 Sonnet v2
                if "bot_id" in message:
                    conversation.append(
                        {
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "text",
                                    "text": message["text"],
                                }
                            ],
                        }
                    )
                # If not, the message came from a user
                else:
                    conversation.append(
                        {"role": "user", "content": thread_conversation_content}
                    )

                    if os.environ.get("VERA_DEBUG", "False") == "True":
                        print(
                            "🚀 State of conversation after threaded message append:",
                            conversation,
                        )

    # Build the user's part of the conversation
    user_conversation_content, unsupported_file_type_found = build_conversation_content(
        event, token
    )

    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 User conversation content:", user_conversation_content)

    # Check if the thread conversation content is empty. This happens when a user sends an unsupported doc type only, with no message
    if user_conversation_content != []:
        # Conversation content is not empty, append to conversation

        # Append the user's prompt to the conversation
        conversation.append(
            {
                "role": "user",
                "content": user_conversation_content,
            }
        )

        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 State of conversation after append user's prompt:", conversation)

    # Check if conversation content is empty, this happens when a user sends an unsupported doc type only, with no message
    # Conversation looks like this: [{'role': 'user', 'content': []}]
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 State of conversation before check if convo is empty:", conversation)
    if conversation == []:
        # Conversation is empty, append to error message
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Conversation is empty, exiting")

        # Announce the error
        say(
            text=f"> `Error`: Unsupported file type found, please ensure you are sending a supported file type. Supported file types are: images (png, jpeg, gif, webp).",
            thread_ts=thread_ts,
        )
        return

    # Call the AI model with the conversation
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 State of conversation before AI request:", conversation)
    response = ai_request(bedrock_client, conversation)

    # Get response
    response_body = response["body"].read().decode("utf-8")
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Response body:", response_body)

    # Conver to JSON
    response_json = json.loads(response_body)
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 response_json['content']:", response_json["content"])

    # Check if response content is empty
    if response_json["content"] == []:
        print("🚀 Response content is empty, setting response_text to blank")
        response_text = ""
    else:
        # There is content in the response, set response_text to the text content
        response_text = response_json.get("content", [{}])[0].get("text", "")

        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 response_text:", response_text)

    # Check if unsupported_file_type_found
    if unsupported_file_type_found == True:
        # If true, prepend error to response text
        response_text = f"> `Error`: Unsupported file type found, please ensure you are sending a supported file type. Supported file types are: images (png, jpeg, gif, webp).\n{
            response_text}"

        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Response text after adding errors:", response_text)

    # Return response in the thread
    say(
        # text=f"Oh hi <@{user_id}>!\n\n{response_text}",
        text=f"{response_text}",
        thread_ts=thread_ts,
    )


# Isolate the event body from the event package
def isolate_event_body(event):
    # Dump the event to a string, then load it as a dict
    event_string = json.dumps(event, indent=2)
    event_dict = json.loads(event_string)

    # Isolate the event body from event package
    event_body = event_dict["body"]
    body = json.loads(event_body)

    # Return the event
    return body


# Generate response
def generate_response(status_code, message):
    """
    Generate a standardized response for AWS Lambda.

    Parameters:
    status_code (int): The HTTP status code for the response.
    message (str): The message to include in the response body.

    Returns:
    dict: A dictionary representing the response.
    """
    return {
        "statusCode": status_code,
        "body": json.dumps({"message": message}),
        "headers": {"Content-Type": "application/json"},
    }


# Define handler function for AWS Lambda
def lambda_handler(event, context):

    print("🚀 Lambda execution starting")

    # Isolate body
    event_body = isolate_event_body(event)

    # Check for duplicate event or trash messages, return 200 and exit if detected
    if check_for_duplicate_event(event["headers"], event_body["event"]):
        return generate_response(
            200, "❌ Detected a re-send or edited message, exiting"
        )

    # Special challenge event for Slack. If receive a challenge request, immediately return the challenge
    if "challenge" in event_body:
        return {
            "statusCode": 200,
            "body": json.dumps({"challenge": event_body["challenge"]}),
        }

    # Print the event
    print("🚀 Event:", event)

    # Fetch secret package
    secrets = get_secret(bot_secret_name, "us-east-1")

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

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say):
        print("🚀 Handling app mention event")
        handle_message_event(client, event_body, say, bedrock_client, app, token)

    # Respond to file share events
    @app.event("message")
    def handle_message_events(client, body, say, req):
        print("🚀 Handling message event")
        handle_message_event(client, event_body, say, bedrock_client, app, token)

    # Initialize the handler
    print("🚀 Initializing the handler")
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)


# Main function
if __name__ == "__main__":

    # Run in local development mode
    print("🚀 Local server starting starting")

    # Fetch secret package
    secrets = get_secret(bot_secret_name, "us-east-1")

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

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say, req, payload):
        # Check for duplicate event or trash messages, return 200 and exit if detected
        if check_for_duplicate_event(req.headers, payload):
            return generate_response(
                200, "❌ Detected a re-send or edited message, exiting"
            )

        # Handle request
        handle_message_event(client, body, say, bedrock_client, app, token)

    # Respond to file share events
    @app.event("message")
    def handle_message_events(client, body, say, req, payload):
        # Check for duplicate event or trash messages, return 200 and exit if detected
        if check_for_duplicate_event(req.headers, payload):
            return generate_response(
                200, "❌ Detected a re-send or edited message, exiting"
            )

        # Handle request
        handle_message_event(client, body, say, bedrock_client, app, token)

    # Start the app in websocket mode for local development
    # Will require a separate terminal to run ngrok, e.g.: ngrok http http://localhost:3000
    print("🚀 Starting the app")
    app.start(
        port=int(os.environ.get("PORT", 3000)),
    )
