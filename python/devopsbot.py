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
import json
import requests
import re
from datetime import datetime, timezone

# Bedrock / AWS
import boto3

# Slack app imports
from slack_bolt import App

# Required for socket mode, used in local development
from slack_bolt.adapter.aws_lambda import SlackRequestHandler


###
# Fetch current date and time
###

# Current date and time, fetched at launch
current_utc = datetime.now(timezone.utc)
current_utc_string = current_utc.strftime("%Y-%m-%d %H:%M:%S %Z")


###
# Constants
###

# Bot info
bot_name = "Vera"

# Slack
slack_buffer_token_size = 10 # Number of tokens to buffer before updating Slack
slack_message_size_limit_words = 350 # Slack limit of characters in response is 4k. That's ~420 words. 350 words is a safe undershot of words that'll fit in a slack response. Used in the system prompt for Vera. 

# Specify model ID and temperature
model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0" # US regional Claude 3.7 Sonnet model
anthropic_version = "bedrock-2023-05-31"
temperature = 0.2
top_k = 25

# Secrets manager secret name. Json payload should contain SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET
bot_secret_name = "DEVOPSBOT_SECRETS_JSON"

# Bedrock guardrail information
enable_guardrails = False # Won't use guardrails if False
guardrailIdentifier = "xxxxxxxxxx"
guardrailVersion = "DRAFT"
guardrailTracing = "enabled" # [enabled, enabled_full, disabled]

# Specify the AWS region for the AI model
model_region_name = "us-west-2"

# Initial context step
enable_initial_model_context_step = False
initial_model_user_status_message = "Adding additional context :waiting:"
initial_model_system_prompt = f"""
    Assistant should...
"""

# Knowledge bases
enabled_knowledge_bases = [
    "confluence",
]

# Knowledge base context
knowledge_base_info = {
    "confluence": {
        "id": "xxxxxxxxxx",  # kyler-test-confluence
        "number_of_results": 50,
        "rerank_number_of_results": 5,
    },
}

# Rerank configuration
enable_rerank = True
rerank_model_id = "amazon.rerank-v1:0"

# Model guidance, shimmed into each conversation as instructions for the model
system_prompt = f"""Assistant is a large language model named {bot_name} who is trained to support our employees in providing the best possible experience for their developers and operations team. 
    Assistant must follow Slack's best practices for formatting messages.
    Assistant must encode all hyperlinks with pipe syntax. For example, "https://www.google.com" should be formatted as "<https://www.google.com|Google>".
    Assistant must limit messages to {slack_message_size_limit_words} words, including code blocks. For longer responses Assistant should provide the first part of the response, and then prompt User to ask for the next part of the response. 
    Assistant should address the user by name, and shouldn't echo user's pronouns. 
    When Assistant finishes responding entirely, Assistant should suggest questions the User can ask. 
    Assistant should always provide a Confluence citation link when providing information from the knowledge base.
    When providing Splunk query advice, Assistant must recommend queries that use the fewest resources. 
    The current date and time is {current_utc_string} UTC.
    """


###
# Functions
###

# Update slack response - handle initial post and streaming response
def update_slack_response(say, client, message_ts, channel_id, thread_ts, message_text):
    
    # If message_ts is None, we're posting a new message
    if message_ts is None:
        slack_response = say(
            text=message_text,
            thread_ts=thread_ts,
        )
        # Set message_ts
        message_ts = slack_response['ts']
    else:
        # We're updating an existing message
        client.chat_update(
            text=message_text,
            channel=channel_id,
            ts=message_ts,
        )
    
    # Return the message_ts
    return message_ts


# Reranking knowledge base results
def rerank_text(flat_conversation, kb_responses, bedrock_client, kb_rerank_number_of_results):
    
    # Data looks like this: 
    # [
    #     {
    #         "text": "text",
    #         "source": "url",
    #     },
    #     {
    #         "text": "text",
    #         "source": "url",
    #     }
    # ]
    
    # Format kb_responses into a list of sources
    kb_responses_text = []
    for kb_response in kb_responses:
        kb_responses_text.append(
            [
                kb_response['text']
            ]
        )
        
    # Flatten
    kb_responses_text = [item[0] for item in kb_responses_text]

    # Construct body
    body = json.dumps(
        {
            "query": flat_conversation,
            "documents": kb_responses_text,
            "top_n": kb_rerank_number_of_results,
        }
    )
    
    # Fetch ranks
    rank_response = bedrock_client.invoke_model(
        modelId=rerank_model_id,
        accept="application/json",
        contentType="application/json",
        body=body,
    )
    
    # Decode response
    rank_response_body = json.loads(
        rank_response['body'].read().decode()
    )
    
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Rerank response body:", rank_response_body)
    
    # Response looks like this: 
    # [
    #     {
    #         "index": 9,
    #         "relevance_score": 0.9438672242987702
    #     },
    #     {
    #         "index": 0,
    #         "relevance_score": 0.9343951625409306
    #     }
    # ]

    # Iterate through the rank response and reorder the kb_responses and add relevance_score
    # We're also filtering just for the most relevant results according to rerank_number_of_results
    ranked_kb_responses = [
        {
            # Use the index value in rank_response to find the correct kb_response
            "text": kb_responses[rank_response['index']]["text"],
            "source": kb_responses[rank_response['index']]["source"],
            "relevance_score": rank_response['relevance_score']
        } for rank_response in rank_response_body['results']
    ]
    
    return ranked_kb_responses


# Function to retrieve info from RAG with knowledge base
def ask_bedrock_llm_with_knowledge_base(flat_conversation, knowledge_base_id, bedrock_client, kb_number_of_results, kb_rerank_number_of_results, say, client, channel_id, thread_ts) -> str:
    
    # Create a Bedrock agent runtime client
    bedrock_agent_runtime_client = boto3.client(
        "bedrock-agent-runtime", 
        region_name=model_region_name
    )
    
    # Uses model to retrieve related vectors from knowledge base
    try:
        kb_response = bedrock_agent_runtime_client.retrieve(
            retrievalQuery={
            'text': flat_conversation
            },
            knowledgeBaseId=knowledge_base_id,
            retrievalConfiguration={
                'vectorSearchConfiguration': {
                    'numberOfResults': kb_number_of_results,
                }
            },
        )
    # Catch exception around Aurora waking up
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to knowledge base: {error}")
        
        # Raise error
        raise error

    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Raw knowledge base responses:", kb_response)

    # Structure response
    kb_responses = [
        {
            "text": result['content']['text'],
            #"source": result['location'].get('confluenceLocation', {}).get('url', 's3')
            # If confluence, it'll be location.confluenceLocation.url, if S3 it'll be location.s3Location.uri
            "source": result['location'].get('confluenceLocation', {}).get('url', result['location'].get('s3Location', {}).get('uri', 'unknown')),
        } for result in kb_response['retrievalResults']
    ]
    
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Structured knowledge base responses:", kb_responses)
    
    if enable_rerank:
        # Rerank the knowledge base results
        kb_responses = rerank_text(
            flat_conversation,
            kb_responses,
            bedrock_client,
            kb_rerank_number_of_results,
        )
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Knowledge reranked response:", kb_responses)

    return kb_responses


# Get GitHubPAT secret from AWS Secrets Manager that we'll use to start the githubcop workflow
def get_secret_with_client(secret_name, region_name):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except requests.exceptions.RequestException as e:
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


# Get the secret using the SSM lambda layer
def get_secret_ssm_layer(secret_name):
    secrets_extension_endpoint = "http://localhost:2773/secretsmanager/get?secretId=" + secret_name
  
    # Create headers
    headers = {"X-Aws-Parameters-Secrets-Token": os.environ.get('AWS_SESSION_TOKEN')}
    
    # Fetch secret
    try:
        secret = requests.get(secrets_extension_endpoint, headers=headers)
    except requests.exceptions.RequestException as e:
        print("Had an error attempting to get secret from AWS Secrets Manager:", e)
        raise e
  
    # Print happy joy joy
    print("🚀 Successfully got secret", secret_name, "from AWS Secrets Manager")
  
    # Decode secret string
    secret = json.loads(secret.text)["SecretString"] # load the Secrets Manager response into a Python dictionary, access the secret
    
    # Return the secret
    return secret


# Create a Bedrock client
def create_bedrock_client(region_name):
    return boto3.client("bedrock-runtime", region_name=region_name)


# Initializes the slack app with the bot token and socket mode handler
def register_slack_app(token, signing_secret):
    app = App(
        process_before_response=True,  # Required for AWS Lambda
        token=token,
        signing_secret=signing_secret,
    )
    
    # Find the bot name
    bot_info = requests.get(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    bot_info_json = bot_info.json()    
    
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Bot info:", bot_info_json)
    
    if bot_info_json.get("ok"):
        bot_name = bot_info_json.get("user")
        registered_bot_id = bot_info_json.get("bot_id")
        slack_team = bot_info_json.get("team")
        print(f"🚀 Successfully registered as bot, can be tagged with @{bot_name} ({registered_bot_id}) from slack @{slack_team}")
    else:
        print("Failed to retrieve bot name:", bot_info_json.get("error"))
        # Exit with error
        raise Exception("Failed to retrieve bot name:", bot_info_json.get("error"))
    
    # Return the app
    return app, registered_bot_id


# Receives the streaming response and updates the slack message, chunk by chunk
def streaming_response_on_slack(client, streaming_response, initial_response, channel_id, thread_ts):
    
    # Counter and buffer vars for streaming response
    response = ""
    token_counter = 0
    buffer = ""
    full_event_payload = []

    guardrail_type = None
    guardrail_confidence = None
    guardrail_filter_strength = None
    guardrail_action = None

    for chunk in streaming_response['stream']:
        full_event_payload.append(chunk)  # accumulate full payload

        # Handle streamed text for Slack updates
        if "contentBlockDelta" in chunk:
            text = chunk["contentBlockDelta"]["delta"]["text"]
            response += text
            buffer += text
            token_counter += 1

            if token_counter >= slack_buffer_token_size:
                client.chat_update(
                    text=response,
                    channel=channel_id,
                    ts=initial_response
                )
                token_counter = 0
                buffer = ""

    # Final Slack update
    if buffer:
        # Check for blocked message
        if "input has been blocked by Veradigm's content filter" in response:
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 Full event payload:", full_event_payload)

            for event in full_event_payload:
                if "metadata" in event and "trace" in event["metadata"]:
                    trace = event["metadata"]["trace"]
                    guardrail = trace.get("guardrail", {})
                    input_assessment = guardrail.get("inputAssessment", {})

                    if guardrailIdentifier in input_assessment:
                        assessment = input_assessment[guardrailIdentifier]
                        filters = assessment.get("contentPolicy", {}).get("filters", [])
                        if filters:
                            first_filter = filters[0]
                            guardrail_type = first_filter.get("type")
                            guardrail_confidence = first_filter.get("confidence")
                            guardrail_filter_strength = first_filter.get("filterStrength")
                            guardrail_action = first_filter.get("action")
                            break

            # Enrich Slack message with guardrail info
            if guardrail_action == "BLOCKED":
                blocked_text = response
                response = (
                    f"🛑 *Our security guardrail blocked this conversation*\n"
                    f"> {blocked_text}\n\n"
                    f"• *Guardrail blocked type:* {guardrail_type}\n"
                    f"• *Strength our guardrail config is set to:* {guardrail_filter_strength}\n"
                    f"• *Confidence this conversation breaks the rules:* {guardrail_confidence}\n\n"
                    f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
                )

        print(f"🚀 Final update to Slack with: {response}")
        client.chat_update(
            text=response,
            channel=channel_id,
            ts=initial_response
        )
    

# Handle ai request input and response
def ai_request(bedrock_client, messages, say, thread_ts, client, message_ts, channel_id, request_streaming_response=True, system_prompt=system_prompt):
        
    # Format model system prompt for the request
    system = [
        {
            "text": system_prompt
        }
    ]
    
    # Base inference parameters to use.
    inference_config = {
        "temperature": temperature,
    }
    
    # Additional inference parameters to use.
    additional_model_fields = {
        "top_k": top_k
    }
    
    # Build converse body. If guardrails is enabled, add those keys to the body
    if enable_guardrails:
           converse_body = {
                "modelId": model_id,
                "guardrailConfig": {
                    "guardrailIdentifier": guardrailIdentifier,
                    "guardrailVersion": guardrailVersion,
                    "trace": guardrailTracing,
                },
                "messages": messages,
                "system": system,
                "inferenceConfig": inference_config,
                "additionalModelRequestFields": additional_model_fields,
            }
    else:
        converse_body = {
            "modelId": model_id,
            "messages": messages,
            "system": system,
            "inferenceConfig": inference_config,
            "additionalModelRequestFields": additional_model_fields,
        }
        
    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 converse_body:", converse_body)
    
    # Try to make the request to the AI model
    # Catch any exceptions and return an error message
    try:
        
        # If streaming response requested
        if request_streaming_response:
            streaming_response_event = bedrock_client.converse_stream(**converse_body)
            
            # Stream response back on slack
            streaming_response_on_slack(client, streaming_response_event, message_ts, channel_id, thread_ts)
        
        # If streaming response not requested
        else:
            # Request entire body response
            response_raw = bedrock_client.converse(**converse_body)
              
            # Extract response
            response = response_raw['output']['message']['content'][0]['text']

            # Return response to caller, don't post to slack
            return response
    
    # Any errors should return a message to the user
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to Bedrock: {error}")

        # Return error as response
        message_ts = update_slack_response(
            say, client, message_ts, channel_id, thread_ts, 
            f"😔 Error with request: " + str(error),
        )


# Check for duplicate events
def check_for_duplicate_event(headers, payload):

    # Debug
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Headers:", headers)
        print("🚀 Payload:", payload)

    # Checking for webhook when we edit our own message, which happens all the time with streaming tokens
    if payload.get("event", {}).get("subtype") == "message_changed":
        print("Detected a message changed event, discarding")
        logging.info("Detected a message changed event, discarding")
        return True
    
    # Check headers, if x-slack-retry-num is present, this is a re-send
    # Really we should be doing async lambda model, but for now detecting resends and exiting
    if "x-slack-retry-num" in headers:
        print("Detected a Slack re-try, exiting")
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

    # Debug 
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Conversation content payload:", payload)
    
    # Initialize the content array
    content = []
    
    # Initialize pronouns as blank
    pronouns = ""
    
    # Initialize bot_id as blank
    bot_id = ""

    # Check if message is from a bot 
    if "bot_id" in payload:
        # User is a bot
        try:
            # Try to find the username of the bot
            speaker_name = payload["username"]
            bot_id = payload["bot_id"]
        except:
            # If no username, use bot_profile name
            speaker_name = payload["bot_profile"]["name"]
            bot_id = payload["bot_id"]
    
    # User is a real human
    else:
        # Identify the user's ID
        user_id = payload["user"]

        # Find the user's information
        user_info = requests.get(
            f"https://slack.com/api/users.info?user={user_id}",
            headers={"Authorization": "Bearer " + token},
        )
        
        # Encode as json
        user_info_json = user_info.json()
        
        # Debug 
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Conversation content user info:", user_info_json)
    
        # Identify the user's real name
        user_real_name = user_info_json["user"]["real_name"]
        speaker_name = user_real_name
        
        # Find the user's pronouns if they're set in slack
        try:
            # If user has pronouns, set to pronouns with round brackets with a space before, like " (they/them)"
            pronouns = f" ({user_info_json["user"]["profile"]["pronouns"]})"
        except:
            # If no pronouns, use the initialized pronouns (blank)
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 User has no pronouns, using default of:", pronouns)

    # If text is not empty, and text length is greater than 0, append to content array
    if "text" in payload and len(payload["text"]) > 1:
        # If debug variable is set to true, print the text found in the payload
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 Text found in payload: " + payload["text"])

        content.append(
            {
                # Combine the user's name with the text to help the model understand who is speaking
                "text": f"{speaker_name}{pronouns} says: {payload['text']}",
            }
        )
    
    if "attachments" in payload:
        # Append the attachment text to the content array
        for attachment in payload["attachments"]:
            
            # If debug variable is set to true, print the text found in the attachments
            if os.environ.get("VERA_DEBUG", "False") == "True" and "text" in attachment:
                print("🚀 Text found in attachment: " + attachment["text"])
                                                                           
            # Check if the attachment contains text
            if "text" in attachment:
                # Append the attachment text to the content array
                content.append(
                    {
                        # Combine the user's name with the text to help the model understand who is speaking
                        "text": f"{speaker_name}{pronouns} says: " + attachment["text"],
                    }
                )

    # If the payload contains files, iterate through them
    if "files" in payload:

        # Append the payload files to the content array
        for file in payload["files"]:

            # Debug
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 File found in payload:", file)
                
            # Isolate name of the file and remove characters before the final period
            file_name = file["name"].split(".")[0]
            
            # File is a supported type
            file_url = file["url_private_download"]

            # Fetch the file and continue
            file_object = requests.get(
                file_url, headers={"Authorization": "Bearer " + token}
            )

            # Decode object into binary file
            file_content = file_object.content
            
            # Check the mime type of the file is a supported image file type
            if file["mimetype"] in [
                "image/png", # png
                "image/jpeg", # jpeg
                "image/gif", # gif
                "image/webp", # webp
            ]:
                
                # Isolate the file type based on the mimetype
                file_type = file["mimetype"].split("/")[1]

                # Append the file to the content array
                content.append(
                    {
                        "image": {
                            "format": file_type,
                            "source": {
                                "bytes": file_content,
                            }
                        }
                    }
                )

            # Check if file is a supported document type
            elif file["mimetype"] in [
                "application/pdf",
                "application/csv",
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/vnd.ms-excel",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "text/html",
                "text/markdown",
            ]:
                
                # Isolate the file type based on the mimetype
                if file["mimetype"] in ["application/pdf"]:
                    file_type = "pdf"
                elif file["mimetype"] in ["application/csv"]:
                    file_type = "csv"
                elif file["mimetype"] in ["application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]:
                    file_type = "docx"
                elif file["mimetype"] in ["application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]:
                    file_type = "xlsx"
                elif file["mimetype"] in ["text/html"]:
                    file_type = "html"
                elif file["mimetype"] in ["text/markdown"]:
                    file_type = "markdown"

                # Append the file to the content array
                content.append(
                    {
                        "document": {
                            "format": file_type,
                            "name": file_name,
                            "source": {
                                "bytes": file_content,
                            }
                        }
                    }
                )
                
                # Append the required text to the content array
                content.append(
                    {
                        "text": "file",
                    }
                )
            
            # Support plaintext snippets
            elif file["mimetype"] in ["text/plain"]:
                # File is a supported type
                snippet_file_url = file["url_private_download"]

                # Fetch the file and continue
                snippet_file_object = requests.get(
                    snippet_file_url, headers={"Authorization": "Bearer " + token}
                )
                
                # Decode the file into plaintext
                snippet_text = snippet_file_object.content.decode("utf-8")

                # Append the file to the content array
                content.append(
                    {
                        "text": f"{speaker_name} {pronouns} attached a snippet of text:\n\n{snippet_text}",
                    }
                )
            
            # If the mime type is not supported, set unsupported_file_type_found to True
            else:
                print(f"Unsupported file type found: {file['mimetype']}")
                unsupported_file_type_found = True
                continue

    # Return
    return bot_id, content, unsupported_file_type_found


# Common function to handle both DMs and app mentions
def handle_message_event(client, body, say, bedrock_client, app, token, registered_bot_id):

    # Initialize message_ts as None
    # This is used to track the slack message timestamp for updating the message
    message_ts = None
    
    channel_id = body["event"]["channel"]
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
            bot_id_from_message, thread_conversation_content, unsupported_file_type_found = (
                build_conversation_content(message, token)
            )

            if os.environ.get("VERA_DEBUG", "False") == "True":
                print("🚀 Thread conversation content:", thread_conversation_content)

            # Check if the thread conversation content is empty. This happens when a user sends an unsupported doc type only, with no message
            if thread_conversation_content != []:
                # Conversation content is not empty, append to conversation

                # Check if message came from our bot
                # We're assuming our bot only generates text content, which is true of Claude v3.5 Sonnet v2
                if bot_id_from_message == registered_bot_id:
                    conversation.append(
                        {
                            "role": "assistant",
                            "content": [
                                {
                                    "text": message["text"],
                                }
                            ],
                        }
                    )
                # If not, the message came from a user
                else:
                    conversation.append(
                        {
                            "role": "user",
                            "content": thread_conversation_content
                        }
                    )

                    if os.environ.get("VERA_DEBUG", "False") == "True":
                        print(
                            "🚀 State of conversation after threaded message append:",
                            conversation,
                        )
    
    else:
        # We're not in a thread, so we just need to add the user's message to the conversation

        # Build the user's part of the conversation
        bot_id_from_message, user_conversation_content, unsupported_file_type_found = build_conversation_content(
            event, token
        )
        
        # Append to the conversation
        conversation.append(
            {
                "role": "user",
                "content": user_conversation_content,
            }
        )

        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 State of conversation after append user's prompt:", conversation)

    # Check if conversation content is empty, this happens when a user sends an unsupported doc type only, with no message
    # Conversation looks like this: [{'role': 'user', 'text': []}]
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
    
    # Before we fetch the knowledge base, do an initial turn with the AI to add context
    if enable_initial_model_context_step:
        message_ts = update_slack_response(
            say, client, message_ts, channel_id, thread_ts, 
            initial_model_user_status_message,
        )
        
        # Ask the AI for a response
        ai_response = ai_request(bedrock_client, conversation, say, thread_ts, client, message_ts, channel_id, False, initial_model_system_prompt)
        
        # Append to conversation
        conversation.append(
            {
                "role": "assistant",
                "content": [
                    {
                        "text": f"Initialization information from the model: {ai_response}",
                    }
                ],
            }
        )
        
        # Debug
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 State of conversation after context request:", conversation)
        
    # If any knowledge bases enabled, fetch citations
    if enabled_knowledge_bases and len(enabled_knowledge_bases) > 0:

        print("🚀 Knowledge base enabled, fetching citations")
        
        if os.environ.get("VERA_DEBUG", "False") == "True":
            print("🚀 State of conversation before AI request:", conversation)
        
        # Flatten the conversation
        flat_conversation = []
        for item in conversation:
            for content in item['content']:
                if 'text' in content:
                    flat_conversation.append(content['text'])
        flat_conversation = '\n'.join(flat_conversation)
        
        # On each conversation line, remove all text before the first colon. It appears the names and pronouns really throw off our context quality
        flat_conversation = re.sub(r".*: ", "", flat_conversation)
        
        for kb_name in enabled_knowledge_bases:
            
            # Respond to the user that we're fetching citations
            message_ts = update_slack_response(
                say, client, message_ts, channel_id, thread_ts, 
                f"Checking knowledge base {kb_name} and ranking results :waiting:",
            )
            
            # Lookup KB info
            kb_id = knowledge_base_info[kb_name]['id']
            kb_number_of_results = knowledge_base_info[kb_name]['number_of_results']
            kb_rerank_number_of_results = knowledge_base_info[kb_name]['rerank_number_of_results']
            
            # Get context data from the knowledge base
            try: 
                knowledge_base_response = ask_bedrock_llm_with_knowledge_base(flat_conversation, kb_id, bedrock_client, kb_number_of_results, kb_rerank_number_of_results, say, client, channel_id, thread_ts) 
            except Exception as error:
                # If the request fails, print the error
                print(f"🚀 Error making request to knowledge base {kb_name}: {error}")
                
                # Split the error message at a colon, grab everything after the third colon
                error = str(error).split(":", 2)[-1].strip()

                # If the error contains "resuming after being auto-paused", ask user to try again later
                if "resuming after being auto-paused" in error:
                    message_ts = update_slack_response(
                        say, client, message_ts, channel_id, thread_ts, 
                        f"😴 This is the first request to {bot_name} in a while, and it needs to wake up. \n\n:pray: Please tag this bot again in a few minutes."
                    )
                else:
                    # Return error as response
                    message_ts = update_slack_response(
                        say, client, message_ts, channel_id, thread_ts, 
                        f"😔 Error fetching from knowledge base: " + str(error),
                    )
                # Raise error
                raise error
            
            if os.environ.get("VERA_DEBUG", "False") == "True":
                print(f"🚀 Knowledge base response: {knowledge_base_response}")
            
            # Iterate through responses
            for result in knowledge_base_response:
                citation_result = result['text']
                citation_source = result['source']
                
                # If reranking enabled, use that information
                if enable_rerank:
                    
                    # Find the relevance score
                    relevance_score = result['relevance_score']
                    
                    # Append to conversation
                    conversation.append(
                        {
                            "role": "assistant",
                            "content": [
                                {
                                    "text": f"Knowledge base citation to supplement your answer: {citation_result} from source {citation_source}. Reranker scored this result relevancy at {relevance_score}",
                                }
                            ],
                        }
                    )
                
                # If reranking not enabled, just use the citation information, no score is available
                else:
                    
                    # Append to conversation
                    conversation.append(
                        {
                            "role": "assistant",
                            "content": [
                                {
                                    "text": f"Knowledge base citation to supplement your answer: {citation_result} from source {citation_source}",
                                }
                            ],
                        }
                    )

    # Update the initial response
    message_ts = update_slack_response(
        say, client, message_ts, channel_id, thread_ts, 
        f"Chatting with the AI :waiting:",
    )
    
    # Call the AI model with the conversation
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 State of conversation before AI request:", conversation)
    
    # Make the AI request
    ai_request(bedrock_client, conversation, say, thread_ts, client, message_ts, channel_id, True)
    
    # Print success
    print("🚀 Successfully responded to message, exiting")


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
    
    # Print the event
    print("🚀 Event:", event)

    # Debug 
    if os.environ.get("VERA_DEBUG", "False") == "True":
        print("🚀 Event body:", event_body)

    # Fetch secret package
    secrets = get_secret_ssm_layer(bot_secret_name)

    # Disambiguate the secrets with json lookups
    secrets_json = json.loads(secrets)
    token = secrets_json["SLACK_BOT_TOKEN"]
    signing_secret = secrets_json["SLACK_SIGNING_SECRET"]

    # Register the Slack handler
    print("🚀 Registering the Slack handler")
    app, registered_bot_id = register_slack_app(token, signing_secret)

    # Register the AWS Bedrock AI client
    print("🚀 Registering the AWS Bedrock client")
    bedrock_client = create_bedrock_client(model_region_name)

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say):
        print("🚀 Handling app mention event")
        handle_message_event(client, event_body, say, bedrock_client, app, token, registered_bot_id)

    # Respond to file share events
    @app.event("message")
    def handle_message_events(client, body, say, req):
        print("🚀 Handling message event")
        handle_message_event(client, event_body, say, bedrock_client, app, token, registered_bot_id)

    # Initialize the handler
    print("🚀 Initializing the handler")
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)


# Main function, primarily for local development
if __name__ == "__main__":
    # Run in local development mode
    print("🚀 Local server starting starting")

    # Fetch secret package
    secrets = get_secret_with_client(bot_secret_name, "us-east-1")

    # Disambiguate the secrets with json lookups
    secrets_json = json.loads(secrets)
    token = secrets_json["SLACK_BOT_TOKEN"]
    signing_secret = secrets_json["SLACK_SIGNING_SECRET"]

    # Register the Slack handler
    print("🚀 Registering the Slack handler")
    app, registered_bot_id = register_slack_app(token, signing_secret)

    # Register the AWS Bedrock AI client
    print("🚀 Registering the AWS Bedrock client")
    bedrock_client = create_bedrock_client(model_region_name)

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say, req, payload):
        # Check for duplicate events in local development
        if check_for_duplicate_event(req.headers, body):
            return
        # Handle request
        handle_message_event(client, body, say, bedrock_client, app, token, registered_bot_id)

    # Respond to file share events
    @app.event("message")
    def handle_message_events(client, body, say, req, payload):
        # Check for duplicate events in local development
        if check_for_duplicate_event(req.headers, body):
            return
        # Handle request
        handle_message_event(client, body, say, bedrock_client, app, token, registered_bot_id)

    # Start the app in websocket mode for local development
    print("🚀 Starting the slack app listener")
    app.start(
        port=int(os.environ.get("PORT", 3000)),
    )
