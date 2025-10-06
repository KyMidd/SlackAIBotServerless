# This is the full worker.py file, which is the main file for the Serverless Slack Bot.
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
bot_name = os.environ.get("BOT_NAME")

# Slack
slack_buffer_token_size = 10  # Number of tokens to buffer before updating Slack
slack_message_size_limit_words = 350  # Slack limit of characters in response is 4k. That's ~420 words. 350 words is a safe undershot of words that'll fit in a slack response. Used in the system prompt for the bot.

# Specify model ID and temperature
model_id = os.environ.get("MODEL_NAME")
temperature = 0.2
top_k = 25

# Debug
debug_enabled = os.environ.get("DEBUG_ENABLED", "True") == "True"

# Bedrock guardrail information
# Guardrails must be in the same region as the model
enable_guardrails = False  # Won't use guardrails if False
guardrailIdentifier = "xxxxxxxxxx"
guardrailVersion = "DRAFT"
guardrailTracing = "enabled"  # [enabled, enabled_full, disabled]

# Specify the AWS region for the AI model
model_region_name = "us-west-2"

# Initial context step
# This fetches an AI response to the compiled conversation and appends it to the conversation
# Before sending the conversation to the knowledge base.
# This can help seed keywords or context for the knowledge base retrieval.
enable_initial_model_context_step = False
initial_model_user_status_message = "Adding additional context :turtle:"
initial_model_system_prompt = f"""
    Assistant should...
"""

# Knowledge bases
enabled_knowledge_bases = [
    # "confluence", # All knowledge bases disabled by default
]

# Knowledge base context
knowledge_base_info = {
    # "confluence": {
    #     "id": "xxxxxxxxxx",
    #     "number_of_results": 50, # Number of results to fetch from the knowledge base
    #     "rerank_number_of_results": 5, # Number of results to return after reranking
    # },
}

# Rerank configuration
enable_rerank = True
rerank_model_id = "amazon.rerank-v1:0"

# Model guidance, shimmed into each conversation as instructions for the model
system_prompt = f"""Assistant is a large language model named {bot_name} who is trained to support our employees in providing the best possible experience for their developers and operations team. 
    Assistant must follow Slack's best practices for formatting messages.
    Assistant must encode all hyperlinks with pipe syntax. For example, "https://www.google.com" should be formatted as "<https://www.google.com|Google>".
    Assistant must use single asterisks for bold text, never double asterisks. 
    Assistant must limit messages to {slack_message_size_limit_words} words, including code blocks. For longer responses Assistant should provide the first part of the response, and then prompt User to ask for the next part of the response. 
    Assistant should address the user by name, and shouldn't echo user's pronouns. 
    When Assistant finishes responding entirely, Assistant should suggest questions the User can ask. 
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
        message_ts = slack_response["ts"]
    else:
        # We're updating an existing message
        slack_response = client.chat_update(
            text=message_text,
            channel=channel_id,
            ts=message_ts,
        )

        # Debug
        if debug_enabled:
            print("🚀 Slack chat update response:", slack_response)

    # Check to see if the response was successful
    # Sucessful response: {'ok': True, 'channel': 'D088U5DEXGW', 'ts': '1748898172.661379', 'text': "Hi Kyler! :wa
    if not slack_response.get("ok"):
        # If the request fails, print the error
        print(f"🚀 Error updating Slack message: {slack_response.get('error')}")

        # Message the user that there was an error
        say(
            text=f"🚨 There was an error updating your message: {slack_response.get('error')}\n\nPlease ask your question again",
            thread_ts=thread_ts,
        )

    # Return the message_ts
    return message_ts


# Reranking knowledge base results
def rerank_text(
    flat_conversation, kb_responses, bedrock_client, kb_rerank_number_of_results
):

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
        kb_responses_text.append([kb_response["text"]])

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
    rank_response_body = json.loads(rank_response["body"].read().decode())

    # Debug
    if debug_enabled:
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
            "text": kb_responses[rank_response["index"]]["text"],
            "source": kb_responses[rank_response["index"]]["source"],
            "relevance_score": rank_response["relevance_score"],
        }
        for rank_response in rank_response_body["results"]
    ]

    return ranked_kb_responses


# Function to retrieve info from RAG with knowledge base
def ask_bedrock_llm_with_knowledge_base(
    flat_conversation,
    knowledge_base_id,
    bedrock_client,
    kb_number_of_results,
    kb_rerank_number_of_results,
    say,
    client,
    channel_id,
    thread_ts,
) -> str:

    # Create a Bedrock agent runtime client
    bedrock_agent_runtime_client = boto3.client(
        "bedrock-agent-runtime", region_name=model_region_name
    )

    # Uses model to retrieve related vectors from knowledge base
    try:
        kb_response = bedrock_agent_runtime_client.retrieve(
            retrievalQuery={"text": flat_conversation},
            knowledgeBaseId=knowledge_base_id,
            retrievalConfiguration={
                "vectorSearchConfiguration": {
                    "numberOfResults": kb_number_of_results,
                }
            },
        )
    # Catch exception around Aurora waking up
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to knowledge base: {error}")

        # Raise error
        raise error

    if debug_enabled:
        print("🚀 Raw knowledge base responses:", kb_response)

    # Structure response
    kb_responses = [
        {
            "text": result["content"]["text"],
            # Check multiple metadata fields for SharePoint URLs, with fallback chain
            "source": (
                result.get("metadata", {}).get("canonical_url")
                or result["location"].get("confluenceLocation", {}).get("url")
                or result["location"].get("s3Location", {}).get("uri")
                or "unknown"
            ),
        }
        for result in kb_response["retrievalResults"]
    ]

    if debug_enabled:
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
        if debug_enabled:
            print("🚀 Knowledge reranked response:", kb_responses)

    return kb_responses


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
        "https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {token}"}
    )

    bot_info_json = bot_info.json()

    if debug_enabled:
        print("🚀 Bot info:", bot_info_json)

    if bot_info_json.get("ok"):
        bot_name = bot_info_json.get("user")
        registered_bot_id = bot_info_json.get("bot_id")
        slack_team = bot_info_json.get("team")
        print(
            f"🚀 Successfully registered as bot, can be tagged with @{bot_name} ({registered_bot_id}) from slack @{slack_team}"
        )
    else:
        print("Failed to retrieve bot name:", bot_info_json.get("error"))
        # Exit with error
        raise Exception("Failed to retrieve bot name:", bot_info_json.get("error"))

    # Return the app
    return app, registered_bot_id


# Enrich response with guardrail trace information
def enrich_guardrail_block(response, full_event_payload):
    if debug_enabled:
        print("🚀 Full event payload:", full_event_payload)

    # Check if the trace.guardrail.inputAssessment.4raioni9cwpe.contentPolicy.filters[0] path exists
    for event in full_event_payload:
        try:
            # If we're blocked by conent policy, this will be present
            try:
                # Try input assessment
                guardrail_trace = event["metadata"]["trace"]["guardrail"][
                    "inputAssessment"
                ][guardrailIdentifier]["contentPolicy"]["filters"][0]
            except:
                # Try output assessment
                guardrail_trace = event["metadata"]["trace"]["guardrail"][
                    "outputAssessment"
                ][guardrailIdentifier]["contentPolicy"]["filters"][0]

            # Set vars to values
            guardrail_type = guardrail_trace.get("type")
            guardrail_confidence = guardrail_trace.get("confidence")
            guardrail_filter_strength = guardrail_trace.get("filterStrength")

            # Enrich blocked message with guardrail trace info
            response = (
                f"🛑 *Our security guardrail blocked this conversation*\n"
                f"> {response}\n\n"
                f"• *Guardrail blocked type:* {guardrail_type}\n"
                f"• *Strength our guardrail config is set to:* {guardrail_filter_strength}\n"
                f"• *Confidence this conversation breaks the rules:* {guardrail_confidence}\n\n"
                f"*You can try rephrasing your question, or open a ticket with the Internal AI Team to investigate*\n"
                f"*For further assistance, visit <https://veradigm.enterprise.slack.com/archives/C06CDN7V3DJ|#team-internal-ai-solutions>*"
            )

            # Return response
            return response

        # If didn't find in this event, continue
        except:
            # If the request fails, print the error
            print(
                f"🚀 Didn't find guardrail content policy block in this event: {event}"
            )

        # Check the event to see if we're blocked by topic policy
        try:
            try:
                # Try input assessment
                guardrail_trace = event["metadata"]["trace"]["guardrail"][
                    "inputAssessment"
                ][guardrailIdentifier]["topicPolicy"]["topics"][0]
            except:
                # Try output assessment
                guardrail_trace = event["metadata"]["trace"]["guardrail"][
                    "outputAssessments"
                ][guardrailIdentifier][0]["topicPolicy"]["topics"][0]

            # Extract individual values
            guardrail_name = guardrail_trace["name"]  # 'healthcare_topic'

            # Enrich the response
            response = (
                f"🛑 *Our security guardrail blocked this conversation based on the topic*\n"
                f"> {response}\n"
                f"• *Guardrail block name:* {guardrail_name}\n"
                f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
            )

            # return response
            return response

        # If didn't find in this event, continue
        except:
            # If the request fails, print the error
            print(f"🚀 Didn't find guardrail topic block in this event: {event}")

    # Not configured to enrich the response with guardrail trace information, just send back response
    response = (
        f"🛑 *Our security guardrail blocked this conversation*\n\n"
        f"> {response}\n\n"
        f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
    )
    return response


# Receives the streaming response and updates the slack message, chunk by chunk
def streaming_response_on_slack(
    client, streaming_response, initial_response, channel_id, thread_ts
):

    # Counter and buffer vars for streaming response
    response = ""
    token_counter = 0
    buffer = ""
    full_event_payload = []

    guardrail_type = None
    guardrail_confidence = None
    guardrail_filter_strength = None
    guardrail_action = None

    for chunk in streaming_response["stream"]:
        full_event_payload.append(chunk)  # accumulate full payload

        # Handle streamed text for Slack updates
        if "contentBlockDelta" in chunk:
            text = chunk["contentBlockDelta"]["delta"]["text"]
            response += text
            buffer += text
            token_counter += 1

            if token_counter >= slack_buffer_token_size:
                client.chat_update(
                    text=response, channel=channel_id, ts=initial_response
                )
                token_counter = 0
                buffer = ""

    # Final Slack update
    if buffer:
        # Check for blocked message
        if "has been blocked by Veradigm's content filter" in response:

            # Enrich response with guardrail trace info
            response = enrich_guardrail_block(response, full_event_payload)

        print(f"🚀 Final update to Slack with: {response}")
        client.chat_update(text=response, channel=channel_id, ts=initial_response)


# Function to clean response text from model
def clean_response_text(response):

    # Response from text sometimes has text like this:
    """
    Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289 Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289Knowledge base citation to supplement your answer: > from source https://veradigm.atlassian.net/wiki/pages/viewpageattachments.action?pageId=61145404&preview=%2F61145404%2F71139455%2FTC_67-9e997e7a-0883-45cd-9c6e-9e117f5707b2.txt. Reranker scored this result relevancy at 0.0007466114612710289 Hi Kyler! :wave:
    """

    # Debug
    if debug_enabled:
        print("🚀 Raw response before cleaning:", response)

    # Find the last instance of "Reranker scored this result relevancy at 0...." and remove everything before it
    # This regex finds all occurrences of the reranker line
    matches = list(
        re.finditer(r"Reranker scored this result relevancy at \d+\.\d+", response)
    )

    # If no hallucination found, return the response as-is
    if not matches:
        return response

    # Get the last match's end position
    last_match_end = matches[-1].end()

    # Isolate everything after the last match
    response = response[last_match_end:].lstrip()

    # Strip any leading whitespace
    response = response.strip()

    # Debug
    if debug_enabled:
        print("🚀 Response after cleaning:", response)

    # Return everything after the last match
    return response


# Handle ai request input and response
def ai_request(
    bedrock_client,
    messages,
    say,
    thread_ts,
    client,
    message_ts,
    channel_id,
    request_streaming_response=True,
    system_prompt=system_prompt,
):

    # Format model system prompt for the request
    system = [{"text": system_prompt}]

    # Base inference parameters to use.
    inference_config = {
        "temperature": temperature,
    }

    # Additional inference parameters to use.
    additional_model_fields = {"top_k": top_k}

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
    if debug_enabled:
        print("🚀 converse_body:", converse_body)

    # Try to make the request to the AI model
    # Catch any exceptions and return an error message
    try:

        # If streaming response requested
        if request_streaming_response:
            streaming_response_event = bedrock_client.converse_stream(**converse_body)

            # Stream response back on slack
            streaming_response_on_slack(
                client, streaming_response_event, message_ts, channel_id, thread_ts
            )

        # If streaming response not requested
        else:
            # Request entire body response
            response_raw = bedrock_client.converse(**converse_body)

            # Check for empty response
            if not response_raw.get("output", {}).get("message", {}).get("content", []):
                # If the request fails, print the error
                print(f"🚀 Empty response from Bedrock: {response_raw}")

                # Format response
                response = (
                    f"🛑 *Vera didn't generate an answer to this questions.*\n\n"
                    f"• *This means Vera had an error.*\n"
                    f"*You can try rephrasing your question, or open a ticket with DevOps to investigate*"
                )

                # Return error as response
                return response

            # Debug raw response
            if debug_enabled:
                print("🚀 Raw response from Bedrock:", response_raw)

            # Extract response where converse() puts it
            try:
                response = response_raw["output"]["message"]["content"][0]["text"]
            except:
                # Thinking models include response on second item in array
                response = response_raw["output"]["message"]["content"][1]["text"]

            # Clean response
            response = clean_response_text(response)

            # Return response to caller, don't post to slack
            return response

    # Any errors should return a message to the user
    except Exception as error:
        # If the request fails, print the error
        print(f"🚀 Error making request to Bedrock: {error}")

        # Return error as response
        message_ts = update_slack_response(
            say,
            client,
            message_ts,
            channel_id,
            thread_ts,
            f"😔 Error with request: " + str(error),
        )


# Function to build the content of a conversation
def build_conversation_content(payload, token):

    # Initialize unsupported file type found canary var
    unsupported_file_type_found = False

    # Debug
    if debug_enabled:
        print("🚀 Conversation content payload:", payload)

    # Initialize the content array
    content = []

    # Initialize pronouns as blank
    pronouns = ""

    # Initialize bot_id as blank
    bot_id = ""

    # Identify user_id
    user_id = payload["user"]
    speaker_name = user_id  # Default speaker name if user info cannot be fetched

    # Fetch user information from Slack API
    user_info = requests.get(
        f"https://slack.com/api/users.info?user={user_id}",
        headers={"Authorization": "Bearer " + token},
    )
    user_info_json = user_info.json()

    # Debug
    if debug_enabled:
        print("🚀 Conversation content user info:", user_info_json)

    # Identify the speaker's name based on their profile data
    profile = user_info_json.get("user", {}).get("profile", {})
    display_name = profile.get("display_name")
    real_name = user_info_json.get("user", {}).get("real_name", "Unknown User")
    speaker_name = display_name or real_name

    # If bot, set pronouns as "Bot"
    if "bot_id" in user_info_json:
        pronouns = " (Bot)"
    else:
        # Pronouns
        try:
            # If user has pronouns, set to pronouns with round brackets with a space before, like " (they/them)"
            pronouns = f" ({profile['pronouns']})"
        except:
            # If no pronouns, use the initialized pronouns (blank)
            if debug_enabled:
                print("🚀 User has no pronouns, using blank pronouns")

    # If text is not empty, and text length is greater than 0, append to content array
    if "text" in payload and len(payload["text"]) > 1:
        # If debug variable is set to true, print the text found in the payload
        if debug_enabled:
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
            if debug_enabled and "text" in attachment:
                print("🚀 Text found in attachment: " + attachment["text"])

            # Check if the attachment contains text
            if "text" in attachment:
                # Append the attachment text to the content array
                content.append(
                    {
                        # Combine the user's name with the text to help the model understand who is speaking
                        "text": f"{speaker_name}{pronouns} says: "
                        + attachment["text"],
                    }
                )

    # If the payload contains files, iterate through them
    if "files" in payload:

        # Append the payload files to the content array
        for file in payload["files"]:

            # Debug
            if debug_enabled:
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
                "image/png",  # png
                "image/jpeg",  # jpeg
                "image/gif",  # gif
                "image/webp",  # webp
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
                            },
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
                elif file["mimetype"] in [
                    "application/msword",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ]:
                    file_type = "docx"
                elif file["mimetype"] in [
                    "application/vnd.ms-excel",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ]:
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
                            },
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
def handle_message_event(
    client, body, say, bedrock_client, app, token, registered_bot_id
):

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
            (
                bot_id_from_message,
                thread_conversation_content,
                unsupported_file_type_found,
            ) = build_conversation_content(message, token)

            if debug_enabled:
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
                        {"role": "user", "content": thread_conversation_content}
                    )

                    if debug_enabled:
                        print(
                            "🚀 State of conversation after threaded message append:",
                            conversation,
                        )

    else:
        # We're not in a thread, so we just need to add the user's message to the conversation

        # Build the user's part of the conversation
        bot_id_from_message, user_conversation_content, unsupported_file_type_found = (
            build_conversation_content(event, token)
        )

        # Append to the conversation
        conversation.append(
            {
                "role": "user",
                "content": user_conversation_content,
            }
        )

        if debug_enabled:
            print("🚀 State of conversation after append user's prompt:", conversation)

    # Check if conversation content is empty, this happens when a user sends an unsupported doc type only, with no message
    # Conversation looks like this: [{'role': 'user', 'text': []}]
    if debug_enabled:
        print("🚀 State of conversation before check if convo is empty:", conversation)
    if conversation == []:
        # Conversation is empty, append to error message
        if debug_enabled:
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
            say,
            client,
            message_ts,
            channel_id,
            thread_ts,
            initial_model_user_status_message,
        )

        # Ask the AI for a response
        ai_response = ai_request(
            bedrock_client,
            conversation,
            say,
            thread_ts,
            client,
            message_ts,
            channel_id,
            False,
            initial_model_system_prompt,
        )

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
        if debug_enabled:
            print("🚀 State of conversation after context request:", conversation)

    # If any knowledge bases enabled, fetch citations
    if enabled_knowledge_bases and len(enabled_knowledge_bases) > 0:

        print("🚀 Knowledge base enabled, fetching citations")

        if debug_enabled:
            print("🚀 State of conversation before AI request:", conversation)

        # Flatten the conversation
        flat_conversation = []
        for item in conversation:
            for content in item["content"]:
                if "text" in content:
                    flat_conversation.append(content["text"])
        flat_conversation = "\n".join(flat_conversation)

        # On each conversation line, remove all text before the first colon. It appears the names and pronouns really throw off our context quality
        flat_conversation = re.sub(r".*: ", "", flat_conversation)

        for kb_name in enabled_knowledge_bases:

            # Respond to the user that we're fetching citations
            message_ts = update_slack_response(
                say,
                client,
                message_ts,
                channel_id,
                thread_ts,
                f"Checking knowledge base {kb_name} and ranking results :turtle:",
            )

            # Lookup KB info
            kb_id = knowledge_base_info[kb_name]["id"]
            kb_number_of_results = knowledge_base_info[kb_name]["number_of_results"]
            kb_rerank_number_of_results = knowledge_base_info[kb_name][
                "rerank_number_of_results"
            ]

            # Get context data from the knowledge base
            try:
                knowledge_base_response = ask_bedrock_llm_with_knowledge_base(
                    flat_conversation,
                    kb_id,
                    bedrock_client,
                    kb_number_of_results,
                    kb_rerank_number_of_results,
                    say,
                    client,
                    channel_id,
                    thread_ts,
                )
            except Exception as error:
                # If the request fails, print the error
                print(f"🚀 Error making request to knowledge base {kb_name}: {error}")

                # Split the error message at a colon, grab everything after the third colon
                error = str(error).split(":", 2)[-1].strip()

                # If the error contains "resuming after being auto-paused", ask user to try again later
                if "resuming after being auto-paused" in error:
                    message_ts = update_slack_response(
                        say,
                        client,
                        message_ts,
                        channel_id,
                        thread_ts,
                        f"😴 This is the first request to {bot_name} in a while, and it needs to wake up. \n\n:pray: Please tag this bot again in a few minutes.",
                    )
                else:
                    # Return error as response
                    message_ts = update_slack_response(
                        say,
                        client,
                        message_ts,
                        channel_id,
                        thread_ts,
                        f"😔 Error fetching from knowledge base: " + str(error),
                    )
                # Raise error
                raise error

            if debug_enabled:
                print(f"🚀 Knowledge base response: {knowledge_base_response}")

            # Iterate through responses
            for result in knowledge_base_response:
                citation_result = result["text"]
                citation_source = result["source"]

                # If reranking enabled, use that information
                if enable_rerank:

                    # Find the relevance score
                    relevance_score = result["relevance_score"]

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
        say,
        client,
        message_ts,
        channel_id,
        thread_ts,
        f"Chatting with the AI :turtle:",
    )

    # Call the AI model with the conversation
    if debug_enabled:
        print("🚀 State of conversation before AI request:", conversation)

    # Make the AI request
    ai_response = ai_request(
        bedrock_client,
        conversation,
        say,
        thread_ts,
        client,
        message_ts,
        channel_id,
        False,
    )

    # Debug
    if debug_enabled:
        print("🚀 AI response:", ai_response)

    # Respond to user
    update_slack_response(say, client, message_ts, channel_id, thread_ts, ai_response)

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
    if debug_enabled:
        print("🚀 Event body:", event_body)

    # Slack secrets
    token = os.environ.get("SLACK_BOT_TOKEN")
    signing_secret = os.environ.get("SLACK_SIGNING_SECRET")

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
        handle_message_event(
            client, event_body, say, bedrock_client, app, token, registered_bot_id
        )

    # Respond to file share events
    @app.event("message")
    def handle_message_events(client, body, say, req):
        print("🚀 Handling message event")
        handle_message_event(
            client, event_body, say, bedrock_client, app, token, registered_bot_id
        )

    # Initialize the handler
    print("🚀 Initializing the handler")
    print(f"🚀 Event type from event_body: {event_body.get('type')}")
    print(
        f"🚀 Event.event.type from event_body: {event_body.get('event', {}).get('type')}"
    )
    slack_handler = SlackRequestHandler(app=app)

    print("🚀 Calling slack_handler.handle()")
    result = slack_handler.handle(event, context)
    print(f"🚀 slack_handler.handle() returned: {result}")
    return result


# Main function, primarily for local development
if __name__ == "__main__":
    # Run in local development mode
    print("🚀 Local server starting starting")

    # Slack secrets
    token = os.environ.get("SLACK_BOT_TOKEN")
    signing_secret = os.environ.get("SLACK_SIGNING_SECRET")

    # Register the Slack handler
    print("🚀 Registering the Slack handler")
    app, registered_bot_id = register_slack_app(token, signing_secret)

    # Register the AWS Bedrock AI client
    print("🚀 Registering the AWS Bedrock client")
    bedrock_client = create_bedrock_client(model_region_name)

    # Responds to app mentions
    @app.event("app_mention")
    def handle_app_mention_events(client, body, say, req, payload):
        handle_message_event(
            client, body, say, bedrock_client, app, token, registered_bot_id
        )

    # Respond to message events
    @app.event("message")
    def handle_message_events(client, body, say, req, payload):
        handle_message_event(
            client, body, say, bedrock_client, app, token, registered_bot_id
        )

    # Start the app in websocket mode for local development
    print("🚀 Starting the slack app listener")
    app.start(
        port=int(os.environ.get("PORT", 3000)),
    )
