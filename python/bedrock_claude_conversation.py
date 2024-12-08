# Purpose: This script demonstrates how to use the Bedrock API to have a conversation with the Claude model.

###
# Imports
###

# Global
import boto3
import json


###
# AWS Stuff
###

# Specify the AWS region
region_name = "us-west-2"


###
# Constants
###

# Replace with your desired model ID
model_id = 'anthropic.claude-3-5-sonnet-20241022-v2:0' 
anthropic_version = "bedrock-2023-05-31"
temperature = 0.2

model_guidance = """Assistant is a large language model trained to provide the best possible experience for developers and operations teams.
Assistant is designed to provide accurate and helpful responses to a wide range of questions. 
Assistant answers should be short and to the point.
Assistant uses Markdown formatting. When using Markdown, Assistant always follows best practices for clarity and consistency. 
Assistant always uses a single space after hash symbols for headers (e.g., ”# Header 1”) and leaves a blank line before and after headers, lists, and code blocks. 
For emphasis, Assistant uses asterisks or underscores consistently (e.g., italic or bold). 
When creating lists, Assistant aligns items properly and uses a single space after the list marker. For nested bullets in bullet point lists, Assistant uses two spaces before the asterisk (*) or hyphen (-) for each level of nesting. 
For nested bullets in numbered lists, Assistant uses three spaces before the number and period (e.g., “1.”) for each level of nesting.
"""

# Create a Bedrock client
bedrock_client = boto3.client(
    'bedrock-runtime',
    region_name=region_name
)

# Create a request to the model
response = bedrock_client.invoke_model(
  modelId=model_id,
  #guardrailIdentifier="xxxxxxxxxx",
  #guardrailVersion = "DRAFT",
  body=json.dumps(
    {
      "anthropic_version": anthropic_version,
      "max_tokens": 1024,
      "temperature": temperature,
      "system": model_guidance,
      "messages": [
        {
          "role": "user",
          "content": [
            {
              "type": "text",
              "text": "Write a short story about a cat",
            }
          ]
        },
        {
          "role": "assistant",
          "content": [
            {
              "type": "text",
              "text": "There once was a cat named Whiskers. Whiskers was a very curious cat who loved to explore the world around him. One day, Whiskers found a mysterious door in the garden. He pushed it open with his nose and found himself in a magical world full of talking animals and enchanted forests. Whiskers had many adventures in this new world and made many new friends. He learned that sometimes, the most magical things can be found in the most unexpected places.",
            }
          ]
        },
        {
          "role": "user",
          "content": [
            {
              "type": "text",
              "text": "Now make it about a dog",
            }
          ]
        },
      ],
    }
  ),
)

# Read the response body
response_body = response['body'].read().decode('utf-8')
response_json = json.loads(response_body)
response_text = response_json.get("content", [{}])[0].get("text", "")
print(response_text)