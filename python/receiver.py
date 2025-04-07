import json
import os
import boto3

# Initialize AWS Lambda client
lambda_client = boto3.client('lambda')

def lambda_handler(event, context):
    """
    Receives Slack events, performs basic validation, and asynchronously invokes the processor Lambda
    """
    print("Received event: %s", json.dumps(event))
    
    try:
        # Parse the event body
        body = json.loads(event['body'])
        
        # Handle Slack URL verification challenge
        if 'challenge' in body:
            return {
                'statusCode': 200,
                'body': json.dumps({'challenge': body['challenge']})
            }
            
        # Get the event type
        event_type = body.get('type', '')
        
        # Check for edited messages
        if (
            event_type == 'event_callback' and 
            'edited' in body.get('event', {})
        ):
            print('Detected edited message, discarding')
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Edited message discarded'})
            }
        
        # Only process events we care about
        if event_type == 'event_callback':
            # Asynchronously invoke the processor Lambda
            lambda_client.invoke(
                FunctionName=os.environ['PROCESSOR_FUNCTION_NAME'],
                InvocationType='Event',  # Async invocation
                Payload=json.dumps(event)
            )
            
        # Always return 200 OK to Slack quickly
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Event received'})
        }
        
    except Exception as e:
        print("Error processing event: %s", str(e))
        # Still return 200 to Slack to prevent retries
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Error processing event'})
        }