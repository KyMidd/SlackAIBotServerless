# SlackAIBotServerless

This repo contains the source files to build a fully functional and interactive AI chatbot and integrate it with Slack as an App. The integration is serverless both on the AWS Bedrock AI side (serverless AI mode) and on the AWS side (Lambda). 

# Architecture

Requests are relayed from the Slack App to a private Lambda URL, which spins up quite quickly. It fetches the necessary secrets from secrets manager (authentication is via IAM role) to enable the slack app for decoding the requests, then extracts both the request, and if applicable, the slack thread, which is all encoded into the request to the AI in Bedrock. The response is relayed and posted to the thread. 

Slack User tags Bot in shared thread (bot must be invited) or DMs Bot --> Slack App sees trigger, sends webhook to Lambda URL --> Lambda reads package and extracts message and thread context, constructs AI request --> AI request to Bedrock, Bedrock creates response --> Lambda relays response back to Slack App --> Slack App posts to Slack within thread. 

All conversations with the bot happen in threads. This is to help separate topics of conversation for the AI, since long or multi-topic conversations can confuse AI responses. 

# Secrets and Security

All authentication except for the Slack app is keyless IAM roles. 

# Privacy

Requests to the Lambda are logged to Cloudtrail, and if the retention period remains the default, they will be kept for 90 days. This can be disabled by commented out the `print()` statement in the Python code that prints the request. 

Responses from the AI bot back to the user are not logged. 

# Maintenance

There are no servers to maintain. We use ARM Lambdas, primarily because I am very lazy. I don't want to maintain servers and patching, and my current development mac has an ARM CPU. 

This is built on Python 3.12, which is not schedule to go EOL until the end of 2028, ref: https://devguide.python.org/versions/

# Monitoring

Lambda can spin up hundreds of concurrencies without much effort, so monitoring isn't a major concern. The `logging` package is installed in the python lambda, so logs could quickly be added for anything of note (and I welcome PRs to add that!)

# Cost

Assuming 100 requests per week (will depend on your biz size, use) that take ~10 seconds total (assuming on the high end)
Lambda cost: $0.03 / month
Lambda concurrency (running 5 concurrencies constantly): ~22/month
AI cost (depends on request complexity), assuming 1k tokens per request: $3.20/month

Total cost for 100 requests per week of moderate complexity is: ~$25

You could easily cut down on concurrency, or remove it altogether. Responses would be slightly slower (3-5 seconds slower-ish), and you'd save $22/month. I don't recommend, folks love and will use fast services, and hate slow services no matter how amazing. 