"""
Stage 0 - Basic Chat Application
This script sends a simple message to Azure OpenAI and prints the response.
It demonstrates the fundamental pattern: you send messages, the model replies.
"""

import os
from dotenv import load_dotenv
from openai import AzureOpenAI

# Load environment variables from the .env file
load_dotenv()

# Create the Azure OpenAI client
# This client handles all communication with the Azure OpenAI API
client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview"
)

# The deployment name is the name you gave to your model in Azure AI Foundry
deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# Send a simple message and get a response
response = client.chat.completions.create(
    model=deployment,
    messages=[
        # The "user" role represents the person talking to the AI
        {"role": "user", "content": "Hello! What is Microsoft Entra ID in one sentence?"}
    ]
)

# Print the model's reply
# The response contains a list of "choices" - we take the first one
print(response.choices[0].message.content)
