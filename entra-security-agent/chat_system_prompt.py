"""
Stage 0 - System Prompt Experimentation
This script shows how system prompts change the AI's behavior.
A system prompt defines WHO the AI is and HOW it should respond.
"""

import os
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview"
)

deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# Define a system prompt that makes the AI act as a cybersecurity expert
# Try changing this text and observe how the responses change
system_prompt = """You are a senior cybersecurity analyst specializing in 
Microsoft Entra ID security. You explain concepts clearly for beginners. 
When asked about security risks, you always explain:
1. What the risk is
2. Why it matters
3. How to fix it
Keep your answers concise and practical."""

# Interactive chat loop - you can keep asking questions
print("Entra ID Security Assistant (type 'quit' to exit)")
print("-" * 50)

# This list stores the conversation history so the AI remembers context
messages = [{"role": "system", "content": system_prompt}]

while True:
    user_input = input("\nYou: ")
    if user_input.lower() == "quit":
        break

    # Add the user's message to the conversation history
    messages.append({"role": "user", "content": user_input})

    response = client.chat.completions.create(
        model=deployment,
        messages=messages
    )

    assistant_reply = response.choices[0].message.content
    print(f"\nAssistant: {assistant_reply}")

    # Add the assistant's reply to history so it remembers the conversation
    messages.append({"role": "assistant", "content": assistant_reply})
