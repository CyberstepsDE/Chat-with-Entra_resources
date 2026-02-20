"""
Stage 0 - Basic Agent with Tool Calling
This script demonstrates the agent pattern: the AI can call functions
that your code defines. Here, a simple 'get_current_time' tool shows
the concept before you connect real Entra ID data.
"""

import os
import json
from datetime import datetime
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview"
)

deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")


# Define a real Python function that the AI can request to call
def get_current_time():
    """Returns the current date and time as a string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Define the tool schema - this tells the AI what tools are available
# and what parameters they accept
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "Returns the current date and time.",
            "parameters": {
                "type": "object",
                "properties": {},  # This function takes no parameters
                "required": []
            }
        }
    }
]

# Map tool names to actual Python functions
# When the AI requests a tool call, you look up the function here
available_functions = {
    "get_current_time": get_current_time
}

messages = [
    {"role": "system", "content": "You are a helpful assistant. Use the available tools when needed."},
    {"role": "user", "content": "What time is it right now?"}
]

print("Sending message to AI: 'What time is it right now?'")
print("-" * 50)

# Step 1: Send the message with tools defined
response = client.chat.completions.create(
    model=deployment,
    messages=messages,
    tools=tools,
    tool_choice="auto"  # Let the model decide if it needs to call a tool
)

response_message = response.choices[0].message

# Step 2: Check if the model wants to call a tool
if response_message.tool_calls:
    print("The AI decided to call a tool!")
    
    # Add the assistant's message (with tool call request) to history
    messages.append(response_message)
    
    # Process each tool call the model requested
    for tool_call in response_message.tool_calls:
        function_name = tool_call.function.name
        print(f"  -> Calling function: {function_name}")
        
        # Execute the actual Python function
        function_response = available_functions[function_name]()
        print(f"  -> Function returned: {function_response}")
        
        # Send the function result back to the AI
        messages.append({
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": function_response
        })
    
    # Step 3: Let the AI generate a final response using the tool result
    final_response = client.chat.completions.create(
        model=deployment,
        messages=messages
    )
    
    print(f"\nFinal Answer: {final_response.choices[0].message.content}")
else:
    # The model answered directly without calling any tool
    print(f"Answer: {response_message.content}")
