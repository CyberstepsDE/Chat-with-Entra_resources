"""
Stage 2 - Entra ID Security Agent with Tool Calling
This agent can query your Entra tenant in real time by calling
Microsoft Graph API functions when it needs data to answer your questions.
"""

import os
import json
import requests
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

# Azure OpenAI setup
ai_client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview"
)
deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# Entra credentials
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ---- Authentication ----

def get_access_token():
    """Get an access token for Microsoft Graph API."""
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default"
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def graph_get(endpoint, params=None):
    """Make a GET request to Microsoft Graph, handling pagination."""
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH_BASE}{endpoint}"
    all_results = []
    while url:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        all_results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        params = None
    return all_results


# ---- Tool Functions (called by the AI) ----

def get_users():
    """Return a list of all users with key security properties."""
    users = graph_get(
        "/users",
        params={
            "$select": "id,displayName,userPrincipalName,userType,"
                       "accountEnabled,createdDateTime",
            "$top": "999"
        }
    )
    return json.dumps(users, indent=2, default=str)


def get_global_admins():
    """Return a list of users/service principals with the Global Administrator role."""
    roles = graph_get("/directoryRoles")
    for role in roles:
        if role["displayName"] == "Global Administrator":
            members = graph_get(f"/directoryRoles/{role['id']}/members")
            return json.dumps(members, indent=2, default=str)
    return json.dumps({"message": "Global Administrator role not found or not activated."})


def get_role_assignments():
    """Return all activated directory roles and their members."""
    roles = graph_get("/directoryRoles")
    result = []
    for role in roles:
        members = graph_get(f"/directoryRoles/{role['id']}/members")
        result.append({
            "role": role["displayName"],
            "memberCount": len(members),
            "members": [
                {"name": m.get("displayName"), "upn": m.get("userPrincipalName")}
                for m in members
            ]
        })
    return json.dumps(result, indent=2, default=str)


def get_conditional_access_policies():
    """Return all Conditional Access policies with their configuration."""
    policies = graph_get("/identity/conditionalAccess/policies")
    return json.dumps(policies, indent=2, default=str)


def get_service_principals_with_high_permissions():
    """Return service principals that have app role assignments (Graph API permissions)."""
    sps = graph_get(
        "/servicePrincipals",
        params={"$select": "id,displayName,appId,servicePrincipalType", "$top": "999"}
    )
    results = []
    for sp in sps:
        assignments = graph_get(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
        if assignments:
            results.append({
                "displayName": sp["displayName"],
                "appId": sp["appId"],
                "type": sp["servicePrincipalType"],
                "appRoleAssignmentCount": len(assignments)
            })
    return json.dumps(results, indent=2, default=str)


def get_guest_users():
    """Return all guest (external) users in the tenant."""
    guests = graph_get(
        "/users",
        params={
            "$filter": "userType eq 'Guest'",
            "$select": "id,displayName,userPrincipalName,createdDateTime,accountEnabled"
        }
    )
    return json.dumps(guests, indent=2, default=str)


# ---- Tool Definitions (schema the AI reads) ----

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_users",
            "description": "Get a list of all users in the Entra ID tenant with their key properties (name, UPN, type, enabled status).",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_global_admins",
            "description": "Get a list of all users and service principals assigned the Global Administrator role.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_role_assignments",
            "description": "Get all activated directory roles and their members, showing who has which admin role.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_conditional_access_policies",
            "description": "Get all Conditional Access policies configured in the tenant, including their conditions and controls.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_service_principals_with_high_permissions",
            "description": "Get service principals that have app role assignments (Microsoft Graph API permissions), which may indicate overprivileged applications.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_guest_users",
            "description": "Get all guest (external) users in the tenant.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

# Map tool names to actual Python functions
available_functions = {
    "get_users": get_users,
    "get_global_admins": get_global_admins,
    "get_role_assignments": get_role_assignments,
    "get_conditional_access_policies": get_conditional_access_policies,
    "get_service_principals_with_high_permissions": get_service_principals_with_high_permissions,
    "get_guest_users": get_guest_users,
}

# ---- System Prompt ----

SYSTEM_PROMPT = """You are an Entra ID Security Analyst AI Agent. You have access to tools 
that query a live Microsoft Entra ID tenant via the Microsoft Graph API.

Your job:
- Answer questions about the tenant's security posture using REAL data from the tools.
- When asked about users, roles, policies, or service principals, ALWAYS use the 
  appropriate tool to get live data. Do not guess or make assumptions.
- When you find a security issue, explain: what the issue is, why it is a risk, 
  and how to fix it.
- Be concise and actionable in your responses.
- Format your responses clearly with bullet points or numbered lists when appropriate."""


# ---- Agent Loop ----

def run_agent():
    """Main agent loop that handles conversation and tool calling."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    print("Entra ID Security Agent (type 'quit' to exit)")
    print("=" * 55)
    print("Try asking: 'Who are the Global Admins?' or")
    print("'What Conditional Access policies do we have?'")
    print("=" * 55)

    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() in ("quit", "exit"):
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        # Send the conversation to the AI with available tools
        response = ai_client.chat.completions.create(
            model=deployment,
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )

        response_message = response.choices[0].message

        # Process tool calls in a loop (the model may call multiple tools
        # or need multiple rounds of tool calls to fully answer)
        while response_message.tool_calls:
            messages.append(response_message)

            for tool_call in response_message.tool_calls:
                fn_name = tool_call.function.name
                print(f"  [Calling: {fn_name}...]")

                # Execute the requested function
                fn = available_functions.get(fn_name)
                if fn:
                    result = fn()
                else:
                    result = json.dumps({"error": f"Unknown function: {fn_name}"})

                # Send the result back to the AI
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result
                })

            # Let the AI process the tool results and possibly call more tools
            response = ai_client.chat.completions.create(
                model=deployment,
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            response_message = response.choices[0].message

        # Print the final answer
        print(f"\nAgent: {response_message.content}")
        messages.append(response_message)


if __name__ == "__main__":
    run_agent()
