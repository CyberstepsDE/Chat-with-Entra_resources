# Entra Security Agent Toolkit

This directory contains a suite of Python scripts designed to interact with Microsoft Entra ID (formerly Azure AD) and Azure OpenAI. The scripts are organized into progressive stages, demonstrating the evolution from a simple chat application to an intelligent, automated security audit agent.

## Stage 0: Foundations

These scripts demonstrate the fundamental concepts of interacting with Azure OpenAI, from simple requests to basic tool usage.

- **`chat_basic.py`**
  A rudimentary chat application that sends a simple message to Azure OpenAI and prints the response. This demonstrates the core interaction pattern.

- **`chat_system_prompt.py`**
  An interactive chat script that illustrates the power of system prompts. It configures the AI to act as a cybersecurity expert, showing how behavior and tone can be controlled.

- **`agent_basic.py`**
  Introduces the concept of "tool calling" (Function Calling). The AI is provided with a simple, local Python function (`get_current_time`) and learns to request execution of this tool when needed, acting as a true agent rather than just a chat interface.

## Stage 1: Data Acquisition

- **`entra_data.py`**
  Connects directly to the Microsoft Entra ID tenant via the Microsoft Graph API using OAuth2 Client Credentials. It retrieves critical security data (users, role assignments, Conditional Access policies, and service principals) and saves it locally to a JSON file (`tenant_data.json`) for offline analysis.

## Stage 2: Live Querying

- **`entra_agent.py`**
  An intelligent security agent capable of answering questions about the tenant's security posture by querying Microsoft Graph API in real-time. The AI decides when to call specific tools (like `get_users`, `get_global_admins`, `get_conditional_access_policies`) based on the user's questions, ensuring it uses live data rather than making assumptions.

## Stage 3: Automated Security Auditing

- **`entra_audit_agent.py`**
  An advanced security audit agent that actively hunts for common Entra ID misconfigurations instead of just answering questions. It contains built-in logic to detect dangerous configurations such as excessive Global Admins, overprivileged service principals, lack of MFA enforcement, and guest user risks. It can run targeted checks or a comprehensive full security audit, providing detailed findings mapped to severity levels.

## Requirements

To execute these scripts, you must configure the following environment variables in a `.env` file:

- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`
- `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` (for Microsoft Graph API access)
