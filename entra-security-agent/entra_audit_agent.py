"""
Stage 3 - Entra ID Security Audit Agent
This agent has built-in audit logic to detect common Entra ID 
misconfigurations. It goes beyond answering questions - it actively
looks for security problems.
"""

import os
import json
import requests
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()

ai_client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview"
)
deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


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


# ---- Audit Tool Functions ----

def audit_admin_accounts():
    """
    AUDIT CHECK: Analyze admin role assignments for security issues.
    Looks for: too many Global Admins, service principals in admin roles,
    guest users with admin roles.
    """
    roles = graph_get("/directoryRoles")
    findings = []

    for role in roles:
        members = graph_get(f"/directoryRoles/{role['id']}/members")
        role_name = role["displayName"]

        # Check: Global Admins count
        if role_name == "Global Administrator":
            if len(members) > 4:
                findings.append({
                    "severity": "HIGH",
                    "finding": f"Too many Global Administrators: {len(members)} found",
                    "detail": "Microsoft recommends no more than 4 Global Admins. "
                              "Excessive admin accounts increase the attack surface.",
                    "recommendation": "Review each Global Admin. Convert users who "
                                      "don't need full control to more specific roles "
                                      "(e.g., User Administrator, Security Administrator)."
                })

            # Check: service principals as Global Admins
            for m in members:
                if "#microsoft.graph.servicePrincipal" in m.get("@odata.type", ""):
                    findings.append({
                        "severity": "HIGH",
                        "finding": f"Service principal '{m.get('displayName')}' is a Global Administrator",
                        "detail": "Service principals with Global Admin are extremely dangerous. "
                                  "If the app credentials are compromised, the attacker gains full control.",
                        "recommendation": "Remove Global Admin from this service principal. "
                                          "Assign only the minimum permissions the application needs."
                    })

        # Check: guest users in any admin role
        for m in members:
            if m.get("userType") == "Guest":
                findings.append({
                    "severity": "HIGH",
                    "finding": f"Guest user '{m.get('displayName')}' has the '{role_name}' role",
                    "detail": "External users with admin roles are a major risk - "
                              "you have less control over their accounts and devices.",
                    "recommendation": "Remove admin roles from guest users. If external "
                                      "access is needed, use B2B collaboration with minimal permissions."
                })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "Admin role assignments appear reasonable",
            "detail": "No obvious admin role misconfigurations detected."
        })

    return json.dumps(findings, indent=2)


def audit_conditional_access():
    """
    AUDIT CHECK: Analyze Conditional Access policies for common gaps.
    Looks for: no MFA policy, no legacy auth blocking policy,
    disabled policies, policies excluding too many users.
    """
    policies = graph_get("/identity/conditionalAccess/policies")
    findings = []

    if not policies:
        findings.append({
            "severity": "CRITICAL",
            "finding": "No Conditional Access policies configured",
            "detail": "Without Conditional Access, there are no rules enforcing MFA, "
                      "blocking risky sign-ins, or preventing legacy authentication.",
            "recommendation": "Create baseline policies: require MFA for all users, "
                              "block legacy authentication, require compliant devices for admins."
        })
        return json.dumps(findings, indent=2)

    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    disabled_policies = [p for p in policies if p.get("state") != "enabled"]

    if disabled_policies:
        names = [p.get("displayName", "Unnamed") for p in disabled_policies]
        findings.append({
            "severity": "MEDIUM",
            "finding": f"{len(disabled_policies)} Conditional Access policies are disabled",
            "detail": f"Disabled policies: {', '.join(names)}. "
                      "Disabled policies provide no protection.",
            "recommendation": "Review each disabled policy. Enable it if still needed, "
                              "or delete it if obsolete to reduce confusion."
        })

    # Check if any enabled policy requires MFA
    mfa_policy_found = False
    legacy_block_found = False

    for p in enabled_policies:
        controls = p.get("grantControls", {})
        if controls:
            built_in = controls.get("builtInControls", [])
            if "mfa" in built_in:
                mfa_policy_found = True

            auth_strength = controls.get("authenticationStrength", {})
            if auth_strength:
                mfa_policy_found = True

        # Check for legacy auth blocking
        conditions = p.get("conditions", {})
        client_apps = conditions.get("clientAppTypes", [])
        if "exchangeActiveSync" in client_apps or "other" in client_apps:
            grant = p.get("grantControls", {})
            if grant and grant.get("operator") == "OR" and "block" in grant.get("builtInControls", []):
                legacy_block_found = True

    if not mfa_policy_found:
        findings.append({
            "severity": "CRITICAL",
            "finding": "No Conditional Access policy enforces MFA",
            "detail": "MFA is the single most effective control against account compromise. "
                      "Without it, stolen passwords give immediate access.",
            "recommendation": "Create a policy that requires MFA for all users on all "
                              "cloud apps. At minimum, enforce it for admin roles."
        })

    if not legacy_block_found:
        findings.append({
            "severity": "HIGH",
            "finding": "No policy blocks legacy authentication protocols",
            "detail": "Legacy protocols (POP, IMAP, SMTP, ActiveSync with basic auth) "
                      "do not support MFA and are frequently exploited in password spray attacks.",
            "recommendation": "Create a Conditional Access policy that blocks legacy "
                              "authentication for all users."
        })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "Conditional Access baseline looks reasonable",
            "detail": f"{len(enabled_policies)} active policies found with MFA and legacy auth controls."
        })

    return json.dumps(findings, indent=2)


def audit_service_principals():
    """
    AUDIT CHECK: Look for overprivileged service principals.
    Service principals with powerful Graph permissions (like RoleManagement,
    AppRoleAssignment, or Application permissions) can be abused for
    privilege escalation.
    """
    sps = graph_get(
        "/servicePrincipals",
        params={"$select": "id,displayName,appId,servicePrincipalType", "$top": "999"}
    )
    findings = []

    # Known dangerous permission IDs in Microsoft Graph
    # These are app role IDs for permissions that allow privilege escalation
    dangerous_permissions = {
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
        "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
        "19dbc75e-c2e2-444c-a770-ec596d83d9ad": "Directory.ReadWrite.All",
    }

    for sp in sps:
        assignments = graph_get(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
        dangerous_found = []
        for assignment in assignments:
            role_id = assignment.get("appRoleId", "")
            if role_id in dangerous_permissions:
                dangerous_found.append(dangerous_permissions[role_id])

        if dangerous_found:
            findings.append({
                "severity": "HIGH",
                "finding": f"Service principal '{sp['displayName']}' has dangerous permissions",
                "detail": f"Permissions: {', '.join(dangerous_found)}. "
                          "These permissions allow the app to modify roles, assignments, "
                          "or applications, which could be used for privilege escalation.",
                "recommendation": "Review if this service principal truly needs these "
                                  "permissions. Apply least-privilege: remove any "
                                  "permission that is not strictly required."
            })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "No overprivileged service principals detected",
            "detail": "None of the service principals have known dangerous permission combinations."
        })

    return json.dumps(findings, indent=2)


def audit_guest_users():
    """
    AUDIT CHECK: Review guest user accounts for risks.
    Guest users are external identities - they may have stale access
    or excessive permissions.
    """
    guests = graph_get(
        "/users",
        params={
            "$filter": "userType eq 'Guest'",
            "$select": "id,displayName,userPrincipalName,createdDateTime,accountEnabled"
        }
    )
    findings = []

    if len(guests) > 50:
        findings.append({
            "severity": "MEDIUM",
            "finding": f"Large number of guest users: {len(guests)}",
            "detail": "A high number of external users increases the attack surface. "
                      "Each guest is an identity you do not fully control.",
            "recommendation": "Implement regular access reviews for guest users. "
                              "Remove guests who no longer need access."
        })

    disabled_guests = [g for g in guests if not g.get("accountEnabled", True)]
    if disabled_guests:
        findings.append({
            "severity": "LOW",
            "finding": f"{len(disabled_guests)} disabled guest accounts exist",
            "detail": "Disabled accounts clutter the directory. While not an immediate "
                      "risk, they should be cleaned up.",
            "recommendation": "Delete disabled guest accounts that are no longer needed."
        })

    if not findings and guests:
        findings.append({
            "severity": "INFO",
            "finding": f"{len(guests)} guest users found, no obvious issues",
            "detail": "Guest user count appears manageable."
        })
    elif not guests:
        findings.append({
            "severity": "INFO",
            "finding": "No guest users found in the tenant"
        })

    return json.dumps(findings, indent=2)


def run_full_audit():
    """
    Run ALL audit checks at once and return a combined report.
    This is triggered when the user asks for a full security audit.
    """
    report = {
        "admin_accounts": json.loads(audit_admin_accounts()),
        "conditional_access": json.loads(audit_conditional_access()),
        "service_principals": json.loads(audit_service_principals()),
        "guest_users": json.loads(audit_guest_users())
    }
    return json.dumps(report, indent=2)


# ---- Tool Definitions ----

tools = [
    {
        "type": "function",
        "function": {
            "name": "audit_admin_accounts",
            "description": "Audit admin role assignments for security issues: too many admins, "
                           "service principals in admin roles, guest users with admin roles.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_conditional_access",
            "description": "Audit Conditional Access policies for gaps: missing MFA enforcement, "
                           "no legacy auth blocking, disabled policies.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_service_principals",
            "description": "Audit service principals for overprivileged permissions that could "
                           "allow privilege escalation (e.g., RoleManagement.ReadWrite.Directory).",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "audit_guest_users",
            "description": "Audit guest (external) user accounts for risks: excessive count, "
                           "stale/disabled accounts.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_audit",
            "description": "Run a comprehensive security audit of the entire Entra ID tenant, "
                           "checking admin accounts, Conditional Access, service principals, "
                           "and guest users at once.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

available_functions = {
    "audit_admin_accounts": audit_admin_accounts,
    "audit_conditional_access": audit_conditional_access,
    "audit_service_principals": audit_service_principals,
    "audit_guest_users": audit_guest_users,
    "run_full_audit": run_full_audit,
}

# ---- Enhanced System Prompt with Audit Knowledge ----

SYSTEM_PROMPT = """You are an Entra ID Security Audit Agent. You have tools that query 
a live Microsoft Entra ID tenant and perform automated security checks.

YOUR CAPABILITIES:
- Audit admin role assignments for misconfigurations
- Check Conditional Access policies for common gaps
- Detect overprivileged service principals
- Review guest user accounts for risks
- Run a full comprehensive security audit

YOUR BEHAVIOR:
- When asked to audit or check security, ALWAYS use the appropriate tool to get real data.
- Present findings organized by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO.
- For each finding, explain: WHAT the issue is, WHY it is dangerous, and HOW to fix it.
- Be direct and actionable. Avoid generic advice - reference specific objects found in the data.
- When running a full audit, summarize the key findings at the top before going into detail.

SECURITY KNOWLEDGE (use this to interpret findings):
- Global Admin is the most powerful role. More than 4 is a red flag.
- MFA is the most important single control. Without it, passwords are the only barrier.
- Legacy authentication (basic auth for POP/IMAP/SMTP) bypasses MFA entirely.
- Service principals with RoleManagement.ReadWrite.Directory or AppRoleAssignment.ReadWrite.All 
  can escalate their own privileges - this is a critical finding.
- Guest users in admin roles is almost always a misconfiguration."""


def run_agent():
    """Main agent loop for the audit agent."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    print("Entra ID Security Audit Agent (type 'quit' to exit)")
    print("=" * 55)
    print("Try: 'Run a full security audit' or")
    print("     'Check if our Conditional Access policies are secure'")
    print("=" * 55)

    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() in ("quit", "exit"):
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        response = ai_client.chat.completions.create(
            model=deployment,
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )

        response_message = response.choices[0].message

        while response_message.tool_calls:
            messages.append(response_message)

            for tool_call in response_message.tool_calls:
                fn_name = tool_call.function.name
                print(f"  [Running audit: {fn_name}...]")

                fn = available_functions.get(fn_name)
                result = fn() if fn else json.dumps({"error": f"Unknown: {fn_name}"})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result
                })

            response = ai_client.chat.completions.create(
                model=deployment,
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            response_message = response.choices[0].message

        print(f"\nAgent: {response_message.content}")
        messages.append(response_message)


if __name__ == "__main__":
    run_agent()
