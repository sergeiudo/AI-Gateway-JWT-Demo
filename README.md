# Enterprise AI Chat UI: Azure AD SSO + Prisma AIRS AI Gateway (RS256 JWT Auth)

A secure, enterprise-grade AI Chat web application built with **Streamlit**, **Azure AD (Microsoft Entra ID)**, and **Prisma AIRS AI Gateway**. 

This application implements Single Sign-On (SSO), dynamically extracts user metadata (Email, Role, Department via MS Graph API), mints ephemeral **RS256 JWTs**, and passes them to Portkey for role-based LLM routing, governance, and audit logging.

---

## 🌟 Value Proposition

* **Zero API Key Exposure:** End-users never handle raw LLM API keys. Access is gated by Azure AD SSO, and requests are authorized via short-lived, locally signed RS256 JWT tokens.
* **Granular Enterprise Observability:** Automatically tracks user identity (`email`), role (`Admin` vs. `User`), and organization unit (`department` via MS Graph API) on every LLM call inside Portkey dashboards.
* **Server-Enforced Governance & Guardrails:** Embeds Portkey Conditional Config IDs directly into cryptographically signed JWT payloads. Users cannot bypass model guardrails or load-balancing policies enforced at the edge.
* **Cost & Memory Control:** Features an interactive sliding window context slider to keep token usage optimized and predictable.

---

## 🏗️ Architecture & Authentication Flow

```
+------------------+         1. OAuth Login          +----------------------+
|                  | ------------------------------> |                      |
|   User Browser   |                                 | Azure AD (Entra ID)  |
|   (Streamlit)    | <------------------------------ |                      |
+------------------+     2. Auth Code / ID Token     +----------------------+
         |                                                      |
         | 3. Fetch Department                                  |
         +------------------------------------------------------+
         |    via MS Graph API (/v1.0/me)
         v
+---------------------------------------------------------------------------+
| Python Application Backend (app.py)                                       |
| 4. Mints RS256 JWT using local private key (private_key.pem)              |
|    Payload: { portkey_oid, email, role, department, config_id }           |
+---------------------------------------------------------------------------+
         |
         | 5. LLM Prompt + JWT (x-portkey-api-key)
         v
+----------------------+     6. Signature Check      +----------------------+
|                      | --------------------------> |  Portkey Admin UI    |
| Portkey AI Gateway   |                             |  (Configured JWKS)   |
| (Conditional Config) | <-------------------------- |                      |
+----------------------+     Public Key Match        +----------------------+
         |
         | 7. Route / Load-Balance Prompt
         v
+---------------------------------------------------------------------------+
| LLM Provider (Groq / OpenAI / Meta Llama)                                 |
+---------------------------------------------------------------------------+
```

---

## 📋 Microsoft Entra ID (Azure AD) Setup Guide

### Step 1: Register the Application
1. Log in to the [Azure Portal](https://portal.azure.com/).
2. Navigate to **Microsoft Entra ID** -> **App registrations** -> **New registration**.
3. Set **Name** to `Enterprise AI Chat UI`.
4. Set **Supported account types** to **Accounts in this organizational directory only (Single tenant)**.
5. Set **Redirect URI**:
   * Platform: **Web**
   * URI: `http://localhost:8501/`
6. Click **Register**.

### Step 2: Collect Client Credentials
1. From the app **Overview** page, copy:
   * **Application (client) ID** -> `AZURE_CLIENT_ID`
   * **Directory (tenant) ID** -> `AZURE_TENANT_ID`
2. Go to **Certificates & secrets** -> **Client secrets** tab -> **New client secret**.
3. Add a description, set expiration, and click **Add**.
4. Copy the **Value** column immediately -> `AZURE_CLIENT_SECRET`.

### Step 3: Configure App Roles
1. In your app registration, select **App roles** -> **Create app role**.
2. **Admin Role:**
   * Display name: `App Admin`
   * Allowed member types: `Users/Groups`
   * Value: `Admin`
   * Description: `Full administrative model access`
3. **Standard User Role:**
   * Display name: `App User`
   * Allowed member types: `Users/Groups`
   * Value: `User`
   * Description: `Standard user access subject to routing policies`

### Step 4: Assign Users to Roles
1. Go to **Microsoft Entra ID** -> **Enterprise applications** -> Select `Enterprise AI Chat UI`.
2. Select **Users and groups** -> **Add user/group**.
3. Select your user account, assign either **App Admin** or **App User**, and click **Assign**.

### Step 5: Configure User Department
1. Go to **Microsoft Entra ID** -> **Users** -> Select a user -> **Properties**.
2. Under **Job information**, set **Department** (e.g., `Sales`, `Engineering`).
3. Click **Save**.

---

## 🚀 Quick Start Guide

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/sergeiudo/AI-Gateway-JWT-Demo
cd AI-Gateway-JWT-Demo

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate Cryptographic RSA Keys

Run the key generator script to create your local private key (`private_key.pem`) and public JWKS (`jwks.json`):

```bash
python3 generate_keys.py
```

### 3. Configure Portkey Admin UI
1. Open **Portkey Admin Dashboard** -> **Admin Settings** -> **Organisation** -> **Authentication**.
2. Select **JWKS JSON** and paste the exact contents of your generated `jwks.json`.
3. Save changes.

### 4. Environment Configuration

Create a `.env` file from the example template:

```bash
cp .env.example .env
```

Configure your `.env` parameters:

```env
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id
REDIRECT_URI=http://localhost:8501/

PORTKEY_ORG_ID=your_portkey_org_id
PORTKEY_WORKSPACE_SLUG=your_workspace_slug
PORTKEY_PROVIDER=@groq
PORTKEY_BASE_URL=https://aigw.portkey.ai/v1
PORTKEY_DEFAULT_CONFIG_ID=pc-your-portkey-config-id

PRIVATE_KEY_PATH=private_key.pem
JWKS_PATH=jwks.json
```

This demo was created using Groq as a model provider. If the model provider is different you would need to update the provider and models accordingly within the app code as well as environment parameters. 


### 5. Run the Application

Launch the Streamlit web server:

```bash
streamlit run app.py
```

Navigate to `http://localhost:8501` in your browser and click **Login with Azure AD**.

---

(Optional Step) - ## ⚙️ Portkey Conditional Config Example

Below is the conditional routing configuration to paste into Portkey for to explore routing decisions based on Metadata received with the JWT Authentication (`strategy.mode = "conditional"`):

In the below config the Admin users requests are passed through with the selected model but for Standard Users regardless the model selected the model request is forwarded to groq/compound or groq/compound-mini models.

```json
{
  "strategy": {
    "mode": "conditional",
    "conditions": [
      {
        "query": {
          "metadata.user_role": { "$eq": "Admin" }
        },
        "then": "admin-pass-through"
      },
      {
        "query": {
          "metadata.user_role": { "$eq": "User" }
        },
        "then": "user-loadbalanced-route"
      }
    ],
    "default": "user-loadbalanced-route"
  },
  "targets": [
    {
      "name": "admin-pass-through",
      "provider": "@groq"
    },
    {
      "name": "user-loadbalanced-route",
      "strategy": {
        "mode": "loadbalance"
      },
      "targets": [
        {
          "provider": "@groq",
          "weight": 0.5,
          "override_params": {
            "model": "groq/compound"
          }
        },
        {
          "provider": "@groq",
          "weight": 0.5,
          "override_params": {
            "model": "groq/compound-mini"
          }
        }
      ]
    }
  ]
}
```

---

## 📂 Repository Structure

```text
├── app.py                # Main Streamlit UI, MSAL OAuth, JWT Minting & Portkey Client
├── generate_keys.py      # Script to generate RSA 2048 keypair & jwks.json
├── .env.example          # Environment variable template
├── .gitignore            # Excludes secrets, keys, and virtual envs from Git
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

---

## 🛡️ Security Considerations

* **Private Key Protection:** `private_key.pem` should never be committed to Git or exposed client-side. It remains strictly on the backend server.
* **Short-Lived Tokens:** RS256 JWTs minted by this application expire automatically after 1 hour (`exp: now + 3600`).
* **Metadata Integrity:** User identity claims (`email_id`, `sub`, `user_role`, `department`) are embedded inside the JWT payload prior to signing, preventing client-side header tampering.
