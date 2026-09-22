import os
import time
import json
import html
import base64
from pathlib import Path
import jwt
import msal
import requests
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
from portkey_ai import Portkey

st.set_page_config(
    page_title="Enterprise AI Access",
    page_icon="⌁",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load environment variables from .env file
load_dotenv()

# ==========================================
# ENVIRONMENT VARIABLES & VALIDATION
# ==========================================
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501/")

PORTKEY_ORG_ID = os.getenv("PORTKEY_ORG_ID")
PORTKEY_WORKSPACE_SLUG = os.getenv("PORTKEY_WORKSPACE_SLUG")
PORTKEY_PROVIDER = os.getenv("PORTKEY_PROVIDER")
PORTKEY_BASE_URL = os.getenv("PORTKEY_BASE_URL", "https://aigw.portkey.ai/v1")
PORTKEY_DEFAULT_CONFIG_ID = os.getenv("PORTKEY_DEFAULT_CONFIG_ID")

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
JWKS_PATH = os.getenv("JWKS_PATH", "jwks.json")

REQUIRED_ENV_VARS = [
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "PORTKEY_ORG_ID", "PORTKEY_WORKSPACE_SLUG", "PORTKEY_PROVIDER",
    "PORTKEY_DEFAULT_CONFIG_ID"
]
missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]

if missing_vars:
    st.error(f"Missing required environment variables in .env: {', '.join(missing_vars)}")
    st.stop()

# ==========================================
# AVAILABLE MODELS LIST
# ==========================================
AVAILABLE_MODELS = {
    "Kimi K2.5": "moonshotai.kimi-k2.5",
    "Claude Opus 5": "anthropic.claude-opus-5",
    "Claude Sonnet 5": "anthropic.claude-sonnet-5",
    "GPT-6 Astra": "openai.gpt-6-astra",
    "Claude Opus 4.8": "us.anthropic.claude-opus-4-8",
    "Claude 3 Haiku": "anthropic.claude-3-haiku-20240307-v1:0",
    "Nemotron Nano 12B": "nvidia.nemotron-nano-12b-v2",
    "Claude 3.5 Sonnet v2": "anthropic.claude-3-5-sonnet-20241022-v2:0",
}

MODEL_LABELS = {model_id: label for label, model_id in AVAILABLE_MODELS.items()}

# One address may be exempted from model routing. Left unset, the exemption branch simply
# does not exist and everyone is routed by role.
POLICY_EXEMPT_EMAIL = os.getenv("POLICY_EXEMPT_EMAIL", "").strip()

# The exact JSON held under PORTKEY_DEFAULT_CONFIG_ID. Keep this in step with the gateway:
# the gateway is what enforces routing, this copy is what the app explains and simulates.
GATEWAY_CONFIG = {
    "strategy": {
        "mode": "conditional",
        "conditions": (
            [
                {
                    "query": {"metadata.email": {"$eq": POLICY_EXEMPT_EMAIL}},
                    "then": "unrestricted",
                }
            ]
            if POLICY_EXEMPT_EMAIL
            else []
        )
        + [
            {
                "query": {"metadata.user_role": {"$eq": "Admin"}},
                "then": "admin-opus",
            },
            {
                "query": {"metadata.user_role": {"$eq": "User"}},
                "then": "user-kimi",
            },
        ],
        "default": "user-kimi",
    },
    "targets": (
        [{"name": "unrestricted", "provider": PORTKEY_PROVIDER}]
        if POLICY_EXEMPT_EMAIL
        else []
    )
    + [
        {
            "name": "admin-opus",
            "provider": PORTKEY_PROVIDER,
            "override_params": {"model": "us.anthropic.claude-opus-4-8"},
        },
        {
            "name": "user-kimi",
            "provider": PORTKEY_PROVIDER,
            "override_params": {"model": "moonshotai.kimi-k2.5"},
        },
    ],
}

TARGETS_BY_NAME = {t["name"]: t for t in GATEWAY_CONFIG["targets"]}
CONDITIONS = GATEWAY_CONFIG["strategy"]["conditions"]


def target_model(target_name: str):
    """The model a target forces, or None when it forwards the request untouched."""
    return TARGETS_BY_NAME.get(target_name, {}).get("override_params", {}).get("model")


ROLE_POLICY = {
    cond["query"]["metadata.user_role"]["$eq"]: target_model(cond["then"])
    for cond in CONDITIONS
    if "metadata.user_role" in cond["query"]
}


def resolve_policy(email: str, role: str):
    """Walks the conditions in the order the gateway does and returns (model or None, why)."""
    facts = {"metadata.email": (email or "").lower(), "metadata.user_role": role}

    def matches(key, test):
        expected = test.get("$eq")
        if key == "metadata.email" and isinstance(expected, str):
            expected = expected.lower()
        return facts.get(key) == expected

    for cond in CONDITIONS:
        query = cond["query"]
        if all(matches(k, v) for k, v in query.items()):
            why = "exempt" if "metadata.email" in query else "role"
            return target_model(cond["then"]), why
    return target_model(GATEWAY_CONFIG["strategy"]["default"]), "default"

# ==========================================
# RSA KEYS & MSAL SETUP
# ==========================================
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY_PEM = f.read()

with open(JWKS_PATH, "r") as f:
    KID = json.load(f)["keys"][0]["kid"]

msal_app = msal.ConfidentialClientApplication(
    AZURE_CLIENT_ID,
    client_credential=AZURE_CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
)

# ==========================================
# PORTKEY JWT MINTING WITH LOCKED CONFIG
# ==========================================
def mint_portkey_jwt(user_email: str, user_sub: str, role: str, department: str) -> str:
    """
    Mints an RS256 JWT containing Portkey required claims, metadata, 
    and locks the PORTKEY_DEFAULT_CONFIG_ID inside the token payload.
    """
    now = int(time.time())
    payload = {
        "portkey_oid": PORTKEY_ORG_ID,
        "portkey_workspace": PORTKEY_WORKSPACE_SLUG,
        "scope": ["completions.write", "logs.view"],
        "email_id": user_email,
        "sub": user_sub,
        "iat": now,
        "exp": now + 3600,  # 1 hour validity
        "defaults": {
            # 🔒 Locks conditional routing/guardrails directly inside the signed JWT
            "config_id": PORTKEY_DEFAULT_CONFIG_ID,
            "metadata": {
                "email": user_email,
                "user_role": role,
                "department": department
            }
        }
    }
    headers = {"alg": "RS256", "typ": "JWT", "kid": KID}
    return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256", headers=headers)


def token_lifetime(token: str):
    """Minutes remaining on our own token. Signature already trusted; we minted it."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return max(0, int((claims["exp"] - time.time()) // 60))
    except Exception:
        return None


# ==========================================
# DESIGN SYSTEM
# ==========================================
THEME = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Sans:wght@400;500;600;700&family=Instrument+Serif:ital@0;1&display=swap');

:root {
  --ink:        #151A2D;
  --ink-raised: #1D2440;
  --ink-line:   #2C3557;
  --ivory:      #F3EEE5;
  --ivory-dim:  #98A1BE;
  --brass:      #C9973F;
  --verdigris:  #4FA396;
  --vermilion:  #D4553C;
}

html, body, [data-testid="stAppViewContainer"] {
  background: var(--ink);
  font-family: 'Instrument Sans', system-ui, sans-serif;
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] { padding-top: 2.2rem; max-width: 980px; }

/* ---------- credential strip : the signature element ---------- */
.cred {
  position: relative; overflow: hidden;
  display: grid; grid-template-columns: repeat(3, 1fr);
  border: 1px solid var(--ink-line); border-radius: 3px;
  background: linear-gradient(180deg, #1A2038, #161B2E);
  margin-bottom: 1.6rem;
}
.cred::before {
  content: ""; position: absolute; inset: 0; pointer-events: none; opacity: .45;
  background:
    repeating-radial-gradient(circle at 10% 50%, transparent 0 7px, rgba(201,151,63,.16) 7px 7.7px),
    repeating-radial-gradient(circle at 90% 50%, transparent 0 9px, rgba(79,163,150,.12) 9px 9.7px);
}
.cred.sealing::after {
  content: ""; position: absolute; top: 0; bottom: 0; width: 26%;
  background: linear-gradient(90deg, transparent, rgba(243,238,229,.10), transparent);
  animation: sweep 2.4s cubic-bezier(.22,.61,.36,1) .15s 1 both;
}
@keyframes sweep { from { transform: translateX(-130%);} to { transform: translateX(260%);} }

.cred-seg {
  position: relative; padding: .7rem .95rem;
  border-right: 1px solid var(--ink-line);
  transition: background .25s ease;
}
.cred-seg:last-child { border-right: 0; }
.cred-seg:hover { background: rgba(243,238,229,.035); }
.cred-tag {
  font-family: 'IBM Plex Mono', monospace; font-size: .58rem;
  letter-spacing: .16em; text-transform: uppercase; color: var(--ivory-dim);
  display: flex; justify-content: space-between; margin-bottom: .3rem;
}
.cred-tag b { font-weight: 500; }
.cred-val {
  font-family: 'IBM Plex Mono', monospace; font-size: .74rem;
  word-break: break-all; line-height: 1.45;
}
.seg-h .cred-val { color: var(--verdigris); }
.seg-p .cred-val { color: var(--ivory); }
.seg-s .cred-val { color: var(--brass); }
.seg-h .cred-tag b { color: var(--verdigris); }
.seg-s .cred-tag b { color: var(--brass); }

/* ---------- masthead ---------- */
.mast { display: flex; align-items: baseline; gap: .8rem; margin-bottom: .2rem; }
.mast h1 {
  font-family: 'Instrument Serif', serif; font-weight: 400;
  font-size: 2.5rem; letter-spacing: -.01em; color: var(--ivory);
  margin: 0; line-height: 1;
}
.mast .glyph { color: var(--brass); font-size: 1.5rem; }
.mast-sub {
  font-family: 'IBM Plex Mono', monospace; font-size: .68rem;
  letter-spacing: .13em; text-transform: uppercase; color: var(--ivory-dim);
  margin: .55rem 0 1.5rem;
}
.mast-sub span { color: var(--verdigris); }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] {
  background: #12172A; border-right: 1px solid var(--ink-line);
}
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .7rem; }
.eyebrow {
  font-family: 'IBM Plex Mono', monospace; font-size: .58rem;
  letter-spacing: .18em; text-transform: uppercase; color: var(--ivory-dim);
  margin: 1.3rem 0 .55rem; display: flex; align-items: center; gap: .55rem;
}
.eyebrow::after { content: ""; flex: 1; height: 1px; background: var(--ink-line); }

/* identity plate */
.plate {
  border: 1px solid var(--ink-line); border-radius: 3px;
  background: var(--ink-raised); padding: .85rem .9rem;
}
.plate-name { font-size: 1rem; font-weight: 600; color: var(--ivory); line-height: 1.2; }
.plate-mail {
  font-family: 'IBM Plex Mono', monospace; font-size: .68rem;
  color: var(--ivory-dim); word-break: break-all; margin-top: .15rem;
}
.plate-rule { height: 1px; background: var(--ink-line); margin: .7rem 0; }
.plate-claims { display: flex; flex-direction: column; gap: .4rem; }
.claim { display: flex; justify-content: space-between; align-items: center; gap: .6rem; }
.claim-k {
  font-family: 'IBM Plex Mono', monospace; font-size: .6rem;
  letter-spacing: .1em; text-transform: uppercase; color: var(--ivory-dim);
}
.claim-v { font-size: .78rem; font-weight: 500; color: var(--ivory); text-align: right; }

.seal {
  display: inline-flex; align-items: center; gap: .35rem;
  font-family: 'IBM Plex Mono', monospace; font-size: .62rem;
  letter-spacing: .1em; text-transform: uppercase;
  padding: .2rem .5rem; border-radius: 2px; border: 1px solid;
}
.seal-admin { color: var(--brass); border-color: rgba(201,151,63,.5); background: rgba(201,151,63,.1); }
.seal-user  { color: var(--verdigris); border-color: rgba(79,163,150,.45); background: rgba(79,163,150,.1); }

/* policy ledger */
.ledger { border: 1px solid var(--ink-line); border-radius: 3px; overflow: hidden; }
.ledger-row { padding: .55rem .8rem; display: flex; flex-direction: column; gap: .12rem; }
.ledger-k {
  font-family: 'IBM Plex Mono', monospace; font-size: .57rem;
  letter-spacing: .14em; text-transform: uppercase; color: var(--ivory-dim);
}
.ledger-v { font-size: .84rem; font-weight: 500; color: var(--ivory); }
.ledger-row.struck .ledger-v { color: var(--ivory-dim); text-decoration: line-through; text-decoration-color: var(--vermilion); }
.ledger-row.held { background: rgba(201,151,63,.09); border-top: 1px solid var(--ink-line); }
.ledger-row.held .ledger-v { color: var(--brass); }
.ledger-row.pass { background: rgba(79,163,150,.08); }
.ledger-row.pass .ledger-v { color: var(--verdigris); }
.ledger-note {
  font-size: .68rem; color: var(--ivory-dim); line-height: 1.45;
  padding: .5rem .8rem .6rem; border-top: 1px solid var(--ink-line);
}

/* ---------- chat ---------- */
[data-testid="stChatMessage"] {
  background: transparent; border: 1px solid var(--ink-line);
  border-radius: 3px; padding: .9rem 1rem; margin-bottom: .75rem;
}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) {
  background: rgba(79,163,150,.05); border-color: rgba(79,163,150,.22);
}
[data-testid="stChatInput"] textarea { font-family: 'Instrument Sans', sans-serif; }

.stamp {
  display: inline-flex; align-items: center; gap: .45rem; margin-top: .7rem;
  font-family: 'IBM Plex Mono', monospace; font-size: .62rem;
  letter-spacing: .09em; padding: .22rem .55rem; border-radius: 2px;
  border: 1px dashed rgba(201,151,63,.45); color: var(--brass);
  background: rgba(201,151,63,.07);
}
.stamp .dot { width: 5px; height: 5px; border-radius: 50%; background: var(--brass); }

.empty {
  border: 1px dashed var(--ink-line); border-radius: 3px;
  padding: 2.2rem 1.6rem; text-align: center; color: var(--ivory-dim);
}
.empty b { display: block; color: var(--ivory); font-size: 1rem; font-weight: 600; margin-bottom: .35rem; }

/* ---------- sign-in ---------- */
.wordmark {
  display: flex; align-items: center; gap: .5rem;
  font-family: 'IBM Plex Mono', monospace; font-size: .64rem;
  letter-spacing: .2em; text-transform: uppercase; color: var(--ivory-dim);
}
.wordmark .glyph { color: var(--brass); font-size: .95rem; letter-spacing: 0; }
.gate { margin: 0 0 1.4rem; }
.gate h1 {
  font-family: 'Instrument Serif', serif; font-weight: 400; font-size: 3.4rem;
  line-height: 1.05; color: var(--ivory); margin: 0 0 1rem;
}
.gate h1 em { font-style: italic; color: var(--brass); }
.gate p { color: var(--ivory-dim); font-size: 1rem; line-height: 1.65; margin: 0; max-width: 52ch; }

/* ---------- gateway config ---------- */
[data-testid="stExpander"] {
  border: 1px solid var(--ink-line) !important; border-radius: 3px !important;
  background: #171C30 !important; margin-bottom: 1.4rem;
}
[data-testid="stExpander"] summary {
  font-family: 'IBM Plex Mono', monospace !important; font-size: .62rem !important;
  letter-spacing: .15em; text-transform: uppercase; color: var(--ivory-dim) !important;
}
[data-testid="stExpander"] summary:hover { color: var(--brass) !important; }

[data-testid="stCode"] {
  border: 1px solid var(--ink-line); border-radius: 3px; background: #12172A;
  margin-bottom: 1rem;
}
[data-testid="stCode"] pre { background: transparent !important; }
[data-testid="stCode"] code { font-family: 'IBM Plex Mono', monospace !important; font-size: .74rem !important; }

.walk { list-style: none; margin: 0 0 .9rem; padding: 0; }
.walk li { display: flex; gap: .65rem; margin-bottom: .5rem; font-size: .8rem; line-height: 1.55; color: #CED4E6; }
.walk .ord {
  flex: 0 0 auto; width: 18px; height: 18px; margin-top: .1rem; border-radius: 2px;
  font-family: 'IBM Plex Mono', monospace; font-size: .6rem; color: var(--brass);
  border: 1px solid rgba(201,151,63,.45); background: rgba(201,151,63,.1);
  display: flex; align-items: center; justify-content: center;
}
.walk code, .cfg-note code {
  font-family: 'IBM Plex Mono', monospace; font-size: .72rem;
  color: var(--verdigris); background: rgba(79,163,150,.1);
  border: 1px solid rgba(79,163,150,.25); border-radius: 2px; padding: .03rem .3rem;
}
.walk b { color: var(--brass); }
.cfg-note { font-size: .76rem; line-height: 1.6; color: var(--ivory-dim); margin: 0; }

/* ---------- buttons ---------- */
.stButton > button {
  font-family: 'IBM Plex Mono', monospace !important;
  font-size: .7rem !important; letter-spacing: .12em !important; text-transform: uppercase;
  border-radius: 2px !important; border: 1px solid var(--ink-line) !important;
  background: var(--ink-raised) !important; color: var(--ivory) !important;
  transition: border-color .2s ease, background .2s ease;
}
.stButton > button:hover {
  border-color: var(--brass) !important; background: rgba(201,151,63,.12) !important;
  color: var(--ivory) !important;
}

/* fixed so it stays reachable while the sign-in page scrolls; right offset clears
   Streamlit's own toolbar button in the header strip */
.signin-wrap { position: fixed; top: .5rem; right: 3.8rem; z-index: 1000001; }
.signin {
  display: inline-flex; align-items: center; gap: .55rem;
  background: #1A2138; border: 1px solid var(--brass); border-radius: 2px;
  padding: .55rem 1.05rem; text-decoration: none; color: var(--ivory) !important;
  font-family: 'IBM Plex Mono', monospace; font-size: .68rem; font-weight: 500;
  letter-spacing: .11em; text-transform: uppercase; white-space: nowrap;
  transition: background .2s ease, transform .2s ease, box-shadow .2s ease;
}
.signin:hover {
  background: rgba(201,151,63,.14); transform: translateY(-1px);
  box-shadow: 0 4px 16px -6px rgba(201,151,63,.55);
}
.signin:focus-visible { outline: 2px solid var(--brass); outline-offset: 3px; }
.signin img { width: 19px; height: 19px; display: block; }
@media (max-width: 760px) {
  .signin-wrap { right: .75rem; top: 3.6rem; }
  .signin { font-size: .6rem; padding: .45rem .7rem; }
}

@media (prefers-reduced-motion: reduce) {
  .cred.sealing::after { animation: none !important; }
}
@media (max-width: 820px) {
  .cred { grid-template-columns: 1fr; }
  .gate h1 { font-size: 2.4rem; }
}
</style>
"""
st.markdown(THEME, unsafe_allow_html=True)


def esc(value) -> str:
    return html.escape(str(value))


def credential_strip(token: str, role: str, department: str, sealing: bool) -> str:
    """Renders the live JWT as three inspectable segments."""
    signature_b64 = token.split(".")[2]
    mins = token_lifetime(token)
    expiry = f"{mins} min left" if mins is not None else "unknown"
    return f"""
<div class="cred{' sealing' if sealing else ''}">
  <div class="cred-seg seg-h" title="Names the key that signed this token, so the gateway knows which public key to verify with.">
    <div class="cred-tag"><b>Header</b><span>RS256</span></div>
    <div class="cred-val">kid {esc(KID[:8])}…{esc(KID[-4:])}</div>
  </div>
  <div class="cred-seg seg-p" title="The claims the gateway routes on. Readable by anyone, changeable by no one.">
    <div class="cred-tag"><b>Payload</b><span>{esc(expiry)}</span></div>
    <div class="cred-val">{esc(role.lower())} · {esc(department.lower())} · {esc(PORTKEY_DEFAULT_CONFIG_ID)}</div>
  </div>
  <div class="cred-seg seg-s" title="Proof the claims came from this app and were not edited in transit.">
    <div class="cred-tag"><b>Signature</b><span>sealed</span></div>
    <div class="cred-val">{esc(signature_b64[:22])}…</div>
  </div>
</div>"""


def policy_ledger(requested_label: str, enforced_label, why: str = "role") -> str:
    if enforced_label is None:
        note = (
            "This account is exempt from model routing. Everyone else is still pinned by role."
            if why == "exempt"
            else "Your role is not restricted to a single model, so the gateway forwards whichever one you pick."
        )
        return f"""
<div class="ledger">
  <div class="ledger-row pass">
    <span class="ledger-k">Sent as requested</span>
    <span class="ledger-v">{esc(requested_label)}</span>
  </div>
  <div class="ledger-note">{note}</div>
</div>"""
    if requested_label == enforced_label:
        return f"""
<div class="ledger">
  <div class="ledger-row pass">
    <span class="ledger-k">Requested and enforced</span>
    <span class="ledger-v">{esc(enforced_label)}</span>
  </div>
  <div class="ledger-note">Your choice already matches the model your role allows.</div>
</div>"""
    return f"""
<div class="ledger">
  <div class="ledger-row struck">
    <span class="ledger-k">You requested</span>
    <span class="ledger-v">{esc(requested_label)}</span>
  </div>
  <div class="ledger-row held">
    <span class="ledger-k">Gateway enforces</span>
    <span class="ledger-v">{esc(enforced_label)}</span>
  </div>
  <div class="ledger-note">The routing rule is sealed inside your signed token, so this cannot be changed from the browser.</div>
</div>"""


def served_stamp(model_id: str) -> str:
    label = MODEL_LABELS.get(model_id, model_id)
    return f'<div class="stamp"><span class="dot"></span>Served by {esc(label)}</div>'


def config_walkthrough() -> str:
    """Explains each branch in the order the gateway evaluates it."""
    rows = []
    for i, cond in enumerate(CONDITIONS, start=1):
        key, test = next(iter(cond["query"].items()))
        field = key.split(".", 1)[1]
        model = target_model(cond["then"])
        outcome = (
            f"forwards whichever model was requested"
            if model is None
            else f"replaces the request with <b>{esc(MODEL_LABELS.get(model, model))}</b>"
        )
        rows.append(
            f'<li><span class="ord">{i}</span>'
            f'<span>When <code>{esc(field)}</code> is <code>{esc(test["$eq"])}</code>, '
            f'the gateway {outcome}.</span></li>'
        )
    fallback = target_model(GATEWAY_CONFIG["strategy"]["default"])
    rows.append(
        f'<li><span class="ord">↓</span><span>Anything that matches nothing falls through to '
        f'<code>{esc(GATEWAY_CONFIG["strategy"]["default"])}</code>, so an unknown caller gets the '
        f'most restricted route rather than the most permissive one.</span></li>'
    )
    return (
        '<ul class="walk">' + "".join(rows) + "</ul>"
        '<p class="cfg-note">Conditions are evaluated top to bottom and the first match wins, '
        'which is why the address exemption sits above the role rules. The claims being matched '
        'here arrive inside the signed token, so a browser cannot alter them.</p>'
    )


def render_config_panel(expanded: bool = False) -> None:
    with st.expander("The routing policy the gateway enforces", expanded=expanded):
        st.markdown(config_walkthrough(), unsafe_allow_html=True)
        st.code(json.dumps(GATEWAY_CONFIG, indent=2), language="json")
        st.markdown(
            f'<p class="cfg-note">Stored in the gateway as <code>{esc(PORTKEY_DEFAULT_CONFIG_ID)}</code>. '
            f'Every request carries this id inside its signed token, so the policy travels with the '
            f'caller instead of being chosen by them.</p>',
            unsafe_allow_html=True,
        )


@st.cache_data(show_spinner=False)
def data_uri(path: str) -> str:
    """Inlines a local image so the browser needs no extra static route."""
    return "data:image/png;base64," + base64.b64encode(Path(path).read_bytes()).decode()


def signin_button(url: str) -> str:
    mark = Path(__file__).with_name("assets") / "entra-mark.png"
    logo = f'<img src="{data_uri(str(mark))}" alt="">' if mark.exists() else ""
    return (
        f'<div class="signin-wrap"><a class="signin" href="{html.escape(url, quote=True)}" '
        f'target="_self">{logo}Sign in with Microsoft Entra ID</a></div>'
    )


def short(value: str, head: int = 8, tail: int = 4) -> str:
    value = str(value or "")
    return value if len(value) <= head + tail + 1 else f"{value[:head]}…{value[-tail:]}"


FLOW_DIAGRAM = """
<!DOCTYPE html><html><head><meta charset="utf-8"><style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Sans:wght@400;500;600;700&display=swap');
* { box-sizing: border-box; }
body {
  margin: 0; background: #151A2D; color: #F3EEE5;
  font-family: 'Instrument Sans', system-ui, sans-serif;
}
.bar {
  display: flex; align-items: center; gap: .45rem; margin-bottom: .7rem; flex-wrap: wrap;
}
.bar .lab {
  font-family: 'IBM Plex Mono', monospace; font-size: .56rem; letter-spacing: .18em;
  text-transform: uppercase; color: #98A1BE; margin-right: .3rem;
}
.tab {
  font-family: 'IBM Plex Mono', monospace; font-size: .6rem; letter-spacing: .1em;
  text-transform: uppercase; background: #1D2440; color: #98A1BE;
  border: 1px solid #2C3557; border-radius: 2px; padding: .3rem .6rem; cursor: pointer;
  transition: all .2s ease;
}
.tab:hover { color: #F3EEE5; border-color: rgba(201,151,63,.6); }
.tab.on { color: #C9973F; border-color: #C9973F; background: rgba(201,151,63,.12); }
.tab:focus-visible { outline: 2px solid #C9973F; outline-offset: 2px; }
.spacer { flex: 1; }
svg { width: 100%; height: auto; display: block; }

.card { fill: #1D2440; stroke: #2C3557; transition: stroke .35s ease, fill .35s ease; }
.card.lit { stroke: #4FA396; fill: rgba(79,163,150,.14); }
.card.hot { stroke: #C9973F; fill: rgba(201,151,63,.16); }
.zone { fill: none; stroke: #C9973F; stroke-dasharray: 5 4; opacity: .55; }
.panel { fill: #1A2038; stroke: #2C3557; }
.wire { fill: none; stroke: #2C3557; stroke-width: 1.1; transition: stroke .3s ease, opacity .3s ease; }
.wire.live { stroke: #4FA396; opacity: 1; }
.wire.route { stroke: #C9973F; }
.chip { fill: #191F35; stroke: #2C3557; transition: all .3s ease; }
.chip.on { fill: rgba(201,151,63,.14); stroke: rgba(201,151,63,.75); }

text { font-family: 'Instrument Sans', sans-serif; fill: #F3EEE5; }
.eye {
  font-family: 'IBM Plex Mono', monospace; font-size: 9.5px; letter-spacing: 1.7px;
  fill: #98A1BE; text-transform: uppercase;
}
.nm { font-size: 14.5px; font-weight: 600; }
.sub { font-family: 'IBM Plex Mono', monospace; font-size: 10px; fill: #98A1BE; }
.chip-t { font-family: 'IBM Plex Mono', monospace; font-size: 10px; fill: #98A1BE; transition: fill .3s ease; }
.chip.on + .chip-t, .chip-t.on { fill: #C9973F; }
.row-t { font-size: 13px; fill: #CED4E6; transition: fill .3s ease, font-weight .3s ease; }
.row-t.win { fill: #C9973F; font-weight: 600; }
.dot { fill: #C9973F; filter: drop-shadow(0 0 5px rgba(201,151,63,.9)); }
.dot.id { fill: #4FA396; filter: drop-shadow(0 0 5px rgba(79,163,150,.9)); }

.story {
  margin-top: .6rem; border: 1px solid #2C3557; border-radius: 3px;
  background: linear-gradient(180deg,#1A2038,#161B2E); padding: .6rem .8rem;
  min-height: 52px; display: flex; align-items: center; gap: .7rem;
}
.story .badge {
  font-family: 'IBM Plex Mono', monospace; font-size: .58rem; letter-spacing: .1em;
  text-transform: uppercase; padding: .2rem .5rem; border-radius: 2px;
  border: 1px solid rgba(201,151,63,.5); color: #C9973F;
  background: rgba(201,151,63,.1); white-space: nowrap;
}
.story p { margin: 0; font-size: .78rem; line-height: 1.5; color: #CED4E6; }
.story b { color: #F3EEE5; }
</style></head><body>

<div class="bar">
  <span class="lab">Watch a request</span>
  <button class="tab" data-s="0" type="button">Standard user</button>
  <button class="tab" data-s="1" type="button">Administrator</button>
  <button class="tab" data-s="2" type="button">Exempt account</button>
  <span class="spacer"></span>
  <button class="tab" id="toggle" type="button">Pause</button>
</div>

<svg viewBox="0 0 1000 430" role="img" aria-label="Request flow from Entra through the gateway to a model">
  <text class="eye" x="20" y="34">Identity</text>
  <text class="eye" x="352" y="34">Broker and gateway</text>
  <text class="eye" x="742" y="34">Targets</text>

  <!-- connectors: identity -> broker -->
  <path id="w0" class="wire" d="M 176 76  C 250 76, 280 104, 352 112"/>
  <path id="w1" class="wire" d="M 176 136 C 250 136, 280 120, 352 118"/>
  <path id="w2" class="wire" d="M 176 196 C 250 196, 280 140, 352 126"/>
  <!-- broker -> gateway -->
  <path id="wg" class="wire" d="M 500 152 L 500 196"/>
  <!-- gateway -> targets -->
  <path id="t0" class="wire" d="M 648 228 C 700 228, 700 84,  742 84"/>
  <path id="t1" class="wire" d="M 648 228 C 700 228, 700 118, 742 118"/>
  <path id="t2" class="wire" d="M 648 228 C 700 228, 700 152, 742 152"/>
  <path id="t3" class="wire" d="M 648 228 C 700 228, 700 186, 742 186"/>
  <path id="t4" class="wire" d="M 648 228 C 700 228, 700 220, 742 220"/>

  <!-- identity cards -->
  <g><rect id="c0" class="card" x="20" y="52" width="156" height="48" rx="4"/>
     <text class="nm" x="34" y="74">Microsoft Entra</text><text class="sub" x="34" y="89">tenant __TENANT__</text></g>
  <g><rect id="c1" class="card" x="20" y="112" width="156" height="48" rx="4"/>
     <text class="nm" x="34" y="134">Microsoft Graph</text><text class="sub" x="34" y="149">department</text></g>
  <g><rect id="c2" class="card" x="20" y="172" width="156" height="48" rx="4"/>
     <text class="nm" x="34" y="194">App role</text><text class="sub" x="34" y="209">admin or user</text></g>

  <!-- centre zone -->
  <rect class="zone" x="352" y="44" width="296" height="216" rx="10"/>
  <g><rect id="brk" class="card" x="376" y="64" width="248" height="72" rx="5"/>
     <text class="nm" x="396" y="94">Token broker</text><text class="sub" x="396" y="111">rs256 · kid __KID__</text></g>
  <g><rect id="gw" class="card" x="376" y="176" width="248" height="72" rx="5"/>
     <text class="nm" x="396" y="206">AIRS AI Gateway</text><text class="sub" x="396" y="223">org __ORG__</text></g>

  <!-- capability chips -->
  <g><rect id="p0" class="chip" x="352" y="284" width="142" height="26" rx="3"/><text class="chip-t" id="p0t" x="364" y="301">verify signature</text></g>
  <g><rect id="p1" class="chip" x="506" y="284" width="142" height="26" rx="3"/><text class="chip-t" id="p1t" x="518" y="301">read claims</text></g>
  <g><rect id="p2" class="chip" x="352" y="318" width="142" height="26" rx="3"/><text class="chip-t" id="p2t" x="364" y="335">config lock</text></g>
  <g><rect id="p3" class="chip" x="506" y="318" width="142" height="26" rx="3"/><text class="chip-t" id="p3t" x="518" y="335">match policy</text></g>
  <g><rect id="p4" class="chip" x="352" y="352" width="142" height="26" rx="3"/><text class="chip-t" id="p4t" x="364" y="369">route model</text></g>
  <g><rect id="p5" class="chip" x="506" y="352" width="142" height="26" rx="3"/><text class="chip-t" id="p5t" x="518" y="369">log identity</text></g>

  <!-- targets -->
  <rect class="panel" x="742" y="44" width="238" height="200" rx="5"/>
  <text class="eye" x="758" y="66">Models · __PROVIDER__</text>
  <text class="row-t" id="m0" x="758" y="88">Kimi K2.5</text>
  <text class="row-t" id="m1" x="758" y="122">Claude Opus 4.8</text>
  <text class="row-t" id="m2" x="758" y="156">Claude Opus 5</text>
  <text class="row-t" id="m3" x="758" y="190">Claude Sonnet 5</text>
  <text class="row-t" id="m4" x="758" y="224">GPT-6 Astra</text>

  <rect class="panel" x="742" y="262" width="238" height="82" rx="5"/>
  <text class="eye" x="758" y="284">Trust anchor</text>
  <text class="sub" x="758" y="303">jwks registered at the gateway</text>
  <text class="sub" x="758" y="320">__CONFIG__</text>

  <circle id="dotA" class="dot id" r="4" cx="-20" cy="-20"/>
  <circle id="dotB" class="dot" r="4.5" cx="-20" cy="-20"/>
</svg>

<div class="story"><span class="badge" id="badge">—</span><p id="note"></p></div>

<script>
const $ = id => document.getElementById(id);
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const SCENARIOS = [
  { tag: "Standard user", win: 0,
    note: "<b>bob@</b> picks Claude Opus 5. The signed token says <b>user_role: User</b>, so the gateway replaces the choice and answers with <b>Kimi K2.5</b>." },
  { tag: "Administrator", win: 1,
    note: "<b>alice@</b> picks Claude Opus 5. The token says <b>user_role: Admin</b>, so the policy pins the request to <b>Claude Opus 4.8</b>." },
  { tag: "Exempt account", win: 2,
    note: "<b>__EXEMPT__</b> picks Claude Opus 5. This address is exempt from routing, so the gateway forwards the request untouched to <b>Claude Opus 5</b>." },
];

let run = 0, timer = null, current = 0;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function travel(pathId, dotId, ms, token) {
  return new Promise(resolve => {
    const path = $(pathId), dot = $(dotId), len = path.getTotalLength();
    if (REDUCED) { dot.setAttribute("cx", -20); resolve(); return; }
    const t0 = performance.now();
    (function step(now) {
      if (token !== run) { resolve(); return; }
      const k = Math.min(1, (now - t0) / ms);
      const pt = path.getPointAtLength(len * k);
      dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y);
      k < 1 ? requestAnimationFrame(step) : (dot.setAttribute("cx", -20), resolve());
    })(t0);
  });
}

function reset() {
  ["c0","c1","c2","brk","gw"].forEach(i => $(i).classList.remove("lit","hot"));
  ["w0","w1","w2","wg","t0","t1","t2","t3","t4"].forEach(i => $(i).classList.remove("live","route"));
  for (let i = 0; i < 6; i++) { $("p"+i).classList.remove("on"); $("p"+i+"t").classList.remove("on"); }
  for (let i = 0; i < 5; i++) $("m"+i).classList.remove("win");
  $("dotA").setAttribute("cx", -20); $("dotB").setAttribute("cx", -20);
}

async function play(idx, token) {
  current = idx;
  document.querySelectorAll(".tab[data-s]").forEach(t =>
    t.classList.toggle("on", +t.dataset.s === idx));
  const s = SCENARIOS[idx];
  reset();
  $("badge").textContent = s.tag;
  $("note").innerHTML = s.note;

  for (let i = 0; i < 3; i++) {
    if (token !== run) return;
    $("c"+i).classList.add("lit"); $("w"+i).classList.add("live");
    travel("w"+i, "dotA", 620, token);
    await sleep(190);
  }
  await sleep(430); if (token !== run) return;

  $("brk").classList.add("hot");
  await sleep(320); if (token !== run) return;
  $("wg").classList.add("route");
  await travel("wg", "dotB", 380, token); if (token !== run) return;
  $("gw").classList.add("hot");

  for (let i = 0; i < 6; i++) {
    if (token !== run) return;
    $("p"+i).classList.add("on"); $("p"+i+"t").classList.add("on");
    await sleep(170);
  }
  await sleep(200); if (token !== run) return;

  $("t"+s.win).classList.add("route");
  await travel("t"+s.win, "dotB", 620, token); if (token !== run) return;
  $("m"+s.win).classList.add("win");
}

async function loop() {
  const token = ++run;
  let i = current;
  while (token === run) {
    await play(i, token);
    if (token !== run) return;
    await sleep(2600);
    i = (i + 1) % SCENARIOS.length;
  }
}
function stop() { run++; clearInterval(timer); timer = null; $("toggle").textContent = "Play"; }

document.querySelectorAll(".tab[data-s]").forEach(tab =>
  tab.addEventListener("click", () => { stop(); const t = ++run; play(+tab.dataset.s, t); }));
$("toggle").addEventListener("click", () => {
  if (timer === null && $("toggle").textContent === "Play") { timer = 1; $("toggle").textContent = "Pause"; loop(); }
  else stop();
});

if (REDUCED) { const t = ++run; play(0, t); $("toggle").textContent = "Play"; }
else { timer = 1; loop(); }
</script></body></html>
"""


def render_flow_diagram(height: int = 560) -> None:
    html_doc = (
        FLOW_DIAGRAM
        .replace("__TENANT__", esc(short(AZURE_TENANT_ID, 6, 4)))
        .replace("__KID__", esc(short(KID, 6, 4)))
        .replace("__ORG__", esc(short(PORTKEY_ORG_ID, 6, 4)))
        .replace("__CONFIG__", esc(PORTKEY_DEFAULT_CONFIG_ID))
        .replace("__EXEMPT__", esc(POLICY_EXEMPT_EMAIL.split("@")[0] + "@" if POLICY_EXEMPT_EMAIL else "An exempt address"))
        .replace("__PROVIDER__", esc(PORTKEY_PROVIDER))
    )
    components.html(html_doc, height=height, scrolling=False)


# ==========================================
# STREAMLIT UI & OAUTH HANDLING
# ==========================================
if "user" not in st.session_state:
    st.session_state.user = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# OAuth Authorization Code Callback
query_params = st.query_params
if "code" in query_params and not st.session_state.user:
    auth_code = query_params["code"]

    result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    if "id_token_claims" in result and "access_token" in result:
        claims = result["id_token_claims"]
        access_token = result["access_token"]

        # 1. Extract Email
        user_email = (
            claims.get("preferred_username")
            or claims.get("email")
            or claims.get("upn")
        )
        user_sub = claims.get("sub")
        user_name = claims.get("name", "User")

        # 2. Extract App Role
        assigned_roles = claims.get("roles", [])
        user_role = "Admin" if "Admin" in assigned_roles else "User"

        # 3. Fetch Department from Microsoft Graph API ($select parameter included)
        user_department = "General"  # Fallback
        try:
            graph_url = "https://graph.microsoft.com/v1.0/me?$select=department,displayName,mail,userPrincipalName"
            graph_response = requests.get(
                graph_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5
            )
            if graph_response.status_code == 200:
                profile_data = graph_response.json()
                user_department = profile_data.get("department") or "General"
        except Exception as err:
            st.warning(f"Could not fetch department from Graph API: {err}")

        # 4. Mint Portkey RS256 JWT containing Metadata and Locked Config ID
        portkey_jwt = mint_portkey_jwt(user_email, user_sub, user_role, user_department)

        st.session_state.user = {
            "name": user_name,
            "email": user_email,
            "role": user_role,
            "department": user_department,
            "portkey_jwt": portkey_jwt
        }
        st.query_params.clear()
        st.rerun()

# Unauthenticated View
if not st.session_state.user:
    # The sign-in page runs wider than the chat so the diagram and the policy can sit together.
    st.markdown(
        '<style>[data-testid="stSidebar"]{display:none}'
        '[data-testid="stMainBlockContainer"]{max-width:1460px}</style>',
        unsafe_allow_html=True,
    )
    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI,
        prompt="select_account"
    )

    st.markdown(signin_button(auth_url), unsafe_allow_html=True)
    st.markdown(
        '<div class="wordmark"><span class="glyph">⌁</span>Enterprise AI Access</div>',
        unsafe_allow_html=True,
    )

    # top, not center: expanding the policy grows this row, and centring would slide the
    # diagram down to match the taller column.
    intro_col, diagram_col = st.columns([2, 3], vertical_alignment="top")
    with intro_col:
        st.markdown(
            """
<div class="gate">
  <h1>Your identity<br>becomes the <em>key</em>.</h1>
  <p>Sign in with your organization account. Your role and department are read from
     the directory, sealed into a short-lived signed token, and sent to the AI gateway
     with every prompt. No API keys are issued to you.</p>
</div>""",
            unsafe_allow_html=True,
        )
        render_config_panel(expanded=False)
    with diagram_col:
        render_flow_diagram(height=430)
    st.stop()

# ==========================================
# AUTHENTICATED CHAT INTERFACE
# ==========================================
user = st.session_state.user
policy_model, policy_why = resolve_policy(user["email"], user["role"])
policy_label = MODEL_LABELS.get(policy_model, policy_model)

# ---------- Sidebar : identity, policy, controls ----------
with st.sidebar:
    st.markdown('<div class="eyebrow">Signed in as</div>', unsafe_allow_html=True)
    seal_class = "seal-admin" if user["role"] == "Admin" else "seal-user"
    seal_text = "Administrator" if user["role"] == "Admin" else "Standard user"
    st.markdown(
        f"""
<div class="plate">
  <div class="plate-name">{esc(user['name'])}</div>
  <div class="plate-mail">{esc(user['email'])}</div>
  <div class="plate-rule"></div>
  <div class="plate-claims">
    <div class="claim"><span class="claim-k">Department</span><span class="claim-v">{esc(user['department'])}</span></div>
    <div class="claim"><span class="claim-k">Role</span><span class="seal {seal_class}">{esc(seal_text)}</span></div>
  </div>
</div>""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="eyebrow">Model</div>', unsafe_allow_html=True)
    selected_label = st.selectbox(
        "Requested model",
        options=list(AVAILABLE_MODELS.keys()),
        index=0,
        label_visibility="collapsed",
    )
    selected_model = f"{PORTKEY_PROVIDER}/{AVAILABLE_MODELS[selected_label]}"
    st.markdown(policy_ledger(selected_label, policy_label, policy_why), unsafe_allow_html=True)

    st.markdown('<div class="eyebrow">Conversation</div>', unsafe_allow_html=True)
    system_prompt = st.text_area(
        "System instructions",
        value="You are a helpful, secure enterprise AI assistant.",
        height=80,
        help="Sent ahead of every prompt to set the assistant's behaviour.",
    )
    max_chat_history = st.slider(
        "Context window",
        min_value=2,
        max_value=30,
        value=10,
        step=2,
        help="How many recent messages travel with each request. Fewer messages cost less.",
    )

    st.markdown('<div class="eyebrow">Session</div>', unsafe_allow_html=True)
    col_clear, col_out = st.columns(2)
    if col_clear.button("Clear", use_container_width=True):
        st.session_state.messages = []
        st.rerun()
    if col_out.button("Sign out", use_container_width=True):
        st.session_state.user = None
        st.session_state.messages = []
        st.session_state.seal_shown = False
        st.rerun()

# ---------- Masthead + live credential ----------
st.markdown(
    f"""
<div class="mast"><span class="glyph">⌁</span><h1>Enterprise AI Access</h1></div>
<div class="mast-sub">{esc(PORTKEY_BASE_URL)} &nbsp;·&nbsp; workspace {esc(PORTKEY_WORKSPACE_SLUG)}
&nbsp;·&nbsp; <span>credential verified</span></div>""",
    unsafe_allow_html=True,
)
sealing = not st.session_state.get("seal_shown")
st.session_state.seal_shown = True
st.markdown(
    credential_strip(user["portkey_jwt"], user["role"], user["department"], sealing),
    unsafe_allow_html=True,
)
render_config_panel(expanded=False)

# ---------- Conversation ----------
if not st.session_state.messages:
    st.markdown(
        """
<div class="empty">
  <b>Ask anything to see the policy act</b>
  Pick a model your role does not allow, then watch which one actually answers.
</div>""",
        unsafe_allow_html=True,
    )

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if message.get("served_model"):
            st.markdown(served_stamp(message["served_model"]), unsafe_allow_html=True)

# User Prompt Input
if prompt := st.chat_input("Send a message"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Initialize Portkey Client using JWT
    portkey_client = Portkey(
        api_key=user["portkey_jwt"],
        base_url=PORTKEY_BASE_URL,
        provider=PORTKEY_PROVIDER
    )

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        try:
            # Construct API payload:
            # 1. Add System Prompt at position 0 (if provided)
            payload_messages = []
            if system_prompt.strip():
                payload_messages.append({"role": "system", "content": system_prompt.strip()})

            # 2. Append the last 'max_chat_history' messages from session state
            recent_messages = st.session_state.messages[-max_chat_history:]
            for msg in recent_messages:
                payload_messages.append({"role": msg["role"], "content": msg["content"]})

            with st.spinner("Routing through the gateway"):
                response = portkey_client.chat.completions.create(
                    model=selected_model,
                    messages=payload_messages,
                    max_tokens=512
                )
            reply = response.choices[0].message.content
            served_model = getattr(response, "model", None)
            message_placeholder.markdown(reply)
            if served_model:
                st.markdown(served_stamp(served_model), unsafe_allow_html=True)
            st.session_state.messages.append(
                {"role": "assistant", "content": reply, "served_model": served_model}
            )
        except Exception as e:
            st.error(f"The gateway refused this request. {str(e)}")
