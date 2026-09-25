import os
import time
import json
import html
import base64
import secrets
import urllib.parse
from pathlib import Path
import jwt
import msal
import requests
import markdown
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
# Model ids for the provider integration named in PORTKEY_PROVIDER. Newer Anthropic and
# Meta models are only invocable through a cross-region inference profile, hence us. ids.
AVAILABLE_MODELS = {
    "Claude Haiku 4.5": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "Claude Sonnet 5": "us.anthropic.claude-sonnet-5",
    "Claude Opus 4.8": "us.anthropic.claude-opus-4-8",
    "Llama 4 Maverick": "us.meta.llama4-maverick-17b-instruct-v1:0",
    "Mistral Large 3": "mistral.mistral-large-3-675b-instruct",
    "GLM 5": "zai.glm-5",
    "MiniMax M2.5": "minimax.minimax-m2.5",
    "Nova Micro": "us.amazon.nova-micro-v1:0",
    "Nemotron Nano 12B": "nvidia.nemotron-nano-12b-v2",
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
                "then": "user-haiku",
            },
        ],
        "default": "user-haiku",
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
            "name": "user-haiku",
            "provider": PORTKEY_PROVIDER,
            "override_params": {"model": "us.anthropic.claude-haiku-4-5-20251001-v1:0"},
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
    JWKS_DOC = json.load(f)
JWKS_KEY = JWKS_DOC["keys"][0]
KID = JWKS_KEY["kid"]

# Authorization requests are recorded here rather than in session state: the redirect to
# Microsoft and back is a full page navigation, so the browser session that built the URL
# is not the one that handles the callback. Keyed by the state we generate.
AUTH_REQUESTS: dict = {}

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
# TOKEN LIFECYCLE CAPTURE
#
# Everything below records the real artifacts moving through the app so the UI can show
# them. It is deliberately verbose: this is a teaching demo, not a production posture.
# The one thing never captured is AZURE_CLIENT_SECRET, which only ever travels in the
# back-channel POST and is not part of any artifact.
# ==========================================
def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def split_jwt(token: str) -> dict:
    """Breaks a JWT into the parts a verifier actually works with."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    return {
        "header": json.loads(b64url_decode(header_b64)),
        "payload": json.loads(b64url_decode(payload_b64)),
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "signing_input": f"{header_b64}.{payload_b64}",
        "signature_bytes": len(b64url_decode(signature_b64)),
        "raw": token,
    }


def epoch(value):
    try:
        return time.strftime("%H:%M:%S", time.localtime(int(value)))
    except Exception:
        return str(value)


def record_stage(key: str, data: dict, started: float = None) -> None:
    stages = st.session_state.setdefault("lifecycle", {})
    stages[key] = {
        "at": time.time(),
        "elapsed_ms": None if started is None else round((time.time() - started) * 1000),
        "data": data,
    }


def clear_lifecycle() -> None:
    st.session_state.lifecycle = {}
    st.session_state.lifecycle_calls = []


def stage(key: str):
    return st.session_state.get("lifecycle", {}).get(key)


# ==========================================
# DESIGN SYSTEM
# ==========================================
# TRACE — near-monochrome. Exactly two chromatic colours exist in either mode, and both
# mean "the gateway acted on your request": signal for enforcement, alert for refusal.
# Every text value below is measured at >=4.5:1 against the surface it sits on.
# Matches the Prisma AIRS demo portal: light paper, white cards, generous radii, soft
# shadows. Brand coral measures 3.2:1 on white, so it is reserved for display type and
# graphics; small accent text uses the deeper --signal-text.
PALETTES = {
    "light": {
        "void": "#FAFAF9", "sunken": "#F4F4F2", "surface": "#FFFFFF", "surface-2": "#F4F4F2",
        "line": "#E7E7E4", "line-lit": "#D6D6D1",
        "text": "#0F1115", "text-dim": "#3F444E", "text-faint": "#666C78",
        "signal": "#FA582D", "signal-text": "#C2410C", "on-signal": "#FFFFFF",
        "signal-bg": "rgba(250,88,45,.08)",
        "signal-glow-0": "rgba(250,88,45,.30)", "signal-glow-1": "rgba(250,88,45,.22)",
        "ok": "#16A34A", "ok-text": "#15803D", "ok-bg": "rgba(22,163,74,.10)",
        "alert": "#C62828", "alert-bg": "rgba(198,40,40,.07)",
        "ink": "#0F1115", "on-ink": "#FFFFFF",
        "shadow-sm": "0 1px 2px rgba(15,17,21,.04), 0 1px 3px rgba(15,17,21,.06)",
        "shadow-md": "0 6px 24px -8px rgba(15,17,21,.12)",
    },
    "dark": {
        "void": "#0F1115", "sunken": "#14171C", "surface": "#181B21", "surface-2": "#1F232B",
        "line": "#282D36", "line-lit": "#3A4049",
        "text": "#F5F6F7", "text-dim": "#A8AEB8", "text-faint": "#868D99",
        "signal": "#FF7A52", "signal-text": "#FF9270", "on-signal": "#0F1115",
        "signal-bg": "rgba(255,122,82,.12)",
        "signal-glow-0": "rgba(255,122,82,.45)", "signal-glow-1": "rgba(255,122,82,.40)",
        "ok": "#34D399", "ok-text": "#4ADE80", "ok-bg": "rgba(52,211,153,.12)",
        "alert": "#FF6B6B", "alert-bg": "rgba(255,107,107,.10)",
        "ink": "#F5F6F7", "on-ink": "#0F1115",
        "shadow-sm": "0 1px 2px rgba(0,0,0,.3)",
        "shadow-md": "0 6px 24px -8px rgba(0,0,0,.5)",
    },
}


def theme_mode() -> str:
    """Follow whichever theme Streamlit is actually rendering, so the custom CSS and the
    built-in widgets can never disagree."""
    try:
        return "dark" if st.context.theme.type == "dark" else "light"
    except Exception:
        return "light"


MODE = theme_mode()
_TOKENS = "".join(f"  --{k}: {v};\n" for k, v in PALETTES[MODE].items())

THEME = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
__TOKENS__  --r-card: 14px;
  --r-sm: 9px;
  --r-pill: 999px;
  color-scheme: __MODE__;
}

html, body, [data-testid="stAppViewContainer"] {
  background: var(--void);
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stMainBlockContainer"] { padding-top: 1.4rem; max-width: 1140px; }
::selection { background: var(--signal); color: #fff; }

/* ---------- top bar ---------- */
.topbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 1rem; padding: .7rem 1rem; margin-bottom: 1.8rem;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--r-pill); box-shadow: var(--shadow-sm);
}
.brand { display: flex; align-items: center; gap: .6rem; font-weight: 600; font-size: .9rem; color: var(--text); }
.brand i { width: 9px; height: 9px; border-radius: 50%; background: var(--signal); font-style: normal; }
.brand span { font-weight: 400; font-size: .74rem; color: var(--text-faint); }
.whoami { display: flex; align-items: center; gap: .55rem; }
.whoami > span:first-child {
  font-family: 'JetBrains Mono', monospace; font-size: .68rem; color: var(--text-faint);
}
.tag {
  font-size: .68rem; font-weight: 500; letter-spacing: .01em;
  border: 1px solid var(--line); border-radius: var(--r-pill);
  padding: .2rem .6rem; color: var(--text-dim); background: var(--surface-2);
  white-space: nowrap;
}
.tag.on { background: var(--ok-bg); border-color: transparent; color: var(--ok-text); }
.tag.hot { background: var(--signal-bg); border-color: transparent; color: var(--signal-text); }

/* ---------- hero ---------- */
.pill-eyebrow {
  display: inline-flex; align-items: center; gap: .45rem;
  border: 1px solid var(--line); border-radius: var(--r-pill);
  padding: .3rem .75rem; background: var(--surface);
  font-size: .68rem; font-weight: 500; letter-spacing: .08em; text-transform: uppercase;
  color: var(--text-dim); margin-bottom: 1.2rem; box-shadow: var(--shadow-sm);
}
.pill-eyebrow i { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); font-style: normal; }
.hero { margin-top: 2.4rem; }  /* clears the fixed sign-in button */
.hero h1 {
  font-size: 2.9rem; font-weight: 800; line-height: 1.1; letter-spacing: -.035em;
  color: var(--text); margin: 0 0 1rem;
}
.hero h1 em { font-style: normal; color: var(--signal); }
.hero p { font-size: .95rem; line-height: 1.65; color: var(--text-dim); margin: 0 0 1.5rem; max-width: 56ch; }

/* ---------- buttons ---------- */
.btn {
  display: inline-flex; align-items: center; gap: .5rem; text-decoration: none;
  border-radius: var(--r-pill); padding: .65rem 1.2rem;
  font-family: 'Inter', sans-serif; font-size: .84rem; font-weight: 600;
  border: 1px solid transparent; transition: transform .15s ease, box-shadow .15s ease;
}
.btn-primary { background: var(--ink); color: var(--on-ink) !important; }
.btn-primary:hover { transform: translateY(-1px); box-shadow: var(--shadow-md); }
.btn-ghost {
  background: var(--surface); border-color: var(--line); color: var(--text) !important;
  box-shadow: var(--shadow-sm);
}
.btn-ghost:hover { border-color: var(--line-lit); }
.btn:focus-visible { outline: 2px solid var(--signal); outline-offset: 3px; }
.btn img { width: 17px; height: 17px; display: block; }
.btn-row { display: flex; gap: .6rem; flex-wrap: wrap; margin-bottom: 1.8rem; }

/* ---------- status card (pre-flight) ---------- */
.card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--r-card); box-shadow: var(--shadow-sm);
  padding: 1.1rem 1.2rem; margin-bottom: 1.2rem;
}
.card-head {
  display: flex; align-items: baseline; justify-content: space-between; gap: 1rem;
  margin-bottom: .2rem;
}
.card-title { font-size: .92rem; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: .45rem; }
.card-when { font-family: 'JetBrains Mono', monospace; font-size: .66rem; color: var(--text-faint); }
.card-sub { font-size: .74rem; color: var(--text-faint); margin-bottom: .9rem; }
.card-note {
  font-size: .72rem; color: var(--text-faint); line-height: 1.6;
  margin-top: .9rem; padding-top: .8rem; border-top: 1px solid var(--line);
}
.card-note code {
  font-family: 'JetBrains Mono', monospace; font-size: .7rem; color: var(--text-dim);
  background: var(--surface-2); border-radius: 4px; padding: .05rem .3rem;
}
.srow {
  display: flex; align-items: center; gap: .6rem; padding: .4rem 0;
  border-bottom: 1px solid var(--line);
}
.srow:last-of-type { border-bottom: 0; }
.srow i { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); flex: 0 0 auto; font-style: normal; }
.srow i.warn { background: var(--signal); }
.srow .k { font-size: .82rem; font-weight: 500; color: var(--text); flex: 1; }
.srow .v {
  font-family: 'JetBrains Mono', monospace; font-size: .7rem; color: var(--text-faint);
  text-align: right; word-break: break-all;
}

/* ---------- metrics ---------- */
.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.6rem; margin: 0 0 1.8rem; }
.metric-n {
  font-size: 2.1rem; font-weight: 700; letter-spacing: -.035em; line-height: 1;
  color: var(--text); display: block; margin-bottom: .3rem;
}
.metric-n small { font-size: .9rem; font-weight: 500; color: var(--text-faint); margin-left: .15rem; }
.metric.accent .metric-n { color: var(--signal); }
.metric-k { font-size: .72rem; color: var(--text-faint); display: block; line-height: 1.45; }
@media (max-width: 860px) { .metrics { grid-template-columns: repeat(2, 1fr); } }

/* ---------- built by ---------- */
.builtby-wrap { display: flex; justify-content: center; margin-top: -.3rem; }
.builtby {
  display: inline-flex; align-items: center; gap: .8rem;
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--r-pill); padding: .6rem 1.1rem .6rem .6rem;
  box-shadow: var(--shadow-sm);
}
.avatar {
  width: 38px; height: 38px; border-radius: 50%; flex: 0 0 auto;
  background: var(--signal); color: #fff; display: flex; align-items: center;
  justify-content: center; font-weight: 700; font-size: .8rem; letter-spacing: .02em;
}
.builtby-k { font-size: .6rem; letter-spacing: .12em; text-transform: uppercase; color: var(--text-faint); }
.builtby-n { font-size: .86rem; font-weight: 600; color: var(--text); line-height: 1.3; }
.builtby-r { font-size: .72rem; color: var(--text-faint); }

/* ---------- numbered tiles ---------- */
.tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: .8rem; margin-bottom: 1.6rem; }
.tile {
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--r-card);
  padding: 1rem 1.05rem; box-shadow: var(--shadow-sm);
  transition: transform .18s ease, box-shadow .18s ease, border-color .18s ease;
}
.tile:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: var(--line-lit); }
.tile-n {
  font-family: 'JetBrains Mono', monospace; font-size: .64rem; font-weight: 600;
  color: var(--signal-text); background: var(--signal-bg); border-radius: 5px;
  padding: .12rem .4rem; display: inline-block; margin-bottom: .6rem;
}
.tile-t { font-size: .88rem; font-weight: 600; color: var(--text); margin-bottom: .3rem; line-height: 1.3; }
.tile-d { font-size: .74rem; color: var(--text-faint); line-height: 1.55; }
@media (max-width: 900px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
.section-h { font-size: 1.15rem; font-weight: 700; letter-spacing: -.02em; margin: 0 0 .2rem; color: var(--text); }
.section-s { font-size: .8rem; color: var(--text-faint); margin: 0 0 1rem; }

/* ---------- request flow ---------- */
.flow { display: flex; flex-direction: column; gap: .9rem; }
.req {
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--r-card);
  box-shadow: var(--shadow-sm); overflow: hidden;
}
.req.lit { border-color: var(--signal); box-shadow: 0 0 0 3px var(--signal-bg), var(--shadow-sm); }
.req.bad { border-color: var(--alert); }
.req-head {
  display: flex; align-items: center; gap: .6rem; flex-wrap: wrap;
  padding: .7rem 1rem; border-bottom: 1px solid var(--line); background: var(--surface-2);
}
.req-n {
  font-family: 'JetBrains Mono', monospace; font-size: .64rem; font-weight: 600;
  color: var(--text-faint); background: var(--surface); border: 1px solid var(--line);
  border-radius: 5px; padding: .12rem .42rem;
}
.req-models { font-size: .78rem; color: var(--text-dim); flex: 1; }
.req-models b { color: var(--text); font-weight: 600; }
.req-models .strike { text-decoration: line-through; color: var(--text-faint); }
.req-models .sig { color: var(--signal-text); font-weight: 600; }
.req-when { font-family: 'JetBrains Mono', monospace; font-size: .64rem; color: var(--text-faint); }
.req-body { padding: .9rem 1rem 1rem; }
.enforce {
  display: inline-flex; align-items: center; gap: .45rem; margin-bottom: .8rem;
  background: var(--signal-bg); color: var(--signal-text); border-radius: var(--r-pill);
  padding: .3rem .7rem; font-size: .74rem; font-weight: 600;
  animation: ignite .45s cubic-bezier(.22,.61,.36,1) both;
}
.enforce i { width: 6px; height: 6px; border-radius: 50%; background: var(--signal); font-style: normal; }
@keyframes ignite {
  from { opacity: 0; box-shadow: 0 0 0 0 var(--signal-glow-0); }
  to   { opacity: 1; box-shadow: 0 0 18px -4px var(--signal-glow-1); }
}
.refuse {
  background: var(--alert-bg); color: var(--alert); border-radius: var(--r-sm);
  padding: .65rem .8rem; font-family: 'JetBrains Mono', monospace;
  font-size: .72rem; line-height: 1.6;
}
.turn-k {
  font-size: .62rem; font-weight: 600; letter-spacing: .1em; text-transform: uppercase;
  color: var(--text-faint); display: block; margin-bottom: .3rem;
}
.ask { font-size: .86rem; color: var(--text-dim); margin-bottom: .9rem; line-height: 1.6; }
.say { font-size: .9rem; color: var(--text); line-height: 1.7; }
.say p:last-child { margin-bottom: 0; }
.say code {
  font-family: 'JetBrains Mono', monospace; font-size: .8rem;
  background: var(--surface-2); border-radius: 4px; padding: .08rem .32rem;
}
.empty {
  border: 1px dashed var(--line-lit); border-radius: var(--r-card);
  padding: 2.4rem 1.5rem; text-align: center; color: var(--text-faint); font-size: .82rem;
}
.empty b { display: block; color: var(--text); font-size: .95rem; font-weight: 600; margin-bottom: .3rem; }

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] { background: var(--sunken); border-right: 1px solid var(--line); }
[data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: .55rem; }
.eyebrow {
  font-size: .62rem; font-weight: 600; letter-spacing: .12em; text-transform: uppercase;
  color: var(--text-faint); margin: 1.3rem 0 .5rem;
}
/* labelled data rows: every value gets its own line and its own key, so a value can be
   pointed at during a demo instead of being read out of a paragraph */
.dl {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--r-sm); overflow: hidden; box-shadow: var(--shadow-sm);
}
.dl-row {
  display: flex; flex-direction: column; gap: .12rem;
  padding: .45rem .65rem; border-bottom: 1px solid var(--line);
}
.dl-row:last-child { border-bottom: 0; }
.dl-k {
  font-size: .56rem; font-weight: 600; letter-spacing: .11em; text-transform: uppercase;
  color: var(--text-faint);
}
.dl-v { font-size: .82rem; font-weight: 500; color: var(--text); word-break: break-all; line-height: 1.35; }
.dl-v.big { font-size: .92rem; font-weight: 600; }
.dl-v.mono { font-family: 'JetBrains Mono', monospace; font-size: .74rem; font-weight: 400; }
.dl-v.ok { color: var(--ok-text); }
.dl-v.sig { color: var(--signal-text); }
.dl-v.dim { color: var(--text-dim); font-weight: 400; font-size: .76rem; }
.dl-row.hi { background: var(--signal-bg); }
.dl-row.good { background: var(--ok-bg); }

.ledger { border: 1px solid var(--line); border-radius: var(--r-sm); overflow: hidden; background: var(--surface); }
.ledger-row { padding: .5rem .7rem; display: flex; flex-direction: column; gap: .1rem; }
.ledger-k { font-size: .6rem; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--text-faint); }
.ledger-v { font-size: .8rem; font-weight: 500; color: var(--text); }
.ledger-row.struck .ledger-v { color: var(--text-faint); text-decoration: line-through; }
.ledger-row.held { background: var(--signal-bg); border-top: 1px solid var(--line); }
.ledger-row.held .ledger-v { color: var(--signal-text); }
.ledger-row.pass { background: var(--ok-bg); }
.ledger-row.pass .ledger-v { color: var(--ok-text); }
.ledger-note { font-size: .68rem; color: var(--text-faint); line-height: 1.5; padding: .45rem .7rem .55rem; border-top: 1px solid var(--line); }

/* ---------- streamlit widgets ---------- */
.stButton > button {
  font-family: 'Inter', sans-serif !important; font-size: .78rem !important; font-weight: 600 !important;
  border-radius: var(--r-pill) !important; border: 1px solid var(--line) !important;
  background: var(--surface) !important; color: var(--text) !important;
}
.stButton > button:hover { border-color: var(--signal) !important; color: var(--signal-text) !important; }
/* our own disclosure: a plain <details>, so opening it never round-trips to Streamlit */
.disc {
  border: 1px solid var(--line); border-radius: var(--r-card); background: var(--surface);
  box-shadow: var(--shadow-sm); margin-bottom: 1.2rem; overflow: hidden;
}
.disc > summary {
  cursor: pointer; list-style: none; padding: .85rem 1.1rem;
  font-size: .86rem; font-weight: 600; color: var(--text);
  display: flex; align-items: center; gap: .55rem;
}
.disc > summary::-webkit-details-marker { display: none; }
.disc > summary::before {
  content: "›"; display: inline-block; font-size: 1rem; color: var(--text-faint);
  transition: transform .18s ease;
}
.disc[open] > summary::before { transform: rotate(90deg); }
.disc > summary:hover { color: var(--signal-text); }
.disc > summary:focus-visible { outline: 2px solid var(--signal); outline-offset: -2px; }
.disc-body { padding: 0 1.1rem 1.1rem; }
.cb {
  white-space: pre; overflow-x: auto; margin: 0 0 1rem;
  background: var(--sunken); border: 1px solid var(--line); border-radius: var(--r-sm);
  padding: .8rem .9rem; font-family: 'JetBrains Mono', monospace;
  font-size: .72rem; line-height: 1.6; color: var(--text-dim);
}
.cb code { font-family: inherit; font-size: inherit; background: none; padding: 0; color: inherit; }

[data-testid="stExpander"] {
  border: 1px solid var(--line) !important; border-radius: var(--r-card) !important;
  background: var(--surface) !important; box-shadow: var(--shadow-sm); margin-bottom: 1.2rem;
}
[data-testid="stExpander"] summary {
  font-family: 'Inter', sans-serif !important; font-size: .8rem !important;
  font-weight: 600 !important; color: var(--text) !important;
}
[data-testid="stExpander"] summary:hover { color: var(--signal-text) !important; }
[data-testid="stCode"] {
  border: 1px solid var(--line); border-radius: var(--r-sm); background: var(--sunken); margin-bottom: 1rem;
}
[data-testid="stCode"] pre { background: transparent !important; }
[data-testid="stCode"] code { font-family: 'JetBrains Mono', monospace !important; font-size: .72rem !important; }
/* the lifecycle step picker, styled as a pill row rather than default radios */
[data-testid="stExpander"] [role="radiogroup"] { gap: .35rem !important; flex-wrap: wrap; }
[data-testid="stExpander"] [role="radiogroup"] label {
  border: 1px solid var(--line); border-radius: var(--r-pill);
  padding: .22rem .7rem; background: var(--surface-2); cursor: pointer;
}
[data-testid="stExpander"] [role="radiogroup"] label:hover { border-color: var(--line-lit); }
[data-testid="stExpander"] [role="radiogroup"] label > div:first-child { display: none; }
[data-testid="stExpander"] [role="radiogroup"] label p {
  font-size: .72rem !important; font-weight: 500; margin: 0 !important; color: var(--text-dim);
}
[data-testid="stExpander"] [role="radiogroup"] label:has(input:checked) {
  background: var(--signal-bg); border-color: var(--signal);
}
[data-testid="stExpander"] [role="radiogroup"] label:has(input:checked) p { color: var(--signal-text); }
[data-testid="stForm"] { border: 0 !important; padding: 0 !important; }
[data-testid="stForm"] input {
  font-family: 'Inter', sans-serif !important; font-size: .9rem !important;
  border-radius: var(--r-pill) !important; padding: .65rem 1.1rem !important;
}
[data-testid="stForm"] button {
  border-radius: var(--r-pill) !important; background: var(--ink) !important;
  color: var(--on-ink) !important; border: 1px solid transparent !important;
  font-weight: 600 !important;
}
[data-testid="stForm"] button:hover { box-shadow: var(--shadow-md); }

/* ---------- sign-in button ---------- */
.signin-wrap { position: fixed; top: .5rem; right: 3.8rem; z-index: 1000001; }
@media (max-width: 760px) { .signin-wrap { right: .75rem; top: 3.6rem; } }

/* ---------- inspector ---------- */
.stage-meta { font-size: .68rem; color: var(--text-faint); margin-bottom: .6rem; }
.anat { border: 1px solid var(--line); border-radius: var(--r-sm); background: var(--sunken); padding: .7rem .8rem; margin-bottom: 1rem; }
.anat-cap { font-size: .62rem; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; color: var(--text-faint); margin-bottom: .5rem; }
.anat-row { display: flex; gap: .6rem; align-items: baseline; margin-bottom: .3rem; }
.anat-k { flex: 0 0 68px; font-size: .62rem; font-weight: 600; text-transform: uppercase; text-align: right; color: var(--text-faint); }
.anat-k.h, .anat-k.p { color: var(--text-dim); }
.anat-k.s { color: var(--signal-text); }
.anat-row code { font-family: 'JetBrains Mono', monospace; font-size: .66rem; line-height: 1.5; word-break: break-all; color: var(--text-dim); background: none; padding: 0; }
.anat-row:nth-child(4) code { color: var(--signal-text); }
.anat-note { font-size: .72rem; color: var(--text-faint); margin-top: .55rem; padding-top: .5rem; border-top: 1px solid var(--line); line-height: 1.55; }
.kv { border: 1px solid var(--line); border-radius: var(--r-sm); margin-bottom: 1rem; overflow: hidden; }
.kv-row { display: flex; gap: 1rem; padding: .4rem .75rem; border-bottom: 1px solid var(--line); }
.kv-row:last-child { border-bottom: 0; }
.kv-k { flex: 0 0 210px; font-size: .68rem; font-weight: 500; color: var(--text-faint); }
.kv-v { font-family: 'JetBrains Mono', monospace; font-size: .7rem; color: var(--text); word-break: break-all; }
.walk { list-style: none; margin: 0 0 .9rem; padding: 0; }
.walk li { display: flex; gap: .6rem; margin-bottom: .45rem; font-size: .8rem; line-height: 1.55; color: var(--text-dim); }
.walk .ord {
  flex: 0 0 20px; height: 20px; border-radius: 5px; font-family: 'JetBrains Mono', monospace;
  font-size: .6rem; font-weight: 600; color: var(--signal-text); background: var(--signal-bg);
  display: flex; align-items: center; justify-content: center;
}
.walk code, .cfg-note code {
  font-family: 'JetBrains Mono', monospace; font-size: .72rem; color: var(--text);
  background: var(--surface-2); border-radius: 4px; padding: .05rem .3rem;
}
.walk b { color: var(--signal-text); }
.cfg-note { font-size: .78rem; line-height: 1.6; color: var(--text-faint); margin: 0; }

@media (prefers-reduced-motion: reduce) {
  .enforce, .tile, .btn { animation: none !important; transition: none !important; }
}
</style>
"""
st.markdown(THEME.replace("__TOKENS__", _TOKENS).replace("__MODE__", MODE),
            unsafe_allow_html=True)
st.markdown(THEME.replace("__TOKENS__", _TOKENS).replace("__MODE__", MODE),
            unsafe_allow_html=True)


def esc(value) -> str:
    return html.escape(str(value))


def clock(ts) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except Exception:
        return "--:--:--"


def md_to_html(text: str) -> str:
    """Assistant replies arrive as markdown; raw HTML blocks don't get markdown-processed,
    so convert here rather than handing the text back to Streamlit."""
    return markdown.markdown(
        text or "", extensions=["fenced_code", "tables", "nl2br"], output_format="html"
    )


def preflight_card(user: dict = None) -> str:
    """The reference portal's pre-flight panel: one row per moving part, green when the
    real value is present rather than assumed."""
    mins = token_lifetime(user["portkey_jwt"]) if user else None
    rules = len(CONDITIONS) + 1
    rows = [
        ("AIRS AI Gateway", esc(PORTKEY_BASE_URL.replace("https://", ""))),
        ("Provider integration", esc(PORTKEY_PROVIDER)),
        ("Routing config", esc(PORTKEY_DEFAULT_CONFIG_ID)),
        ("Signing key", f"rs256 &middot; kid {esc(short(KID, 6, 4))}"),
        ("Models reachable", f"{len(AVAILABLE_MODELS)} behind {rules} rules"),
        ("Credential", f"{mins} min remaining" if mins is not None else "minted per sign-in"),
    ]
    body = "".join(
        f'<div class="srow"><i></i><span class="k">{k}</span><span class="v">{v}</span></div>'
        for k, v in rows
    )
    return f"""
<div class="card">
  <div class="card-head">
    <span class="card-title">Pre-flight</span>
    <span class="card-when">checked {clock(time.time())}</span>
  </div>
  <div class="card-sub">Read from this app's configuration &mdash; set, not probed.</div>
  {body}
  <div class="card-note">The gateway is the enforcement point. This panel only shows what
  the app will send; the routing decision is made server side against the
  <code>{esc(PORTKEY_DEFAULT_CONFIG_ID)}</code> config.</div>
</div>"""


LIFECYCLE_TILES = [
    ("01", "Identity", "Microsoft Entra ID authenticates the user and returns the app role."),
    ("02", "Attributes", "Department is read from Microsoft Graph; it is not a token claim."),
    ("03", "Credential", "A short-lived RS256 token is minted with the claims sealed inside."),
    ("04", "Enforcement", "The gateway verifies the signature, then routes on what it read."),
]


def tiles_section() -> str:
    tiles = "".join(
        f'<div class="tile"><span class="tile-n">{n}</span>'
        f'<div class="tile-t">{esc(t)}</div><div class="tile-d">{esc(d)}</div></div>'
        for n, t, d in LIFECYCLE_TILES
    )
    return ('<div class="section-h">A request, in running order</div>'
            '<div class="section-s">Every step runs for real on each prompt you send.</div>'
            f'<div class="tiles">{tiles}</div>')


def built_by() -> str:
    return """
<div class="builtby">
  <div class="avatar">SU</div>
  <div>
    <div class="builtby-k">Built by</div>
    <div class="builtby-n">Sergei (SUDO) Udovenko</div>
    <div class="builtby-r">Systems Engineer &middot; Palo Alto Networks</div>
  </div>
</div>"""


def dl(rows) -> str:
    """rows: (label, value, css classes on the value, css classes on the row)."""
    out = []
    for label, value, vcls, rcls in rows:
        out.append(
            f'<div class="dl-row {rcls}"><span class="dl-k">{esc(label)}</span>'
            f'<span class="dl-v {vcls}">{value}</span></div>'
        )
    return f'<div class="dl">{"".join(out)}</div>'


def sidebar_facts(user: dict) -> str:
    """Session preamble as labelled rows, so each value is individually readable."""
    mins = token_lifetime(user["portkey_jwt"])
    if mins is None:
        expiry, expiry_cls = "unknown", "dim"
    else:
        expiry, expiry_cls = f"{mins} min", "sig" if mins <= 15 else "ok"

    policy_model, why = resolve_policy(user["email"], user["role"])
    if policy_model is None:
        effect = ("Exempt — your choice is sent through" if why == "exempt"
                  else "Not pinned to a single model")
        effect_cls, row_cls = "ok", "good"
    else:
        effect = f"Pinned to {esc(MODEL_LABELS.get(policy_model, policy_model))}"
        effect_cls, row_cls = "sig", "hi"

    role = "Administrator" if user["role"] == "Admin" else "Standard user"

    identity = dl([
        ("Name", esc(user["name"]), "big", ""),
        ("Email", esc(user["email"]), "mono", ""),
        ("App role", esc(role), "", ""),
        ("Department", esc(user["department"]), "", ""),
    ])
    credential = dl([
        ("Algorithm", "RS256", "mono", ""),
        ("Key id", esc(short(KID, 8, 4)), "mono", ""),
        ("Expires in",
         f'<span role="status" aria-atomic="true" '
         f'aria-label="Credential expires in {esc(str(mins))} minutes">{esc(expiry)}</span>',
         expiry_cls, ""),
        ("Sealed claims", "email · user_role · department · config_id", "dim", ""),
    ])
    policy = dl([
        ("Config", esc(PORTKEY_DEFAULT_CONFIG_ID), "mono", ""),
        ("Matched on", "email address" if why == "exempt" else "app role", "dim", ""),
        ("Effect", effect, effect_cls, row_cls),
    ])
    return (f'<div class="eyebrow">Identity</div>{identity}'
            f'<div class="eyebrow">Credential</div>{credential}'
            f'<div class="eyebrow">Policy</div>{policy}')


def render_trace(user: dict) -> str:
    """The request flow: one card per call, coral only when policy acted."""
    calls = st.session_state.get("lifecycle_calls", [])
    if not calls:
        return ('<div class="empty"><b>No requests yet</b>'
                'Pick a model your role does not allow, then watch which one answers.</div>')

    cards = []
    for i, c in enumerate(calls, start=1):
        requested = MODEL_LABELS.get(
            c["model_sent"].split("/", 1)[-1], c["model_sent"].split("/", 1)[-1])
        served_id = c.get("served_model")
        served = MODEL_LABELS.get(served_id, served_id)
        overridden = bool(served_id) and served != requested
        failed = c.get("outcome") == "rejected"

        if failed:
            models = f'requested <b>{esc(requested)}</b> &middot; refused'
            banner = f'<div class="refuse">{esc(c.get("error", "unknown error"))}</div>'
            state = "bad"
        elif overridden:
            models = (f'<span class="strike">{esc(requested)}</span> '
                      f'&rarr; <span class="sig">{esc(served)}</span>')
            banner = (f'<div class="enforce" role="status" aria-atomic="true"><i></i>'
                      f'Policy replaced your choice with {esc(served)}</div>')
            state = "lit"
        else:
            models = f'<b>{esc(served or requested)}</b>'
            banner = ""
            state = ""

        took = f' &middot; {c["elapsed_ms"]} ms' if c.get("elapsed_ms") else ""
        body = banner
        body += (f'<span class="turn-k">Prompt</span>'
                 f'<div class="ask">{esc(c.get("prompt", ""))}</div>')
        if c.get("reply"):
            body += (f'<span class="turn-k">Response</span>'
                     f'<div class="say">{md_to_html(c["reply"])}</div>')

        cards.append(f"""
<div class="req {state}">
  <div class="req-head">
    <span class="req-n">{i:02d}</span>
    <span class="req-models">{models}{took}</span>
    <span class="req-when">{clock(c.get("at", time.time()))}</span>
  </div>
  <div class="req-body">{body}</div>
</div>""")
    return f'<div class="flow">{"".join(cards)}</div>'


def topbar(user: dict) -> str:
    tag = "administrator" if user["role"] == "Admin" else "standard user"
    return f"""
<div class="topbar">
  <div class="brand"><i></i>Enterprise AI Access<span>&middot; JWT gateway demo</span></div>
  <div class="whoami">
    <span>{esc(PORTKEY_BASE_URL.replace("https://", ""))}</span>
    <span class="tag on">credential verified</span>
    <span class="tag">{esc(tag)}</span>
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


def metrics_band() -> str:
    """Key indicators. Every number is derived from live configuration, so it cannot drift
    away from what the app actually enforces."""
    rules = len(CONDITIONS) + 1  # conditions plus the default branch
    return f"""
<div class="metrics">
  <div class="metric accent">
    <span class="metric-n">0</span><span class="metric-k">API keys issued</span>
  </div>
  <div class="metric">
    <span class="metric-n">{len(AVAILABLE_MODELS)}</span><span class="metric-k">models reachable</span>
  </div>
  <div class="metric">
    <span class="metric-n">{rules}</span><span class="metric-k">routing rules</span>
  </div>
  <div class="metric">
    <span class="metric-n">60<small>min</small></span><span class="metric-k">credential life</span>
  </div>
</div>"""


def code_block(text: str, lang: str = "") -> str:
    """A code block we own, so it can live inside our own markup."""
    return (f'<pre class="cb" data-lang="{esc(lang)}"><code>{esc(text)}</code></pre>')


def disclosure(summary: str, body: str, open_: bool = False) -> str:
    """Native <details>: the browser handles the toggle, so Streamlit never reruns and
    nothing gets scrolled into view."""
    return (f'<details class="disc"{" open" if open_ else ""}>'
            f'<summary>{esc(summary)}</summary>'
            f'<div class="disc-body">{body}</div></details>')


def render_config_panel(expanded: bool = False) -> None:
    body = (
        config_walkthrough()
        + code_block(json.dumps(GATEWAY_CONFIG, indent=2), "json")
        + f'<p class="cfg-note">Stored in the gateway as '
          f'<code>{esc(PORTKEY_DEFAULT_CONFIG_ID)}</code>. Every request carries this id '
          f'inside its signed token, so the policy travels with the caller instead of '
          f'being chosen by them.</p>'
    )
    st.markdown(disclosure("The routing policy the gateway enforces", body, expanded),
                unsafe_allow_html=True)


def jwt_anatomy(parts: dict, caption: str) -> str:
    """Shows a token as the three segments a verifier separates it into."""
    return f"""
<div class="anat">
  <div class="anat-cap">{esc(caption)}</div>
  <div class="anat-row"><span class="anat-k h">header</span><code>{esc(parts['header_b64'])}</code></div>
  <div class="anat-row"><span class="anat-k p">payload</span><code>{esc(parts['payload_b64'])}</code></div>
  <div class="anat-row"><span class="anat-k s">signature</span><code>{esc(parts['signature_b64'])}</code></div>
  <div class="anat-note">Signed input is <code>header.payload</code> &mdash;
  {len(parts['signing_input'])} characters hashed with SHA-256, then RSA-signed into
  {parts['signature_bytes']} bytes.</div>
</div>"""


def kv(rows: dict) -> str:
    cells = "".join(
        f'<div class="kv-row"><span class="kv-k">{esc(k)}</span>'
        f'<span class="kv-v">{esc(v)}</span></div>'
        for k, v in rows.items()
    )
    return f'<div class="kv">{cells}</div>'


def stage_meta(entry: dict) -> str:
    when = time.strftime("%H:%M:%S", time.localtime(entry["at"]))
    took = "" if entry["elapsed_ms"] is None else f" &nbsp;·&nbsp; took {entry['elapsed_ms']} ms"
    return f'<div class="stage-meta">captured {when}{took}</div>'


def render_lifecycle_inspector() -> None:
    stages = st.session_state.get("lifecycle", {})
    calls = st.session_state.get("lifecycle_calls", [])
    if not stages:
        return

    with st.expander("Token lifecycle — every artifact from this session", expanded=False):
        st.markdown(
            '<p class="cfg-note">Real values captured from this sign-in, not examples. '
            'The client secret is the one thing never recorded: it travels only in the '
            'back-channel POST and never becomes part of an artifact.</p>',
            unsafe_allow_html=True,
        )
        # Deliberately not st.tabs: it calls scrollIntoView on the selected tab whenever
        # it is laid out, which drags the page down to this panel. A radio does not.
        STEPS = ["1 · Authorize", "2 · Callback", "3 · Exchange",
                 "4 · Claims", "5 · Graph", "6 · Minting", "7 · Gateway"]
        sel = STEPS.index(st.radio("Lifecycle step", STEPS, horizontal=True,
                                   label_visibility="collapsed"))

        if sel == 0:
            entry = stage("authorize")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                if not d["matched_state"]:
                    st.warning(d["note"])
                else:
                    st.caption(d["note"])
                if d.get("url"):
                    st.code(d["url"], language="text")
                    st.markdown("**Query parameters Microsoft received**")
                    st.code(json.dumps(d["params"], indent=2), language="json")

        if sel == 1:
            entry = stage("callback")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                st.caption(d["note"])
                st.code(d["redirect_url"], language="text")
                st.markdown(kv({
                    "authorization code": d["code"],
                    "code length": f"{d['code_length']} chars",
                    "state returned": d["state"] or "none",
                    "state matches our request": "yes" if d["state_matches_request"] else "no",
                }), unsafe_allow_html=True)

        if sel == 2:
            entry = stage("exchange")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                st.caption(d["note"])
                if d.get("error"):
                    st.error(f"{d['error']}: {d.get('error_description')}")
                st.markdown(kv({
                    "token type": d.get("token_type") or "-",
                    "expires in": f"{d.get('expires_in')} s",
                    "scope granted": d.get("scope") or "-",
                    "keys returned": ", ".join(d.get("keys_returned", [])),
                }), unsafe_allow_html=True)
                for label, key in (("ID token", "id_token"), ("Graph access token", "access_token")):
                    parts = d.get(key)
                    if not parts:
                        continue
                    st.markdown(f"**{label}**")
                    st.markdown(jwt_anatomy(parts, f"{label} as issued by Microsoft"),
                                unsafe_allow_html=True)
                    st.code(json.dumps(parts["header"], indent=2), language="json")
                    st.code(json.dumps(parts["payload"], indent=2), language="json")

        if sel == 3:
            entry = stage("claims")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                st.caption(d["note"])
                st.markdown(kv({
                    "email resolved from claim": d["email_resolved_from"] or "none matched",
                    "email": d["email"],
                    "subject": d["sub"],
                    "roles claim present": "yes" if d["roles_claim_present"] else "no",
                    "roles": ", ".join(d["roles_claim"]) or "empty",
                    "role decided": d["role_decision"],
                    "audience": str(d["audience"]),
                    "issued / expires": f"{d['issued_at']} - {d['expires_at']}",
                }), unsafe_allow_html=True)
                st.markdown("**Every claim in the ID token**")
                st.code(json.dumps(d["all_id_token_claims"], indent=2, default=str), language="json")

        if sel == 4:
            entry = stage("graph")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                st.caption(d["note"])
                st.markdown(kv({
                    "status": str(d.get("status_code", d.get("exception", "-"))),
                    "department used": d["department_used"],
                }), unsafe_allow_html=True)
                if d.get("request_url"):
                    st.code(f"GET {d['request_url']}", language="text")
                    st.markdown("**Request headers**")
                    st.code(json.dumps(d["request_headers"], indent=2), language="json")
                    st.markdown("**Response body**")
                    st.code(json.dumps(d["response_body"], indent=2, default=str), language="json")

        if sel == 5:
            entry = stage("mint")
            if entry:
                d = entry["data"]
                st.markdown(stage_meta(entry), unsafe_allow_html=True)
                st.caption(d["note"])
                st.markdown(jwt_anatomy(d["jwt"], "Minted by this application"),
                            unsafe_allow_html=True)
                st.markdown("**JOSE header**")
                st.code(json.dumps(d["jwt"]["header"], indent=2), language="json")
                st.markdown("**Payload — the claims the gateway will route on**")
                st.code(json.dumps(d["jwt"]["payload"], indent=2), language="json")
                st.markdown("**Public key the gateway verifies against**")
                st.code(json.dumps(d["jwks_entry"], indent=2), language="json")
                st.markdown(kv({
                    "kid in token header": d["kid_in_header"],
                    "kid in registered JWKS": d["kid_in_jwks"],
                    "match": "yes" if d["kid_match"] else "NO — every request will 401",
                    "modulus length": f"{d['modulus_length']} chars"
                                      f"{'' if d['modulus_length'] == 342 else '  (expected 342 — truncated?)'}",
                    "private key": d["private_key_path"],
                }), unsafe_allow_html=True)

        if sel == 6:
            if not calls:
                st.caption("Send a message and the request and response land here.")
            else:
                labels = [
                    f"{i + 1}. {c['model_sent'].split('/')[-1]} → "
                    f"{c.get('served_model') or c.get('outcome', '?')}"
                    for i, c in enumerate(calls)
                ]
                pick = st.selectbox("Request", options=list(range(len(calls)))[::-1],
                                    format_func=lambda i: labels[i])
                c = calls[pick]
                st.caption(c.get("note", ""))
                st.markdown(kv({
                    "outcome": c.get("outcome", "-"),
                    "model requested": c["model_sent"],
                    "model served": str(c.get("served_model", "-")),
                    "overridden by policy": "yes" if c.get("model_was_overridden") else "no",
                    "round trip": f"{c.get('elapsed_ms', '-')} ms",
                    "response id": str(c.get("response_id", "-")),
                }), unsafe_allow_html=True)
                if c.get("error"):
                    st.error(c["error"])
                st.markdown("**Request headers — the JWT is the API key**")
                st.code(json.dumps(c.get("request_headers", {}), indent=2), language="json")
                st.markdown("**Request body**")
                st.code(json.dumps(c.get("request_body", {}), indent=2, default=str), language="json")
                if c.get("response_headers"):
                    st.markdown("**Response headers from the gateway**")
                    st.code(json.dumps(c["response_headers"], indent=2, default=str), language="json")
                if c.get("usage"):
                    st.markdown("**Usage**")
                    st.code(json.dumps(c["usage"], indent=2, default=str), language="json")


@st.cache_data(show_spinner=False)
def data_uri(path: str) -> str:
    """Inlines a local image so the browser needs no extra static route."""
    return "data:image/png;base64," + base64.b64encode(Path(path).read_bytes()).decode()


def signin_button(url: str) -> str:
    mark = Path(__file__).with_name("assets") / "entra-mark.png"
    logo = f'<img src="{data_uri(str(mark))}" alt="">' if mark.exists() else ""
    return (
        f'<div class="signin-wrap"><a class="btn btn-ghost" href="{html.escape(url, quote=True)}" '
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
  margin: 0; background: __VOID__; color: __TEXT__;
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
}
.bar {
  display: flex; align-items: center; gap: .45rem; margin-bottom: .7rem; flex-wrap: wrap;
}
.bar .lab {
  font-family: 'JetBrains Mono', monospace; font-size: .56rem; letter-spacing: .18em;
  text-transform: uppercase; color: __DIM__; margin-right: .3rem;
}
.tab {
  font-family: 'JetBrains Mono', monospace; font-size: .6rem; letter-spacing: .1em;
  text-transform: uppercase; background: __SURFACE2__; color: __DIM__;
  border: 1px solid __LINE__; border-radius: 2px; padding: .3rem .6rem; cursor: pointer;
  transition: all .2s ease;
}
.tab:hover { color: __TEXT__; border-color: rgba(255,176,32,.6); }
.tab.on { color: __SIGNAL__; border-color: __SIGNAL__; background: __SIGNALBG__; }
.tab:focus-visible { outline: 2px solid __SIGNAL__; outline-offset: 2px; }
.spacer { flex: 1; }
/* cap at the natural viewBox width so the frame height stays predictable and the
   labels never scale past their designed size */
svg { width: 100%; max-width: 1000px; height: auto; display: block; margin: 0 auto; }

.card { fill: __SURFACE2__; stroke: __LINE__; transition: stroke .35s ease, fill .35s ease; }
.card.lit { stroke: __FAINT__; fill: rgba(92,101,119,.14); }
.card.hot { stroke: __SIGNAL__; fill: rgba(255,176,32,.16); }
.zone { fill: none; stroke: __SIGNAL__; stroke-dasharray: 5 4; opacity: .55; }
.panel { fill: __SURFACE__; stroke: __LINE__; }
.wire { fill: none; stroke: __LINE__; stroke-width: 1.1; transition: stroke .3s ease, opacity .3s ease; }
.wire.live { stroke: __FAINT__; opacity: 1; }
.wire.route { stroke: __SIGNAL__; }
.chip { fill: __SURFACE2__; stroke: __LINE__; transition: all .3s ease; }
.chip.on { fill: rgba(255,176,32,.14); stroke: rgba(255,176,32,.75); }

text { font-family: 'IBM Plex Sans', sans-serif; fill: __TEXT__; }
.eye {
  font-family: 'JetBrains Mono', monospace; font-size: 9.5px; letter-spacing: 1.7px;
  fill: __DIM__; text-transform: uppercase;
}
.nm { font-size: 14.5px; font-weight: 600; }
.sub { font-family: 'JetBrains Mono', monospace; font-size: 10px; fill: __DIM__; }
.chip-t { font-family: 'JetBrains Mono', monospace; font-size: 10px; fill: __DIM__; transition: fill .3s ease; }
.chip.on + .chip-t, .chip-t.on { fill: __SIGNAL__; }
.row-t { font-size: 13px; fill: __DIM__; transition: fill .3s ease, font-weight .3s ease; }
.row-t.win { fill: __SIGNAL__; font-weight: 600; }
.dot { fill: __SIGNAL__; filter: drop-shadow(0 0 5px rgba(255,176,32,.9)); }
.dot.id { fill: __FAINT__; filter: drop-shadow(0 0 5px rgba(92,101,119,.9)); }

.story {
  margin-top: .6rem; border: 1px solid __LINE__; border-radius: 3px;
  background: linear-gradient(180deg,__SURFACE__,__SUNKEN__); padding: .6rem .8rem;
  min-height: 52px; display: flex; align-items: center; gap: .7rem;
}
.story .badge {
  font-family: 'JetBrains Mono', monospace; font-size: .58rem; letter-spacing: .1em;
  text-transform: uppercase; padding: .2rem .5rem; border-radius: 2px;
  border: 1px solid rgba(255,176,32,.5); color: __SIGNAL__;
  background: rgba(255,176,32,.1); white-space: nowrap;
}
.story p { margin: 0; font-size: .78rem; line-height: 1.5; color: __DIM__; }
.story b { color: __TEXT__; }
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
  <text class="row-t" id="m0" x="758" y="88">Claude Haiku 4.5</text>
  <text class="row-t" id="m1" x="758" y="122">Claude Opus 4.8</text>
  <text class="row-t" id="m2" x="758" y="156">Claude Sonnet 5</text>
  <text class="row-t" id="m3" x="758" y="190">and 6 more models</text>

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
    note: "<b>bob@</b> picks Claude Sonnet 5. The signed token says <b>user_role: User</b>, so the gateway replaces the choice and answers with <b>Claude Haiku 4.5</b>." },
  { tag: "Administrator", win: 1,
    note: "<b>alice@</b> picks Claude Sonnet 5. The token says <b>user_role: Admin</b>, so the policy pins the request to <b>Claude Opus 4.8</b>." },
  { tag: "Exempt account", win: 2,
    note: "<b>__EXEMPT__</b> picks Claude Sonnet 5. This address is exempt from routing, so the gateway forwards the request untouched to <b>Claude Sonnet 5</b>." },
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
  ["w0","w1","w2","wg","t0","t1","t2","t3"].forEach(i => $(i).classList.remove("live","route"));
  for (let i = 0; i < 6; i++) { $("p"+i).classList.remove("on"); $("p"+i+"t").classList.remove("on"); }
  for (let i = 0; i < 4; i++) $("m"+i).classList.remove("win");
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

// Stop animating while the tab or this panel is hidden, then resume where it left off.
let pausedByVisibility = false;
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (timer !== null) { pausedByVisibility = true; stop(); }
  } else if (pausedByVisibility) {
    pausedByVisibility = false; timer = 1; $("toggle").textContent = "Pause"; loop();
  }
});

if (REDUCED) { const t = ++run; play(0, t); $("toggle").textContent = "Play"; }
else { timer = 1; loop(); }
</script></body></html>
"""


def render_flow_diagram(height: int = 560) -> None:
    # The iframe is its own document and cannot read the app's CSS variables, so the
    # active palette is substituted in at render time.
    p = PALETTES[MODE]
    html_doc = (
        FLOW_DIAGRAM
        .replace("__VOID__", p["void"]).replace("__SUNKEN__", p["sunken"])
        .replace("__SURFACE__", p["surface"]).replace("__SURFACE2__", p["surface-2"])
        .replace("__LINE__", p["line"]).replace("__LINELIT__", p["line-lit"])
        .replace("__TEXT__", p["text"]).replace("__DIM__", p["text-dim"])
        .replace("__FAINT__", p["text-faint"])
        # signal-text, not signal: the diagram paints coral onto small labels, where the
        # brand value only reaches 3.2:1 against white.
        .replace("__SIGNAL__", p["signal-text"]).replace("__SIGNALBG__", p["signal-bg"])
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
    returned_state = query_params.get("state")
    clear_lifecycle()

    # Stage 1 — the authorize request that started this, looked up by the state we minted.
    # If the sign-in page was served by an earlier process the record is gone, so fall back
    # to rebuilding an equivalent URL and say so rather than showing an empty tab.
    originating = AUTH_REQUESTS.get(returned_state)
    if originating:
        authorize_url = originating["url"]
        authorize_note = "Built by MSAL and opened in the browser. No token exists yet."
    else:
        authorize_url = msal_app.get_authorization_request_url(
            scopes=["User.Read"], redirect_uri=REDIRECT_URI,
            prompt="select_account", state=returned_state or "unavailable",
        )
        authorize_note = (
            "Rebuilt for display: the sign-in page was served by an earlier app process, "
            "so the original request was not in memory. Every parameter is identical "
            "except the nonce. Sign out and in again to capture a live one."
        )
    record_stage("authorize", {
        "matched_state": bool(originating),
        "url": authorize_url,
        "params": {
            k: v[0] if len(v) == 1 else v
            for k, v in urllib.parse.parse_qs(
                urllib.parse.urlparse(authorize_url).query).items()
        },
        "note": authorize_note,
    })

    # Stage 2 — what Microsoft handed back on the redirect
    record_stage("callback", {
        "redirect_url": f"{REDIRECT_URI}?{urllib.parse.urlencode(dict(query_params))}",
        "code": auth_code,
        "code_length": len(auth_code),
        "state": returned_state,
        "state_matches_request": bool(originating),
        "note": "The code is a single-use voucher, not a token. It is worthless without "
                "the client secret, which is why the next step happens server side.",
    })

    exchange_started = time.time()
    result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    # Stage 3 — everything the token endpoint returned
    id_token_raw = result.get("id_token")
    access_token_raw = result.get("access_token")
    record_stage("exchange", {
        "error": result.get("error"),
        "error_description": result.get("error_description"),
        "keys_returned": sorted(result.keys()),
        "token_type": result.get("token_type"),
        "expires_in": result.get("expires_in"),
        "scope": result.get("scope"),
        "id_token": split_jwt(id_token_raw) if id_token_raw else None,
        "access_token": split_jwt(access_token_raw) if access_token_raw else None,
        "note": "Two tokens arrive. The id token describes the user; the access token is "
                "addressed to Microsoft Graph. Neither is addressed to the AI gateway.",
    }, started=exchange_started)
    
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

        # Stage 4 — which claims were used, and what was decided from them
        record_stage("claims", {
            "all_id_token_claims": claims,
            "email_resolved_from": next(
                (c for c in ("preferred_username", "email", "upn") if claims.get(c)), None
            ),
            "email": user_email,
            "sub": user_sub,
            "roles_claim": assigned_roles,
            "roles_claim_present": "roles" in claims,
            "role_decision": user_role,
            "issued_at": epoch(claims.get("iat")),
            "expires_at": epoch(claims.get("exp")),
            "audience": claims.get("aud"),
            "issuer": claims.get("iss"),
            "note": "An absent roles claim is not an error here; the code falls back to "
                    "User, which is why an unassigned account looks like a normal user.",
        })
        
        # 3. Fetch Department from Microsoft Graph API ($select parameter included)
        user_department = "General"  # Fallback
        graph_started = time.time()
        graph_capture = {"attempted": True}
        try:
            graph_url = "https://graph.microsoft.com/v1.0/me?$select=department,displayName,mail,userPrincipalName"
            graph_response = requests.get(
                graph_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5
            )
            graph_capture.update({
                "request_url": graph_url,
                "request_headers": {"Authorization": f"Bearer {access_token}"},
                "status_code": graph_response.status_code,
                "response_headers": dict(graph_response.headers),
                "response_body": (
                    graph_response.json() if graph_response.headers
                    .get("content-type", "").startswith("application/json")
                    else graph_response.text
                ),
            })
            if graph_response.status_code == 200:
                profile_data = graph_response.json()
                user_department = profile_data.get("department") or "General"
        except Exception as err:
            graph_capture["exception"] = f"{type(err).__name__}: {err}"
            st.warning(f"Could not fetch department from Graph API: {err}")
        graph_capture["department_used"] = user_department
        graph_capture["note"] = (
            "Department is not a token claim, so it costs a round trip. A non-200 here "
            "falls through to the General fallback without raising."
        )
        record_stage("graph", graph_capture, started=graph_started)
        
        # 4. Mint Portkey RS256 JWT containing Metadata and Locked Config ID
        mint_started = time.time()
        portkey_jwt = mint_portkey_jwt(user_email, user_sub, user_role, user_department)

        # Stage 5 — the token this app signed, and the key a verifier will need
        minted = split_jwt(portkey_jwt)
        record_stage("mint", {
            "jwt": minted,
            "jwks_entry": JWKS_KEY,
            "kid_in_header": minted["header"].get("kid"),
            "kid_in_jwks": JWKS_KEY.get("kid"),
            "kid_match": minted["header"].get("kid") == JWKS_KEY.get("kid"),
            "modulus_length": len(JWKS_KEY.get("n", "")),
            "private_key_path": PRIVATE_KEY_PATH,
            "note": "The payload is signed, not encrypted: anyone can read these claims, "
                    "but altering one invalidates the signature. The gateway finds the "
                    "right public key by matching kid.",
        }, started=mint_started)
        
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
    auth_state = secrets.token_urlsafe(16)
    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI,
        prompt="select_account",
        state=auth_state,
    )
    AUTH_REQUESTS[auth_state] = {
        "url": auth_url,
        "params": {
            k: v[0] if len(v) == 1 else v
            for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query).items()
        },
        "at": time.time(),
    }
    for stale in list(AUTH_REQUESTS)[:-20]:
        AUTH_REQUESTS.pop(stale, None)

    st.markdown(signin_button(auth_url), unsafe_allow_html=True)

    # top, not center: expanding the policy grows the left column, and centring would
    # slide the pre-flight card down to match it.
    hero_col, card_col = st.columns([3, 2], vertical_alignment="top")
    with hero_col:
        st.markdown(
            f"""
<div class="hero">
  <div class="pill-eyebrow"><i></i>Enterprise AI Access &middot; live demo</div>
  <h1>Real prompts, real models &mdash;<br><em>routed by policy, not by trust.</em></h1>
  <p>Sign in with your organization account. Your role and department are read from the
     directory, sealed into a short-lived RS256 credential, and verified by the AI gateway
     on every prompt. Nobody is issued an API key, and the model you get is decided
     server side.</p>
  <div class="btn-row">
    <a class="btn btn-primary" href="{html.escape(auth_url, quote=True)}" target="_self">
      Start the demo</a>
    <a class="btn btn-ghost" href="https://github.com/sergeiudo/AI-Gateway-JWT-Demo"
       target="_blank" rel="noopener">View the source</a>
  </div>
</div>""",
            unsafe_allow_html=True,
        )
    with card_col:
        st.markdown(preflight_card(), unsafe_allow_html=True)
        st.markdown(f'<div class="builtby-wrap">{built_by()}</div>', unsafe_allow_html=True)

    st.markdown(tiles_section(), unsafe_allow_html=True)
    # svg is capped at its 1000x430 viewBox, so 430 + ~97px of bar and caption.
    render_flow_diagram(height=540)
    st.markdown(metrics_band(), unsafe_allow_html=True)
    render_config_panel(expanded=False)
    st.stop()

# ==========================================
# AUTHENTICATED CHAT INTERFACE
# ==========================================
user = st.session_state.user
policy_model, policy_why = resolve_policy(user["email"], user["role"])
policy_label = MODEL_LABELS.get(policy_model, policy_model)

# ---------- Sidebar : identity, policy, controls ----------
with st.sidebar:
    st.markdown(sidebar_facts(user), unsafe_allow_html=True)

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

    st.markdown(
        f'<div class="eyebrow">Appearance</div>'
        + dl([("Theme", esc(MODE), "", ""),
              ("Switch it", "Toolbar menu, then Settings", "dim", "")]),
        unsafe_allow_html=True,
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
        clear_lifecycle()
        st.rerun()

# ---------- Top bar, then the two reference panels, then the conversation ----------
st.markdown(topbar(user), unsafe_allow_html=True)
render_config_panel(expanded=False)
render_lifecycle_inspector()

st.markdown(render_trace(user), unsafe_allow_html=True)

if st.session_state.get("last_error"):
    st.error(f"The gateway refused this request. {st.session_state.last_error}")

# Deliberately not st.chat_input: that renders into Streamlit's fixed bottom container,
# which re-scrolls the page whenever content height changes — so opening a panel above
# would jump you to the end. An in-flow form has no such behaviour.
with st.form("ask", clear_on_submit=True, border=False):
    msg_col, send_col = st.columns([8, 1], vertical_alignment="bottom")
    prompt = msg_col.text_input("Message", placeholder="Ask something…",
                                label_visibility="collapsed")
    submitted = send_col.form_submit_button("Send", use_container_width=True)

if submitted and prompt.strip():
    st.session_state.last_error = None
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Initialize Portkey Client using JWT
    portkey_client = Portkey(
        api_key=user["portkey_jwt"],
        base_url=PORTKEY_BASE_URL,
        provider=PORTKEY_PROVIDER
    )

    if True:
        call = {"prompt": prompt, "model_sent": selected_model, "at": time.time()}
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

            request_headers = {
                k: v for k, v in
                (portkey_client.chat.completions.openai_client.default_headers or {}).items()
                if isinstance(v, str)
            }
            call.update({
                "request_headers": request_headers,
                "request_body": {
                    "model": selected_model,
                    "messages": payload_messages,
                    "max_tokens": 512,
                },
                "note": "The JWT travels in x-portkey-api-key. The gateway reads "
                        "portkey_oid from it, loads that org's JWKS, verifies the "
                        "signature, and only then applies the routing rules.",
            })

            call_started = time.time()
            with st.spinner("Routing through the gateway"):
                response = portkey_client.chat.completions.create(
                    model=selected_model,
                    messages=payload_messages,
                    max_tokens=512
                )
            call["elapsed_ms"] = round((time.time() - call_started) * 1000)

            reply = response.choices[0].message.content
            served_model = getattr(response, "model", None)
            try:
                call["response_headers"] = dict(response.get_headers() or {})
            except Exception as header_err:
                call["response_headers"] = {"unavailable": str(header_err)}
            call.update({
                "outcome": "accepted",
                "served_model": served_model,
                "reply": reply,
                "model_was_overridden": served_model not in (None, selected_model)
                and not selected_model.endswith(str(served_model)),
                "response_id": getattr(response, "id", None),
                "usage": getattr(getattr(response, "usage", None), "__dict__", None)
                or getattr(response, "usage", None),
                "system_fingerprint": getattr(response, "system_fingerprint", None),
            })
            st.session_state.setdefault("lifecycle_calls", []).append(call)
            st.session_state.messages.append(
                {"role": "assistant", "content": reply, "served_model": served_model}
            )
            # The trace renders above the input, so rerun to fold this turn into it.
            st.rerun()
        except Exception as e:
            call.update({"outcome": "rejected", "error": f"{type(e).__name__}: {e}"})
            st.session_state.setdefault("lifecycle_calls", []).append(call)
            st.session_state.last_error = str(e)
            st.rerun()
