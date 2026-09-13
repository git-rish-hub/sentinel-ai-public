# ============================================================
# SENTINEL//AI
# Autonomous Cyber Defense OS
#
# Capstone Project:
# Phishing Detection + Explainable Threat Intelligence
# + Cloud GenAI + Automated Incident Response
# ============================================================


# ============================================================
# IMPORTS
# ============================================================

import streamlit as st
import joblib
import re
import time
import requests
import hashlib
import os
import html
import pandas as pd
from groq import Groq


from datetime import datetime


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="SENTINEL//AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# LOAD TRAINED ASSETS
# ============================================================

model = joblib.load("sentinel_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")


# ============================================================
# CONFIGURATION
# ============================================================

GROQ_MODEL = "openai/gpt-oss-20b"


def get_secret_or_env(name):
    """Read a Streamlit secret first, then fall back to an environment variable."""
    try:
        value = st.secrets[name]
        if value:
            return str(value)
    except Exception:
        pass

    return os.getenv(name, "")


GROQ_API_KEY = get_secret_or_env("GROQ_API_KEY")
N8N_WEBHOOK_URL = get_secret_or_env("SENTINEL_N8N_WEBHOOK")


# ============================================================
# TEXT PREPROCESSING
# Same logic used during model preparation
# ============================================================

def clean_text(text):

    text = text.lower()

    text = re.sub(
        r"[^a-z\s]",
        " ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# RISK ENGINE
# ============================================================

def get_risk_level(probability):

    if probability >= 0.70:
        return "HIGH"

    elif probability >= 0.30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RESPONSE ENGINE
# ============================================================

def get_action(risk):

    if risk == "HIGH":

        return (
            "Block email and alert security team"
        )

    elif risk == "MEDIUM":

        return (
            "Hold email for manual review"
        )

    return "Allow email"


# ============================================================
# INCIDENT ID
# ============================================================

def create_scan_id(text):

    raw = (
        text
        + str(time.time())
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

    return (
        "SNT-"
        + digest[:8].upper()
    )


# ============================================================
# CLOUD AI STATUS
# ============================================================

def check_oracle():
    """Oracle is ready when the Groq API key is configured."""
    return bool(GROQ_API_KEY)


# ============================================================
# THREAT DNA
#
# This is intentionally separate from the ML model.
# It shows simple observable evidence inside the email.
# ============================================================

def analyse_threat_dna(text):

    lower = text.lower()

    categories = {

        "Urgency": [
            "urgent",
            "immediately",
            "act now",
            "within 24 hours",
            "within 12 hours",
            "within 6 hours",
            "deadline",
            "as soon as possible"
        ],

        "Credential Request": [
            "password",
            "username",
            "login",
            "sign in",
            "credentials",
            "verify account",
            "confirm account"
        ],

        "Financial Context": [
            "bank",
            "banking",
            "payment",
            "salary",
            "payroll",
            "card",
            "account number",
            "billing"
        ],

        "Authentication Request": [
            "otp",
            "authentication code",
            "verification code",
            "security code",
            "one time password"
        ],

        "Threat / Pressure": [
            "suspended",
            "disabled",
            "deactivated",
            "terminated",
            "blocked",
            "locked",
            "restricted",
            "permanent deletion"
        ],

        "Suspicious CTA": [
            "click here",
            "click the link",
            "open the link",
            "verification portal",
            "verify immediately",
            "confirm now",
            "access the"
        ]
    }

    output = {}

    for category, keywords in categories.items():

        detected = [
            keyword
            for keyword in keywords
            if keyword in lower
        ]

        score = min(
            len(detected) * 35,
            100
        )

        output[category] = {
            "score": score,
            "matches": detected
        }


    # ---------------- URL Detection ----------------

    urls = re.findall(
        r"https?://\S+|www\.\S+",
        text,
        flags=re.IGNORECASE
    )

    output["URL Presence"] = {
        "score": min(
            len(urls) * 70,
            100
        ),
        "matches": urls[:3]
    }


    return output


# ============================================================
# ATTACK PATH RECONSTRUCTION
#
# This is a transparent rule-based visualization.
# It does NOT claim to reconstruct the real attacker.
# ============================================================

def build_attack_path(threat_dna):

    def active(name):

        return (
            threat_dna
            .get(
                name,
                {}
            )
            .get(
                "score",
                0
            )
            > 0
        )


    path = [

        {
            "stage": "LURE",
            "description":
                "Email attempts to attract user attention",
            "active":
                active("Urgency")
                or active("Threat / Pressure")
        },

        {
            "stage": "ENGAGE",
            "description":
                "User is pushed toward an action",
            "active":
                active("Suspicious CTA")
                or active("URL Presence")
        },

        {
            "stage": "HARVEST",
            "description":
                "Credentials or authentication data requested",
            "active":
                active("Credential Request")
                or active("Authentication Request")
        },

        {
            "stage": "TARGET",
            "description":
                "Financial or account context appears",
            "active":
                active("Financial Context")
        },

        {
            "stage": "PRESSURE",
            "description":
                "Threat or consequence encourages compliance",
            "active":
                active("Threat / Pressure")
        }
    ]

    return path


# ============================================================
# ORACLE CLOUD THREAT INTELLIGENCE
# ============================================================

def get_ai_analysis(
    email_text,
    prediction,
    probability,
    risk,
    action
):

    classification = (
        "Phishing"
        if prediction == 1
        else "Safe"
    )

    prompt = f"""
You are ORACLE, the cybersecurity threat analyst inside SENTINEL AI.

The classification below has already been generated by the security detection layer.

Classification: {classification}
Phishing Probability: {probability * 100:.2f}%
Risk Level: {risk}
Response Decision: {action}

Email Content:
{email_text}

Return ONLY these four lines:

Threat Type: <very short description>
Indicators: <short comma-separated evidence visible in the email>
Likely Objective: <very short answer>
Recommended Analyst Response: <very short answer>

Strict rules:
- No introduction.
- No conclusion.
- No markdown.
- No bullets.
- Do not mention machine learning.
- Do not debate the classification.
- Do not invent evidence.
- Do not invent malware.
- Do not invent organisations.
- Do not invent attacker identity.
- Do not invent geographic location.
- Use only evidence visible in the supplied email.
- Maximum 100 words total.
"""

    if not GROQ_API_KEY:
        return (
            "Threat Type: Cloud AI analyst unavailable\n"
            "Indicators: GROQ_API_KEY is not configured\n"
            "Likely Objective: Not available\n"
            "Recommended Analyst Response: Follow Sentinel response decision"
        )

    try:
        client = Groq(api_key=GROQ_API_KEY)

        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are ORACLE, a concise cybersecurity threat analyst. "
                        "Follow the requested four-line output format exactly. "
                        "Never invent evidence and never override the supplied security decision."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_completion_tokens=1000,
            reasoning_effort="low"
        )

        generated = response.choices[0].message.content or ""
        generated = generated.strip()

        if not generated:
            raise ValueError("Groq returned empty output")

        return generated

    except Exception:
       return (
        "Threat Type: Cloud AI analyst unavailable\n"
        "Indicators: Oracle cloud service could not be reached\n"
        "Likely Objective: Not available\n"
        "Recommended Analyst Response: Follow Sentinel response decision"
        )


# ============================================================
# PARSE ORACLE OUTPUT
# ============================================================

def parse_ai_analysis(text):

    fields = {

        "Threat Type":
            "Not available",

        "Indicators":
            "Not available",

        "Likely Objective":
            "Not available",

        "Recommended Analyst Response":
            "Not available"
    }


    for line in text.splitlines():

        line = line.strip()


        for key in fields:

            if line.lower().startswith(
                key.lower() + ":"
            ):

                fields[key] = (
                    line.split(
                        ":",
                        1
                    )[1]
                    .strip()
                )


    return fields


# ============================================================
# n8n STRIKE ENGINE
# ============================================================

def trigger_n8n(payload):

    if not N8N_WEBHOOK_URL:

        return {
            "status":
                "STANDBY",

            "message":
                "n8n webhook not configured"
        }


    try:

        response = requests.post(
            N8N_WEBHOOK_URL,
            json=payload,
            timeout=15
        )


        response.raise_for_status()


        return {
            "status":
                "EXECUTED",

            "message":
                "Incident workflow successfully triggered"
        }


    except requests.exceptions.RequestException:

        return {
            "status":
                "FAILED",

            "message":
                "Configured n8n webhook could not be reached"
        }


# ============================================================
# SESSION STATE
# ============================================================

if "scan_history" not in st.session_state:

    st.session_state.scan_history = []


if "last_result" not in st.session_state:

    st.session_state.last_result = None


# ============================================================
# LIVE SERVICE STATUS
# ============================================================

oracle_online = check_oracle()

n8n_ready = bool(
    N8N_WEBHOOK_URL
)


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
<style>

/* =======================================================
   GLOBAL
   ======================================================= */

html {
    scroll-behavior: smooth;
}

.stApp {

    background:

        radial-gradient(
            circle at 8% 0%,
            rgba(0, 221, 255, 0.16),
            transparent 26%
        ),

        radial-gradient(
            circle at 92% 2%,
            rgba(111, 66, 255, 0.14),
            transparent 24%
        ),

        radial-gradient(
            circle at 50% 100%,
            rgba(0, 119, 255, 0.06),
            transparent 30%
        ),

        linear-gradient(
            180deg,
            #03101a 0%,
            #020912 45%,
            #010408 100%
        );

    color: #eefaff;
}


.block-container {

    max-width: 1500px;

    padding-top: 1.25rem;

    padding-bottom: 4rem;
}


/* =======================================================
   HERO
   ======================================================= */

.hero {

    position: relative;

    overflow: hidden;

    border-radius: 25px;

    padding: 36px 40px;

    margin-bottom: 22px;

    background:

        linear-gradient(
            118deg,
            rgba(6, 30, 46, 0.97),
            rgba(4, 14, 27, 0.99)
        );

    border:

        1px solid
        rgba(0, 220, 255, 0.24);

    box-shadow:

        0 0 70px
        rgba(0, 190, 255, 0.055);
}


.hero::before {

    content: "";

    position: absolute;

    inset: 0;

    background:

        repeating-linear-gradient(
            90deg,
            transparent,
            transparent 79px,
            rgba(0,220,255,0.015) 80px
        );
}


.hero::after {

    content: "";

    position: absolute;

    width: 30%;

    height: 160%;

    top: -30%;

    left: -40%;

    transform: rotate(15deg);

    background:

        linear-gradient(
            90deg,
            transparent,
            rgba(0, 230, 255, 0.08),
            transparent
        );

    animation:
        scanLine 8s linear infinite;
}


@keyframes scanLine {

    from {
        left: -40%;
    }

    to {
        left: 130%;
    }
}


.hero-kicker {

    position: relative;

    z-index: 2;

    color: #51ddff;

    font-size: 11px;

    letter-spacing: 4px;

    margin-bottom: 9px;
}


.hero-title {

    position: relative;

    z-index: 2;

    font-size: 51px;

    font-weight: 850;

    letter-spacing: 7px;

    line-height: 1;

    color: #f4fbff;
}


.hero-subtitle {

    position: relative;

    z-index: 2;

    color: #8aaabc;

    font-size: 15px;

    margin-top: 13px;

    margin-bottom: 19px;
}


.badge {

    position: relative;

    z-index: 2;

    display: inline-block;

    padding: 7px 13px;

    margin-right: 7px;

    margin-top: 5px;

    border-radius: 100px;

    font-size: 10px;

    letter-spacing: 1.3px;
}


.badge-online {

    color: #d9fff0;

    border:
        1px solid
        rgba(0, 255, 174, 0.33);

    background:
        rgba(0, 255, 174, 0.055);
}


.badge-offline {

    color: #ffd9df;

    border:
        1px solid
        rgba(255, 91, 112, 0.35);

    background:
        rgba(255, 91, 112, 0.055);
}


.badge-purple {

    color: #e7deff;

    border:
        1px solid
        rgba(158, 123, 255, 0.35);

    background:
        rgba(158, 123, 255, 0.055);
}


/* =======================================================
   GLASS PANELS
   ======================================================= */

.panel {

    border-radius: 17px;

    padding: 20px;

    margin-bottom: 12px;

    background:

        linear-gradient(
            145deg,
            rgba(7, 25, 38, 0.95),
            rgba(3, 13, 22, 0.98)
        );

    border:
        1px solid
        rgba(0, 213, 255, 0.16);

    box-shadow:

        inset 0 0 28px
        rgba(0, 210, 255, 0.012);
}


.panel-alert {

    border:
        1px solid
        rgba(255, 91, 112, 0.26);

    background:

        linear-gradient(
            145deg,
            rgba(39, 10, 18, 0.55),
            rgba(7, 14, 22, 0.98)
        );
}


.panel-safe {

    border:
        1px solid
        rgba(54, 229, 165, 0.24);

    background:

        linear-gradient(
            145deg,
            rgba(7, 35, 28, 0.5),
            rgba(6, 16, 22, 0.98)
        );
}


.label {

    color: #7198aa;

    font-size: 10px;

    letter-spacing: 2px;

    margin-bottom: 9px;
}


.value {

    color: #f0fbff;

    font-size: 26px;

    font-weight: 770;
}


.red {
    color: #ff6375;
}


.green {
    color: #42e8ad;
}


.yellow {
    color: #ffd166;
}


/* =======================================================
   ARCHITECTURE
   ======================================================= */

.pipeline-step {

    display: flex;

    align-items: center;

    gap: 13px;

    margin-top: 9px;

    padding: 13px;

    border-radius: 11px;

    background:
        rgba(255, 255, 255, 0.024);

    border:
        1px solid
        rgba(0, 220, 255, 0.09);
}


.module {

    min-width: 112px;

    color: #48e1ff;

    font-weight: 800;

    font-size: 12px;

    letter-spacing: 0.8px;
}


.module-description {

    color: #d8f0fa;

    font-size: 12px;
}


/* =======================================================
   THREAT CORE
   ======================================================= */

.core-wrap {

    display: flex;

    justify-content: center;

    align-items: center;

    padding: 8px 0;
}


.core {

    width: 225px;

    height: 225px;

    border-radius: 50%;

    display: flex;

    align-items: center;

    justify-content: center;

    filter:
        drop-shadow(
            0 0 22px
            rgba(0, 220, 255, 0.08)
        );
}


.core-inner {

    width: 168px;

    height: 168px;

    border-radius: 50%;

    display: flex;

    flex-direction: column;

    align-items: center;

    justify-content: center;

    background:

        radial-gradient(
            circle,
            #071a25,
            #031019
        );

    border:
        1px solid
        rgba(255,255,255,0.045);

    box-shadow:
        inset 0 0 35px
        rgba(0,0,0,0.45);
}


.core-number {

    color: #f2fbff;

    font-size: 34px;

    font-weight: 850;
}


.core-label {

    color: #719aaa;

    font-size: 9px;

    letter-spacing: 2px;

    margin-top: 4px;
}


/* =======================================================
   THREAT DNA
   ======================================================= */

.dna-row {

    margin-top: 13px;
}


.dna-header {

    display: flex;

    justify-content: space-between;

    margin-bottom: 6px;

    color: #afcbd7;

    font-size: 12px;
}


.dna-track {

    width: 100%;

    height: 8px;

    overflow: hidden;

    border-radius: 20px;

    background:
        rgba(255,255,255,0.05);
}


.dna-fill {

    height: 100%;

    border-radius: 20px;

    background:

        linear-gradient(
            90deg,
            #12bce7,
            #865cff
        );
}


/* =======================================================
   ATTACK PATH
   ======================================================= */

.attack-stage {

    padding: 15px;

    margin-bottom: 9px;

    border-radius: 12px;

    background:
        rgba(255,255,255,0.022);

    border:
        1px solid
        rgba(255,255,255,0.055);
}


.attack-stage-active {

    border:
        1px solid
        rgba(255, 92, 117, 0.23);

    background:
        rgba(255, 92, 117, 0.035);
}


.attack-name {

    color: #ff7f90;

    font-size: 11px;

    font-weight: 800;

    letter-spacing: 1.4px;
}


.attack-text {

    color: #c6dce5;

    font-size: 12px;

    margin-top: 5px;
}


/* =======================================================
   AI
   ======================================================= */

.ai-shell {

    padding: 21px;

    margin-top: 10px;

    border-radius: 19px;

    background:

        linear-gradient(
            135deg,
            rgba(23, 15, 48, 0.86),
            rgba(4, 17, 29, 0.98)
        );

    border:
        1px solid
        rgba(155, 119, 255, 0.29);
}


.ai-heading {

    color: #bca8ff;

    font-size: 10px;

    letter-spacing: 2.4px;

    margin-bottom: 14px;
}


.ai-card {

    padding: 14px;

    margin-top: 9px;

    border-radius: 12px;

    background:
        rgba(255,255,255,0.025);

    border:
        1px solid
        rgba(157, 124, 255, 0.13);
}


.ai-label {

    color: #9d86f4;

    font-size: 9px;

    letter-spacing: 1.6px;

    margin-bottom: 6px;
}


.ai-value {

    color: #edf7ff;

    font-size: 13px;

    line-height: 1.55;
}


/* =======================================================
   INCIDENT ID
   ======================================================= */

.incident-id {

    display: inline-block;

    padding: 8px 12px;

    border-radius: 8px;

    color: #5fe6ff;

    background:
        rgba(0, 211, 255, 0.035);

    border:
        1px dashed
        rgba(0, 211, 255, 0.25);

    font-family: monospace;

    font-size: 11px;

    letter-spacing: 1.1px;
}


/* =======================================================
   DECISION LEDGER
   ======================================================= */

.ledger-row {

    display: flex;

    justify-content: space-between;

    gap: 15px;

    padding: 11px 0;

    border-bottom:
        1px solid
        rgba(255,255,255,0.05);
}


.ledger-left {

    color: #6f9bad;

    font-size: 11px;

    letter-spacing: 1px;
}


.ledger-right {

    color: #e8f6fc;

    font-size: 12px;

    text-align: right;
}


/* =======================================================
   RESPONSE TIMELINE
   ======================================================= */

.timeline-step {

    padding: 12px 14px;

    margin-top: 8px;

    border-radius: 10px;

    background:
        rgba(255,255,255,0.025);

    border:
        1px solid
        rgba(255,255,255,0.05);

    font-size: 12px;

    color: #d9eff7;
}


/* =======================================================
   STREAMLIT ELEMENTS
   ======================================================= */

div[data-testid="stTextArea"] textarea {

    background:
        rgba(3, 15, 25, 0.95);

    color: #effaff;

    border:
        1px solid
        rgba(0, 220, 255, 0.24);

    border-radius: 14px;
}


div.stButton > button {

    width: 100%;

    min-height: 50px;

    border-radius: 12px;

    font-weight: 760;

    letter-spacing: 1px;

    border:
        1px solid
        rgba(0, 215, 255, 0.3);
}


div.stButton > button:hover {

    border-color:
        rgba(0, 230, 255, 0.75);

    box-shadow:
        0 0 22px
        rgba(0, 220, 255, 0.08);
}


div[data-testid="stMetric"] {

    padding: 14px;

    border-radius: 13px;

    background:
        rgba(5,20,32,0.75);

    border:
        1px solid
        rgba(0,210,255,0.12);
}


.footer {

    text-align: center;

    margin-top: 42px;

    color: #506f7e;

    font-size: 9px;

    letter-spacing: 1.7px;
}

</style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

oracle_badge_class = (
    "badge-online"
    if oracle_online
    else "badge-offline"
)

oracle_badge_text = (
    "● ORACLE ONLINE"
    if oracle_online
    else "● ORACLE OFFLINE"
)


n8n_badge_class = (
    "badge-online"
    if n8n_ready
    else "badge-purple"
)

n8n_badge_text = (
    "● STRIKE ARMED"
    if n8n_ready
    else "STRIKE // STANDBY"
)


st.markdown(
    f"""
<div class="hero">

<div class="hero-kicker">
AUTONOMOUS CYBER DEFENSE OS
</div>

<div class="hero-title">
SENTINEL//AI
</div>

<div class="hero-subtitle">

Phishing Detection · Explainable Threat Intelligence ·
Cloud GenAI · Automated Incident Response

</div>

<span class="badge badge-online">
● SENTINEL CORE ONLINE
</span>

<span class="badge {oracle_badge_class}">
{oracle_badge_text}
</span>

<span class="badge {n8n_badge_class}">
{n8n_badge_text}
</span>

</div>
    """,
    unsafe_allow_html=True
)


# ============================================================
# NAVIGATION
# ============================================================

tab_scan, tab_soc, tab_model = st.tabs(
    [
        "◉ Defense Console",
        "▦ SOC Command",
        "◇ Model Intelligence"
    ]
)


# ============================================================
# TAB 1
# DEFENSE CONSOLE
# ============================================================

with tab_scan:

    left_col, right_col = st.columns(
        [1.55, 1]
    )


    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    with left_col:

        st.markdown(
            "## Watchtower // Email Ingestion"
        )


        email_text = st.text_area(

            "Email content",

            height=300,

            placeholder=(
                "Paste suspicious or legitimate email content here..."
            ),

            label_visibility="collapsed"
        )


        analyse = st.button(
            "◉ INITIATE SENTINEL SCAN",
            use_container_width=True
        )


    # --------------------------------------------------------
    # ARCHITECTURE
    # --------------------------------------------------------

    with right_col:

        st.markdown(
            """
<div class="panel">

<div class="label">
DEFENSE ARCHITECTURE
</div>

<div class="pipeline-step">
<span class="module">WATCHTOWER</span>
<span class="module-description">
Email ingestion
</span>
</div>

<div class="pipeline-step">
<span class="module">VECTOR</span>
<span class="module-description">
TF-IDF representation
</span>
</div>

<div class="pipeline-step">
<span class="module">SENTINEL ML</span>
<span class="module-description">
Calibrated SVM
</span>
</div>

<div class="pipeline-step">
<span class="module">RISK CORE</span>
<span class="module-description">
Deterministic response policy
</span>
</div>

<div class="pipeline-step">
<span class="module">ORACLE</span>
<span class="module-description">
Cloud AI intelligence
</span>
</div>

<div class="pipeline-step">
<span class="module">STRIKE</span>
<span class="module-description">
n8n incident automation
</span>
</div>

</div>
            """,
            unsafe_allow_html=True
        )


    # ========================================================
    # RUN ANALYSIS
    # ========================================================

    if analyse:

        if not email_text.strip():

            st.warning(
                "Watchtower requires email content before scanning."
            )


        else:

            scan_id = create_scan_id(
                email_text
            )


            scan_time = datetime.now().strftime(
                "%d %b %Y · %H:%M:%S"
            )


            # ------------------------------------------------
            # MACHINE LEARNING
            # ------------------------------------------------

            with st.spinner(
                "WATCHTOWER → VECTOR → SENTINEL ML..."
            ):

                cleaned = clean_text(
                    email_text
                )


                vector = tfidf.transform(
                    [cleaned]
                )


                prediction = int(
                    model.predict(
                        vector
                    )[0]
                )


                probability = float(
                    model.predict_proba(
                        vector
                    )[0][1]
                )


                risk = get_risk_level(
                    probability
                )


                action = get_action(
                    risk
                )


            # ------------------------------------------------
            # THREAT DNA
            # ------------------------------------------------

            threat_dna = analyse_threat_dna(
                email_text
            )


            attack_path = build_attack_path(
                threat_dna
            )


            # ------------------------------------------------
            # ORACLE
            # ------------------------------------------------

            with st.spinner(
                "ORACLE // Generating threat intelligence..."
            ):

                ai_raw = get_ai_analysis(

                    email_text,

                    prediction,

                    probability,

                    risk,

                    action
                )


                ai = parse_ai_analysis(
                    ai_raw
                )


            # ------------------------------------------------
            # STRIKE
            # Only HIGH-risk phishing events trigger n8n
            # ------------------------------------------------

            automation = {

                "status":
                    "NOT REQUIRED",

                "message":
                    "No high-risk escalation required"
            }


            if (
                prediction == 1
                and risk == "HIGH"
            ):

                payload = {

                    "incident_id":
                        scan_id,

                    "timestamp":
                        scan_time,

                    "classification":
                        "Phishing",

                    "phishing_probability":
                        round(
                            probability * 100,
                            2
                        ),

                    "risk":
                        risk,

                    "action":
                        action,

                    "threat_type":
                        ai["Threat Type"],

                    "indicators":
                        ai["Indicators"],

                    "likely_objective":
                        ai["Likely Objective"]
                }


                automation = trigger_n8n(
                    payload
                )


            # ------------------------------------------------
            # SAVE RESULT
            # ------------------------------------------------

            result = {

                "incident_id":
                    scan_id,

                "time":
                    scan_time,

                "prediction":
                    prediction,

                "probability":
                    probability,

                "risk":
                    risk,

                "action":
                    action,

                "ai":
                    ai,

                "threat_dna":
                    threat_dna,

                "attack_path":
                    attack_path,

                "automation":
                    automation
            }


            st.session_state.last_result = (
                result
            )


            st.session_state.scan_history.append(
                {
                    "Incident ID":
                        scan_id,

                    "Time":
                        scan_time,

                    "Classification":
                        (
                            "Phishing"
                            if prediction == 1
                            else "Safe"
                        ),

                    "Probability":
                        probability * 100,

                    "Risk":
                        risk,

                    "Action":
                        action,

                    "Automation":
                        automation["status"]
                }
            )


    # ========================================================
    # RENDER LAST RESULT
    # ========================================================

    result = st.session_state.last_result


    if result is not None:

        prediction = result[
            "prediction"
        ]

        probability = result[
            "probability"
        ]

        risk = result[
            "risk"
        ]

        action = result[
            "action"
        ]

        scan_id = result[
            "incident_id"
        ]

        scan_time = result[
            "time"
        ]

        ai = result[
            "ai"
        ]

        threat_dna = result[
            "threat_dna"
        ]

        attack_path = result[
            "attack_path"
        ]

        automation = result[
            "automation"
        ]


        classification = (
            "PHISHING"
            if prediction == 1
            else "SAFE"
        )


        if risk == "HIGH":

            risk_class = "red"
            gauge_color = "#ff6074"

        elif risk == "MEDIUM":

            risk_class = "yellow"
            gauge_color = "#ffd166"

        else:

            risk_class = "green"
            gauge_color = "#40e7aa"


        classification_class = (
            "red"
            if prediction == 1
            else "green"
        )


        panel_state = (
            "panel-alert"
            if prediction == 1
            else "panel-safe"
        )


        score = (
            probability * 100
        )


        degrees = min(
            score * 3.6,
            360
        )


        st.markdown("---")

        st.markdown(
            "## Sentinel Threat Event"
        )


        result_left, result_right = st.columns(
            [1.55, 1]
        )


        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        with result_left:

            a, b, c = st.columns(
                3
            )


            with a:

                st.markdown(
                    f"""
<div class="panel {panel_state}">

<div class="label">
CLASSIFICATION
</div>

<div class="value {classification_class}">
{classification}
</div>

</div>
                    """,
                    unsafe_allow_html=True
                )


            with b:

                st.markdown(
                    f"""
<div class="panel">

<div class="label">
RISK STATE
</div>

<div class="value {risk_class}">
{risk}
</div>

</div>
                    """,
                    unsafe_allow_html=True
                )


            with c:

                st.markdown(
                    """
<div class="panel">

<div class="label">
DETECTION ENGINE
</div>

<div class="value">
SVM
</div>

</div>
                    """,
                    unsafe_allow_html=True
                )


            st.markdown(
                f"""
<div class="panel">

<div class="label">
RESPONSE DECISION
</div>

<div class="value">
{html.escape(action)}
</div>

</div>
                """,
                unsafe_allow_html=True
            )


            st.markdown(
                f"""
<span class="incident-id">
INCIDENT // {html.escape(scan_id)}
</span>
                """,
                unsafe_allow_html=True
            )


            st.caption(
                scan_time
            )


        # ----------------------------------------------------
        # THREAT CORE
        # ----------------------------------------------------

        with result_right:

            st.markdown(
                f"""
<div class="panel">

<div class="label">
SENTINEL THREAT CORE
</div>

<div class="core-wrap">

<div
class="core"
style="
background:
conic-gradient(
{gauge_color} 0deg,
{gauge_color} {degrees}deg,
rgba(255,255,255,0.055) {degrees}deg,
rgba(255,255,255,0.055) 360deg
);
"
>

<div class="core-inner">

<div class="core-number">
{score:.1f}%
</div>

<div class="core-label">
PHISHING PROBABILITY
</div>

</div>

</div>

</div>

</div>
                """,
                unsafe_allow_html=True
            )


        # ====================================================
        # THREAT DNA
        # ====================================================

        st.markdown(
            "## Threat DNA // Observable Evidence"
        )


        dna_left, dna_right = st.columns(
            2
        )


        dna_items = list(
            threat_dna.items()
        )


        for index, (
            category,
            details
        ) in enumerate(
            dna_items
        ):

            target = (
                dna_left
                if index % 2 == 0
                else dna_right
            )


            score_dna = details[
                "score"
            ]


            matches = details[
                "matches"
            ]


            if matches:

                match_text = ", ".join(
                    str(item)
                    for item in matches[:3]
                )

            else:

                match_text = (
                    "No direct signal detected"
                )


            with target:

                st.markdown(
                    f"""
<div class="panel">

<div class="dna-header">

<span>
{html.escape(category)}
</span>

<span>
{score_dna}%
</span>

</div>

<div class="dna-track">

<div
class="dna-fill"
style="width:{score_dna}%;">
</div>

</div>

<div style="
color:#627f8d;
font-size:10px;
margin-top:7px;
">
Evidence:
{html.escape(match_text)}
</div>

</div>
                    """,
                    unsafe_allow_html=True
                )


        st.caption(
            "Threat DNA is a transparent heuristic evidence layer. "
            "It is not presented as SVM feature importance."
        )


        # ====================================================
        # ATTACK PATH
        # ====================================================

        st.markdown(
            "## Attack Path // Behaviour Reconstruction"
        )


        attack_columns = st.columns(
            len(
                attack_path
            )
        )


        for index, stage in enumerate(
            attack_path
        ):

            stage_class = (
                "attack-stage-active"
                if stage["active"]
                else ""
            )


            symbol = (
                "●"
                if stage["active"]
                else "○"
            )


            with attack_columns[
                index
            ]:

                st.markdown(
                    f"""
<div class="attack-stage {stage_class}">

<div class="attack-name">
{symbol} {html.escape(stage["stage"])}
</div>

<div class="attack-text">
{html.escape(stage["description"])}
</div>

</div>
                    """,
                    unsafe_allow_html=True
                )


        st.caption(
            "Attack Path uses transparent rules to visualise behaviour "
            "visible in the email. It does not claim to identify the "
            "real attacker."
        )


        # ====================================================
        # ORACLE
        # ====================================================

        st.markdown(
            "## Oracle // Cloud AI Threat Intelligence"
        )


        ai1, ai2 = st.columns(
            2
        )


        with ai1:

            st.markdown(
                f"""
<div class="ai-shell">

<div class="ai-heading">
ORACLE // THREAT INTERPRETATION
</div>

<div class="ai-card">

<div class="ai-label">
THREAT TYPE
</div>

<div class="ai-value">
{html.escape(ai["Threat Type"])}
</div>

</div>

<div class="ai-card">

<div class="ai-label">
OBSERVED INDICATORS
</div>

<div class="ai-value">
{html.escape(ai["Indicators"])}
</div>

</div>

</div>
                """,
                unsafe_allow_html=True
            )


        with ai2:

            st.markdown(
                f"""
<div class="ai-shell">

<div class="ai-heading">
ORACLE // RESPONSE INTELLIGENCE
</div>

<div class="ai-card">

<div class="ai-label">
LIKELY OBJECTIVE
</div>

<div class="ai-value">
{html.escape(ai["Likely Objective"])}
</div>

</div>

<div class="ai-card">

<div class="ai-label">
RECOMMENDED ANALYST RESPONSE
</div>

<div class="ai-value">
{html.escape(ai["Recommended Analyst Response"])}
</div>

</div>

</div>
                """,
                unsafe_allow_html=True
            )


        # ====================================================
        # DECISION LEDGER
        # ====================================================

        st.markdown(
            "## Decision Ledger // Why Sentinel Acted"
        )


        st.markdown(
            f"""
<div class="panel">

<div class="ledger-row">

<div class="ledger-left">
WATCHTOWER
</div>

<div class="ledger-right">
Email content accepted
</div>

</div>


<div class="ledger-row">

<div class="ledger-left">
VECTOR
</div>

<div class="ledger-right">
Text transformed using TF-IDF
</div>

</div>


<div class="ledger-row">

<div class="ledger-left">
SENTINEL ML
</div>

<div class="ledger-right">
Phishing probability = {score:.2f}%
</div>

</div>


<div class="ledger-row">

<div class="ledger-left">
RISK CORE
</div>

<div class="ledger-right">
{html.escape(risk)} → {html.escape(action)}
</div>

</div>


<div class="ledger-row">

<div class="ledger-left">
ORACLE
</div>

<div class="ledger-right">
Grounded intelligence generated via cloud AI
</div>

</div>


<div class="ledger-row">

<div class="ledger-left">
STRIKE
</div>

<div class="ledger-right">
{html.escape(automation["status"])}
</div>

</div>

</div>
            """,
            unsafe_allow_html=True
        )


        # ====================================================
        # INCIDENT RESPONSE
        # ====================================================

        st.markdown(
            "## Strike // Incident Response"
        )


        st.markdown(
            """
<div class="panel">

<div class="timeline-step">
✓ WATCHTOWER // Email ingested
</div>

<div class="timeline-step">
✓ VECTOR // TF-IDF representation generated
</div>

<div class="timeline-step">
✓ SENTINEL ML // Detection completed
</div>

<div class="timeline-step">
✓ RISK CORE // Security policy evaluated
</div>

<div class="timeline-step">
✓ THREAT DNA // Observable evidence extracted
</div>

<div class="timeline-step">
✓ ORACLE // Threat intelligence generated
</div>

</div>
            """,
            unsafe_allow_html=True
        )


        if automation[
            "status"
        ] == "EXECUTED":

            st.success(
                "✓ STRIKE // Automated n8n incident-response workflow executed."
            )


        elif automation[
            "status"
        ] == "STANDBY":

            st.info(
                "STRIKE // High-risk phishing event detected. "
                "Automation is ready but the n8n webhook has not yet "
                "been configured."
            )


        elif automation[
            "status"
        ] == "FAILED":

            st.error(
                "STRIKE // n8n webhook is configured but could not be reached."
            )


        else:

            st.success(
                "✓ STRIKE // No automated escalation required for this event."
            )


        # ====================================================
        # FORENSICS
        # ====================================================

        with st.expander(
            "Forensic / Technical Details"
        ):

            st.write(
                f"Incident ID: {scan_id}"
            )

            st.write(
                f"Timestamp: {scan_time}"
            )

            st.write(
                "Detection Model: Calibrated Linear SVM"
            )

            st.write(
                "Feature Engineering: TF-IDF"
            )

            st.write(
                "Maximum TF-IDF Features: 10,000"
            )

            st.write(
                f"Predicted Class: {prediction}"
            )

            st.write(
                f"Phishing Probability: {probability:.6f}"
            )

            st.write(
                f"Risk Level: {risk}"
            )

            st.write(
                f"Action: {action}"
            )

            st.write(
                f"Oracle AI Model: {GROQ_MODEL}"
            )

            st.write(
                f"Oracle Configured: {oracle_online}"
            )

            st.write(
                f"n8n Automation State: {automation['status']}"
            )


# ============================================================
# TAB 2
# SOC COMMAND
# ============================================================

with tab_soc:

    st.markdown(
        "## SOC Command // Live Session Intelligence"
    )


    history = (
        st.session_state.scan_history
    )


    total = len(
        history
    )


    threats = sum(
        1
        for event in history
        if event[
            "Classification"
        ] == "Phishing"
    )


    safe = (
        total
        - threats
    )


    high_risk = sum(
        1
        for event in history
        if event[
            "Risk"
        ] == "HIGH"
    )


    automation_count = sum(
        1
        for event in history
        if event[
            "Automation"
        ] == "EXECUTED"
    )


    threat_rate = (
        threats / total * 100
        if total
        else 0
    )


    m1, m2, m3, m4, m5 = st.columns(
        5
    )


    with m1:

        st.metric(
            "Scans",
            total
        )


    with m2:

        st.metric(
            "Threats",
            threats
        )


    with m3:

        st.metric(
            "Safe",
            safe
        )


    with m4:

        st.metric(
            "High Risk",
            high_risk
        )


    with m5:

        st.metric(
            "Threat Rate",
            f"{threat_rate:.1f}%"
        )


    if total == 0:

        st.info(
            "No Sentinel incidents have been analysed in this session."
        )


    else:

        history_df = pd.DataFrame(
            history
        )


        # ----------------------------------------------------
        # THREAT PROBABILITY TIMELINE
        # ----------------------------------------------------

        st.markdown(
            "### Threat Probability Timeline"
        )


        timeline_df = pd.DataFrame(
            {
                "Scan": range(
                    1,
                    total + 1
                ),

                "Threat Probability":
                    history_df[
                        "Probability"
                    ]
            }
        ).set_index(
            "Scan"
        )


        st.line_chart(
            timeline_df
        )


        # ----------------------------------------------------
        # RISK DISTRIBUTION
        # ----------------------------------------------------

        st.markdown(
            "### Risk Distribution"
        )


        risk_distribution = (
            history_df[
                "Risk"
            ]
            .value_counts()
            .reindex(
                [
                    "LOW",
                    "MEDIUM",
                    "HIGH"
                ],
                fill_value=0
            )
        )


        st.bar_chart(
            risk_distribution
        )


        # ----------------------------------------------------
        # INCIDENT FEED
        # ----------------------------------------------------

        st.markdown(
            "### Incident Feed"
        )


        display_df = history_df[
            [
                "Incident ID",
                "Time",
                "Classification",
                "Probability",
                "Risk",
                "Automation"
            ]
        ].copy()


        display_df[
            "Probability"
        ] = display_df[
            "Probability"
        ].round(
            2
        )


        st.dataframe(

            display_df.iloc[
                ::-1
            ],

            use_container_width=True,

            hide_index=True
        )


        if automation_count:

            st.success(
                f"{automation_count} autonomous response workflow(s) "
                "executed in this session."
            )


# ============================================================
# TAB 3
# MODEL INTELLIGENCE
# ============================================================

with tab_model:

    st.markdown(
        "## Model Intelligence // Sentinel Core"
    )


    a, b, c, d = st.columns(
        4
    )


    with a:

        st.metric(
            "Final Accuracy",
            "98.79%"
        )


    with b:

        st.metric(
            "Feature Space",
            "10,000"
        )


    with c:

        st.metric(
            "Detection Model",
            "Calibrated SVM"
        )


    with d:

        st.metric(
            "AI Analyst",
            "GPT-OSS 20B"
        )


    # --------------------------------------------------------
    # ARCHITECTURE
    # --------------------------------------------------------

    st.markdown(
        "### Autonomous Defense Architecture"
    )


    st.markdown(
        """
<div class="panel">

<div class="pipeline-step">

<span class="module">
01 WATCHTOWER
</span>

<span class="module-description">
Accepts raw email content
</span>

</div>


<div class="pipeline-step">

<span class="module">
02 VECTOR
</span>

<span class="module-description">
Text preprocessing + TF-IDF feature transformation
</span>

</div>


<div class="pipeline-step">

<span class="module">
03 SENTINEL ML
</span>

<span class="module-description">
Calibrated Linear SVM predicts phishing probability
</span>

</div>


<div class="pipeline-step">

<span class="module">
04 RISK CORE
</span>

<span class="module-description">
Deterministic LOW / MEDIUM / HIGH security policy
</span>

</div>


<div class="pipeline-step">

<span class="module">
05 THREAT DNA
</span>

<span class="module-description">
Transparent evidence extraction from email content
</span>

</div>


<div class="pipeline-step">

<span class="module">
06 ORACLE
</span>

<span class="module-description">
Groq-hosted GPT-OSS 20B produces grounded security intelligence
</span>

</div>


<div class="pipeline-step">

<span class="module">
07 STRIKE
</span>

<span class="module-description">
n8n performs automated incident-response workflow
</span>

</div>

</div>
        """,
        unsafe_allow_html=True
    )


    # --------------------------------------------------------
    # BENCHMARK
    # --------------------------------------------------------

    st.markdown(
        "### Model Benchmark"
    )


    benchmark = pd.DataFrame(
        {
            "Model": [

                "Logistic Regression",

                "Multinomial Naive Bayes",

                "Linear SVM",

                "Calibrated Linear SVM"
            ],

            "Accuracy": [

                "98.48%",

                "96.66%",

                "98.73%",

                "98.79%"
            ]
        }
    )


    st.dataframe(

        benchmark,

        use_container_width=True,

        hide_index=True
    )


    # --------------------------------------------------------
    # DESIGN PRINCIPLE
    # --------------------------------------------------------

    st.markdown(
        """
### Sentinel Design Principle

**SENTINEL ML** owns the phishing classification.

**RISK CORE** converts model probability into a deterministic
security response.

**THREAT DNA** shows observable evidence directly present in
the submitted email.

**ATTACK PATH** visualises behavioural patterns using
transparent rules.

**ORACLE** explains the incident using a local Llama model,
but does not replace the ML classifier.

**STRIKE** executes the incident workflow through n8n.

This separation makes the system more interpretable,
auditable and easier to defend during evaluation.
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div class="footer">

SENTINEL//AI //
WATCHTOWER × VECTOR × SENTINEL ML × RISK CORE ×
THREAT DNA × ORACLE × STRIKE

<br><br>

AUTONOMOUS CYBER DEFENSE OS

</div>
    """,
    unsafe_allow_html=True
)
