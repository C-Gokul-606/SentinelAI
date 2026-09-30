
import streamlit as st
import streamlit.components.v1 as components
import joblib
import re
import json

# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="SentinelAI",
    page_icon="◉",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load("sentinelai_model.pkl")

with open("sentinelai_metadata.json", "r") as f:
    metadata = json.load(f)


# ============================================================
# THREAT PATTERNS
# ============================================================

THREAT_PATTERNS = {
    "Suspicious URL": r"(https?://|www\.|\.com/|bit\.ly|tinyurl|t\.co)",
    "Urgency": r"\b(urgent|immediately|now|today|hurry|expire|expires|limited|act fast)\b",
    "Financial request": r"\b(bank|account|payment|pay|money|cash|credit|debit|loan|transaction|refund)\b",
    "Credential request": r"\b(password|pin|otp|passcode|verify|verification|login|username)\b",
    "Prize / reward": r"\b(prize|winner|won|reward|free|bonus|claim|offer)\b",
    "Phone number": r"(\+?\d[\d\s-]{8,}\d)"
}


# ============================================================
# ANALYSIS ENGINE
# ============================================================

def analyze_message(message):

    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]

    spam_index = list(model.classes_).index(1)
    spam_probability = probabilities[spam_index]

    indicators = []

    for name, pattern in THREAT_PATTERNS.items():
        if re.search(pattern, message, flags=re.IGNORECASE):
            indicators.append(name)

    indicator_bonus = min(len(indicators) * 0.03, 0.15)

    risk_score = min(
        spam_probability + indicator_bonus,
        0.99
    )

    if risk_score >= 0.75:
        level = "HIGH"
    elif risk_score >= 0.40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "prediction": prediction,
        "spam_probability": spam_probability,
        "safe_probability": 1 - spam_probability,
        "risk_score": risk_score,
        "level": level,
        "indicators": indicators
    }


# ============================================================
# GLOBAL CSS
# ============================================================

st.html("""
<style>

@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Manrope', sans-serif !important;
}

.stApp {
    background: #08090b;
    color: #f1f2f3;
}

#MainMenu,
footer,
header {
    visibility: hidden;
}

.block-container {
    max-width: 1120px;
    padding-top: 1.5rem;
    padding-bottom: 4rem;
}

/* NAV */

.navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 1.4rem;
    border-bottom: 1px solid #20242a;
}

.logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 800;
    font-size: 1rem;
}

.logo-mark {
    width: 27px;
    height: 27px;
    border: 1px solid #343941;
    border-radius: 7px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #9dff78;
    font-family: 'DM Mono', monospace;
}

.nav-right {
    color: #626870;
    font-family: 'DM Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: .08em;
}

/* HERO */

.hero {
    padding: 5.5rem 0 3.2rem;
    max-width: 780px;
}

.kicker {
    color: #9dff78;
    font-family: 'DM Mono', monospace;
    font-size: .67rem;
    letter-spacing: .13em;
    margin-bottom: 1.2rem;
}

.hero-title {
    font-size: clamp(3.1rem, 7vw, 6rem);
    line-height: .92;
    letter-spacing: -.07em;
    font-weight: 800;
}

.hero-title span {
    color: #565c65;
}

.hero-copy {
    margin-top: 1.4rem;
    max-width: 600px;
    color: #858b94;
    font-size: .96rem;
    line-height: 1.75;
}

/* SCANNER */

.scan-shell {
    border: 1px solid #20242a;
    background: #0d0f12;
    border-radius: 16px 16px 0 0;
    overflow: hidden;
}

.scan-top {
    display: flex;
    justify-content: space-between;
    padding: 13px 17px;
    border-bottom: 1px solid #20242a;
}

.scan-label,
.scan-type {
    font-family: 'DM Mono', monospace;
    font-size: .63rem;
    letter-spacing: .08em;
}

.scan-label {
    color: #858b94;
    text-transform: uppercase;
}

.scan-type {
    color: #4f555d;
}

.stTextArea textarea {
    background: #0d0f12 !important;
    color: #e8eaed !important;
    border: 1px solid #20242a !important;
    border-top: none !important;
    border-radius: 0 0 16px 16px !important;
    padding: 20px !important;
    font-size: .95rem !important;
    line-height: 1.8 !important;
}

.stTextArea textarea:focus {
    border-color: #30363d !important;
    box-shadow: none !important;
}

.stTextArea textarea::placeholder {
    color: #444950 !important;
}

/* BUTTON */

.stButton > button {
    background: #9dff78 !important;
    color: #080908 !important;
    border: none !important;
    border-radius: 8px !important;
    height: 47px !important;
    font-weight: 800 !important;
    font-size: .78rem !important;
    letter-spacing: .02em !important;
    transition: .2s ease !important;
}

.stButton > button:hover {
    filter: brightness(1.08);
    transform: translateY(-1px);
}

/* RESULT */

.result-wrap {
    margin-top: 4rem;
}

.result-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    padding-bottom: 1.4rem;
    border-bottom: 1px solid #20242a;
}

.result-kicker {
    color: #626870;
    font-family: 'DM Mono', monospace;
    font-size: .62rem;
    letter-spacing: .1em;
    text-transform: uppercase;
}

.result-verdict {
    font-size: clamp(2.5rem, 5vw, 4.4rem);
    line-height: 1;
    letter-spacing: -.06em;
    font-weight: 800;
    margin-top: .4rem;
}

.high {
    color: #ff5c61;
}

.medium {
    color: #ffc857;
}

.low {
    color: #9dff78;
}

.score {
    text-align: right;
}

.score-number {
    font-family: 'DM Mono', monospace;
    font-size: 3rem;
}

.score-label {
    color: #5f656d;
    font-family: 'DM Mono', monospace;
    font-size: .6rem;
    margin-top: 5px;
}

/* GRID */

.result-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1px;
    background: #20242a;
    border: 1px solid #20242a;
}

.result-cell {
    background: #0d0f12;
    padding: 1.5rem;
    min-height: 145px;
}

.cell-label {
    color: #626870;
    font-family: 'DM Mono', monospace;
    font-size: .61rem;
    letter-spacing: .09em;
    text-transform: uppercase;
    margin-bottom: .9rem;
}

.cell-value {
    color: #d9dce0;
    font-size: .95rem;
    font-weight: 600;
}

/* SIGNALS */

.signal {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    border: 1px solid #272b31;
    background: #111419;
    padding: 7px 10px;
    border-radius: 6px;
    margin: 0 5px 5px 0;
    color: #c5c9ce;
    font-family: 'DM Mono', monospace;
    font-size: .61rem;
}

.signal-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: #ff5c61;
}

/* BARS */

.bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
}

.bar-name {
    width: 60px;
    color: #777d85;
    font-family: 'DM Mono', monospace;
    font-size: .61rem;
}

.bar-bg {
    flex: 1;
    height: 4px;
    background: #1b1e23;
    border-radius: 99px;
    overflow: hidden;
}

.bar-safe {
    height: 100%;
    background: #6d747d;
}

.bar-risk {
    height: 100%;
    background: #ff5c61;
}

.bar-number {
    width: 42px;
    text-align: right;
    color: #b8bdc3;
    font-family: 'DM Mono', monospace;
    font-size: .61rem;
}

/* MESSAGE */

.message-preview {
    background: #090b0e;
    border: 1px solid #1d2025;
    border-radius: 8px;
    padding: 15px;
    color: #9a9fa7;
    line-height: 1.65;
    font-size: .82rem;
    white-space: pre-wrap;
}

/* FOOTER */

.footer {
    display: flex;
    justify-content: space-between;
    border-top: 1px solid #20242a;
    margin-top: 5rem;
    padding-top: 1.3rem;
    color: #464b52;
    font-family: 'DM Mono', monospace;
    font-size: .59rem;
    letter-spacing: .05em;
}

@media (max-width: 700px) {

    .hero {
        padding-top: 3.5rem;
    }

    .result-header {
        display: block;
    }

    .score {
        text-align: left;
        margin-top: 1.8rem;
    }

    .result-grid {
        grid-template-columns: 1fr;
    }

    .footer {
        display: block;
    }

    .footer div {
        margin-bottom: 7px;
    }
}

</style>
""")


# ============================================================
# NAV
# ============================================================

st.html("""
<div class="navbar">
    <div class="logo">
        <div class="logo-mark">◉</div>
        SENTINELAI
    </div>

    <div class="nav-right">
        THREAT INTELLIGENCE / V1.0
    </div>
</div>
""")


# ============================================================
# HERO
# ============================================================

st.html("""
<div class="hero">

    <div class="kicker">
        AI THREAT DETECTION
    </div>

    <div class="hero-title">
        Read between<br>
        <span>the lines.</span>
    </div>

    <div class="hero-copy">
        Analyze suspicious messages before you interact with them.
        SentinelAI uses natural language processing and machine learning
        to identify spam and suspicious communication patterns.
    </div>

</div>
""")


# ============================================================
# INPUT
# ============================================================

st.html("""
<div class="scan-shell">

    <div class="scan-top">

        <div class="scan-label">
            Message input
        </div>

        <div class="scan-type">
            SMS / EMAIL / CHAT
        </div>

    </div>

</div>
""")

message = st.text_area(
    "message",
    placeholder="Paste the suspicious message here...",
    height=200,
    label_visibility="collapsed"
)

st.write("")

_, button_col, _ = st.columns([2, 1, 2])

with button_col:
    scan = st.button(
        "SCAN MESSAGE  →",
        use_container_width=True
    )


# ============================================================
# RESULT
# ============================================================

if scan:

    if not message.strip():

        st.html("""
        <div style="
            margin-top:18px;
            padding:13px 15px;
            border:1px solid #302326;
            background:#120d0f;
            border-radius:8px;
            color:#ff777c;
            font-family:'DM Mono',monospace;
            font-size:.68rem;">
            INPUT REQUIRED — PASTE A MESSAGE TO BEGIN ANALYSIS
        </div>
        """)

    else:

        result = analyze_message(message)

        level = result["level"]

        if level == "HIGH":
            css_class = "high"
            verdict = "HIGH RISK"
        elif level == "MEDIUM":
            css_class = "medium"
            verdict = "MEDIUM RISK"
        else:
            css_class = "low"
            verdict = "LOW RISK"

        risk_pct = result["risk_score"]
        safe_pct = result["safe_probability"]
        spam_pct = result["spam_probability"]

        # ----------------------------------------------------
        # HEADER
        # ----------------------------------------------------

        st.html(f"""
        <div class="result-wrap">

            <div class="result-header">

                <div>
                    <div class="result-kicker">
                        Analysis complete
                    </div>

                    <div class="result-verdict {css_class}">
                        {verdict}
                    </div>
                </div>

                <div class="score">

                    <div class="score-number">
                        {risk_pct:.0%}
                    </div>

                    <div class="score-label">
                        THREAT SCORE
                    </div>

                </div>

            </div>

        </div>
        """)

        # ----------------------------------------------------
        # SIGNALS
        # ----------------------------------------------------

        indicators_html = ""

        if result["indicators"]:

            for indicator in result["indicators"]:

                indicators_html += f"""
                <span class="signal">
                    <span class="signal-dot"></span>
                    {indicator}
                </span>
                """

        else:

            indicators_html = """
            <span style="
                color:#777d85;
                font-family:'DM Mono',monospace;
                font-size:.68rem;">
                NO ADDITIONAL SIGNALS DETECTED
            </span>
            """

        # ----------------------------------------------------
        # RESULT GRID
        # ----------------------------------------------------

        classification = (
            "Potential spam / suspicious"
            if result["prediction"] == 1
            else
            "No significant spam detected"
        )

        st.html(f"""
        <div class="result-grid">

            <div class="result-cell">

                <div class="cell-label">
                    Classification
                </div>

                <div class="cell-value">
                    {classification}
                </div>

            </div>


            <div class="result-cell">

                <div class="cell-label">
                    Detected signals
                </div>

                <div>
                    {indicators_html}
                </div>

            </div>


            <div class="result-cell">

                <div class="cell-label">
                    Model confidence
                </div>

                <div>

                    <div class="bar-row">

                        <div class="bar-name">
                            SAFE
                        </div>

                        <div class="bar-bg">

                            <div
                                class="bar-safe"
                                style="width:{safe_pct * 100}%">
                            </div>

                        </div>

                        <div class="bar-number">
                            {safe_pct:.0%}
                        </div>

                    </div>


                    <div class="bar-row">

                        <div class="bar-name">
                            RISK
                        </div>

                        <div class="bar-bg">

                            <div
                                class="bar-risk"
                                style="width:{spam_pct * 100}%">
                            </div>

                        </div>

                        <div class="bar-number">
                            {spam_pct:.0%}
                        </div>

                    </div>

                </div>

            </div>


            <div class="result-cell">

                <div class="cell-label">
                    Message analyzed
                </div>

                <div class="message-preview">
                    {message}
                </div>

            </div>

        </div>
        """)


# ============================================================
# FOOTER
# ============================================================

st.html("""
<div class="footer">

    <div>
        SENTINELAI / AI THREAT INTELLIGENCE
    </div>

    <div>
        TF-IDF + LOGISTIC REGRESSION
    </div>

    <div>
        97.31% TEST ACCURACY
    </div>

</div>
""")
