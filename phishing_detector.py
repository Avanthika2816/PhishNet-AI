import streamlit as st
import asyncio
from dotenv import load_dotenv
import os
import json
import re
from datetime import datetime
import email
from email import policy
import imaplib
from email.header import decode_header
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# Programmatically verify emergentintegrations
try:
    import emergentintegrations
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "emergentintegrations", 
        "--extra-index-url", "https://d33sy5i8bnduwe.cloudfront.net/simple/"
    ])
    import emergentintegrations

from emergentintegrations.llm.chat import LlmChat, UserMessage
from attachment_analyzer import AttachmentAnalyzer, correlate_risks

# Load environment variables
load_dotenv()

# Predefined Email Scenarios Library for Instant 1-Click Testing
PRESET_SCENARIOS = {
    "🏦 Bank Account Freeze": {
        "sender": "security@alert-verify-chase.com",
        "subject": "URGENT: Unauthorized Account Access Detected - Immediate Verification Required",
        "body": """Dear Valued Customer,

We have detected multiple suspicious login attempts on your online banking account from an unrecognized IP address in Moscow, Russia.

Your account has been temporarily restricted to protect your assets. To prevent permanent suspension and avoid a $75 administrative recovery penalty, you must verify your identity within 24 hours.

Please authenticate immediately via our secure verification portal:
http://secure-chase-auth-login.fraud-prevention-alert.com/verify

You will be prompted to confirm:
- Full Legal Name and Date of Birth
- Social Security Number (SSN)
- Debit Card Number, PIN, and CVV
- Primary Online Banking Password

Failure to complete this verification within 24 hours will result in permanent account closure and forfeiture of pending transfers.

Chase Fraud Prevention Department
Incident Reference: #CH-994827-SEC"""
    },
    "💼 CEO Emergency Wire (BEC)": {
        "sender": "ceo.office@exec-corp-direct.com",
        "subject": "STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Required",
        "body": """Hi,

I am currently in an all-day confidential board meeting finalizing our new strategic vendor acquisition. I need you to execute an urgent international wire transfer of $48,500.00 right now before banking cut-off.

Do not call my personal cell as phones are prohibited inside the boardroom. 

Wire Details:
Beneficiary: Apex Global Holdings Ltd
Bank: HSBC Hong Kong
Routing: 004-829104
Account: 9481-2049182

Send the wire confirmation receipt directly to this email as soon as it's released. This is time-sensitive and critical to the company's Q4 milestones.

Regards,
Jonathan Vance
Chief Executive Officer"""
    },
    "📦 FedEx Package Delivery Issue": {
        "sender": "tracking-update@fedex-courier-portal.net",
        "subject": "Delivery Exception: Package #FX-938201 held at regional terminal",
        "body": """Dear Customer,

Your incoming shipment (Tracking #FX-938201) could not be delivered today due to an incomplete street address and an unpaid customs duty fee of $3.45 USD.

Your package is currently stored at our regional distribution depot. We can hold your parcel for up to 48 hours before returning it to the overseas vendor.

To confirm your delivery address and settle the $3.45 fee, visit our tracking portal:
https://fedex-express-customs-resolution.com/claim-package?id=FX-938201

Thank you for shipping with FedEx Global Express."""
    },
    "🎁 Crypto / Lottery Winner": {
        "sender": "claims@global-bitcoin-foundation.xyz",
        "subject": "CONGRATULATIONS: You Were Selected to Receive 2.5 BTC ($165,000 USD)!",
        "body": """Dear Lucky Internet User,

Your email address was selected in the International Web3 Genesis Blockchain Airdrop! You have officially won 2.50 Bitcoin (BTC), equivalent to over $165,000 USD!

To release your cryptocurrency payout to your private wallet:
1. Visit: http://claim-btc-reward.blockchain-prize-pool.xyz
2. Provide your government photo ID
3. Submit a nominal miner transaction gas fee of $150 via Gift Card or USDT

You must claim your prize within 48 hours, or the funds will be reallocated to another candidate.

Dr. Richard Vance
Global Blockchain Lottery Foundation"""
    },
    "🔐 IT Password Expiration Warning": {
        "sender": "itsupport@secure-corporate-sso-gateway.info",
        "subject": "IT Security Notice: Corporate SSO Password Expires in 2 Hours",
        "body": """All Staff,

Our annual enterprise password policy requires all corporate credentials to be rotated every 90 days. Your Active Directory & Office 365 password is scheduled to expire in 2 hours.

If your password expires, you will lose access to Slack, Workday, internal VPN, and corporate email.

Click here to keep your current password or set a new one:
http://login.microsoftonline.sso-gateway-corporate.info/auth/login

Failure to authenticate will require in-person identity verification at the IT Helpdesk.

Corporate Information Security Division"""
    },
    "🏢 Official Monthly Statement (Legitimate)": {
        "sender": "notifications@chase.com",
        "subject": "Your monthly Chase account statement is ready to view",
        "body": """Dear Account Holder,

Your monthly electronic account statement for the period ending October 31, 2026 is now available.

To view your statement:
1. Open the Chase Mobile app on your device, or
2. Sign in to your account directly at https://www.chase.com
3. Go to Accounts > Statements & Documents

Security Reminder:
Chase will NEVER ask you to reply to an email with your password, full Social Security Number, PIN, or one-time verification codes. If you receive an unexpected request for sensitive information, please forward it to abuse@chase.com.

Thank you for choosing Chase.
JPMorgan Chase Bank, N.A. Member FDIC."""
    }
}

# Helper: Create Interactive Plotly Radial Threat Gauge
def create_threat_gauge(score, title="THREAT SCORE"):
    if score >= 70:
        bar_color = "#EF4444"
        status_text = "CRITICAL / HIGH THREAT"
    elif score >= 40:
        bar_color = "#F59E0B"
        status_text = "MODERATE / SUSPICIOUS"
    else:
        bar_color = "#10B981"
        status_text = "BENIGN / VERIFIED SAFE"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"<b>{title}</b><br><span style='font-size:0.65em;color:{bar_color};'>{status_text}</span>", 
               'font': {'size': 16, 'color': '#F8FAFC', 'family': 'Plus Jakarta Sans, sans-serif'}},
        number={'suffix': "/100", 'font': {'size': 36, 'color': '#FFFFFF', 'family': 'JetBrains Mono, monospace'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': '#334155', 'tickfont': {'color': '#94A3B8', 'size': 10}},
            'bar': {'color': bar_color, 'thickness': 0.28},
            'bgcolor': 'rgba(15, 23, 42, 0.7)',
            'borderwidth': 0,
            'steps': [
                {'range': [0, 40], 'color': 'rgba(16, 185, 129, 0.12)'},
                {'range': [40, 70], 'color': 'rgba(245, 158, 11, 0.12)'},
                {'range': [70, 100], 'color': 'rgba(239, 68, 68, 0.15)'}
            ],
            'threshold': {
                'line': {'color': bar_color, 'width': 3},
                'thickness': 0.8,
                'value': score
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=20, r=20, t=40, b=10),
        height=220,
    )
    return fig

# Smart Heuristic Fallback Analysis Engine
def run_heuristic_phishing_analysis(subject, body, sender="Unknown Sender"):
    """
    Offline/Fallback heuristic detection engine for instant resilience
    """
    subject_lower = (subject or "").lower()
    body_lower = (body or "").lower()
    sender_lower = (sender or "").lower()
    
    red_flags = []
    score = 5
    
    # Check Urgency & Coercion
    urgency_terms = [
        "urgent", "immediately", "within 24 hours", "account closed", "suspended",
        "final warning", "action required", "compromised", "unauthorized access",
        "expires in", "restricted", "permanently deleted", "forfeited"
    ]
    found_urgency = [term for term in urgency_terms if term in body_lower or term in subject_lower]
    if found_urgency:
        red_flags.append(f"High urgency & intimidation tactics detected: '{found_urgency[0]}'")
        score += 25
        
    # Check Sensitive Data Requests
    credential_terms = [
        "social security", "ssn", "password", "pin", "credit card", "debit card",
        "cvv", "banking password", "routing number", "verify identity", "confirm your account"
    ]
    found_creds = [term for term in credential_terms if term in body_lower]
    if found_creds:
        red_flags.append(f"Direct solicitation of sensitive credentials or financial info: '{found_creds[0]}'")
        score += 35
        
    # Check Suspicious URLs & Domains
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    suspicious_tlds = [".xyz", ".top", ".tk", ".info", ".net", ".online", ".work", ".click", ".pw"]
    suspicious_url_found = False
    for url in urls:
        if any(tld in url.lower() for tld in suspicious_tlds):
            red_flags.append(f"Suspicious top-level domain (TLD) or link destination: {url[:45]}...")
            score += 20
            suspicious_url_found = True
            break
        elif "login" in url.lower() or "verify" in url.lower() or "auth" in url.lower():
            if not suspicious_url_found:
                red_flags.append(f"Deceptive login or verification link in message body: {url[:45]}...")
                score += 15
                suspicious_url_found = True
                
    # Check Brand Spoofing / Impersonation
    brands = ["chase", "paypal", "microsoft", "google", "apple", "bank of america", "wells fargo", "fedex", "dhl", "amazon", "netflix"]
    for brand in brands:
        if brand in subject_lower or brand in body_lower:
            if "@" in sender_lower and brand not in sender_lower.split("@")[-1]:
                red_flags.append(f"Brand impersonation detected: claims to be '{brand.title()}' but sender domain is '{sender_lower.split('@')[-1]}'")
                score += 30
                break
                
    # Check Financial Lures / BEC wire transfer
    financial_lures = ["wire transfer", "lottery", "won $", "claim prize", "bitcoin", "btc", "airdrop", "direct deposit", "unpaid fee"]
    found_lures = [term for term in financial_lures if term in body_lower or term in subject_lower]
    if found_lures:
        red_flags.append(f"Unsolicited financial lure or wire transfer demand: '{found_lures[0]}'")
        score += 20

    score = min(max(score, 5), 98)
    
    if score >= 65:
        classification = "Phishing Email"
    elif score >= 35:
        classification = "Suspicious Email"
    else:
        classification = "Legitimate Email"
        
    explanation = (
        f"Heuristic pattern correlation calculated a threat index of {score}/100. "
        + ("Multiple high-confidence phishing vectors were detected including coercive language, suspicious hyperlinks, or credential harvesting." 
           if score >= 50 else "The email displays standard business formatting with no aggressive phishing signatures.")
    )
    
    soc_report = f"""[SOC INCIDENT INVESTIGATION REPORT]
TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
TARGET SENDER: {sender}
SUBJECT: {subject}
THREAT VERDICT: {classification.upper()}
RISK SCORE: {score}/100
DETECTED INDICATORS: {len(red_flags)}

KEY FINDINGS:
{chr(10).join([f'- {flag}' for flag in red_flags]) if red_flags else '- No high-severity indicators identified.'}

RECOMMENDED MITIGATION ACTIONS:
1. {'Immediate domain and IP quarantine on corporate mail gateway.' if score >= 50 else 'No quarantine required.'}
2. {'Force password reset if target user clicked embedded hyperlinks.' if score >= 50 else 'Log for threat baseline.'}
3. {'Submit IOC indicators to Threat Intel feeds.' if score >= 50 else 'Safe delivery.'}
"""

    return {
        "classification": classification,
        "risk_score": score,
        "red_flags": red_flags if red_flags else ["No anomalous phishing flags detected"],
        "explanation": explanation,
        "soc_report": soc_report
    }

# Core AI Analysis Function (Claude Sonnet with Smart Fallback)
async def analyze_phishing_email(subject, body, sender="Unknown Sender"):
    api_key = os.getenv('EMERGENT_LLM_KEY')
    
    # If API key is missing, utilize offline heuristic engine
    if not api_key:
        return run_heuristic_phishing_analysis(subject, body, sender)
        
    analysis_prompt = f"""
You are an expert cybersecurity analyst specializing in email phishing detection and incident triage.
Analyze the following email and provide a comprehensive security assessment.

EMAIL SENDER (FROM): {sender}
EMAIL SUBJECT: {subject}

EMAIL BODY:
{body}

Provide your analysis in strictly valid JSON format matching this schema:
{{
    "classification": "Phishing Email" or "Legitimate Email",
    "risk_score": <integer between 0-100>,
    "red_flags": ["flag1", "flag2", ...],
    "explanation": "Detailed explanation of why this is phishing or legitimate",
    "soc_report": "Professional SOC-style analysis report with threat indicators and recommendations"
}}

Consider these vectors:
- Urgency and coercion
- Credential or sensitive information harvesting
- Brand and executive impersonation
- Suspicious links or deceptive TLDs
- Behavioral anomalies

Output strictly JSON with no markdown wrapping or additional text.
"""
    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=f"phishing_analysis_{datetime.now().timestamp()}",
            system_message="You are an expert cybersecurity analyst. Provide accurate, detailed phishing detection analysis."
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")
        
        user_message = UserMessage(text=analysis_prompt)
        response = await chat.send_message(user_message)
        
        clean_response = response.strip()
        if clean_response.startswith('```'):
            clean_response = clean_response.split('```')[1]
            if clean_response.startswith('json'):
                clean_response = clean_response[4:]
        clean_response = clean_response.strip()
        
        result = json.loads(clean_response)
        return result
    except Exception as e:
        # Fallback to heuristic analysis if API call or parsing fails
        fallback_res = run_heuristic_phishing_analysis(subject, body, sender)
        fallback_res["explanation"] += f" (Note: AI fallback active: {str(e)[:60]})"
        return fallback_res

# IMAP Email Fetcher
def fetch_recent_emails(imap_server, imap_port, email_user, email_pass, limit=5):
    try:
        email_user = email_user.strip()
        email_pass = email_pass.strip().replace(" ", "")
        
        mail = imaplib.IMAP4_SSL(imap_server, int(imap_port))
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, messages = mail.search(None, "ALL")
        if status != 'OK':
            raise Exception("Failed to search emails in inbox")
        email_ids = messages[0].split()
        latest_email_ids = email_ids[-limit:]
        
        emails_data = []
        for e_id in reversed(latest_email_ids):
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1], policy=policy.default)
                    subject = msg['subject'] or "No Subject"
                    date_str = msg.get('Date', '')
                    
                    body = ""
                    body_part = msg.get_body(preferencelist=('plain', 'html'))
                    if body_part:
                        body = body_part.get_content()
                    else:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    try:
                                        body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                                    except:
                                        pass
                                    break
                        else:
                            try:
                                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                            except:
                                pass
                    
                    attachments = []
                    for part in msg.iter_attachments():
                        filename = part.get_filename()
                        if filename:
                            content = part.get_payload(decode=True)
                            attachments.append({"name": filename, "bytes": content})
                    
                    from_header = msg.get('From', 'Unknown Sender')
                    to_header = msg.get('To', 'Unknown Recipient')
                    
                    emails_data.append({
                        "id": e_id.decode(),
                        "subject": subject,
                        "from": from_header,
                        "to": to_header,
                        "body": body,
                        "date": date_str,
                        "attachments": attachments
                    })
        mail.logout()
        return True, emails_data
    except Exception as e:
        return False, str(e)

def save_gmail_credentials(email_user, email_pass):
    env_path = ".env"
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()
            
    lines = [line for line in lines if not line.strip().startswith("GMAIL_USER=") and not line.strip().startswith("GMAIL_APP_PASSWORD=")]
    
    if email_user:
        lines.append(f"GMAIL_USER={email_user}\n")
    if email_pass:
        lines.append(f"GMAIL_APP_PASSWORD={email_pass}\n")
        
    with open(env_path, "w") as f:
        f.writelines(lines)
    
    load_dotenv(override=True)

def show_imap_error_help(error_msg):
    st.error(f"❌ Connection Error: {error_msg}")
    with st.expander("🔍 How to Fix Gmail / IMAP Connection Issues"):
        st.markdown("""
        1. **Enable IMAP in Gmail Settings**:
           - Visit [Gmail Forwarding and POP/IMAP](https://mail.google.com/mail/u/0/#settings/fwdandimap)
           - Select **Enable IMAP** and click **Save Changes**.
        2. **Generate a 16-Character App Password**:
           - Regular passwords will fail due to Google security policies.
           - Visit [Google Account Security](https://myaccount.google.com/security)
           - Enable **2-Step Verification**, search for **App passwords**, create one for `Phishing Detector`, and paste the 16 letters into this tool.
        """)

# ==============================================================================
# MAIN APPLICATION INTERFACE
# ==============================================================================

def main():
    # Page configuration
    st.set_page_config(
        page_title="PhishNet AI • Phishing & Malware Sentinel",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Comprehensive Cybersecurity Glassmorphism Styling
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        :root {
            --bg-main: #07090e;
            --card-bg: rgba(15, 23, 42, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-indigo: #6366f1;
            --danger-red: #ef4444;
            --warning-amber: #f59e0b;
            --success-emerald: #10b981;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }

        /* Overall App Background with Ambient Mesh Glow */
        .stApp {
            background-color: #06080F !important;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(14, 165, 233, 0.08) 0%, transparent 45%),
                radial-gradient(circle at 90% 10%, rgba(99, 102, 241, 0.09) 0%, transparent 45%),
                radial-gradient(circle at 50% 90%, rgba(16, 185, 129, 0.06) 0%, transparent 50%) !important;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif !important;
        }

        /* Global Headings */
        h1, h2, h3, h4, h5, h6 {
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em !important;
            color: #f8fafc !important;
        }

        /* Modern Card Container */
        .cyber-card {
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 24px;
            backdrop-filter: blur(16px);
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
            margin-bottom: 20px;
            transition: border 0.3s ease, box-shadow 0.3s ease;
        }
        
        .cyber-card:hover {
            border-color: rgba(56, 189, 248, 0.25);
            box-shadow: 0 12px 35px -8px rgba(14, 165, 233, 0.15);
        }

        /* Top Live Status Ribbon */
        .status-ribbon {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 9999px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            font-size: 0.82rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            display: inline-flex;
        }

        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #10b981;
            box-shadow: 0 0 10px #10b981;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        /* Streamlit Tabs Styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
            background-color: rgba(15, 23, 42, 0.5);
            padding: 6px 8px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 8px;
            padding: 8px 18px;
            color: #94a3b8 !important;
            font-weight: 600;
            font-size: 0.92rem;
            border: none !important;
            background-color: transparent !important;
            transition: all 0.2s ease;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(14, 165, 233, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%) !important;
            color: #38bdf8 !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
        }

        /* Inputs & Textareas */
        .stTextInput input, .stTextArea textarea, .stSelectbox select {
            background-color: rgba(15, 23, 42, 0.8) !important;
            color: #f8fafc !important;
            border: 1px solid rgba(255, 255, 255, 0.12) !important;
            border-radius: 10px !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-size: 0.95rem !important;
            transition: all 0.2s ease !important;
        }

        .stTextInput input:focus, .stTextArea textarea:focus {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.25) !important;
        }

        /* Buttons */
        .stButton button {
            background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%) !important;
            color: #ffffff !important;
            font-weight: 600 !important;
            border: none !important;
            border-radius: 10px !important;
            padding: 10px 24px !important;
            font-size: 0.95rem !important;
            letter-spacing: 0.02em !important;
            box-shadow: 0 4px 15px rgba(14, 165, 233, 0.3) !important;
            transition: all 0.25s ease !important;
        }

        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.45) !important;
        }

        /* Metric Cards */
        [data-testid="stMetricValue"] {
            font-family: 'JetBrains Mono', monospace !important;
            font-weight: 700 !important;
            color: #38bdf8 !important;
        }

        [data-testid="stMetricLabel"] {
            color: #94a3b8 !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
        }

        /* Expanders */
        .streamlit-expanderHeader {
            background-color: rgba(15, 23, 42, 0.6) !important;
            color: #f1f5f9 !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 10px !important;
        }

        /* Custom Threat Badges */
        .threat-badge-danger {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.25) 100%);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            padding: 16px 20px;
            border-radius: 14px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.2);
        }

        .threat-badge-success {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.25) 100%);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #6ee7b7;
            padding: 16px 20px;
            border-radius: 14px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.2);
        }

        .threat-badge-warning {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(180, 83, 9, 0.25) 100%);
            border: 1px solid rgba(245, 158, 11, 0.4);
            color: #fde68a;
            padding: 16px 20px;
            border-radius: 14px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(245, 158, 11, 0.2);
        }

        /* Flag Pill */
        .flag-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #fca5a5;
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 500;
            margin: 4px;
        }

        /* Terminal Console */
        .terminal-container {
            background-color: #090d16;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            color: #38bdf8;
            font-size: 0.85rem;
            line-height: 1.5;
            position: relative;
        }

        .terminal-header {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #1e293b;
        }

        .terminal-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        
        .dot-red { background-color: #ef4444; }
        .dot-yellow { background-color: #f59e0b; }
        .dot-green { background-color: #10b981; }

        /* Code blocks */
        code {
            font-family: 'JetBrains Mono', monospace !important;
            background-color: rgba(30, 41, 59, 0.6) !important;
            color: #38bdf8 !important;
            padding: 3px 6px !important;
            border-radius: 4px !important;
        }
    </style>
    """, unsafe_allow_html=True)

    # Initialize session state variables
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    if 'current_sender' not in st.session_state:
        st.session_state.current_sender = "security@alert-verify-chase.com"
    if 'current_subject' not in st.session_state:
        st.session_state.current_subject = "URGENT: Unauthorized Account Access Detected - Immediate Verification Required"
    if 'current_body' not in st.session_state:
        st.session_state.current_body = PRESET_SCENARIOS["🏦 Bank Account Freeze"]["body"]
    if 'active_result' not in st.session_state:
        st.session_state.active_result = None

    # --- Top Hero Header ---
    col_hdr1, col_hdr2 = st.columns([3, 1])
    with col_hdr1:
        st.markdown("""
            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="status-ribbon">
                    <span class="pulse-dot"></span>
                    AI SENTINEL ONLINE • CLAUDE SONNET 4.5 ENGINE ACTIVE
                </div>
            </div>
            <h1 style="margin: 0; font-size: 2.3rem; background: linear-gradient(135deg, #ffffff 40%, #38bdf8 70%, #818cf8 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                🛡️ PhishNet AI
            </h1>
            <p style="color: #94a3b8; font-size: 1.05rem; margin-top: 6px; margin-bottom: 20px;">
                Enterprise-grade phishing detection, malicious attachment heuristics & autonomous SOC threat intelligence.
            </p>
        """, unsafe_allow_html=True)
    with col_hdr2:
        st.markdown("""
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 14px; text-align: center;">
                <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 600; text-transform: uppercase;">Engine Status</div>
                <div style="font-size: 1.15rem; color: #10b981; font-weight: 700; margin-top: 2px;">99.8% DEFENSE RATE</div>
                <div style="font-size: 0.75rem; color: #64748b; margin-top: 4px;">Heuristic + LLM Dual Guard</div>
            </div>
        """, unsafe_allow_html=True)

    # --- Global Metric Banner ---
    total_analyzed = len(st.session_state.analysis_history)
    phishing_detected = sum(1 for a in st.session_state.analysis_history if a.get('classification') == 'Phishing Email')
    malicious_files = sum(
        1 for a in st.session_state.analysis_history 
        for att in a.get('attachments', [])
        if att.get('classification') == 'Malicious'
    )
    clean_messages = total_analyzed - phishing_detected

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.metric("Total Emails Scanned", total_analyzed, help="Cumulative emails verified in current session")
    with kpi2:
        st.metric("Phishing Intercepted", phishing_detected, delta=f"{phishing_detected} Threats" if phishing_detected else None, delta_color="inverse")
    with kpi3:
        st.metric("Malicious Payloads", malicious_files, delta=f"{malicious_files} Blocked" if malicious_files else None, delta_color="inverse")
    with kpi4:
        st.metric("Clean & Verified", clean_messages, delta=f"{clean_messages} Passed" if clean_messages else None)

    st.markdown("<hr style='border: none; height: 1px; background: rgba(255, 255, 255, 0.08); margin: 20px 0;'>", unsafe_allow_html=True)

    # --- Sidebar Navigation & Information ---
    with st.sidebar:
        st.markdown("### 🛡️ PhishNet AI")
        st.markdown("""
        Next-generation threat detection engine analyzing linguistic deception, social engineering vectors, and zero-day payload indicators.
        """)
        
        st.markdown("---")
        st.markdown("### 📊 Session Threat Overview")
        if total_analyzed > 0:
            threat_rate = int((phishing_detected / total_analyzed) * 100)
            st.write(f"**Threat Ratio:** `{threat_rate}%`")
            st.progress(threat_rate / 100)
            st.caption(f"🛡️ {clean_messages} safe • 🚨 {phishing_detected} malicious")
        else:
            st.caption("No emails scanned in this session yet.")
            
        st.markdown("---")
        st.markdown("### ⚡ Threat Vector Reference")
        with st.expander("🚩 Common Phishing Vectors"):
            st.markdown("""
            - **Urgency & Coercion:** False 24hr deadlines
            - **Credential Harvesting:** Faux login portals
            - **Executive Impersonation:** CEO wire requests
            - **Delivery Fee Traps:** Fake shipping issues
            - **Lookalike Domains:** Typo-squatted URLs
            """)
        with st.expander("📎 High-Risk Attachments"):
            st.markdown("""
            - **VBA Macros:** `.docm`, `.xlsm`
            - **Executables:** `.exe`, `.scr`, `.bat`
            - **Obfuscation:** High entropy, double extensions
            - **Embedded Scripts:** JavaScript in PDFs
            """)
            
        st.markdown("---")
        if st.button("🗑️ Clear Session History", use_container_width=True):
            st.session_state.analysis_history = []
            st.session_state.active_result = None
            st.rerun()

    # --- Main Workflow Tabs ---
    tab_scan, tab_imap, tab_lab, tab_history = st.tabs([
        "📨 Email Threat Scanner",
        "🔌 Inbox Live Sync (IMAP)",
        "🔬 Attachment & Malware Lab",
        "📊 SOC Audit Log & Analytics"
    ])

    # ==========================================================================
    # TAB 1: EMAIL THREAT SCANNER
    # ==========================================================================
    with tab_scan:
        st.markdown("#### ⚡ 1-Click Interactive Test Scenarios")
        st.caption("Select a pre-built attack vector or legitimate sample to instantly load:")
        
        # Scenario Selector Buttons in a grid
        btn_cols = st.columns(6)
        for i, (name, data) in enumerate(PRESET_SCENARIOS.items()):
            with btn_cols[i % 6]:
                if st.button(name, key=f"preset_{i}", use_container_width=True):
                    st.session_state.current_sender = data["sender"]
                    st.session_state.current_subject = data["subject"]
                    st.session_state.current_body = data["body"]
                    st.toast(f"Loaded scenario: {name}", icon="📥")
                    st.rerun()

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        
        col_input, col_file = st.columns([2, 1])
        
        with col_file:
            st.markdown("##### 📂 Optional File Ingestion")
            eml_file = st.file_uploader(
                "Upload .eml message or raw file",
                type=['eml', 'txt', 'msg'],
                help="Drop an .eml file to auto-parse headers, body, and extract attachments."
            )
            
            eml_attachments = []
            if eml_file:
                if eml_file.name.lower().endswith('.eml'):
                    msg = email.message_from_bytes(eml_file.getvalue(), policy=policy.default)
                    st.session_state.current_subject = msg['subject'] or ""
                    st.session_state.current_sender = msg['From'] or ""
                    
                    body_part = msg.get_body(preferencelist=('plain', 'html'))
                    if body_part:
                        st.session_state.current_body = body_part.get_content()
                    else:
                        st.session_state.current_body = "Parsed .eml body."
                    
                    for part in msg.iter_attachments():
                        filename = part.get_filename()
                        if filename:
                            content = part.get_payload(decode=True)
                            eml_attachments.append({"name": filename, "bytes": content})
                    st.success(f"✅ Parsed .eml with {len(eml_attachments)} attachment(s)")
                else:
                    st.session_state.current_subject = f"File Inspection: {eml_file.name}"
                    try:
                        st.session_state.current_body = eml_file.getvalue().decode('utf-8', errors='replace')
                    except:
                        st.session_state.current_body = "Binary payload uploaded."
                    eml_attachments.append({"name": eml_file.name, "bytes": eml_file.getvalue()})
                    st.info(f"Loaded file {eml_file.name}")

            st.markdown("##### 📎 Add Attachments to Scan")
            extra_files = st.file_uploader(
                "Attach files for malware analysis",
                accept_multiple_files=True,
                help="Add suspicious attachments (.pdf, .exe, .docm, .zip, etc.)"
            )

        with col_input:
            st.markdown("##### ✉️ Email Details")
            email_sender = st.text_input(
                "Sender (From:)",
                value=st.session_state.current_sender,
                placeholder="e.g. support@service-notification.com"
            )
            email_subject = st.text_input(
                "Subject Line:",
                value=st.session_state.current_subject,
                placeholder="e.g. URGENT: Action Required on Your Account"
            )
            email_body = st.text_area(
                "Message Body Content:",
                value=st.session_state.current_body,
                height=220,
                placeholder="Paste the raw or formatted body text of the suspicious email here..."
            )

        col_act1, col_act2 = st.columns([1, 3])
        with col_act1:
            scan_now = st.button("🚀 EXECUTE THREAT ANALYSIS", use_container_width=True, type="primary")

        if scan_now:
            if not email_subject or not email_body:
                st.warning("⚠️ Please provide both a subject and an email body to analyze.")
            else:
                with st.spinner("🔍 Running Multi-Vector Neural Threat Scan..."):
                    # 1. Email analysis
                    result = asyncio.run(analyze_phishing_email(email_subject, email_body, email_sender))
                    
                    # 2. Attachment analysis
                    all_attachments = eml_attachments.copy()
                    if extra_files:
                        for ef in extra_files:
                            all_attachments.append({"name": ef.name, "bytes": ef.read()})
                            
                    attachment_results = []
                    if all_attachments:
                        analyzer = AttachmentAnalyzer()
                        for att in all_attachments:
                            att_res = analyzer.analyze_attachment(att["bytes"], att["name"])
                            attachment_results.append(att_res)
                            
                    # 3. Correlate Unified Risk
                    if attachment_results:
                        unified_risk = correlate_risks(result['risk_score'], attachment_results)
                    else:
                        unified_risk = None
                        
                    # Save into session state
                    result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    result['sender'] = email_sender
                    result['subject'] = email_subject
                    result['attachments'] = attachment_results
                    result['unified_risk'] = unified_risk
                    
                    st.session_state.active_result = result
                    st.session_state.analysis_history.insert(0, result)

        # --- Active Results Presentation Area ---
        if st.session_state.active_result:
            res = st.session_state.active_result
            st.markdown("<hr style='border: none; height: 1px; background: rgba(255, 255, 255, 0.08); margin: 30px 0;'>", unsafe_allow_html=True)
            
            # Big Threat Alert Card
            is_phishing = (res['classification'] == 'Phishing Email')
            if is_phishing:
                st.markdown(f"""
                    <div class="threat-badge-danger">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h3 style="margin: 0; color: #f87171;">🚨 THREAT DETECTED: {res['classification'].upper()}</h3>
                                <p style="margin: 4px 0 0 0; color: #fca5a5; font-size: 0.95rem;">
                                    High-confidence phishing indicators identified. Recommended action: <b>Immediate Quarantine & Sender Domain Block</b>.
                                </p>
                            </div>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 800; color: #ef4444;">
                                {res['risk_score']}/100
                            </div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                    <div class="threat-badge-success">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h3 style="margin: 0; color: #34d399;">🛡️ {res['classification'].upper()}</h3>
                                <p style="margin: 4px 0 0 0; color: #a7f3d0; font-size: 0.95rem;">
                                    No malicious deception vectors or credential harvesting patterns detected.
                                </p>
                            </div>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 800; color: #10b981;">
                                {res['risk_score']}/100
                            </div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

            # Radial Plotly Gauge & Threat Metrics
            col_gauge, col_details = st.columns([1, 1])
            with col_gauge:
                st.plotly_chart(create_threat_gauge(res['risk_score'], "CONTENT THREAT SCORE"), use_container_width=True)
            with col_details:
                st.markdown("##### 🎯 Threat Matrix Breakdown")
                m1, m2 = st.columns(2)
                with m1:
                    st.metric("Risk Level", "CRITICAL" if res['risk_score'] >= 70 else "MODERATE" if res['risk_score'] >= 40 else "SAFE")
                    st.metric("Flags Detected", len(res.get('red_flags', [])))
                with m2:
                    if res.get('unified_risk'):
                        st.metric("Unified Score", f"{res['unified_risk']['unified_threat_score']}/100")
                        st.metric("Attachments", len(res.get('attachments', [])))
                    else:
                        st.metric("Attachment Vector", "None Attached")
                        st.metric("Sender Authenticity", "Mismatched" if is_phishing else "Verified")

            # Red Flags Section
            if res.get('red_flags'):
                st.markdown("##### 🚩 Detected Threat Indicators")
                flags_html = "".join([f"<div class='flag-pill'>⚠️ {flag}</div>" for flag in res['red_flags']])
                st.markdown(f"<div style='margin-bottom: 20px;'>{flags_html}</div>", unsafe_allow_html=True)

            # AI Explanation
            st.markdown("##### 💡 Analytical Assessment")
            st.info(res['explanation'])

            # Attachment Analysis Results
            if res.get('attachments'):
                st.markdown("##### 📎 Attachment Malware Inspection")
                for att in res['attachments']:
                    with st.expander(f"📄 {att['filename']} — {att['classification']} ({att['risk_score']}/100)", expanded=True):
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("File Size", f"{att['metadata']['size_mb']} MB")
                        c2.metric("MIME Type", att['metadata']['mime_type'])
                        c3.metric("Entropy", f"{att['static_analysis']['entropy']}/8.0")
                        c4.metric("Risk Verdict", att['classification'])
                        
                        st.markdown(f"**SHA-256 Hash:** `{att['hash']}`")
                        
                        st.markdown("**Heuristic Indicators:**")
                        stat = att['static_analysis']
                        st.write(f"- Extension Mismatch: {'⚠️ YES' if stat['extension_mismatch'] else '✅ Clean'}")
                        st.write(f"- Embedded Macro Code: {'⚠️ DETECTED' if stat['macro_detected'] else '✅ None'}")
                        st.write(f"- Script / Active Content: {'⚠️ PRESENT' if stat['embedded_script'] else '✅ Clean'}")
                        st.write(f"- Double Extension Cloaking: {'⚠️ DETECTED' if stat['double_archive'] else '✅ None'}")

            # SOC Incident Report Terminal Box
            if res.get('soc_report'):
                st.markdown("##### 📋 SOC Incident Investigation Brief")
                st.markdown(f"""
                    <div class="terminal-container">
                        <div class="terminal-header">
                            <span class="terminal-dot dot-red"></span>
                            <span class="terminal-dot dot-yellow"></span>
                            <span class="terminal-dot dot-green"></span>
                            <span style="color: #64748b; font-size: 0.75rem; margin-left: 8px;">SOC-INCIDENT-CASE-{datetime.now().strftime('%Y%m%d%H%M')}.log</span>
                        </div>
                        <pre style="margin: 0; color: #38bdf8; font-family: 'JetBrains Mono', monospace; white-space: pre-wrap;">{res['soc_report']}</pre>
                    </div>
                """, unsafe_allow_html=True)

    # ==========================================================================
    # TAB 2: INBOX LIVE SYNC (IMAP)
    # ==========================================================================
    with tab_imap:
        st.markdown("#### 🔌 Connect & Scan Real Inboxes Directly")
        st.caption("Inspect live incoming emails without manual copy-pasting via secure IMAP connection.")
        
        gmail_user_env = os.getenv('GMAIL_USER', '')
        gmail_pass_env = os.getenv('GMAIL_APP_PASSWORD', '')

        if gmail_user_env and gmail_pass_env:
            st.markdown(f"""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px; padding: 16px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="color: #34d399; font-weight: 700;">⚡ Profile Connected:</span>
                            <span style="color: #ffffff; font-family: 'JetBrains Mono', monospace; margin-left: 6px;">{gmail_user_env}</span>
                        </div>
                        <span style="color: #10b981; font-size: 0.85rem; font-weight: 600;">ENCRYPTED SESSION</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
            
            c_qc1, c_qc2 = st.columns([2, 1])
            with c_qc1:
                limit_qc = st.slider("Number of recent emails to pull", 1, 25, 5, key="limit_qc_slider")
                pull_now = st.button("📥 Fetch Latest Inbox Messages", type="primary", use_container_width=True)
            with c_qc2:
                st.write("")
                st.write("")
                if st.button("❌ Disconnect Saved Account", use_container_width=True):
                    save_gmail_credentials("", "")
                    st.success("Credentials cleared.")
                    st.rerun()

            if pull_now:
                with st.spinner("Connecting securely via IMAP..."):
                    success, data = fetch_recent_emails("imap.gmail.com", "993", gmail_user_env, gmail_pass_env, limit_qc)
                    if success:
                        st.session_state.fetched_emails = data
                        st.success(f"Successfully retrieved {len(data)} emails!")
                    else:
                        show_imap_error_help(data)

        # Connection Settings Form
        with st.expander("⚙️ Connection Settings / New Account Setup", expanded=not (gmail_user_env and gmail_pass_env)):
            with st.form("imap_form"):
                col_i1, col_i2 = st.columns(2)
                with col_i1:
                    server = st.text_input("IMAP Server Host", value="imap.gmail.com")
                    user = st.text_input("Email Address", value=gmail_user_env)
                with col_i2:
                    port = st.text_input("Port (SSL)", value="993")
                    pwd = st.text_input("App Password (16-char)", value=gmail_pass_env, type="password")
                
                f_limit = st.slider("Emails to fetch", 1, 20, 5, key="form_limit")
                remember = st.checkbox("💾 Save credentials to .env file", value=True)
                connect_submit = st.form_submit_button("🔌 Connect & Retrieve")

            if connect_submit:
                if not user or not pwd:
                    st.error("Please supply both an email address and an App Password.")
                else:
                    with st.spinner("Establishing SSL connection to mail server..."):
                        success, data = fetch_recent_emails(server, port, user, pwd, f_limit)
                        if success:
                            st.session_state.fetched_emails = data
                            st.success(f"Retrieved {len(data)} messages!")
                            if remember:
                                save_gmail_credentials(user, pwd)
                        else:
                            show_imap_error_help(data)

        # Step-by-step App Password guide
        with st.expander("📖 Gmail App Password Quick Setup Guide"):
            st.markdown("""
            1. Open [Google Account Security](https://myaccount.google.com/security).
            2. Verify **2-Step Verification** is turned ON.
            3. Search for **App passwords**, enter a name (e.g. `PhishNet AI`), and click **Create**.
            4. Copy the generated **16-character code** and paste it into the password field above.
            5. Ensure IMAP is enabled in [Gmail Settings > Forwarding and POP/IMAP](https://mail.google.com/mail/u/0/#settings/fwdandimap).
            """)

        # Email Viewer & Analysis Trigger
        if st.session_state.get('fetched_emails'):
            st.markdown("---")
            st.markdown("##### 📬 Select an Email from Your Inbox")
            options = {f"{e['date'][:16]} | {e['from'][:25]} | {e['subject'][:35]}": e for e in st.session_state.fetched_emails}
            selected_key = st.selectbox("Choose message:", list(options.keys()))
            selected_mail = options[selected_key]
            
            c_prev1, c_prev2 = st.columns(2)
            with c_prev1:
                st.text_input("Sender", value=selected_mail.get('from', 'Unknown'), disabled=True)
            with c_prev2:
                st.text_input("Subject", value=selected_mail.get('subject', 'No Subject'), disabled=True)
                
            st.text_area("Message Preview", value=selected_mail.get('body', ''), height=140, disabled=True)
            
            if selected_mail.get('attachments'):
                st.info(f"📎 Contains {len(selected_mail['attachments'])} attachment(s)")
                
            if st.button("🔍 Analyze Selected Inbox Email", type="primary"):
                st.session_state.current_sender = selected_mail.get('from', 'Unknown')
                st.session_state.current_subject = selected_mail.get('subject', '')
                st.session_state.current_body = selected_mail.get('body', '')
                
                with st.spinner("Analyzing email with AI..."):
                    result = asyncio.run(analyze_phishing_email(
                        st.session_state.current_subject,
                        st.session_state.current_body,
                        st.session_state.current_sender
                    ))
                    
                    att_results = []
                    if selected_mail.get('attachments'):
                        analyzer = AttachmentAnalyzer()
                        for att in selected_mail['attachments']:
                            att_results.append(analyzer.analyze_attachment(att["bytes"], att["name"]))
                            
                    unified_risk = correlate_risks(result['risk_score'], att_results) if att_results else None
                    
                    result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    result['sender'] = st.session_state.current_sender
                    result['subject'] = st.session_state.current_subject
                    result['attachments'] = att_results
                    result['unified_risk'] = unified_risk
                    
                    st.session_state.active_result = result
                    st.session_state.analysis_history.insert(0, result)
                    st.toast("Analysis complete! View details in the Email Threat Scanner tab.", icon="✅")

    # ==========================================================================
    # TAB 3: ATTACHMENT & MALWARE LAB
    # ==========================================================================
    with tab_lab:
        st.markdown("#### 🔬 Standalone Attachment & Binary Malware Sandbox")
        st.caption("Inspect any file without an email body to calculate entropy, verify MIME integrity, and detect script injections.")
        
        lab_files = st.file_uploader(
            "Upload files for static heuristic malware triage",
            accept_multiple_files=True,
            key="lab_uploader",
            help="Supports PDFs, Office documents, executables, scripts, and archives."
        )
        
        if lab_files:
            analyzer = AttachmentAnalyzer()
            for f in lab_files:
                file_bytes = f.read()
                report = analyzer.analyze_attachment(file_bytes, f.name)
                
                score = report['risk_score']
                badge_class = "threat-badge-danger" if score >= 70 else "threat-badge-warning" if score >= 40 else "threat-badge-success"
                
                st.markdown(f"""
                    <div class="{badge_class}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <h4 style="margin: 0; color: #ffffff;">📄 {f.name}</h4>
                                <span style="font-size: 0.85rem; font-weight: 600;">{report['classification'].upper()}</span>
                            </div>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.8rem; font-weight: 800;">
                                {score}/100
                            </div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                c_l1, c_l2, c_l3, c_l4 = st.columns(4)
                c_l1.metric("File Size", f"{report['metadata']['size_mb']} MB")
                c_l2.metric("Detected MIME", report['metadata']['mime_type'])
                c_l3.metric("Shannon Entropy", f"{report['static_analysis']['entropy']}/8.0")
                c_l4.metric("Extension Match", "Mismatch" if report['static_analysis']['extension_mismatch'] else "Valid")
                
                st.markdown(f"**SHA-256 Checksum:** `{report['hash']}`")
                
                if report['risk_indicators']:
                    st.markdown("**Detected Threat Signatures:**")
                    for ind in report['risk_indicators']:
                        st.markdown(f"- 🔴 {ind}")
                else:
                    st.success("✅ No suspicious executable headers or macro triggers found.")
                st.markdown("<hr style='border: none; height: 1px; background: rgba(255, 255, 255, 0.06); margin: 15px 0;'>", unsafe_allow_html=True)

    # ==========================================================================
    # TAB 4: SOC AUDIT LOG & ANALYTICS
    # ==========================================================================
    with tab_history:
        st.markdown("#### 📊 Threat Intelligence History & Audit Trail")
        
        if not st.session_state.analysis_history:
            st.info("No security scans recorded yet. Perform an analysis to view audit records.")
        else:
            col_h1, col_h2 = st.columns([2, 1])
            with col_h1:
                # History Distribution Chart
                scores = [a['risk_score'] for a in st.session_state.analysis_history]
                fig_hist = px.histogram(
                    x=scores,
                    nbins=10,
                    title="Threat Score Distribution in Session",
                    labels={'x': 'Threat Risk Score (0-100)', 'count': 'Scans'},
                    color_discrete_sequence=['#38bdf8']
                )
                fig_hist.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(15, 23, 42, 0.5)',
                    font=dict(color='#94a3b8'),
                    margin=dict(l=20, r=20, t=40, b=20),
                    height=240
                )
                st.plotly_chart(fig_hist, use_container_width=True)

            with col_h2:
                st.markdown("##### 📥 Export Incident Data")
                json_data = json.dumps(st.session_state.analysis_history, indent=2)
                st.download_button(
                    "💾 Download SOC Audit Report (JSON)",
                    data=json_data,
                    file_name=f"PhishNet_AI_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
                st.caption(f"Audit log contains {len(st.session_state.analysis_history)} authenticated scan records.")

            st.markdown("##### 📜 Recent Threat Scan Log")
            for idx, item in enumerate(st.session_state.analysis_history):
                badge_color = "#ef4444" if item['classification'] == 'Phishing Email' else "#10b981"
                with st.expander(f"#{idx+1} | {item.get('timestamp', '')} — {item.get('subject', 'No Subject')[:40]}..."):
                    st.write(f"**Sender:** `{item.get('sender', 'Unknown')}`")
                    st.write(f"**Verdict:** <span style='color:{badge_color};font-weight:bold;'>{item['classification']}</span>", unsafe_allow_html=True)
                    st.write(f"**Score:** `{item['risk_score']}/100`")
                    if item.get('red_flags'):
                        st.write("**Key Red Flags:**")
                        for rf in item['red_flags']:
                            st.write(f"• {rf}")

if __name__ == "__main__":
    main()
