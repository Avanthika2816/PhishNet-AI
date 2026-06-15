import streamlit as st
import asyncio
from dotenv import load_dotenv
import os
import json
from datetime import datetime
import email
from email import policy
import imaplib
from email.header import decode_header

# Programmatically install emergentintegrations if it is not installed
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


def fetch_recent_emails(imap_server, imap_port, email_user, email_pass, limit=5):
    try:
        # Sanitize credentials (remove spaces from app password, strip whitespace from user)
        email_user = email_user.strip()
        email_pass = email_pass.strip().replace(" ", "")
        
        mail = imaplib.IMAP4_SSL(imap_server, int(imap_port))
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, messages = mail.search(None, "ALL")
        if status != 'OK':
            raise Exception("Failed to search emails")
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
            
    # Remove existing GMAIL keys
    lines = [line for line in lines if not line.strip().startswith("GMAIL_USER=") and not line.strip().startswith("GMAIL_APP_PASSWORD=")]
    
    # Add new keys if not empty
    if email_user:
        lines.append(f"GMAIL_USER={email_user}\n")
    if email_pass:
        lines.append(f"GMAIL_APP_PASSWORD={email_pass}\n")
        
    with open(env_path, "w") as f:
        f.writelines(lines)
    
    load_dotenv(override=True)

def show_imap_error_help(error_msg):
    st.error(f"❌ Failed to Connect: {error_msg}")
    
    # Check for common authentication or connection failures
    if "authenticationfailed" in error_msg.lower() or "login failed" in error_msg.lower() or "credential" in error_msg.lower():
        st.warning("""
        ### 🔍 Troubleshooting Credentials Issues:
        
        1. **Enable IMAP in Gmail Settings (CRITICAL)**:
           - Go to **[Gmail settings in browser](https://mail.google.com/mail/u/0/#settings/fwdandimap)**.
           - Under the **"Forwarding and POP/IMAP"** tab, make sure **"Enable IMAP"** is selected.
           - Click **"Save Changes"** at the bottom of the page.
        
        2. **App Password Requirement**:
           - You **cannot** use your normal Gmail login password. You must generate a 16-character **App Password** from your Google account. See the guide below!
        
        3. **2-Step Verification**:
           - Ensure that **2-Step Verification** is turned on in your Google Account security settings, otherwise App Passwords won't be available.
        """)

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="AI Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark cybersecurity theme
st.markdown("""
    <style>
    /* Main background */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #00ff9f !important;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 10px rgba(0, 255, 159, 0.5);
    }
    
    /* Text areas and inputs */
    .stTextArea textarea, .stTextInput input {
        background-color: #1a1f3a !important;
        color: #00ff9f !important;
        border: 1px solid #00ff9f !important;
        border-radius: 5px;
        font-family: 'Courier New', monospace;
    }
    
    /* Buttons */
    .stButton button {
        background: linear-gradient(90deg, #00ff9f 0%, #00d4ff 100%) !important;
        color: #0a0e27 !important;
        font-weight: bold;
        border: none;
        border-radius: 5px;
        padding: 10px 30px;
        font-family: 'Courier New', monospace;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s;
    }
    
    .stButton button:hover {
        box-shadow: 0 0 20px rgba(0, 255, 159, 0.8);
        transform: translateY(-2px);
    }
    
    /* Sidebar */
    .css-1d391kg, [data-testid="stSidebar"] {
        background-color: #0d1117 !important;
    }
    
    /* Cards and containers */
    .css-1r6slb0, .css-12oz5g7 {
        background-color: #1a1f3a;
        border: 1px solid #00ff9f;
        border-radius: 10px;
        padding: 20px;
    }
    
    /* Alert boxes */
    .alert-danger {
        background-color: #3d1f1f !important;
        border-left: 4px solid #ff4444 !important;
        color: #ff6b6b !important;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .alert-success {
        background-color: #1f3d1f !important;
        border-left: 4px solid #00ff9f !important;
        color: #00ff9f !important;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    /* Progress bar */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #ff4444 0%, #ffaa00 50%, #00ff9f 100%);
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background-color: #1a1f3a !important;
        color: #00ff9f !important;
        border: 1px solid #00ff9f !important;
        border-radius: 5px;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        color: #00ff9f !important;
        font-size: 2em !important;
    }
    
    /* Code blocks */
    code {
        background-color: #0d1117 !important;
        color: #00ff9f !important;
        padding: 2px 6px;
        border-radius: 3px;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

async def analyze_phishing_email(subject, body, sender="Unknown Sender"):
    """
    Analyze email using Claude Sonnet AI to detect phishing attempts
    """
    api_key = os.getenv('EMERGENT_LLM_KEY')
    
    if not api_key:
        raise ValueError("EMERGENT_LLM_KEY not found in environment variables")
    
    # Create analysis prompt
    analysis_prompt = f"""
You are an expert cybersecurity analyst specializing in phishing email detection. Analyze the following email and provide a comprehensive security assessment.

EMAIL SENDER (FROM): {sender}
EMAIL SUBJECT: {subject}

EMAIL BODY:
{body}

Provide your analysis in the following JSON format:
{{
    "classification": "Phishing Email" or "Legitimate Email",
    "risk_score": <number between 0-100>,
    "red_flags": ["flag1", "flag2", ...],
    "explanation": "Detailed explanation of why this is phishing or legitimate",
    "soc_report": "Professional SOC-style analysis report with threat indicators and recommendations"
}}

Consider these phishing indicators:
- Urgency and pressure tactics
- Requests for sensitive information (passwords, SSN, credit cards)
- Suspicious links or attachments
- Impersonation (banks, HR, government, delivery services)
- Poor grammar or spelling
- Threats or fear tactics
- Too-good-to-be-true offers
- Mismatched sender information
- Generic greetings

Provide only the JSON response, no additional text.
"""
    
    try:
        # Initialize chat with Claude Sonnet
        chat = LlmChat(
            api_key=api_key,
            session_id=f"phishing_analysis_{datetime.now().timestamp()}",
            system_message="You are an expert cybersecurity analyst. Provide accurate, detailed phishing detection analysis."
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")
        
        # Create user message
        user_message = UserMessage(text=analysis_prompt)
        
        # Get response
        response = await chat.send_message(user_message)
        
        # Parse JSON response
        try:
            # Clean response if it contains markdown code blocks
            clean_response = response.strip()
            if clean_response.startswith('```'):
                clean_response = clean_response.split('```')[1]
                if clean_response.startswith('json'):
                    clean_response = clean_response[4:]
            clean_response = clean_response.strip()
            
            result = json.loads(clean_response)
            return result
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return {
                "classification": "Analysis Error",
                "risk_score": 50,
                "red_flags": ["Unable to parse AI response"],
                "explanation": response,
                "soc_report": "Error: Could not generate proper analysis format."
            }
    
    except Exception as e:
        raise Exception(f"Analysis failed: {str(e)}")

def display_risk_score(score):
    """Display risk score with color coding"""
    if score >= 70:
        color = "#ff4444"
        status = "HIGH RISK"
    elif score >= 40:
        color = "#ffaa00"
        status = "MEDIUM RISK"
    else:
        color = "#00ff9f"
        status = "LOW RISK"
    
    return color, status

def main():
    # Header
    st.markdown("""
        <div style='text-align: center; padding: 20px; margin-bottom: 30px;'>
            <h1>🛡️ AI PHISHING EMAIL DETECTOR</h1>
            <p style='color: #00d4ff; font-size: 1.2em;'>Powered by Claude Sonnet AI | Cybersecurity Analysis System</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### 🔒 About")
        st.markdown("""
        This AI-powered tool detects phishing emails using advanced language analysis.
        
        **Detection Criteria:**
        - Urgency & pressure tactics
        - Sensitive info requests
        - Suspicious links
        - Impersonation attempts
        - Fear & threat tactics
        - Grammar anomalies
        """)
        
        st.markdown("---")
        st.markdown("### 📊 Statistics")
        st.metric("Total Analyzed", len(st.session_state.analysis_history))
        
        if st.session_state.analysis_history:
            phishing_count = sum(1 for a in st.session_state.analysis_history 
                               if a['classification'] == 'Phishing Email')
            st.metric("Phishing Detected", phishing_count)
            
            # EXTENDED: Attachment statistics
            total_attachments = sum(len(a.get('attachments', [])) for a in st.session_state.analysis_history)
            if total_attachments > 0:
                st.metric("Attachments Analyzed", total_attachments)
                malicious_attachments = sum(
                    1 for a in st.session_state.analysis_history 
                    for att in a.get('attachments', [])
                    if att['classification'] == 'Malicious'
                )
                if malicious_attachments > 0:
                    st.metric("Malicious Attachments", malicious_attachments)
        
        st.markdown("---")
        if st.button("🗑️ Clear History"):
            st.session_state.analysis_history = []
            st.rerun()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📧 Email Analysis")
        
        input_method = st.radio("Choose Input Method", 
            ["upload", "imap"], 
            format_func=lambda x: "Manual / File Upload" if x == "upload" else "Connect Inbox (IMAP)",
            horizontal=True)
            
        target_sender = "Unknown Sender"
        target_subject = ""
        target_body = ""
        target_attachments = []
        perform_analysis = False
        
        if input_method == "upload":
            eml_file = st.file_uploader("📂 Upload .eml or any file (Optional)", help="Upload an .eml to extract its contents, or any other file to analyze its text and attachments.")
            default_subj = ""
            default_body = ""
            default_from = ""
            eml_attachments = []
            
            if eml_file:
                if eml_file.name.lower().endswith('.eml'):
                    msg = email.message_from_bytes(eml_file.getvalue(), policy=policy.default)
                    default_subj = msg['subject'] or ""
                    default_from = msg['From'] or ""
                    
                    body_part = msg.get_body(preferencelist=('plain', 'html'))
                    if body_part:
                        default_body = body_part.get_content()
                    else:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    try:
                                        default_body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                                    except:
                                        pass
                                    break
                        else:
                            try:
                                default_body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                            except:
                                pass
                    
                    for part in msg.iter_attachments():
                        filename = part.get_filename()
                        if filename:
                            content = part.get_payload(decode=True)
                            eml_attachments.append({"name": filename, "bytes": content})
                            
                    st.success(f"Parsed .eml file successfully. Found {len(eml_attachments)} attachment(s).")
                else:
                    # Not an EML file, load its raw content as the email body
                    default_subj = f"File Analysis: {eml_file.name}"
                    try:
                        default_body = eml_file.getvalue().decode('utf-8', errors='replace')
                    except:
                        default_body = "Binary file uploaded."
                    # Also analyze it as an attachment
                    eml_attachments.append({"name": eml_file.name, "bytes": eml_file.getvalue()})
                    st.success(f"Loaded {eml_file.name} for verification.")
            
            with st.form("email_form"):
                email_sender = st.text_input(
                    "Sender (From)",
                    value=default_from if not st.session_state.get('example_loaded') else "security@yourbank-verify.com",
                    placeholder="e.g., support@paypal.com or security@yourbank.com",
                    help="The sender email address/name"
                )
                email_subject = st.text_input(
                    "Email Subject",
                    value=default_subj if not st.session_state.get('example_loaded') else "URGENT: Your Account Will Be Closed!",
                    placeholder="Enter the email subject line...",
                    help="The subject line of the suspicious email"
                )
                
                email_body = st.text_area(
                    "Email Body",
                    value=default_body if not st.session_state.get('example_loaded') else "Dear Valued Customer,\n\nWe have detected suspicious activity on your account. Your account will be permanently closed within 24 hours unless you verify your identity immediately.\n\nClick here to verify now: http://secure-bank-verify.suspicious-link.com\n\nYou must provide:\n- Full name\n- Social Security Number\n- Credit card details\n- Online banking password\n\nFailure to comply will result in permanent account suspension and legal action.\n\nThis is your final warning.\n\nSecurity Department\nYour Bank",
                    placeholder="Paste the email body content here...",
                    height=200,
                    help="The full text content of the email"
                )
                
                st.markdown("---")
                st.markdown("**📎 Extra Email Attachments (Optional)**")
                uploaded_files = st.file_uploader(
                    "Upload additional attachments",
                    accept_multiple_files=True,
                    help="Upload files to analyze for malware indicators",
                    label_visibility="collapsed"
                )
                
                col_btn1, col_btn2 = st.columns([1, 3])
                with col_btn1:
                    submit_button = st.form_submit_button("🔍 Analyze Email")
                with col_btn2:
                    load_example = st.form_submit_button("📝 Load Example")
            
            if load_example:
                st.session_state.example_loaded = True
                st.rerun()
                
            if 'example_loaded' in st.session_state and st.session_state.example_loaded:
                st.session_state.example_loaded = False
                st.info("📝 Example phishing email loaded! Click 'Analyze Email'.")
                
            if submit_button:
                target_sender = email_sender
                target_subject = email_subject
                target_body = email_body
                target_attachments = eml_attachments.copy()
                if uploaded_files:
                    for uf in uploaded_files:
                        target_attachments.append({"name": uf.name, "bytes": uf.read()})
                perform_analysis = True
                
        else:
            # Read saved Gmail credentials
            gmail_user_env = os.getenv('GMAIL_USER', '')
            gmail_pass_env = os.getenv('GMAIL_APP_PASSWORD', '')
            
            st.info("🔌 Connect to your email inbox directly using IMAP to fetch real emails without copy-pasting.")
            
            # If credentials exist, show Quick Connect option
            if gmail_user_env and gmail_pass_env:
                st.success(f"⚡ Saved Gmail profile detected: **{gmail_user_env}**")
                col_qc1, col_qc2 = st.columns(2)
                with col_qc1:
                    limit_qc = st.slider("Emails to fetch", 1, 20, 5, key="limit_qc")
                    quick_connect = st.button("📥 Direct Connect & Fetch", type="primary", use_container_width=True)
                with col_qc2:
                    st.write("") # Spacer
                    st.write("") # Spacer
                    disconnect = st.button("❌ Remove Saved Credentials", use_container_width=True)
                
                if disconnect:
                    save_gmail_credentials("", "")
                    st.success("Credentials removed. Rerunning...")
                    st.rerun()
                
                if quick_connect:
                    with st.spinner("Connecting securely to Gmail..."):
                        success, data = fetch_recent_emails("imap.gmail.com", "993", gmail_user_env, gmail_pass_env, limit_qc)
                        if success:
                            st.session_state.fetched_emails = data
                            st.success(f"Successfully fetched {len(data)} emails!")
                        else:
                            show_imap_error_help(data)
                            
                st.markdown("---")
            
            # Detailed manual credentials / configuration form
            with st.expander("⚙️ Connection Settings / New Account Setup", expanded=not (gmail_user_env and gmail_pass_env)):
                with st.form("imap_auth"):
                    col_imap1, col_imap2 = st.columns(2)
                    with col_imap1:
                        imap_server = st.text_input("IMAP Server", value="imap.gmail.com")
                        email_user = st.text_input("Email Address", value=gmail_user_env)
                    with col_imap2:
                        imap_port = st.text_input("IMAP Port", value="993")
                        email_pass = st.text_input("App Password", value=gmail_pass_env, type="password", help="Use an App Password instead of your real password for security.")
                    
                    limit = st.slider("Emails to fetch", 1, 20, 5, key="limit_form")
                    save_creds = st.checkbox("💾 Remember credentials in .env file", value=True)
                    connect_btn = st.form_submit_button("🔌 Connect & Fetch")
                    
                if connect_btn:
                    if not email_user or not email_pass:
                        st.error("Please provide email and app password.")
                    else:
                        with st.spinner("Connecting to inbox..."):
                            success, data = fetch_recent_emails(imap_server, imap_port, email_user, email_pass, limit)
                            if success:
                                st.session_state.fetched_emails = data
                                st.success(f"Successfully fetched {len(data)} emails!")
                                if save_creds:
                                    save_gmail_credentials(email_user, email_pass)
                                    st.info("Credentials saved securely to .env file.")
                            else:
                                show_imap_error_help(data)

            # Step-by-step Gmail configuration guide
            with st.expander("📖 Gmail App Password Configuration Guide (Required)"):
                st.markdown("""
                ### How to connect your Gmail Account:
                Because Google disabled 'Less Secure Apps', you **cannot** use your regular Gmail password. You must generate an **App Password**:
                
                1. Go to your **[Google Account Security Settings](https://myaccount.google.com/security)**.
                2. Make sure **2-Step Verification** is turned **ON** for your account.
                3. Click on **2-Step Verification**, scroll to the bottom, and select **App passwords** (or search "App passwords" in the search bar at the top).
                4. Enter a name (e.g., `Phishing Detector`) and click **Create**.
                5. Google will display a **16-character code** (e.g., `abcd efgh ijkl mnop`).
                6. Copy this 16-character code and paste it into the **App Password** field in this app.
                7. Check the **Remember credentials** option so you only have to do this once!
                """)
                
            if st.session_state.get('fetched_emails'):
                st.markdown("### 📥 Select an Email")
                email_opts = {f"{em['date']} - {em['subject'][:30]}": em for em in st.session_state.fetched_emails}
                selected_em_label = st.selectbox("Choose an email to analyze", list(email_opts.keys()))
                
                selected_em = email_opts[selected_em_label]
                st.text_input("Sender (From)", value=selected_em.get('from', 'Unknown Sender'), disabled=True)
                st.text_input("Subject Preview", value=selected_em['subject'], disabled=True)
                st.text_area("Body Preview", value=selected_em['body'], height=150, disabled=True)
                if selected_em['attachments']:
                    st.info(f"📎 Has {len(selected_em['attachments'])} attachment(s)")
                
                if st.button("🔍 Analyze Selected Inbox Email", type="primary"):
                    target_sender = selected_em.get('from', 'Unknown Sender')
                    target_subject = selected_em['subject']
                    target_body = selected_em['body']
                    target_attachments = selected_em['attachments']
                    perform_analysis = True

        # Analyze email
        if perform_analysis:
            if not target_subject or not target_body:
                st.error("⚠️ Please provide both email subject and body.")
            else:
                with st.spinner("🔄 Analyzing email with AI... This may take a few seconds."):
                    try:
                        # Run async analysis
                        result = asyncio.run(analyze_phishing_email(target_subject, target_body, target_sender))
                        
                        # EXTENDED: Analyze attachments if provided
                        attachment_results = []
                        if target_attachments:
                            st.info(f"📎 Analyzing {len(target_attachments)} attachment(s)...")
                            analyzer = AttachmentAnalyzer()
                            
                            for att in target_attachments:
                                attachment_result = analyzer.analyze_attachment(
                                    att["bytes"], 
                                    att["name"]
                                )
                                attachment_results.append(attachment_result)
                        
                        # EXTENDED: Correlate risks if attachments present
                        if attachment_results:
                            unified_risk = correlate_risks(
                                result['risk_score'],
                                attachment_results
                            )
                        else:
                            unified_risk = None
                        
                        # Add to history
                        result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        result['subject'] = target_subject
                        result['attachments'] = attachment_results  # EXTENDED: Store attachment results
                        result['unified_risk'] = unified_risk  # EXTENDED: Store unified risk
                        st.session_state.analysis_history.insert(0, result)
                        
                        # Display results
                        st.markdown("---")
                        st.markdown("## 📋 Analysis Results")
                        
                        # Classification
                        if result['classification'] == 'Phishing Email':
                            st.markdown(f"""
                                <div class='alert-danger'>
                                    <h2>⚠️ THREAT DETECTED: {result['classification']}</h2>
                                </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                                <div class='alert-success'>
                                    <h2>✅ {result['classification']}</h2>
                                </div>
                            """, unsafe_allow_html=True)
                        
                        # Risk score
                        st.markdown("### 🎯 Risk Assessment")
                        color, status = display_risk_score(result['risk_score'])
                        
                        col_r1, col_r2, col_r3 = st.columns(3)
                        with col_r1:
                            st.metric("Risk Score", f"{result['risk_score']}/100")
                        with col_r2:
                            st.markdown(f"<h3 style='color: {color};'>{status}</h3>", unsafe_allow_html=True)
                        with col_r3:
                            st.progress(result['risk_score'] / 100)
                        
                        # Red flags
                        if result['red_flags']:
                            st.markdown("### 🚩 Detected Red Flags")
                            for flag in result['red_flags']:
                                st.markdown(f"- 🔴 {flag}")
                        
                        # Explanation
                        st.markdown("### 💡 Analysis Explanation")
                        st.info(result['explanation'])
                        
                        # EXTENDED: Display Attachment Analysis Results
                        if attachment_results:
                            st.markdown("---")
                            st.markdown("## 📎 Attachment Analysis Results")
                            
                            for idx, att_result in enumerate(attachment_results, 1):
                                with st.expander(f"📄 {att_result['filename']} - {att_result['classification']} ({att_result['risk_score']}/100)", expanded=True):
                                    
                                    # Attachment risk visualization
                                    att_color, att_status = display_risk_score(att_result['risk_score'])
                                    
                                    col_a1, col_a2, col_a3 = st.columns(3)
                                    with col_a1:
                                        st.metric("Attachment Risk", f"{att_result['risk_score']}/100")
                                    with col_a2:
                                        st.markdown(f"<h4 style='color: {att_color};'>{att_status}</h4>", unsafe_allow_html=True)
                                    with col_a3:
                                        st.progress(att_result['risk_score'] / 100)
                                    
                                    # Risk indicators
                                    if att_result['risk_indicators']:
                                        st.markdown("**🚨 Risk Indicators:**")
                                        for indicator in att_result['risk_indicators']:
                                            st.markdown(f"• {indicator}")
                                    else:
                                        st.success("✅ No significant risk indicators detected")
                                    
                                    # Technical details
                                    st.markdown("**🔍 Technical Details:**")
                                    st.markdown(f"• **File Hash (SHA-256):** `{att_result['hash'][:32]}...`")
                                    st.markdown(f"• **File Size:** {att_result['metadata']['size_mb']} MB")
                                    st.markdown(f"• **MIME Type:** {att_result['metadata']['mime_type']}")
                                    st.markdown(f"• **Extension:** {att_result['metadata']['extension']}")
                                    st.markdown(f"• **Entropy:** {att_result['static_analysis']['entropy']}/8.0")
                                    
                                    # Static analysis summary
                                    static = att_result['static_analysis']
                                    st.markdown("**⚙️ Static Analysis:**")
                                    st.markdown(f"• Extension Mismatch: {'⚠️ Yes' if static['extension_mismatch'] else '✅ No'}")
                                    st.markdown(f"• Macro Detected: {'⚠️ Yes' if static['macro_detected'] else '✅ No'}")
                                    st.markdown(f"• Embedded Scripts: {'⚠️ Yes' if static['embedded_script'] else '✅ No'}")
                                    st.markdown(f"• Double Archive: {'⚠️ Yes' if static['double_archive'] else '✅ No'}")
                            
                            # EXTENDED: Unified Threat Assessment
                            if unified_risk:
                                st.markdown("---")
                                st.markdown("## ⚡ Unified Threat Assessment")
                                
                                unified_color = "#ff4444" if unified_risk['unified_threat_score'] >= 70 else \
                                              "#ffaa00" if unified_risk['unified_threat_score'] >= 40 else "#00ff9f"
                                
                                st.markdown(f"""
                                    <div style='background-color: rgba(255,68,68,0.1); padding: 20px; border-radius: 10px; border-left: 4px solid {unified_color};'>
                                        <h3 style='color: {unified_color};'>{unified_risk['overall_classification']}</h3>
                                        <p style='color: #00d4ff;'><strong>Unified Threat Score: {unified_risk['unified_threat_score']}/100</strong></p>
                                        <p style='color: #00ff9f;'>{unified_risk['threat_correlation']}</p>
                                    </div>
                                """, unsafe_allow_html=True)
                                
                                col_u1, col_u2, col_u3 = st.columns(3)
                                with col_u1:
                                    st.metric("Email Risk", f"{unified_risk['email_risk']}/100")
                                with col_u2:
                                    st.metric("Avg Attachment Risk", f"{unified_risk['attachment_avg_risk']}/100")
                                with col_u3:
                                    st.metric("Max Attachment Risk", f"{unified_risk['attachment_max_risk']}/100")
                                
                                st.markdown(f"**📊 Analysis Summary:**")
                                st.markdown(f"• Email content risk: {unified_risk['email_risk']}/100")
                                st.markdown(f"• Attachments analyzed: {unified_risk['attachment_count']}")
                                st.markdown(f"• Average attachment risk: {unified_risk['attachment_avg_risk']}/100")
                                st.markdown(f"• Highest attachment risk: {unified_risk['attachment_max_risk']}/100")
                                st.markdown(f"• **Final unified score: {unified_risk['unified_threat_score']}/100**")
                        
                        # SOC Report
                        with st.expander("📄 View SOC Analysis Report", expanded=False):
                            st.markdown("```")
                            st.markdown(result['soc_report'])
                            st.markdown("```")
                        
                        st.success("✅ Analysis complete!")
                        
                    except Exception as e:
                        st.error(f"❌ Error during analysis: {str(e)}")
                        st.info("💡 Make sure your EMERGENT_LLM_KEY is properly configured in the .env file.")
    
    with col2:
        st.markdown("### 📚 Quick Examples")
        
        st.markdown("""
        **Common Phishing Indicators:**
        
        🔴 **Urgency**
        - "Act now or account will be closed"
        - "Limited time offer"
        - "Immediate action required"
        
        🔴 **Information Requests**
        - Asking for passwords
        - Social Security Numbers
        - Credit card details
        - Personal information
        
        🔴 **Suspicious Links**
        - Misspelled URLs
        - Shortened links
        - Non-HTTPS links
        - Mismatched domains
        
        🔴 **Impersonation**
        - Fake bank emails
        - Fake government notices
        - Fake delivery notifications
        - Fake HR communications
        
        🔴 **Threats**
        - Legal action warnings
        - Account suspension threats
        - Security breach claims
        """)
        
        # EXTENDED: Attachment risk indicators
        st.markdown("---")
        st.markdown("### 📎 Attachment Risk Indicators")
        st.markdown("""
        **Common Malware Indicators:**
        
        🔴 **Dangerous Extensions**
        - .exe, .dll, .bat, .cmd
        - .scr, .vbs, .js
        - .ps1, .msi, .hta
        
        🔴 **Document Threats**
        - Macros in Office files
        - Embedded scripts in PDFs
        - Password-protected archives
        
        🔴 **Obfuscation Techniques**
        - High entropy (encryption)
        - Double extensions (.pdf.exe)
        - Nested archives (ZIP in ZIP)
        - Unicode tricks in filename
        """)
        
        # Recent history
        if st.session_state.analysis_history:
            st.markdown("---")
            st.markdown("### 🕐 Recent Analysis")
            for i, analysis in enumerate(st.session_state.analysis_history[:3]):
                attachment_count = len(analysis.get('attachments', []))
                title_suffix = f" | {attachment_count} attachment(s)" if attachment_count > 0 else ""
                
                with st.expander(f"{analysis['subject'][:30]}...{title_suffix}"):
                    st.markdown(f"**Classification:** {analysis['classification']}")
                    st.markdown(f"**Risk Score:** {analysis['risk_score']}/100")
                    
                    # EXTENDED: Show unified risk if available
                    if analysis.get('unified_risk'):
                        st.markdown(f"**Unified Threat:** {analysis['unified_risk']['unified_threat_score']}/100")
                    
                    # EXTENDED: Show attachment summary
                    if attachment_count > 0:
                        st.markdown(f"**Attachments:** {attachment_count}")
                        malicious = sum(1 for a in analysis['attachments'] if a['classification'] == 'Malicious')
                        if malicious > 0:
                            st.markdown(f"⚠️ {malicious} malicious attachment(s)")
                    
                    st.markdown(f"**Time:** {analysis['timestamp']}")

if __name__ == "__main__":
    main()