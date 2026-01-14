import streamlit as st
import asyncio
from dotenv import load_dotenv
import os
import json
from datetime import datetime
from emergentintegrations.llm.chat import LlmChat, UserMessage

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
    |    /* Main background */
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
        color: #00ff9f !important
        padding: 2px 6px;
        border-radius: 3px;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

async def analyze_phishing_email(subject, body):
    """
    Analyze email using Claude Sonnet AI to detect phishing attempts
    """
    api_key = os.getenv('EMERGENT_LLM_KEY')
    
    if not api_key:
        raise ValueError("EMERGENT_LLM_KEY not found in environment variables")
    
    # Create analysis prompt
    analysis_prompt = f"""
You are an expert cybersecurity analyst specializing in phishing email detection. Analyze the following email and provide a comprehensive security assessment.

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
        
        st.markdown("---")
        if st.button("🗑️ Clear History"):
            st.session_state.analysis_history = []
            st.rerun()
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📧 Email Analysis")
        
        # Email input form
        with st.form("email_form"):
            email_subject = st.text_input(
                "Email Subject",
                placeholder="Enter the email subject line...",
                help="The subject line of the suspicious email"
            )
            
            email_body = st.text_area(
                "Email Body",
                placeholder="Paste the email body content here...",
                height=200,
                help="The full text content of the email"
            )
            
            col_btn1, col_btn2 = st.columns([1, 3])
            with col_btn1:
                submit_button = st.form_submit_button("🔍 Analyze Email")
            with col_btn2:
                load_example = st.form_submit_button("📝 Load Example")
        
        # Handle example loading
        if load_example:
            st.session_state.example_loaded = True
            st.rerun()
        
        if 'example_loaded' in st.session_state and st.session_state.example_loaded:
            email_subject = "URGENT: Your Account Will Be Closed!"
            email_body = """Dear Valued Customer,

We have detected suspicious activity on your account. Your account will be permanently closed within 24 hours unless you verify your identity immediately.

Click here to verify now: http://secure-bank-verify.suspicious-link.com

You must provide:
- Full name
- Social Security Number
- Credit card details
- Online banking password

Failure to comply will result in permanent account suspension and legal action.

This is your final warning.

Security Department
Your Bank"""
            st.session_state.example_loaded = False
            st.info("📝 Example phishing email loaded! Click 'Analyze Email' to detect threats.")
        
        # Analyze email
        if submit_button:
            if not email_subject or not email_body:
                st.error("⚠️ Please provide both email subject and body.")
            else:
                with st.spinner("🔄 Analyzing email with AI... This may take a few seconds."):
                    try:
                        # Run async analysis
                        result = asyncio.run(analyze_phishing_email(email_subject, email_body))
                        
                        # Add to history
                        result['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        result['subject'] = email_subject
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
        
        # Recent history
        if st.session_state.analysis_history:
            st.markdown("---")
            st.markdown("### 🕐 Recent Analysis")
            for i, analysis in enumerate(st.session_state.analysis_history[:3]):
                with st.expander(f"{analysis['subject'][:30]}..."):
                    st.markdown(f"**Classification:** {analysis['classification']}")
                    st.markdown(f"**Risk Score:** {analysis['risk_score']}/100")
                    st.markdown(f"**Time:** {analysis['timestamp']}")

if __name__ == "__main__":
            main()