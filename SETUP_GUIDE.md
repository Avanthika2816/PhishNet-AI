Action: file_editor create /app/phishing_detector/SETUP_GUIDE.md --file-text "# 🚀 Quick Setup Guide for Phishing Email Detector

## ⚡ Fast Setup (5 Minutes)

### Step 1: Copy All Files
Copy these 6 files to a folder on your computer:
```
phishing_detector/
├── app.py                    # Main application
├── .env                      # API key configuration
├── requirements.txt          # Dependencies
├── example_emails.txt        # Test samples
├── README.md                # Full documentation
└── test_analysis.py         # Test script
```

### Step 2: Install Python Dependencies
```bash
# Navigate to your project folder
cd phishing_detector

# Create virtual environment (recommended)
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install emergentintegrations (IMPORTANT - install this first!)
pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/

# Install other dependencies
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
streamlit run app.py
```

Your browser will automatically open to `http://localhost:8501`

### Step 4: Test It!
1. Click the **\"📝 Load Example\"** button
2. Click **\"🔍 Analyze Email\"**
3. Watch the AI detect the phishing attempt!

---

## 🎯 What You Get

### File Descriptions

**app.py** (Main Application)
- Complete Streamlit web interface
- Dark cybersecurity theme
- AI integration with Claude Sonnet
- Risk scoring system
- SOC report generation

**.env** (Configuration)
- Pre-configured with Emergent LLM key
- Ready to use immediately
- Limited credits available

**requirements.txt** (Dependencies)
```
streamlit==1.32.0
python-dotenv==1.0.1
emergentintegrations
```

**example_emails.txt** (Test Cases)
- 6 different phishing scenarios
- 1 legitimate email example
- Copy-paste ready

**test_analysis.py** (Testing Script)
- Verify the system works
- Run from command line
- See AI analysis output

---

## 🐛 Troubleshooting

### Issue: emergentintegrations not found
```bash
# Solution:
pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
```

### Issue: Streamlit command not found
```bash
# Solution:
pip install streamlit
```

### Issue: .env file error
Make sure the .env file contains:
```
EMERGENT_LLM_KEY=sk-emergent-d69D0D4BfD065E6E83
```

### Issue: Port 8501 already in use
```bash
# Use different port:
streamlit run app.py --server.port 8502
```

---

## 📊 Tech Stack Summary

| Component | Technology |
|-----------|-----------|
| **AI Model** | Claude Sonnet 4.5 (Anthropic) |
| **Framework** | Streamlit (Python) |
| **Integration** | Emergent Integrations Library |
| **Language** | Python 3.8+ |
| **Theme** | Custom dark cybersecurity CSS |

---

## 🎨 Features

✅ AI-powered phishing detection
✅ Risk scoring (0-100)
✅ Red flag identification
✅ Detailed explanations
✅ SOC-style reports
✅ Analysis history
✅ Dark cybersecurity UI
✅ Example emails included
✅ No ML training required

---

## 💡 How It Works

1. **Input**: User provides email subject and body
2. **Analysis**: Claude Sonnet AI analyzes content for:
   - Urgency tactics
   - Sensitive data requests
   - Suspicious links
   - Impersonation attempts
   - Fear tactics
   - Grammar issues
3. **Output**: System generates:
   - Classification (Phishing/Legitimate)
   - Risk score (0-100)
   - List of red flags
   - Detailed explanation
   - SOC analysis report

---

## 🔒 Security Notes

- The provided API key has limited credits
- Email content is sent to Claude API for analysis
- No data is stored permanently
- Analysis history clears on restart

---

## 📚 Project Structure

```
phishing_detector/
│
├── app.py                    # 500+ lines, complete Streamlit app
│   ├── AI integration
│   ├── Risk scoring logic
│   ├── UI components
│   └── Analysis history
│
├── .env                      # Environment configuration
│   └── EMERGENT_LLM_KEY
│
├── requirements.txt          # Python dependencies
│   ├── streamlit
│   ├── python-dotenv
│   └── emergentintegrations
│
├── example_emails.txt        # 6 phishing + 1 legitimate
│   ├── Bank phishing
│   ├── Lottery scam
│   ├── IT support phishing
│   ├── Delivery scam
│   ├── HR phishing
│   └── Legitimate email
│
├── test_analysis.py          # Automated testing
│   └── Verifies AI analysis
│
└── README.md                 # Full documentation
    ├── Installation guide
    ├── Usage instructions
    ├── Troubleshooting
    └── Learning resources
```

---

## 🎓 Perfect For

- 📚 **Learning**: Understand phishing techniques
- 🎯 **Portfolios**: Showcase AI/cybersecurity skills
- 🏆 **Hackathons**: Impressive, functional project
- 👥 **Training**: Cybersecurity awareness tool
- 🔐 **Personal Use**: Verify suspicious emails

---

## 🚀 Next Steps After Setup

1. **Test with examples**: Use example_emails.txt
2. **Try real emails**: Paste suspicious emails you receive
3. **Customize theme**: Edit CSS in app.py
4. **Add features**: Extend functionality
5. **Deploy online**: Use Streamlit Cloud (free)

---

## 📞 Need Help?

1. Read the full README.md
2. Run test_analysis.py to verify setup
3. Check example_emails.txt for test cases
4. Verify .env file configuration

---

## ⚡ One-Command Setup (Advanced)

For experienced users:

```bash
mkdir phishing_detector && cd phishing_detector
# (Copy all files here)
python -m venv venv && source venv/bin/activate
pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/ && pip install -r requirements.txt
streamlit run app.py
```

---

**🎉 You're ready to detect phishing emails with AI!**
"
Observation: Create successful: /app/phishing_detector/SETUP_GUIDE.md