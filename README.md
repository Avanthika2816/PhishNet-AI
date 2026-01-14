---

## 📄 FILE 5: README.md
Action: file_editor view /app/phishing_detector/README.md
Observation: /app/phishing_detector/README.md:
1|# 🛡️ AI-Powered Phishing Email Detection System
2|
3|## Overview
4|A professional cybersecurity tool that uses Claude Sonnet 4.5 AI to detect phishing emails. The system analyzes email content for suspicious patterns, generates risk scores, identifies red flags, and produces SOC-style analysis reports.
5|
6|## 🎯 Features
7|
8|### Core Functionality
9|- **AI-Powered Detection**: Uses Claude Sonnet 4.5 for advanced language analysis
10|- **Risk Scoring**: Generates 0-100 risk scores with color-coded severity levels
11|- **Red Flag Detection**: Identifies specific phishing indicators
12|- **Detailed Explanations**: Provides clear reasoning for classifications
13|- **SOC Reports**: Generates professional security analysis reports
14|- **Analysis History**: Tracks previously analyzed emails
15|
16|### Detection Criteria
17|The AI analyzes emails for:
18|- ⚠️ Urgency and pressure tactics
19|- 🔑 Requests for sensitive information (passwords, SSN, credit cards)
20|- 🔗 Suspicious links or attachments
21|- 🎭 Impersonation attempts (banks, HR, government, delivery)
22|- 📝 Poor grammar or spelling errors
23|- 😨 Threats or fear-based manipulation
24|- 🎁 Too-good-to-be-true offers
25|- 📧 Mismatched sender information
26|- 👤 Generic greetings
27|
28|## 🚀 Tech Stack
29|
30|- **Frontend**: Streamlit (Python web framework)
31|- **AI Model**: Claude Sonnet 4.5 (Anthropic)
32|- **Integration**: Emergent Integrations Library
33|- **Language**: Python 3.8+
34|- **Styling**: Custom CSS (Dark cybersecurity theme)
35|
36|## 📋 Prerequisites
37|
38|- Python 3.8 or higher
39|- pip (Python package manager)
40|- Internet connection (for AI API calls)
41|- Emergent LLM Key (provided in .env file)
42|
43|## 🛠️ Installation Instructions
44|
45|### Step 1: Set Up Project Directory
46|```bash
47|# Create project folder
48|mkdir phishing_detector
49|cd phishing_detector
50|
51|# Copy all files from this project into the directory
52|# Make sure you have:
53|# - app.py
54|# - .env
55|# - requirements.txt
56|# - example_emails.txt
57|# - README.md
58|```
59|
60|### Step 2: Create Virtual Environment (Recommended)
61|```bash
62|# Create virtual environment
63|python -m venv venv
64|
65|# Activate virtual environment
66|# On Windows:
67|venv\Scripts\activate
68|
69|# On macOS/Linux:
70|source venv/bin/activate
71|```
72|
73|### Step 3: Install Dependencies
74|```bash
75|# Install emergentintegrations library
76|pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
77|
78|# Install other requirements
79|pip install -r requirements.txt
80|```
81|
82|### Step 4: Configure Environment
83|The `.env` file is already configured with the Emergent LLM key:
84|```
85|EMERGENT_LLM_KEY=sk-emergent-d69D0D4BfD065E6E83
86|```
87|
88|**Note**: This key has limited credits. For production use, you can:
89|- Add more balance to your Emergent account
90|- Replace with your own Claude API key from Anthropic
91|
92|## 🎮 Running the Application
93|
94|### Start the Application
95|```bash
96|streamlit run app.py
97|```
98|
99|The application will automatically open in your default browser at:
100|```
101|http://localhost:8501
102|```
103|
104|### Using the Application
105|
106|1. **Load Example Email**:
107|   - Click "📝 Load Example" to see a sample phishing email
108|   - Click "🔍 Analyze Email" to run detection
109|
110|2. **Analyze Custom Email**:
111|   - Enter email subject in the "Email Subject" field
112|   - Paste email body in the "Email Body" text area
113|   - Click "🔍 Analyze Email"
114|
115|3. **Review Results**:
116|   - View classification (Phishing/Legitimate)
117|   - Check risk score (0-100)
118|   - Read detected red flags
119|   - Review detailed explanation
120|   - Expand SOC report for professional analysis
121|
122|4. **View History**:
123|   - Check sidebar for analysis statistics
124|   - View recent analyses in the right panel
125|   - Clear history using "🗑️ Clear History" button
126|
127|## 📧 Example Test Emails
128|
129|The `example_emails.txt` file contains 6 sample emails:
130|1. Bank phishing (account closure threat)
131|2. Prize/lottery scam
132|3. IT security alert phishing
133|4. Package delivery scam
134|5. HR payroll phishing
135|6. Legitimate email (for comparison)
136|
137|You can copy and paste these into the application for testing.
138|
139|## 🔍 How Detection Works
140|
141|### Analysis Process
142|1. **Input Processing**: Email subject and body are captured
143|2. **AI Analysis**: Claude Sonnet 4.5 analyzes the content using:
144|   - Natural language processing
145|   - Pattern recognition
146|   - Contextual understanding
147|   - Threat intelligence patterns
148|3. **Risk Assessment**: Generates score based on detected indicators
149|4. **Classification**: Determines if email is phishing or legitimate
150|5. **Report Generation**: Creates detailed explanation and SOC report
151|
152|### Risk Score Levels
153|- 🟢 **0-39**: Low Risk (Likely legitimate)
154|- 🟡 **40-69**: Medium Risk (Suspicious elements)
155|- 🔴 **70-100**: High Risk (Likely phishing)
156|
157|## 🎨 UI Design
158|
159|The application features a dark cybersecurity theme:
160|- Matrix-inspired color scheme (cyan and green accents)
161|- Monospace fonts for technical appearance
162|- Gradient buttons with hover effects
163|- Color-coded risk indicators
164|- Professional SOC-style layout
165|
166|## 🐛 Troubleshooting
167|
168|### Common Issues
169|
170|**Issue**: `ModuleNotFoundError: No module named 'emergentintegrations'`
171|```bash
172|# Solution:
173|pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
174|```
175|
176|**Issue**: `ValueError: EMERGENT_LLM_KEY not found`
177|```bash
178|# Solution: Make sure .env file exists in the same directory as app.py
179|# Check that .env contains:
180|EMERGENT_LLM_KEY=sk-emergent-d69D0D4BfD065E6E83
181|```
182|
183|**Issue**: Application doesn't start
184|```bash
185|# Solution: Check if Streamlit is installed
186|pip install streamlit
187|
188|# Or reinstall all dependencies
189|pip install -r requirements.txt
190|```
191|
192|**Issue**: Analysis fails or times out
193|- Check internet connection
194|- Verify API key has available credits
195|- Try with a shorter email body
196|
197|**Issue**: Port 8501 already in use
198|```bash
199|# Solution: Use different port
200|streamlit run app.py --server.port 8502
201|```
202|
203|## 📊 Project Structure
204|
205|```
206|phishing_detector/
207|│
208|├── app.py                 # Main Streamlit application
209|├── .env                   # Environment variables (API key)
210|├── requirements.txt       # Python dependencies
211|├── example_emails.txt     # Sample phishing emails for testing
212|└── README.md             # This file
213|```
214|
215|## 🔒 Security Notes
216|
217|- Never share your API keys publicly
218|- The provided Emergent LLM key is for testing only
219|- Email content is sent to Claude API for analysis
220|- No email data is stored permanently (only in session)
221|- Analysis history is cleared when application restarts
222|
223|## 🚀 Future Enhancements
224|
225|Potential improvements for the project:
226|- Email header analysis (sender verification)
227|- Link extraction and safety checking
228|- Attachment scanning capabilities
229|- Database integration for persistent history
230|- Export reports to PDF
231|- Batch email analysis
232|- Custom rule configuration
233|- Integration with email clients
234|- Multi-language support
235|
236|## 💡 Use Cases
237|
238|- **Personal**: Verify suspicious emails before taking action
239|- **Educational**: Learn about phishing techniques
240|- **Training**: Cybersecurity awareness training tool
241|- **SOC Teams**: Quick initial assessment of reported emails
242|- **Portfolio**: Demonstrate AI and cybersecurity skills
243|- **Hackathons**: Impressive project showcasing AI application
244|
245|## 📝 Credits
246|
247|- **AI Model**: Claude Sonnet 4.5 by Anthropic
248|- **Integration**: Emergent Integrations Library
249|- **Framework**: Streamlit
250|- **Theme**: Custom dark cybersecurity design
251|
252|## 🎓 Learning Resources
253|
254|- [Streamlit Documentation](https://docs.streamlit.io/)
255|- [Claude AI Documentation](https://docs.anthropic.com/)
256|- [Phishing Detection Techniques](https://www.cisa.gov/phishing)
257|- [Email Security Best Practices](https://www.us-cert.gov/ncas/tips/ST04-014)
258|
259|## 📞 Support
260|
261|If you encounter issues:
262|1. Check the Troubleshooting section
263|2. Verify all dependencies are installed
264|3. Ensure .env file is properly configured
265|4. Check example_emails.txt for test cases
266|
267|## 🎉 Getting Started Quickly
268|
269|```bash
270|# Quick start (copy-paste these commands)
271|cd phishing_detector
272|python -m venv venv
273|source venv/bin/activate  # On Windows: venv\Scripts\activate
274|pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
275|pip install -r requirements.txt
276|streamlit run app.py
277|```
278|
279|Then:
280|1. Click "Load Example" button
281|2. Click "Analyze Email" button
282|3. View the AI-powered phishing detection results!
283|
284|---
285|
286|**Ready for hackathons, portfolios, and cybersecurity demonstrations!** 🛡️🚀
287|