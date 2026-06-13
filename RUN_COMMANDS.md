# 🚀 Quick Run Commands for Phishing Detector

## Important: Create .env file first!

Create a `.env` file in the project root with:
```
EMERGENT_LLM_KEY=sk-emergent-d69D0D4BfD065E6E83
```

## Installation & Run Commands

```bash
# Step 1: Install emergentintegrations
python -m pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/

# Step 2: Install other dependencies
python -m pip install streamlit python-dotenv

# Step 3: Run the application
python -m streamlit run phishing_detector.py
```

## Alternative: Using Virtual Environment

If you want to use the virtual environment (recommended):

```bash
# Activate virtual environment
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# On Windows (CMD):
.venv\Scripts\activate.bat

# On macOS/Linux:
source .venv/bin/activate

# Then install and run:
python -m pip install emergentintegrations --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/
python -m pip install streamlit python-dotenv
python -m streamlit run phishing_detector.py
```

## Notes

- Your file is named `phishing_detector.py` (NOT `app.py`)
- The app will open at: http://localhost:8501
- If port 8501 is busy, use: `python -m streamlit run phishing_detector.py --server.port 8502`
