'use client';

import { useState } from 'react';

const EXAMPLES = [
  {
    label: '🎣 Bank Phish',
    subject: 'URGENT: Your Account Has Been Suspended',
    sender: 'security@bankofamerica-alerts.net',
    body: `Dear Valued Customer,

We have detected unusual activity on your account. Your account has been temporarily suspended for security reasons.

You must verify your information within 24 hours or your account will be permanently closed.

Click here to verify: http://bankofamerica-secure-login.xyz/verify

Provide your:
- Full name
- Social Security Number
- Account number and PIN
- Credit card details

Failure to act immediately will result in permanent account closure and legal action.

Security Department
Bank of America`,
  },
  {
    label: '🏆 Lottery Scam',
    subject: 'YOU HAVE WON $1,500,000 - Claim Now!',
    sender: 'claims@intl-lottery-winners.com',
    body: `CONGRATULATIONS!!!

Your email has been selected as the LUCKY WINNER of our International Email Lottery!

Prize Amount: USD $1,500,000.00

To claim your prize, you must pay a small processing fee of $250 via Western Union.

Send fee to: John Smith, Lagos, Nigeria

Reply with your:
- Full name
- Home address  
- Phone number
- Bank account details

This is NOT a scam. You must act within 48 hours.`,
  },
  {
    label: '✅ Legitimate',
    subject: 'Your GitHub pull request has been reviewed',
    sender: 'noreply@github.com',
    body: `Hi there,

Your pull request #142 "Fix navigation bug on mobile" has been reviewed.

Repository: myorg/my-project
Reviewer: @johndoe
Status: Approved ✓

View the pull request: https://github.com/myorg/my-project/pull/142

You can merge this pull request when you're ready.

Thanks,
The GitHub Team`,
  },
];

function getRiskColor(score) {
  if (score >= 70) return '#ff4757';
  if (score >= 40) return '#ffa502';
  return '#00ff9f';
}

function getRiskLevel(score) {
  if (score >= 70) return { label: 'HIGH RISK', color: '#ff4757' };
  if (score >= 40) return { label: 'MEDIUM RISK', color: '#ffa502' };
  return { label: 'LOW RISK', color: '#00ff9f' };
}

export default function Home() {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [body, setBody] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [socOpen, setSocOpen] = useState(false);

  const phishingCount = history.filter(h => h.classification === 'Phishing Email').length;
  const legitCount = history.filter(h => h.classification === 'Legitimate Email').length;

  async function analyze() {
    if (!subject.trim() && !body.trim()) {
      setError('Please enter an email subject or body to analyze.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    setSocOpen(false);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, sender, body }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Analysis failed');
      setResult(data);
      setHistory(prev => [{
        ...data,
        subject: subject || 'No Subject',
        time: new Date().toLocaleTimeString(),
      }, ...prev].slice(0, 20));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function loadExample(ex) {
    setSubject(ex.subject);
    setSender(ex.sender);
    setBody(ex.body);
    setResult(null);
    setError(null);
    setSocOpen(false);
  }

  function clearHistory() {
    setHistory([]);
  }

  const isPhishing = result?.classification === 'Phishing Email';

  return (
    <div className="shell">
      {/* ── HEADER ── */}
      <div className="header">
        <div className="header-badge">⚡ Powered by Google Gemini AI</div>
        <h1>🛡️ PhishNet AI</h1>
        <p>Instantly detect phishing emails with AI-powered cybersecurity analysis. Paste any email to get a full threat assessment.</p>
      </div>

      {/* ── STATS ── */}
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-icon cyan">📊</div>
          <div>
            <div className="stat-label">Total Analyzed</div>
            <div className="stat-value cyan">{history.length}</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon red">🎣</div>
          <div>
            <div className="stat-label">Phishing Detected</div>
            <div className="stat-value red">{phishingCount}</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon green">✅</div>
          <div>
            <div className="stat-label">Legitimate Emails</div>
            <div className="stat-value green">{legitCount}</div>
          </div>
        </div>
      </div>

      {/* ── MAIN GRID ── */}
      <div className="main-grid">

        {/* LEFT: INPUT */}
        <div className="card">
          <div className="card-title">📧 Email Input</div>

          {/* Example Pills */}
          <div className="example-pills">
            {EXAMPLES.map(ex => (
              <button key={ex.label} className="pill" onClick={() => loadExample(ex)}>
                {ex.label}
              </button>
            ))}
          </div>

          <div className="field">
            <label>From (Sender)</label>
            <input
              id="sender-input"
              type="text"
              placeholder="sender@example.com"
              value={sender}
              onChange={e => setSender(e.target.value)}
            />
          </div>

          <div className="field">
            <label>Subject</label>
            <input
              id="subject-input"
              type="text"
              placeholder="Enter email subject..."
              value={subject}
              onChange={e => setSubject(e.target.value)}
            />
          </div>

          <div className="field">
            <label>Email Body</label>
            <textarea
              id="body-input"
              rows={12}
              placeholder="Paste the full email body here..."
              value={body}
              onChange={e => setBody(e.target.value)}
            />
          </div>

          <button
            id="analyze-btn"
            className={`btn-analyze${loading ? ' loading' : ''}`}
            onClick={analyze}
            disabled={loading}
          >
            {loading ? '⏳ Analyzing...' : '🔍 Analyze Email'}
          </button>
        </div>

        {/* RIGHT: RESULTS */}
        <div className="card">
          <div className="card-title">🎯 Analysis Results</div>

          {loading && (
            <div className="loader">
              <div className="spinner" />
              <p>Running AI threat analysis...</p>
            </div>
          )}

          {!loading && !result && !error && (
            <div className="result-empty">
              <div className="icon">🔒</div>
              <p>Enter an email on the left and click <strong>Analyze Email</strong> to get your threat assessment.</p>
              <p style={{ fontSize: '12px', marginTop: '8px' }}>Try one of the example emails to see it in action.</p>
            </div>
          )}

          {error && !loading && (
            <div className="error-box">
              <strong>⚠️ Error:</strong><br />{error}
              {error.includes('GEMINI_API_KEY') && (
                <div style={{ marginTop: '12px', lineHeight: 1.8 }}>
                  <strong>How to fix:</strong><br />
                  1. Get a free API key from{' '}
                  <a href="https://aistudio.google.com/apikey" target="_blank" rel="noreferrer"
                    style={{ color: '#00d4ff' }}>aistudio.google.com</a><br />
                  2. Add <code style={{ background: 'rgba(0,212,255,0.1)', padding: '2px 6px', borderRadius: '4px' }}>GEMINI_API_KEY</code> to Vercel Environment Variables
                </div>
              )}
            </div>
          )}

          {result && !loading && (
            <>
              {/* Verdict */}
              <div className={`verdict ${isPhishing ? 'phishing' : 'legitimate'}`}>
                <div className="verdict-icon">{isPhishing ? '🚨' : '✅'}</div>
                <div>
                  <div className="verdict-label">Classification</div>
                  <div className="verdict-text">{result.classification}</div>
                </div>
              </div>

              {/* Risk Score */}
              <div className="risk-section">
                <div className="risk-header">
                  <span className="risk-label">Risk Score</span>
                  <span className="risk-score-val" style={{ color: getRiskColor(result.risk_score) }}>
                    {result.risk_score}<span style={{ fontSize: '16px', color: 'var(--text-muted)' }}>/100</span>
                  </span>
                </div>
                <div className="risk-bar-track">
                  <div
                    className="risk-bar-fill"
                    style={{
                      width: `${result.risk_score}%`,
                      background: result.risk_score >= 70
                        ? 'linear-gradient(90deg, #ff4757, #ff6b81)'
                        : result.risk_score >= 40
                        ? 'linear-gradient(90deg, #ffa502, #ffcc00)'
                        : 'linear-gradient(90deg, #00ff9f, #00d4ff)',
                    }}
                  />
                </div>
                <div className="risk-level" style={{ color: getRiskLevel(result.risk_score).color }}>
                  {getRiskLevel(result.risk_score).label}
                </div>
              </div>

              {/* Red Flags */}
              <div className="flags-title">🚩 Red Flags Detected ({result.red_flags?.length || 0})</div>
              {result.red_flags?.length > 0 ? (
                <div className="flags-list">
                  {result.red_flags.map((flag, i) => (
                    <div key={i} className="flag-item">
                      <div className="dot" />
                      {flag}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="no-flags">✅ No red flags detected — email appears safe.</div>
              )}

              {/* Explanation */}
              <div className="explanation">{result.explanation}</div>

              {/* SOC Report */}
              {result.soc_report && (
                <>
                  <button className="soc-toggle" onClick={() => setSocOpen(o => !o)}>
                    <span>📋 SOC Analysis Report</span>
                    <span>{socOpen ? '▲' : '▼'}</span>
                  </button>
                  {socOpen && <div className="soc-body">{result.soc_report}</div>}
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* ── HISTORY ── */}
      {history.length > 0 && (
        <div className="history-section">
          <div className="history-header">
            <div className="history-title">📜 Analysis History ({history.length})</div>
            <button className="btn-clear" onClick={clearHistory}>Clear</button>
          </div>
          <div className="history-grid">
            {history.map((item, i) => {
              const isP = item.classification === 'Phishing Email';
              return (
                <div
                  key={i}
                  className={`history-card ${isP ? 'phishing' : 'legitimate'}`}
                  onClick={() => setResult(item)}
                >
                  <div className="hc-top">
                    <span className={`hc-badge ${isP ? 'phishing' : 'legitimate'}`}>
                      {isP ? '🎣 PHISHING' : '✅ LEGIT'}
                    </span>
                    <span className="hc-score" style={{ color: getRiskColor(item.risk_score) }}>
                      {item.risk_score}/100
                    </span>
                  </div>
                  <div className="hc-subject">{item.subject}</div>
                  <div className="hc-time">{item.time}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── FOOTER ── */}
      <div className="footer">
        PhishNet AI • Powered by Google Gemini • Built for cybersecurity awareness
      </div>
    </div>
  );
}
