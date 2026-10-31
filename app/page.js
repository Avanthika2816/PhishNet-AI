'use client';

import { useState, useRef } from 'react';

const PRESET_SCENARIOS = {
  '🏦 Bank Account Freeze': {
    sender: 'security@alert-verify-chase.com',
    subject: 'URGENT: Unauthorized Account Access Detected - Immediate Verification Required',
    body: `Dear Valued Customer,

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
Incident Reference: #CH-994827-SEC`
  },
  '💼 CEO Wire Transfer (BEC)': {
    sender: 'ceo.office@exec-corp-direct.com',
    subject: 'STRICTLY CONFIDENTIAL: Immediate Acquisition Wire Transfer Required',
    body: `Hi,

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
Chief Executive Officer`
  },
  '📦 FedEx Delivery Scam': {
    sender: 'tracking-update@fedex-courier-portal.net',
    subject: 'Delivery Exception: Package #FX-938201 held at regional terminal',
    body: `Dear Customer,

Your incoming shipment (Tracking #FX-938201) could not be delivered today due to an incomplete street address and an unpaid customs duty fee of $3.45 USD.

Your package is currently stored at our regional distribution depot. We can hold your parcel for up to 48 hours before returning it to the overseas vendor.

To confirm your delivery address and settle the $3.45 fee, visit our tracking portal:
https://fedex-express-customs-resolution.com/claim-package?id=FX-938201

Thank you for shipping with FedEx Global Express.`
  },
  '🎁 Crypto Lottery Winner': {
    sender: 'claims@global-bitcoin-foundation.xyz',
    subject: 'CONGRATULATIONS: You Were Selected to Receive 2.5 BTC ($165,000 USD)!',
    body: `Dear Lucky Internet User,

Your email address was selected in the International Web3 Genesis Blockchain Airdrop! You have officially won 2.50 Bitcoin (BTC), equivalent to over $165,000 USD!

To release your cryptocurrency payout to your private wallet:
1. Visit: http://claim-btc-reward.blockchain-prize-pool.xyz
2. Provide your government photo ID
3. Submit a nominal miner transaction gas fee of $150 via Gift Card or USDT

You must claim your prize within 48 hours, or the funds will be reallocated to another candidate.

Dr. Richard Vance
Global Blockchain Lottery Foundation`
  },
  '🔐 IT Password Expiration': {
    sender: 'itsupport@secure-corporate-sso-gateway.info',
    subject: 'IT Security Notice: Corporate SSO Password Expires in 2 Hours',
    body: `All Staff,

Our annual enterprise password policy requires all corporate credentials to be rotated every 90 days. Your Active Directory & Office 365 password is scheduled to expire in 2 hours.

If your password expires, you will lose access to Slack, Workday, internal VPN, and corporate email.

Click here to keep your current password or set a new one:
http://login.microsoftonline.sso-gateway-corporate.info/auth/login

Failure to authenticate will require in-person identity verification at the IT Helpdesk.

Corporate Information Security Division`
  },
  '🏢 Legitimate Statement': {
    sender: 'notifications@chase.com',
    subject: 'Your monthly Chase account statement is ready to view',
    body: `Dear Account Holder,

Your monthly electronic account statement for the period ending October 31, 2026 is now available.

To view your statement:
1. Open the Chase Mobile app on your device, or
2. Sign in to your account directly at https://www.chase.com
3. Go to Accounts > Statements & Documents

Security Reminder:
Chase will NEVER ask you to reply to an email with your password, full Social Security Number, PIN, or one-time verification codes. If you receive an unexpected request for sensitive information, please forward it to abuse@chase.com.

Thank you for choosing Chase.
JPMorgan Chase Bank, N.A. Member FDIC.`
  }
};

// Calculate Shannon Entropy of a file buffer
function calculateEntropy(byteArray) {
  if (!byteArray || byteArray.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < byteArray.length; i++) {
    frequencies[byteArray[i]]++;
  }
  let entropy = 0;
  const len = byteArray.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return parseFloat(entropy.toFixed(2));
}

// Compute SHA-256 Hex Digest in Browser
async function computeSha256(arrayBuffer) {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'unavailable';
  }
}

// Static Heuristic File Analysis
function analyzeFileHeuristics(filename, byteLength, entropy) {
  const nameLower = filename.toLowerCase();
  const dangerousExts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.msi', '.hta', '.jar'];
  const macroExts = ['.docm', '.xlsm', '.pptm', '.dotm'];
  
  const indicators = [];
  let riskScore = 10;

  // Double extension check (e.g. invoice.pdf.exe)
  const parts = nameLower.split('.');
  if (parts.length > 2) {
    indicators.push(`Double extension detected (possible obfuscation: "${nameLower}")`);
    riskScore += 45;
  }

  // Dangerous extension check
  if (dangerousExts.some(ext => nameLower.endsWith(ext))) {
    indicators.push(`High-risk executable binary extension: .${parts.pop()}`);
    riskScore += 60;
  }

  // Macro check
  if (macroExts.some(ext => nameLower.endsWith(ext))) {
    indicators.push(`Macro-enabled Office document format capable of running embedded VBA`);
    riskScore += 40;
  }

  // Entropy check (Packed / Encrypted payload)
  if (entropy > 7.0) {
    indicators.push(`Unusually high entropy (${entropy}/8.0) indicating potential encryption, packing, or obfuscation`);
    riskScore += 25;
  }

  // Suspicious keywords in filename
  const keywords = ['invoice', 'payment', 'wire', 'receipt', 'update', 'urgent', 'order', 'statement'];
  if (keywords.some(kw => nameLower.includes(kw))) {
    indicators.push(`Filename contains social engineering keywords`);
    riskScore += 10;
  }

  riskScore = Math.min(Math.max(riskScore, 5), 98);
  const classification = riskScore >= 70 ? 'Malicious' : riskScore >= 40 ? 'Suspicious' : 'Clean';

  return { riskScore, classification, indicators };
}

export default function Home() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [subject, setSubject] = useState(PRESET_SCENARIOS['🏦 Bank Account Freeze'].subject);
  const [sender, setSender] = useState(PRESET_SCENARIOS['🏦 Bank Account Freeze'].sender);
  const [body, setBody] = useState(PRESET_SCENARIOS['🏦 Bank Account Freeze'].body);
  const [attachments, setAttachments] = useState([]);
  const [labFiles, setLabFiles] = useState([]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [copied, setCopied] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  const fileInputRef = useRef(null);
  const labInputRef = useRef(null);

  // File Ingestion Handler
  async function handleFileUpload(files) {
    if (!files || files.length === 0) return;
    const newAttachments = [...attachments];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const buffer = await file.arrayBuffer();
      const byteArray = new Uint8Array(buffer);
      const entropy = calculateEntropy(byteArray);
      const hash = await computeSha256(buffer);
      const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, entropy);

      // If EML, attempt client-side parsing
      if (file.name.toLowerCase().endsWith('.eml') || file.name.toLowerCase().endsWith('.txt')) {
        const text = new TextDecoder().decode(byteArray);
        
        // Simple header extraction
        const subjectMatch = text.match(/^Subject:\s*(.+)$/im);
        const fromMatch = text.match(/^From:\s*(.+)$/im);
        
        if (subjectMatch) setSubject(subjectMatch[1].trim());
        if (fromMatch) setSender(fromMatch[1].trim());

        // Extract body preview (after empty line)
        const parts = text.split(/\r?\n\r?\n/);
        if (parts.length > 1) {
          setBody(parts.slice(1).join('\n\n').slice(0, 4000));
        }
      }

      newAttachments.push({
        name: file.name,
        size: (file.size / (1024 * 1024)).toFixed(2),
        type: file.type || 'application/octet-stream',
        entropy,
        hash,
        risk_score: riskScore,
        classification,
        risk_indicators: indicators
      });
    }

    setAttachments(newAttachments);
  }

  // Standalone Lab File Upload Handler
  async function handleLabUpload(files) {
    if (!files || files.length === 0) return;
    const newLab = [...labFiles];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const buffer = await file.arrayBuffer();
      const byteArray = new Uint8Array(buffer);
      const entropy = calculateEntropy(byteArray);
      const hash = await computeSha256(buffer);
      const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, entropy);

      newLab.unshift({
        name: file.name,
        size: (file.size / (1024 * 1024)).toFixed(2),
        type: file.type || 'application/octet-stream',
        entropy,
        hash,
        risk_score: riskScore,
        classification,
        risk_indicators: indicators
      });
    }
    setLabFiles(newLab);
  }

  function removeAttachment(index) {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  }

  // Execute Threat Analysis
  async function executeAnalysis() {
    if (!subject.trim() && !body.trim() && attachments.length === 0) {
      setError('Please provide an email subject, body, or upload an attachment to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject,
          sender,
          body,
          attachments
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Threat analysis failed');

      setResult({
        ...data,
        attachmentsAnalyzed: attachments
      });

      setHistory(prev => [{
        ...data,
        subject: subject || (attachments.length ? `Attachment: ${attachments[0].name}` : 'No Subject'),
        sender: sender || 'Unknown',
        time: new Date().toLocaleTimeString(),
        attachmentsCount: attachments.length
      }, ...prev].slice(0, 25));

    } catch (err) {
      setError(err.message || 'Error executing threat analysis');
    } finally {
      setLoading(false);
    }
  }

  function loadScenario(key) {
    const sc = PRESET_SCENARIOS[key];
    if (sc) {
      setSender(sc.sender);
      setSubject(sc.subject);
      setBody(sc.body);
      setResult(null);
      setError(null);
    }
  }

  function copySocReport() {
    if (result?.soc_report) {
      navigator.clipboard.writeText(result.soc_report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  function downloadAuditJson() {
    const jsonStr = JSON.stringify(history, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PhishNet_AI_Audit_${Date.now()}.json`;
    a.click();
  }

  // Calculate stats
  const totalScanned = history.length;
  const phishingCount = history.filter(h => h.classification === 'Phishing Email').length;
  const cleanCount = totalScanned - phishingCount;
  const maliciousAttachmentsCount = attachments.filter(a => a.classification === 'Malicious').length;

  return (
    <div className="shell">
      {/* ── HERO BANNER ── */}
      <div className="hero">
        <div className="status-ribbon">
          <span className="pulse-dot"></span>
          AI SENTINEL ONLINE • CLAUDE SONNET 4.5 &amp; GEMINI DUAL ENGINE ACTIVE
        </div>
        <h1>🛡️ PhishNet AI</h1>
        <p>
          Next-generation threat detection engine analyzing linguistic deception, social engineering vectors, and zero-day payload indicators.
        </p>
      </div>

      {/* ── KPI STATS ROW ── */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">Total Emails Scanned</div>
          <div className="kpi-value cyan">{totalScanned}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Phishing Intercepted</div>
          <div className="kpi-value red">{phishingCount}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Malicious Payloads</div>
          <div className="kpi-value amber">{maliciousAttachmentsCount}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Clean &amp; Verified</div>
          <div className="kpi-value emerald">{cleanCount}</div>
        </div>
      </div>

      {/* ── TABS NAVIGATION ── */}
      <div className="tabs-bar">
        <button
          className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          📨 Email Threat Scanner
        </button>
        <button
          className={`tab-btn ${activeTab === 'lab' ? 'active' : ''}`}
          onClick={() => setActiveTab('lab')}
        >
          🔬 Attachment &amp; Malware Lab
        </button>
        <button
          className={`tab-btn ${activeTab === 'scenarios' ? 'active' : ''}`}
          onClick={() => setActiveTab('scenarios')}
        >
          ⚡ Attack Scenarios (1-Click)
        </button>
        <button
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          📊 SOC Audit Log ({history.length})
        </button>
      </div>

      {/* ── TAB 1: EMAIL THREAT SCANNER ── */}
      {activeTab === 'scanner' && (
        <>
          {/* Quick Scenario Chips Bar */}
          <div className="presets-scroller">
            {Object.keys(PRESET_SCENARIOS).map(key => (
              <button
                key={key}
                className="preset-chip"
                onClick={() => loadScenario(key)}
              >
                {key}
              </button>
            ))}
          </div>

          <div className="scanner-grid">
            {/* Input Form & Drag/Drop */}
            <div className="glass-card">
              <div className="card-heading">
                <span>✉️ Email &amp; File Ingestion</span>
              </div>

              {/* Drag and Drop Zone with Browse Files Button */}
              <div
                className={`dropzone ${isDragOver ? 'dragover' : ''}`}
                onDragOver={e => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={e => {
                  e.preventDefault();
                  setIsDragOver(false);
                  handleFileUpload(e.dataTransfer.files);
                }}
                onClick={() => fileInputRef.current?.click()}
              >
                <div className="dropzone-icon">📂</div>
                <div className="dropzone-text">
                  <strong>Click to Browse Files</strong> or drag &amp; drop here
                </div>
                <div className="dropzone-sub">
                  Supports .eml messages, PDFs, Office docs (.docm/.xlsm), executables, scripts (.bat/.ps1), and archives
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  className="file-input-hidden"
                  onChange={e => handleFileUpload(e.target.files)}
                />
              </div>

              {/* Uploaded Attachments List */}
              {attachments.length > 0 && (
                <div className="attachment-list">
                  {attachments.map((att, idx) => (
                    <div key={idx} className="attachment-pill">
                      <div className="attachment-pill-info">
                        <span>📎 <strong>{att.name}</strong></span>
                        <span style={{ color: 'var(--text-muted)' }}>({att.size} MB)</span>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          background: att.risk_score >= 70 ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)',
                          color: att.risk_score >= 70 ? '#fca5a5' : '#6ee7b7'
                        }}>
                          {att.classification} ({att.risk_score}/100)
                        </span>
                      </div>
                      <button className="btn-remove-att" onClick={() => removeAttachment(idx)}>✕</button>
                    </div>
                  ))}
                </div>
              )}

              <div className="field">
                <label>Sender Address (From:)</label>
                <input
                  type="text"
                  placeholder="e.g. security@alert-verify-chase.com"
                  value={sender}
                  onChange={e => setSender(e.target.value)}
                />
              </div>

              <div className="field">
                <label>Subject Line</label>
                <input
                  type="text"
                  placeholder="e.g. URGENT: Unauthorized Account Access Detected"
                  value={subject}
                  onChange={e => setSubject(e.target.value)}
                />
              </div>

              <div className="field">
                <label>Email Body Content</label>
                <textarea
                  rows={9}
                  placeholder="Paste raw email text or headers..."
                  value={body}
                  onChange={e => setBody(e.target.value)}
                />
              </div>

              <button
                className="btn-primary"
                onClick={executeAnalysis}
                disabled={loading}
              >
                {loading ? '⏳ EXECUTING THREAT SCAN...' : '🚀 EXECUTE THREAT ANALYSIS'}
              </button>
            </div>

            {/* Live Results Panel */}
            <div className="glass-card">
              <div className="card-heading">
                <span>🎯 Assessment Results</span>
              </div>

              {loading && (
                <div style={{ textAlign: 'center', padding: '60px 0' }}>
                  <div className="pulse-dot" style={{ width: '20px', height: '20px', margin: '0 auto 16px' }} />
                  <p style={{ color: '#38bdf8', fontWeight: 600 }}>Analyzing vectors &amp; heuristic patterns...</p>
                </div>
              )}

              {error && !loading && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  padding: '16px',
                  borderRadius: '10px',
                  color: '#fca5a5'
                }}>
                  <strong>⚠️ Analysis Error:</strong> {error}
                </div>
              )}

              {!loading && !result && !error && (
                <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '12px' }}>🛡️</div>
                  <h4 style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>Sentinel Ready</h4>
                  <p style={{ fontSize: '0.9rem' }}>
                    Select a 1-click test scenario above or paste an email to generate a SOC threat assessment.
                  </p>
                </div>
              )}

              {result && !loading && (
                <>
                  {/* Top Verdict Banner */}
                  <div className={`verdict-banner ${result.risk_score >= 70 ? 'danger' : result.risk_score >= 40 ? 'warning' : 'success'}`}>
                    <div>
                      <h3 style={{ margin: 0 }}>
                        {result.risk_score >= 70 ? '🚨 THREAT DETECTED: ' : result.risk_score >= 40 ? '⚠️ SUSPICIOUS EMAIL: ' : '🛡️ VERIFIED: '}
                        {result.classification.toUpperCase()}
                      </h3>
                      <p style={{ margin: '4px 0 0 0', fontSize: '0.88rem' }}>
                        {result.risk_score >= 70
                          ? 'Immediate quarantine & sender domain block recommended.'
                          : result.risk_score >= 40
                          ? 'Anomalous indicators detected. Exercise caution.'
                          : 'No deceptive vectors or credential harvesting patterns detected.'}
                      </p>
                    </div>
                  </div>

                  {/* Radial Speedometer Gauge */}
                  <div className="gauge-container">
                    <svg className="gauge-svg" viewBox="0 0 200 120">
                      {/* Outer Arc Track */}
                      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="18" strokeLinecap="round" />
                      {/* Green Safe Zone */}
                      <path d="M 20 100 A 80 80 0 0 1 73 34" fill="none" stroke="rgba(16, 185, 129, 0.3)" strokeWidth="18" />
                      {/* Amber Warning Zone */}
                      <path d="M 73 34 A 80 80 0 0 1 127 34" fill="none" stroke="rgba(245, 158, 11, 0.3)" strokeWidth="18" />
                      {/* Red Danger Zone */}
                      <path d="M 127 34 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(239, 68, 68, 0.3)" strokeWidth="18" />
                      
                      {/* Needle */}
                      {(() => {
                        const angle = -180 + (result.risk_score / 100) * 180;
                        const rad = (angle * Math.PI) / 180;
                        const x = 100 + 65 * Math.cos(rad);
                        const y = 100 + 65 * Math.sin(rad);
                        const color = result.risk_score >= 70 ? '#ef4444' : result.risk_score >= 40 ? '#f59e0b' : '#10b981';
                        return (
                          <>
                            <line x1="100" y1="100" x2={x} y2={y} stroke={color} strokeWidth="4" strokeLinecap="round" />
                            <circle cx="100" cy="100" r="7" fill="#ffffff" />
                            <circle cx="100" cy="100" r="4" fill={color} />
                          </>
                        );
                      })()}

                      <text x="100" y="80" className="gauge-score-text">{result.risk_score}</text>
                      <text x="100" y="98" fill="var(--text-muted)" fontSize="11" textAnchor="middle">/ 100 THREAT SCORE</text>
                    </svg>
                  </div>

                  {/* Red Flags Chips */}
                  {result.red_flags && result.red_flags.length > 0 && (
                    <div style={{ marginTop: '16px' }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        🚩 DETECTED THREAT INDICATORS:
                      </div>
                      <div className="flags-grid">
                        {result.red_flags.map((flag, i) => (
                          <div key={i} className="flag-badge">
                            ⚠️ {flag}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Explanation */}
                  <div style={{
                    background: 'rgba(30, 41, 59, 0.5)',
                    border: '1px solid var(--border)',
                    borderRadius: '10px',
                    padding: '14px',
                    fontSize: '0.9rem',
                    lineHeight: 1.6,
                    color: '#e2e8f0',
                    margin: '16px 0'
                  }}>
                    {result.explanation}
                  </div>

                  {/* Attachment Deep-Dive Cards */}
                  {result.attachmentsAnalyzed && result.attachmentsAnalyzed.length > 0 && (
                    <div style={{ marginTop: '16px' }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        📎 ATTACHMENT MALWARE INSPECTION:
                      </div>
                      {result.attachmentsAnalyzed.map((att, i) => (
                        <div key={i} style={{
                          background: 'rgba(15, 23, 42, 0.9)',
                          border: '1px solid var(--border)',
                          borderRadius: '10px',
                          padding: '12px 16px',
                          marginBottom: '8px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <strong>📄 {att.name}</strong>
                            <span style={{
                              color: att.risk_score >= 70 ? '#f87171' : '#34d399',
                              fontWeight: 700,
                              fontFamily: 'JetBrains Mono',
                              fontSize: '0.9rem'
                            }}>
                              {att.classification} ({att.risk_score}/100)
                            </span>
                          </div>
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                            SHA-256: {att.hash}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            Entropy: {att.entropy}/8.0 • Size: {att.size} MB • MIME: {att.type}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Terminal SOC Incident Report */}
                  {result.soc_report && (
                    <div className="terminal-window">
                      <div className="terminal-header">
                        <div className="terminal-dots">
                          <span className="dot red"></span>
                          <span className="dot yellow"></span>
                          <span className="dot green"></span>
                        </div>
                        <span className="terminal-title">SOC-INCIDENT-INVESTIGATION.log</span>
                        <button className="copy-btn" onClick={copySocReport}>
                          {copied ? '✓ Copied' : '📋 Copy Log'}
                        </button>
                      </div>
                      <div className="terminal-body">{result.soc_report}</div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── TAB 2: ATTACHMENT & MALWARE LAB ── */}
      {activeTab === 'lab' && (
        <div className="glass-card">
          <div className="card-heading">
            <span>🔬 Standalone Attachment &amp; Binary Malware Sandbox</span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '20px' }}>
            Directly inspect any document, script, or binary file. Computes client-side cryptographic SHA-256 checksums, Shannon entropy (randomness), and extension spoofing vectors.
          </p>

          <div
            className="dropzone"
            onClick={() => labInputRef.current?.click()}
          >
            <div className="dropzone-icon">🧪</div>
            <div className="dropzone-text">
              <strong>Click to Browse Files for Sandbox Inspection</strong>
            </div>
            <div className="dropzone-sub">
              Drag &amp; drop any executable (.exe), script (.bat, .ps1, .vbs), macro document (.docm), or archive (.zip)
            </div>
            <input
              ref={labInputRef}
              type="file"
              multiple
              className="file-input-hidden"
              onChange={e => handleLabUpload(e.target.files)}
            />
          </div>

          {labFiles.length > 0 && (
            <div style={{ marginTop: '24px' }}>
              <h4 style={{ marginBottom: '14px', color: 'var(--text-primary)' }}>
                Analyzed Payload Artifacts ({labFiles.length})
              </h4>
              {labFiles.map((file, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.85)',
                    border: `1px solid ${file.risk_score >= 70 ? 'rgba(239,68,68,0.4)' : 'var(--border)'}`,
                    borderRadius: '12px',
                    padding: '18px 20px',
                    marginBottom: '14px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div style={{ fontSize: '1.05rem', fontWeight: 700 }}>📄 {file.name}</div>
                    <div style={{
                      fontFamily: 'JetBrains Mono',
                      fontSize: '1.1rem',
                      fontWeight: 800,
                      color: file.risk_score >= 70 ? '#f87171' : file.risk_score >= 40 ? '#fbbf24' : '#34d399'
                    }}>
                      {file.classification.toUpperCase()} • {file.risk_score}/100
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', margin: '12px 0' }}>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '8px 12px', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FILE SIZE</span>
                      <div style={{ fontWeight: 600 }}>{file.size} MB</div>
                    </div>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '8px 12px', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SHANNON ENTROPY</span>
                      <div style={{ fontWeight: 600, color: file.entropy > 7 ? '#f87171' : '#38bdf8' }}>
                        {file.entropy} / 8.0
                      </div>
                    </div>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '8px 12px', borderRadius: '8px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>MIME TYPE</span>
                      <div style={{ fontWeight: 600 }}>{file.type}</div>
                    </div>
                  </div>

                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    SHA-256: <code>{file.hash}</code>
                  </div>

                  {file.risk_indicators && file.risk_indicators.length > 0 ? (
                    <div>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#fca5a5' }}>Threat Signatures:</span>
                      <ul style={{ margin: '4px 0 0 20px', fontSize: '0.85rem', color: '#fca5a5' }}>
                        {file.risk_indicators.map((ind, i) => (
                          <li key={i}>{ind}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div style={{ color: '#34d399', fontSize: '0.85rem' }}>
                      ✅ No dangerous executable headers or macro triggers identified.
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 3: ATTACK VECTOR SCENARIOS ── */}
      {activeTab === 'scenarios' && (
        <div className="glass-card">
          <div className="card-heading">
            <span>⚡ Interactive Attack Vectors &amp; Benchmark Scenarios</span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '20px' }}>
            Test PhishNet AI with verified real-world attack campaigns and legitimate baselines. Click any card to load it directly into the scanner.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px' }}>
            {Object.entries(PRESET_SCENARIOS).map(([title, item]) => (
              <div
                key={title}
                style={{
                  background: 'rgba(15, 23, 42, 0.85)',
                  border: '1px solid var(--border)',
                  borderRadius: '12px',
                  padding: '20px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between'
                }}
              >
                <div>
                  <h4 style={{ color: 'var(--text-primary)', marginBottom: '8px' }}>{title}</h4>
                  <p style={{ fontSize: '0.82rem', color: '#38bdf8', marginBottom: '6px' }}>
                    <strong>From:</strong> {item.sender}
                  </p>
                  <p style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '10px' }}>
                    {item.subject}
                  </p>
                  <p style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-muted)',
                    lineHeight: 1.5,
                    maxHeight: '100px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis'
                  }}>
                    {item.body.slice(0, 160)}...
                  </p>
                </div>

                <button
                  style={{
                    marginTop: '16px',
                    background: 'rgba(56, 189, 248, 0.15)',
                    border: '1px solid rgba(56, 189, 248, 0.3)',
                    color: '#38bdf8',
                    padding: '8px 16px',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    fontWeight: 600,
                    fontSize: '0.85rem'
                  }}
                  onClick={() => {
                    loadScenario(title);
                    setActiveTab('scanner');
                  }}
                >
                  📥 Load into Scanner
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── TAB 4: SOC AUDIT LOG & ANALYTICS ── */}
      {activeTab === 'history' && (
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <div className="card-heading" style={{ margin: 0 }}>
              <span>📊 Threat Intelligence History &amp; Audit Trail</span>
            </div>
            {history.length > 0 && (
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="copy-btn"
                  style={{ padding: '8px 14px', fontSize: '0.85rem' }}
                  onClick={downloadAuditJson}
                >
                  💾 Download Audit Report (JSON)
                </button>
                <button
                  className="copy-btn"
                  style={{ padding: '8px 14px', fontSize: '0.85rem', color: '#f87171' }}
                  onClick={() => setHistory([])}
                >
                  🗑️ Clear Log
                </button>
              </div>
            )}
          </div>

          {history.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
              No threat scans recorded in this session. Run an analysis in the scanner to build an audit trail.
            </div>
          ) : (
            <div className="history-grid">
              {history.map((item, idx) => {
                const isP = item.classification === 'Phishing Email';
                return (
                  <div
                    key={idx}
                    className={`history-card ${isP ? 'danger' : 'success'}`}
                    onClick={() => {
                      setResult(item);
                      setActiveTab('scanner');
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        padding: '3px 8px',
                        borderRadius: '4px',
                        background: isP ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)',
                        color: isP ? '#f87171' : '#34d399'
                      }}>
                        {isP ? '🎣 PHISHING' : '✅ SAFE'}
                      </span>
                      <span style={{
                        fontFamily: 'JetBrains Mono',
                        fontWeight: 700,
                        color: isP ? '#f87171' : '#34d399'
                      }}>
                        {item.risk_score}/100
                      </span>
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '0.92rem', marginBottom: '4px' }}>
                      {item.subject}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>{item.sender}</span>
                      <span>{item.time}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── FOOTER ── */}
      <div className="footer">
        PhishNet AI • Autonomous Cybersecurity Threat Intelligence Platform • Streamlit &amp; Next.js Dual Engine
      </div>
    </div>
  );
}
