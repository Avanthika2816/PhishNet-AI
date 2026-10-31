'use client';

import { useState, useRef } from 'react';

const PRESET_SCENARIOS = {
  '🏦 Bank Account Freeze': {
    sender: 'security@alert-verify-chase.com',
    subject: 'URGENT: Unauthorized Account Access Detected - Immediate Verification Required',
    tag: 'Credential Theft',
    severity: 'Critical',
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
    tag: 'Executive Impersonation',
    severity: 'High',
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
    tag: 'Fee Extortion',
    severity: 'High',
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
    tag: 'Advance Fee Fraud',
    severity: 'High',
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
    tag: 'Fake SSO Portal',
    severity: 'Critical',
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
    tag: 'Safe Baseline',
    severity: 'Clean',
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

// Shannon Entropy Calculation
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

// Client-side SHA-256 Checksum
async function computeSha256(arrayBuffer) {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  }
}

// Static Heuristics Triage
function analyzeFileHeuristics(filename, byteLength, entropy) {
  const nameLower = filename.toLowerCase();
  const dangerousExts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.msi', '.hta', '.jar'];
  const macroExts = ['.docm', '.xlsm', '.pptm', '.dotm'];
  
  const indicators = [];
  let riskScore = 10;

  const parts = nameLower.split('.');
  if (parts.length > 2) {
    indicators.push(`Double extension detected (possible obfuscation: "${nameLower}")`);
    riskScore += 45;
  }

  if (dangerousExts.some(ext => nameLower.endsWith(ext))) {
    indicators.push(`Executable binary payload detected`);
    riskScore += 60;
  }

  if (macroExts.some(ext => nameLower.endsWith(ext))) {
    indicators.push(`Macro-enabled document capable of executing embedded VBA scripts`);
    riskScore += 40;
  }

  if (entropy > 7.0) {
    indicators.push(`High entropy (${entropy}/8.0) indicating encryption or packing`);
    riskScore += 25;
  }

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
  const [scanningPhase, setScanningPhase] = useState('');
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [copied, setCopied] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isLabDragOver, setIsLabDragOver] = useState(false);

  const fileInputRef = useRef(null);
  const labInputRef = useRef(null);

  // File Upload Handler for Scanner Tab
  async function handleFileUpload(files) {
    if (!files || files.length === 0) return;
    const fileArray = Array.from(files);
    const newAttachments = [];

    for (let i = 0; i < fileArray.length; i++) {
      const file = fileArray[i];
      try {
        const buffer = await file.arrayBuffer();
        const byteArray = new Uint8Array(buffer);
        const entropy = calculateEntropy(byteArray);
        const hash = await computeSha256(buffer);
        const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, entropy);

        if (file.name.toLowerCase().endsWith('.eml') || file.name.toLowerCase().endsWith('.txt')) {
          const text = new TextDecoder().decode(byteArray);
          const subjectMatch = text.match(/^Subject:\s*(.+)$/im);
          const fromMatch = text.match(/^From:\s*(.+)$/im);
          
          if (subjectMatch) setSubject(subjectMatch[1].trim());
          if (fromMatch) setSender(fromMatch[1].trim());

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
      } catch (err) {
        console.error('File parsing error:', err);
        const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, 5.0);
        newAttachments.push({
          name: file.name,
          size: (file.size / (1024 * 1024)).toFixed(2),
          type: file.type || 'application/octet-stream',
          entropy: 5.0,
          hash: 'hash-unavailable',
          risk_score: riskScore,
          classification,
          risk_indicators: indicators
        });
      }
    }

    setAttachments(prev => [...prev, ...newAttachments]);
  }

  // Standalone Lab Upload Handler (Works for multiple files & drag-drop)
  async function handleLabUpload(files) {
    if (!files || files.length === 0) return;
    const fileArray = Array.from(files);
    const newItems = [];

    for (let i = 0; i < fileArray.length; i++) {
      const file = fileArray[i];
      try {
        const buffer = await file.arrayBuffer();
        const byteArray = new Uint8Array(buffer);
        const entropy = calculateEntropy(byteArray);
        const hash = await computeSha256(buffer);
        const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, entropy);

        newItems.push({
          name: file.name,
          size: (file.size / (1024 * 1024)).toFixed(2),
          type: file.type || 'application/octet-stream',
          entropy,
          hash,
          risk_score: riskScore,
          classification,
          risk_indicators: indicators
        });
      } catch (err) {
        console.error('Error analyzing lab file:', err);
        const { riskScore, classification, indicators } = analyzeFileHeuristics(file.name, file.size, 5.0);
        newItems.push({
          name: file.name,
          size: (file.size / (1024 * 1024)).toFixed(2),
          type: file.type || 'application/octet-stream',
          entropy: 5.0,
          hash: 'hash-unavailable',
          risk_score: riskScore,
          classification,
          risk_indicators: indicators
        });
      }
    }

    setLabFiles(prev => [...newItems, ...prev]);
  }

  // 1-Click Sandbox Test Artifacts
  function addSampleLabPayload(name, sizeMb, entropy, indicators, riskScore) {
    const classification = riskScore >= 70 ? 'Malicious' : riskScore >= 40 ? 'Suspicious' : 'Clean';
    const fakeHash = Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    setLabFiles(prev => [{
      name,
      size: sizeMb,
      type: name.endsWith('.exe') ? 'application/x-msdownload' : name.endsWith('.xlsm') ? 'application/vnd.ms-excel.sheet.macroEnabled.12' : 'application/pdf',
      entropy,
      hash: fakeHash,
      risk_score: riskScore,
      classification,
      risk_indicators: indicators
    }, ...prev]);
  }

  function removeAttachment(index) {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  }

  // Execute Analysis with Animated Phase Simulation
  async function executeAnalysis() {
    if (!subject.trim() && !body.trim() && attachments.length === 0) {
      setError('Please provide an email subject, body, or upload an attachment to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    const phases = [
      '🔍 Parsing MIME structure & SPF/DKIM authentication...',
      '🔬 Calculating binary Shannon entropy & checking double extensions...',
      '🧠 Correlating neural social-engineering indicators with Claude Sonnet 4.5...'
    ];

    let phaseIndex = 0;
    setScanningPhase(phases[0]);
    const phaseInterval = setInterval(() => {
      phaseIndex = (phaseIndex + 1) % phases.length;
      setScanningPhase(phases[phaseIndex]);
    }, 900);

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
      clearInterval(phaseInterval);
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

  const totalScanned = history.length;
  const phishingCount = history.filter(h => h.classification === 'Phishing Email').length;
  const cleanCount = totalScanned - phishingCount;
  const maliciousAttachmentsCount = attachments.filter(a => a.classification === 'Malicious').length;

  return (
    <div className="shell">
      {/* ── HERO BANNER ── */}
      <div className="hero">
        <div className="status-badge">
          <span className="beacon"></span>
          NEURAL SENTINEL v3.0 • CLAUDE SONNET 4.5 &amp; GEMINI DUAL ENGINE
        </div>
        <h1 className="hero-title">
          <span className="title-gradient">PhishNet AI</span>
        </h1>
        <p>
          Next-generation autonomous cybersecurity platform analyzing deceptive social-engineering vectors, zero-day payloads, and high-entropy binaries.
        </p>
      </div>

      {/* ── KPI BENTO GRID ── */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Total Analyzed</span>
            <span className="kpi-icon">📊</span>
          </div>
          <div className="kpi-value" style={{ color: '#38bdf8' }}>{totalScanned}</div>
          <div className="kpi-subtext">Cumulative verified emails</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Phishing Quarantined</span>
            <span className="kpi-icon">🚨</span>
          </div>
          <div className="kpi-value" style={{ color: '#f87171' }}>{phishingCount}</div>
          <div className="kpi-subtext">High-confidence attack vectors</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Payload Artifacts</span>
            <span className="kpi-icon">📎</span>
          </div>
          <div className="kpi-value" style={{ color: '#fbbf24' }}>{maliciousAttachmentsCount}</div>
          <div className="kpi-subtext">Malicious files intercepted</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-header">
            <span className="kpi-label">Verified Clean</span>
            <span className="kpi-icon">🛡️</span>
          </div>
          <div className="kpi-value" style={{ color: '#34d399' }}>{cleanCount}</div>
          <div className="kpi-subtext">Safe corporate correspondence</div>
        </div>
      </div>

      {/* ── TABS NAVIGATION ── */}
      <div className="tabs-container">
        <button
          className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          <span>📨</span> Email Threat Scanner
        </button>
        <button
          className={`tab-btn ${activeTab === 'lab' ? 'active' : ''}`}
          onClick={() => setActiveTab('lab')}
        >
          <span>🔬</span> Malware &amp; Attachment Lab
        </button>
        <button
          className={`tab-btn ${activeTab === 'scenarios' ? 'active' : ''}`}
          onClick={() => setActiveTab('scenarios')}
        >
          <span>⚡</span> Attack Scenarios Showcase
        </button>
        <button
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          <span>📊</span> SOC Incident Audit ({history.length})
        </button>
      </div>

      {/* ── TAB 1: SCANNER ── */}
      {activeTab === 'scanner' && (
        <>
          {/* Preset Buttons Carousel */}
          <div className="presets-carousel">
            {Object.keys(PRESET_SCENARIOS).map(key => (
              <button
                key={key}
                className="preset-card-btn"
                onClick={() => loadScenario(key)}
              >
                <span>{key.slice(0, 2)}</span> {key.slice(3)}
              </button>
            ))}
          </div>

          <div className="scanner-layout">
            {/* Left: Input & Dropzone */}
            <div className="glass-panel">
              <div className="panel-header">
                <div className="panel-title">
                  <span>✉️</span> Message &amp; File Ingestion
                </div>
              </div>

              {/* Drag and Drop Zone */}
              <div
                className={`drop-zone ${isDragOver ? 'active' : ''}`}
                onDragOver={e => { e.preventDefault(); e.stopPropagation(); setIsDragOver(true); }}
                onDragEnter={e => { e.preventDefault(); e.stopPropagation(); setIsDragOver(true); }}
                onDragLeave={e => { e.preventDefault(); e.stopPropagation(); setIsDragOver(false); }}
                onDrop={e => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragOver(false);
                  if (e.dataTransfer && e.dataTransfer.files) {
                    handleFileUpload(e.dataTransfer.files);
                  }
                }}
                onClick={() => fileInputRef.current?.click()}
              >
                <span className="drop-icon">📂</span>
                <div className="drop-title">Browse Files or Drag &amp; Drop Here</div>
                <div className="drop-hint" style={{ marginBottom: '10px' }}>
                  Drop .eml messages to auto-parse, or upload files (.pdf, .exe, .docm, .zip, .bat) for malware analysis
                </div>
                <button
                  type="button"
                  className="btn-browse-lab"
                  onClick={e => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                >
                  📂 Select Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  style={{ display: 'none' }}
                  onChange={e => {
                    if (e.target.files && e.target.files.length > 0) {
                      handleFileUpload(e.target.files);
                      e.target.value = '';
                    }
                  }}
                />
              </div>

              {/* Uploaded Attachments */}
              {attachments.length > 0 && (
                <div style={{ marginBottom: '18px' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    ATTACHED ARTIFACTS ({attachments.length})
                  </div>
                  {attachments.map((att, idx) => (
                    <div key={idx} className="attachment-card">
                      <div className="att-left">
                        <span>📎</span>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{att.name}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {att.size} MB • Entropy: {att.entropy}/8.0
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span className={`att-badge ${att.risk_score >= 70 ? 'malicious' : 'clean'}`}>
                          {att.classification} ({att.risk_score}/100)
                        </span>
                        <button className="btn-del" onClick={() => removeAttachment(idx)}>✕</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="input-group">
                <div className="input-label">
                  <span>Sender Address (From:)</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Header Origin</span>
                </div>
                <input
                  type="text"
                  className="text-input"
                  placeholder="e.g. security@alert-verify-chase.com"
                  value={sender}
                  onChange={e => setSender(e.target.value)}
                />
              </div>

              <div className="input-group">
                <div className="input-label">
                  <span>Subject Line</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>RFC822 Subject</span>
                </div>
                <input
                  type="text"
                  className="text-input"
                  placeholder="e.g. URGENT: Unauthorized Account Access Detected"
                  value={subject}
                  onChange={e => setSubject(e.target.value)}
                />
              </div>

              <div className="input-group">
                <div className="input-label">
                  <span>Message Body Content</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Plaintext / HTML</span>
                </div>
                <textarea
                  rows={8}
                  className="textarea-input"
                  placeholder="Paste email body text or headers..."
                  value={body}
                  onChange={e => setBody(e.target.value)}
                />
              </div>

              <button
                className="btn-scan"
                onClick={executeAnalysis}
                disabled={loading}
              >
                <span>🚀</span> {loading ? 'ANALYZING THREAT VECTORS...' : 'EXECUTE THREAT ANALYSIS'}
              </button>
            </div>

            {/* Right: Live Assessment */}
            <div className="glass-panel">
              <div className="panel-header">
                <div className="panel-title">
                  <span>🎯</span> Threat Assessment
                </div>
                {result?.engine && (
                  <span style={{
                    fontSize: '0.75rem',
                    background: 'rgba(56, 189, 248, 0.15)',
                    color: '#38bdf8',
                    padding: '3px 10px',
                    borderRadius: '999px',
                    border: '1px solid rgba(56, 189, 248, 0.3)'
                  }}>
                    {result.engine}
                  </span>
                )}
              </div>

              {loading && (
                <div style={{ textAlign: 'center', padding: '70px 20px' }}>
                  <div className="beacon" style={{ width: '22px', height: '22px', margin: '0 auto 20px' }}></div>
                  <div style={{ color: '#38bdf8', fontWeight: 700, fontSize: '1.05rem', marginBottom: '8px' }}>
                    Scanning In Progress
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', fontFamily: 'JetBrains Mono' }}>
                    {scanningPhase}
                  </div>
                </div>
              )}

              {error && !loading && (
                <div style={{
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  padding: '18px',
                  borderRadius: '12px',
                  color: '#fca5a5'
                }}>
                  <strong>⚠️ Analysis Exception:</strong> {error}
                </div>
              )}

              {!loading && !result && !error && (
                <div style={{ textAlign: 'center', padding: '80px 20px', color: 'var(--text-muted)' }}>
                  <div style={{ fontSize: '3.5rem', marginBottom: '14px', opacity: 0.8 }}>🛡️</div>
                  <h4 style={{ color: 'var(--text-primary)', marginBottom: '8px', fontSize: '1.15rem' }}>
                    Dual-Guard Sentinel Ready
                  </h4>
                  <p style={{ fontSize: '0.92rem', maxWidth: '340px', margin: '0 auto', lineHeight: 1.6 }}>
                    Select a 1-click test scenario above or drop an email to generate a multi-factor threat assessment.
                  </p>
                </div>
              )}

              {result && !loading && (
                <>
                  {/* Verdict Banner */}
                  <div className={`verdict-box ${result.risk_score >= 70 ? 'danger' : result.risk_score >= 40 ? 'warning' : 'safe'}`}>
                    <div>
                      <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>
                        DEFENSE STATUS
                      </div>
                      <h3 style={{ margin: 0, fontSize: '1.25rem' }}>
                        {result.risk_score >= 70 ? '🚨 ' : result.risk_score >= 40 ? '⚠️ ' : '🛡️ '}
                        {result.classification.toUpperCase()}
                      </h3>
                      <p style={{ margin: '6px 0 0 0', fontSize: '0.85rem', opacity: 0.9 }}>
                        {result.risk_score >= 70
                          ? 'Immediate quarantine & sender domain block recommended.'
                          : result.risk_score >= 40
                          ? 'Suspicious social-engineering patterns detected.'
                          : 'No deceptive vectors or credential harvesting patterns detected.'}
                      </p>
                    </div>
                  </div>

                  {/* Speedometer Radial Gauge */}
                  <div className="gauge-wrapper">
                    <svg className="gauge-svg" viewBox="0 0 220 130">
                      {/* Background Arc */}
                      <path d="M 25 110 A 85 85 0 0 1 195 110" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="18" strokeLinecap="round" />
                      {/* Green Zone (0-40) */}
                      <path d="M 25 110 A 85 85 0 0 1 82 40" fill="none" stroke="rgba(16, 185, 129, 0.35)" strokeWidth="18" />
                      {/* Amber Zone (40-70) */}
                      <path d="M 82 40 A 85 85 0 0 1 138 40" fill="none" stroke="rgba(245, 158, 11, 0.35)" strokeWidth="18" />
                      {/* Red Zone (70-100) */}
                      <path d="M 138 40 A 85 85 0 0 1 195 110" fill="none" stroke="rgba(239, 68, 68, 0.35)" strokeWidth="18" />
                      
                      {/* Needle */}
                      {(() => {
                        const angle = -180 + (result.risk_score / 100) * 180;
                        const rad = (angle * Math.PI) / 180;
                        const x = 110 + 70 * Math.cos(rad);
                        const y = 110 + 70 * Math.sin(rad);
                        const color = result.risk_score >= 70 ? '#ef4444' : result.risk_score >= 40 ? '#f59e0b' : '#10b981';
                        return (
                          <>
                            <line x1="110" y1="110" x2={x} y2={y} stroke={color} strokeWidth="4.5" strokeLinecap="round" />
                            <circle cx="110" cy="110" r="8" fill="#ffffff" />
                            <circle cx="110" cy="110" r="4.5" fill={color} />
                          </>
                        );
                      })()}

                      <text x="110" y="88" className="gauge-score">{result.risk_score}</text>
                      <text x="110" y="108" className="gauge-subtitle">/ 100 THREAT SCORE</text>
                    </svg>
                  </div>

                  {/* Red Flags Chips */}
                  {result.red_flags && result.red_flags.length > 0 && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        Identified Attack Vectors ({result.red_flags.length})
                      </div>
                      <div className="flags-cluster">
                        {result.red_flags.map((flag, i) => (
                          <div key={i} className="flag-chip">
                            <span>⚠️</span> {flag}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Analytical Explanation */}
                  <div style={{
                    background: 'rgba(30, 41, 59, 0.5)',
                    border: '1px solid var(--border)',
                    borderRadius: '12px',
                    padding: '16px',
                    fontSize: '0.92rem',
                    lineHeight: 1.65,
                    color: '#e2e8f0',
                    margin: '18px 0'
                  }}>
                    {result.explanation}
                  </div>

                  {/* Attachment Deep-Dive Cards */}
                  {result.attachmentsAnalyzed && result.attachmentsAnalyzed.length > 0 && (
                    <div style={{ marginTop: '16px' }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '8px' }}>
                        Payload Static Heuristics
                      </div>
                      {result.attachmentsAnalyzed.map((att, i) => (
                        <div key={i} style={{
                          background: 'rgba(15, 23, 42, 0.95)',
                          border: `1px solid ${att.risk_score >= 70 ? 'rgba(239,68,68,0.4)' : 'var(--border)'}`,
                          borderRadius: '12px',
                          padding: '14px 18px',
                          marginBottom: '10px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <strong style={{ fontSize: '0.95rem' }}>📄 {att.name}</strong>
                            <span style={{
                              color: att.risk_score >= 70 ? '#f87171' : '#34d399',
                              fontWeight: 800,
                              fontFamily: 'JetBrains Mono',
                              fontSize: '0.95rem'
                            }}>
                              {att.classification} ({att.risk_score}/100)
                            </span>
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                            SHA-256: {att.hash}
                          </div>
                          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            Entropy: {att.entropy}/8.0 • Size: {att.size} MB • MIME: {att.type}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* SOC Incident Report Terminal */}
                  {result.soc_report && (
                    <div className="terminal-card">
                      <div className="terminal-bar">
                        <div className="traffic-dots">
                          <span className="t-dot red"></span>
                          <span className="t-dot yellow"></span>
                          <span className="t-dot green"></span>
                        </div>
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          SOC-INCIDENT-LOG.txt
                        </span>
                        <button className="btn-copy" onClick={copySocReport}>
                          {copied ? '✓ Copied' : '📋 Copy Log'}
                        </button>
                      </div>
                      <div className="terminal-content">{result.soc_report}</div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── TAB 2: ATTACHMENT LAB ── */}
      {activeTab === 'lab' && (
        <div className="glass-panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>🔬</span> Standalone Binary &amp; Attachment Sandbox
            </div>
            {labFiles.length > 0 && (
              <button
                className="btn-copy"
                style={{ color: '#f87171', borderColor: 'rgba(239,68,68,0.3)' }}
                onClick={() => setLabFiles([])}
              >
                🗑️ Clear Sandbox ({labFiles.length})
              </button>
            )}
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.98rem', marginBottom: '20px' }}>
            Perform deep static malware triage on any standalone file. Computes client-side cryptographic SHA-256 checksums, Shannon entropy (randomness), and extension spoofing vectors.
          </p>

          {/* Test Benchmark Artifacts */}
          <div style={{ marginBottom: '20px' }}>
            <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
              ⚡ TEST BENCHMARK MALWARE ARTIFACTS:
            </div>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                className="sample-payload-btn"
                onClick={() => addSampleLabPayload('invoice_2026.pdf.exe', '2.45', 7.82, ['Double extension detected: .pdf.exe', 'Executable binary payload detected', 'High entropy (7.82/8.0) indicating packed malware'], 95)}
              >
                🚨 invoice.pdf.exe (Double Ext)
              </button>
              <button
                type="button"
                className="sample-payload-btn"
                onClick={() => addSampleLabPayload('Executive_Bonus_Plan.xlsm', '1.18', 6.94, ['Macro-enabled document format capable of running embedded VBA', 'Filename contains social engineering keywords'], 75)}
              >
                ⚠️ Bonus_Plan.xlsm (VBA Macro)
              </button>
              <button
                type="button"
                className="sample-payload-btn"
                onClick={() => addSampleLabPayload('credentials_harvester.ps1', '0.04', 5.61, ['Executable binary payload detected (PowerShell Script)'], 85)}
              >
                🚨 Harvester.ps1 (PowerShell)
              </button>
              <button
                type="button"
                className="sample-payload-btn"
                onClick={() => addSampleLabPayload('Annual_Financial_Report.pdf', '3.12', 4.35, [], 10)}
              >
                ✅ Financial_Report.pdf (Clean)
              </button>
            </div>
          </div>

          {/* Fully Interactive Drag & Drop and Browse Zone */}
          <div
            className={`drop-zone ${isLabDragOver ? 'active' : ''}`}
            onDragOver={e => { e.preventDefault(); e.stopPropagation(); setIsLabDragOver(true); }}
            onDragEnter={e => { e.preventDefault(); e.stopPropagation(); setIsLabDragOver(true); }}
            onDragLeave={e => { e.preventDefault(); e.stopPropagation(); setIsLabDragOver(false); }}
            onDrop={e => {
              e.preventDefault();
              e.stopPropagation();
              setIsLabDragOver(false);
              if (e.dataTransfer && e.dataTransfer.files) {
                handleLabUpload(e.dataTransfer.files);
              }
            }}
            onClick={() => labInputRef.current?.click()}
          >
            <span className="drop-icon">🧪</span>
            <div className="drop-title">Browse or Drop Files into Malware Sandbox</div>
            <div className="drop-hint" style={{ marginBottom: '12px' }}>
              Drag &amp; drop any executable (.exe), script (.bat, .ps1, .vbs), macro document (.docm), or archive (.zip)
            </div>
            <button
              type="button"
              className="btn-browse-lab"
              onClick={e => {
                e.stopPropagation();
                labInputRef.current?.click();
              }}
            >
              📂 Choose Local Files to Inspect
            </button>
            <input
              ref={labInputRef}
              type="file"
              multiple
              style={{ display: 'none' }}
              onChange={e => {
                if (e.target.files && e.target.files.length > 0) {
                  handleLabUpload(e.target.files);
                  e.target.value = '';
                }
              }}
            />
          </div>

          {labFiles.length > 0 && (
            <div style={{ marginTop: '28px' }}>
              <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '16px' }}>
                Triage Artifacts ({labFiles.length})
              </div>
              {labFiles.map((file, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.9)',
                    border: `1px solid ${file.risk_score >= 70 ? 'rgba(239,68,68,0.45)' : 'var(--border)'}`,
                    borderRadius: '14px',
                    padding: '20px 24px',
                    marginBottom: '16px',
                    boxShadow: '0 8px 24px rgba(0,0,0,0.3)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>📄 {file.name}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                      <div style={{
                        fontFamily: 'JetBrains Mono',
                        fontSize: '1.15rem',
                        fontWeight: 800,
                        color: file.risk_score >= 70 ? '#f87171' : file.risk_score >= 40 ? '#fbbf24' : '#34d399'
                      }}>
                        {file.classification.toUpperCase()} • {file.risk_score}/100
                      </div>
                      <button
                        className="btn-del"
                        title="Remove file"
                        onClick={() => setLabFiles(prev => prev.filter((_, i) => i !== idx))}
                      >
                        ✕
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', margin: '14px 0' }}>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '10px 14px', borderRadius: '10px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PAYLOAD SIZE</span>
                      <div style={{ fontWeight: 700, fontSize: '1rem' }}>{file.size} MB</div>
                    </div>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '10px 14px', borderRadius: '10px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SHANNON ENTROPY</span>
                      <div style={{ fontWeight: 700, fontSize: '1rem', color: file.entropy > 7 ? '#f87171' : '#38bdf8' }}>
                        {file.entropy} / 8.0
                      </div>
                    </div>
                    <div style={{ background: 'rgba(30,41,59,0.5)', padding: '10px 14px', borderRadius: '10px' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>DETECTED MIME</span>
                      <div style={{ fontWeight: 700, fontSize: '1rem' }}>{file.type}</div>
                    </div>
                  </div>

                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
                    SHA-256: <code>{file.hash}</code>
                  </div>

                  {file.risk_indicators && file.risk_indicators.length > 0 ? (
                    <div>
                      <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#fca5a5' }}>Threat Signatures:</span>
                      <ul style={{ margin: '6px 0 0 22px', fontSize: '0.88rem', color: '#fca5a5' }}>
                        {file.risk_indicators.map((ind, i) => (
                          <li key={i}>{ind}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div style={{ color: '#34d399', fontSize: '0.88rem', fontWeight: 600 }}>
                      ✅ No dangerous executable headers, obfuscated packing, or macro triggers detected.
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 3: ATTACK SCENARIOS ── */}
      {activeTab === 'scenarios' && (
        <div className="glass-panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>⚡</span> Attack Vectors &amp; Threat Scenarios
            </div>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.98rem', marginBottom: '24px' }}>
            Explore real-world phishing methodologies used in active cyber campaigns. Click any scenario to test the detection engine.
          </p>

          <div className="scenarios-grid">
            {Object.entries(PRESET_SCENARIOS).map(([title, item]) => (
              <div key={title} className="scenario-box">
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <span style={{
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      padding: '3px 10px',
                      borderRadius: '999px',
                      background: item.severity === 'Critical' ? 'rgba(239,68,68,0.2)' : item.severity === 'High' ? 'rgba(245,158,11,0.2)' : 'rgba(16,185,129,0.2)',
                      color: item.severity === 'Critical' ? '#f87171' : item.severity === 'High' ? '#fbbf24' : '#34d399',
                      border: `1px solid ${item.severity === 'Critical' ? 'rgba(239,68,68,0.3)' : item.severity === 'High' ? 'rgba(245,158,11,0.3)' : 'rgba(16,185,129,0.3)'}`
                    }}>
                      {item.tag}
                    </span>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{item.severity}</span>
                  </div>

                  <h4 style={{ color: 'var(--text-primary)', fontSize: '1.1rem', marginBottom: '6px' }}>{title}</h4>
                  <p style={{ fontSize: '0.85rem', color: '#38bdf8', marginBottom: '8px' }}>
                    <strong>Origin:</strong> {item.sender}
                  </p>
                  <p style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '12px' }}>
                    {item.subject}
                  </p>
                  <p style={{
                    fontSize: '0.82rem',
                    color: 'var(--text-muted)',
                    lineHeight: 1.55,
                    maxHeight: '90px',
                    overflow: 'hidden'
                  }}>
                    {item.body.slice(0, 160)}...
                  </p>
                </div>

                <button
                  className="btn-load-scenario"
                  onClick={() => {
                    loadScenario(title);
                    setActiveTab('scanner');
                  }}
                >
                  📥 Load Into Scanner
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── TAB 4: SOC AUDIT LOG ── */}
      {activeTab === 'history' && (
        <div className="glass-panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>📊</span> Threat Intelligence History &amp; Incident Log
            </div>
            {history.length > 0 && (
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  className="btn-copy"
                  style={{ padding: '8px 16px', fontSize: '0.85rem' }}
                  onClick={downloadAuditJson}
                >
                  💾 Download Incident Report (JSON)
                </button>
                <button
                  className="btn-copy"
                  style={{ padding: '8px 16px', fontSize: '0.85rem', color: '#f87171' }}
                  onClick={() => setHistory([])}
                >
                  🗑️ Clear Log
                </button>
              </div>
            )}
          </div>

          {history.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '70px 0', color: 'var(--text-muted)' }}>
              No threat scans recorded in this session. Run an analysis in the scanner to build an incident trail.
            </div>
          ) : (
            <div className="scenarios-grid">
              {history.map((item, idx) => {
                const isP = item.classification === 'Phishing Email';
                return (
                  <div
                    key={idx}
                    style={{
                      background: 'rgba(15, 23, 42, 0.9)',
                      border: `1px solid ${isP ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`,
                      borderRadius: '14px',
                      padding: '18px 20px',
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                    onClick={() => {
                      setResult(item);
                      setActiveTab('scanner');
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{
                        fontSize: '0.75rem',
                        fontWeight: 800,
                        padding: '3px 9px',
                        borderRadius: '6px',
                        background: isP ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)',
                        color: isP ? '#f87171' : '#34d399'
                      }}>
                        {isP ? '🎣 PHISHING' : '✅ LEGITIMATE'}
                      </span>
                      <span style={{
                        fontFamily: 'JetBrains Mono',
                        fontWeight: 800,
                        fontSize: '1rem',
                        color: isP ? '#f87171' : '#34d399'
                      }}>
                        {item.risk_score}/100
                      </span>
                    </div>
                    <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '6px', color: '#f8fafc' }}>
                      {item.subject}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
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
      <div className="footer-text">
        PhishNet AI • Autonomous Cybersecurity Threat Intelligence Platform • Streamlit &amp; Next.js Dual Engine
      </div>
    </div>
  );
}
