import { GoogleGenerativeAI } from '@google/generative-ai';

// Intelligent Heuristic Phishing & Malware Analyzer Fallback
function runHeuristicAnalysis(subject, body, sender, attachments = []) {
  const subjectLower = (subject || '').toLowerCase();
  const bodyLower = (body || '').toLowerCase();
  const senderLower = (sender || '').toLowerCase();

  const redFlags = [];
  let score = 5;

  // 1. Urgency & Coercion
  const urgencyTerms = [
    'urgent', 'immediately', 'within 24 hours', 'account closed', 'suspended',
    'final warning', 'action required', 'compromised', 'unauthorized access',
    'expires in', 'restricted', 'permanently deleted', 'forfeited', 'terminate'
  ];
  const foundUrgency = urgencyTerms.find(term => bodyLower.includes(term) || subjectLower.includes(term));
  if (foundUrgency) {
    redFlags.push(`High urgency & intimidation tactics detected: "${foundUrgency}"`);
    score += 25;
  }

  // 2. Sensitive Information Harvesting
  const credentialTerms = [
    'social security', 'ssn', 'password', 'pin', 'credit card', 'debit card',
    'cvv', 'banking password', 'routing number', 'verify identity', 'confirm your account'
  ];
  const foundCreds = credentialTerms.find(term => bodyLower.includes(term));
  if (foundCreds) {
    redFlags.push(`Direct solicitation of sensitive credentials or financial data: "${foundCreds}"`);
    score += 35;
  }

  // 3. Suspicious Links & Deceptive TLDs
  const urlRegex = /https?:\/\/[^\s<>"]+|www\.[^\s<>"]+/gi;
  const urls = body.match(urlRegex) || [];
  const suspiciousTlds = ['.xyz', '.top', '.tk', '.info', '.net', '.online', '.work', '.click', '.pw'];
  let foundSuspiciousUrl = false;
  for (const url of urls) {
    const urlLower = url.toLowerCase();
    if (suspiciousTlds.some(tld => urlLower.includes(tld))) {
      redFlags.push(`Suspicious top-level domain (TLD) or destination link: ${url.slice(0, 45)}...`);
      score += 20;
      foundSuspiciousUrl = true;
      break;
    } else if (urlLower.includes('login') || urlLower.includes('verify') || urlLower.includes('auth')) {
      if (!foundSuspiciousUrl) {
        redFlags.push(`Deceptive authentication or credential harvesting URL: ${url.slice(0, 45)}...`);
        score += 15;
        foundSuspiciousUrl = true;
      }
    }
  }

  // 4. Brand Impersonation Check
  const brands = ['chase', 'paypal', 'microsoft', 'google', 'apple', 'bank of america', 'wells fargo', 'fedex', 'dhl', 'amazon', 'netflix'];
  for (const brand of brands) {
    if (subjectLower.includes(brand) || bodyLower.includes(brand)) {
      if (senderLower.includes('@')) {
        const domain = senderLower.split('@')[1];
        if (!domain.includes(brand.replace(/\s+/g, ''))) {
          redFlags.push(`Brand impersonation detected: claims to be "${brand.toUpperCase()}" but sender domain is "${domain}"`);
          score += 30;
          break;
        }
      }
    }
  }

  // 5. Financial Lures / BEC / Wire Transfer
  const financialTerms = ['wire transfer', 'lottery', 'won $', 'claim prize', 'bitcoin', 'btc', 'airdrop', 'direct deposit', 'unpaid fee', 'customs fee'];
  const foundFinance = financialTerms.find(term => bodyLower.includes(term) || subjectLower.includes(term));
  if (foundFinance) {
    redFlags.push(`Unsolicited financial lure or wire payment coercion: "${foundFinance}"`);
    score += 20;
  }

  // 6. Attachment Risk Correlation
  if (attachments && attachments.length > 0) {
    let maxAttScore = 0;
    for (const att of attachments) {
      if (att.risk_score && att.risk_score > maxAttScore) {
        maxAttScore = att.risk_score;
      }
      if (att.risk_indicators && att.risk_indicators.length > 0) {
        att.risk_indicators.forEach(ind => {
          redFlags.push(`Attachment "${att.name}": ${ind}`);
        });
      }
    }
    if (maxAttScore >= 70) {
      score = Math.max(score, Math.round(score * 0.4 + maxAttScore * 0.6));
    }
  }

  score = Math.min(Math.max(score, 5), 98);

  let classification = 'Legitimate Email';
  if (score >= 65) {
    classification = 'Phishing Email';
  } else if (score >= 35) {
    classification = 'Suspicious Email';
  }

  const explanation = (
    `Heuristic pattern correlation calculated a threat index of ${score}/100. ` +
    (score >= 50
      ? 'Multiple high-confidence phishing indicators were identified, including deceptive links, coercive urgency, or credential harvesting.'
      : 'The message exhibits standard formatting with no aggressive phishing signatures detected.')
  );

  const socReport = `[SOC INCIDENT INVESTIGATION REPORT]
TIMESTAMP: ${new Date().toISOString()}
TARGET SENDER: ${sender || 'Unknown'}
SUBJECT: ${subject || 'No Subject'}
THREAT VERDICT: ${classification.toUpperCase()}
RISK SCORE: ${score}/100
DETECTED RED FLAGS: ${redFlags.length}
ATTACHMENTS ANALYZED: ${attachments ? attachments.length : 0}

KEY FINDINGS:
${redFlags.length ? redFlags.map(f => `- ${f}`).join('\n') : '- No critical threat indicators identified.'}

RECOMMENDED MITIGATION ACTIONS:
1. ${score >= 50 ? 'Immediate domain and IP quarantine on corporate mail gateway.' : 'No quarantine required.'}
2. ${score >= 50 ? 'Force password reset if target user clicked embedded hyperlinks.' : 'Log message for security baseline.'}
3. ${score >= 50 ? 'Submit malicious indicators to threat intelligence feeds.' : 'Allow normal delivery.'}`;

  return {
    classification,
    risk_score: score,
    red_flags: redFlags.length ? redFlags : ['No anomalous phishing flags detected'],
    explanation,
    soc_report: socReport,
    engine: 'Heuristic Defense Engine'
  };
}

export async function POST(request) {
  try {
    const { subject, body, sender, attachments = [] } = await request.json();

    if (!subject && !body && (!attachments || attachments.length === 0)) {
      return Response.json({ error: 'Please provide an email subject, body, or attachment to analyze.' }, { status: 400 });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    const emergentKey = process.env.EMERGENT_LLM_KEY;

    // Build attachment context string if attachments are present
    let attachmentContext = '';
    if (attachments && attachments.length > 0) {
      attachmentContext = `\nATTACHMENTS (${attachments.length}):\n` + attachments.map(att => 
        `- Filename: ${att.name}, Size: ${att.size} bytes, MIME: ${att.type || 'unknown'}, Entropy: ${att.entropy || 'N/A'}, Hash: ${att.hash || 'N/A'}, Risk Score: ${att.risk_score || 0}/100`
      ).join('\n');
    }

    // If no API keys are provided in Vercel environment variables, use our smart heuristic engine
    if (!apiKey && !emergentKey) {
      const fallbackResult = runHeuristicAnalysis(subject, body, sender, attachments);
      return Response.json(fallbackResult);
    }

    const prompt = `You are an expert cybersecurity analyst specializing in email phishing detection and malware payload triage.
Analyze the following email and attachments and provide a comprehensive security assessment.

EMAIL SENDER (FROM): ${sender || 'Unknown'}
EMAIL SUBJECT: ${subject || 'No Subject'}

EMAIL BODY:
${body || 'No body provided'}
${attachmentContext}

Provide your analysis in the following JSON format ONLY (no markdown code fences, no extra text):
{
  "classification": "Phishing Email" or "Legitimate Email",
  "risk_score": <number between 0-100>,
  "red_flags": ["flag1", "flag2", ...],
  "explanation": "Detailed explanation of why this is phishing or legitimate",
  "soc_report": "Professional SOC-style analysis report with threat indicators and recommendations"
}

Consider these indicators:
- Urgency and pressure tactics
- Requests for sensitive information (passwords, SSN, credit cards)
- Suspicious links, mismatched sender information, or impersonation
- Malicious attachment indicators (executable extensions, macro scripts, high entropy)
- Poor grammar or spelling, threats or fear tactics

Return ONLY the JSON object, nothing else.`;

    let textResponse = '';

    if (emergentKey) {
      // Use Emergent LLM (Claude Sonnet)
      try {
        const response = await fetch('https://llm-api.emergent-integrations.com/v1/chat', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${emergentKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            session_id: `phishing_analysis_${Date.now()}`,
            provider: 'anthropic',
            model: 'claude-sonnet-4-5-20250929',
            system_message: 'You are an expert cybersecurity analyst. Provide accurate, detailed phishing detection analysis.',
            messages: [
              {
                role: 'user',
                content: prompt
              }
            ]
          })
        });

        if (response.ok) {
          const data = await response.json();
          textResponse = data.response.trim();
        } else {
          console.warn('Emergent LLM failed, falling back to heuristic engine');
          return Response.json(runHeuristicAnalysis(subject, body, sender, attachments));
        }
      } catch (err) {
        console.warn('Emergent LLM error, falling back to heuristic:', err);
        return Response.json(runHeuristicAnalysis(subject, body, sender, attachments));
      }
    } else if (apiKey) {
      // Use Google Gemini API
      try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        const result = await model.generateContent(prompt);
        textResponse = result.response.text().trim();
      } catch (err) {
        console.warn('Gemini API error, falling back to heuristic:', err);
        return Response.json(runHeuristicAnalysis(subject, body, sender, attachments));
      }
    }

    let parsed;
    try {
      let clean = textResponse;
      if (clean.startsWith('```')) {
        clean = clean.replace(/```json\n?/, '').replace(/```\n?$/, '').trim();
      }
      parsed = JSON.parse(clean);
      parsed.engine = emergentKey ? 'Claude Sonnet 4.5' : 'Gemini 1.5 Flash';
    } catch {
      parsed = runHeuristicAnalysis(subject, body, sender, attachments);
    }

    return Response.json(parsed);
  } catch (error) {
    console.error('Analysis error:', error);
    return Response.json({ error: error.message || 'Analysis failed' }, { status: 500 });
  }
}
