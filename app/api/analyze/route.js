import { GoogleGenerativeAI } from '@google/generative-ai';

export async function POST(request) {
  try {
    const { subject, body, sender } = await request.json();

    if (!subject && !body) {
      return Response.json({ error: 'Email subject or body is required' }, { status: 400 });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    const emergentKey = process.env.EMERGENT_LLM_KEY;

    if (!apiKey && !emergentKey) {
      return Response.json({ error: 'AI API Key not configured. Please add GEMINI_API_KEY or EMERGENT_LLM_KEY in Vercel environment variables.' }, { status: 500 });
    }

    const prompt = `You are an expert cybersecurity analyst specializing in phishing email detection. Analyze the following email and provide a comprehensive security assessment.

EMAIL SENDER (FROM): ${sender || 'Unknown'}
EMAIL SUBJECT: ${subject || 'No Subject'}

EMAIL BODY:
${body || 'No body provided'}

Provide your analysis in the following JSON format ONLY (no markdown, no extra text):
{
  "classification": "Phishing Email" or "Legitimate Email",
  "risk_score": <number between 0-100>,
  "red_flags": ["flag1", "flag2"],
  "explanation": "Detailed explanation of why this is phishing or legitimate",
  "soc_report": "Professional SOC-style analysis report with threat indicators and recommendations"
}

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

Return ONLY the JSON object, nothing else.`;

    let textResponse = '';

    if (emergentKey) {
      // Use Emergent LLM (Claude Sonnet) via its proxy
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

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Emergent LLM API failed: ${response.status} ${errText}`);
      }

      const data = await response.json();
      textResponse = data.response.trim();
    } else {
      // Use Google Gemini API
      const genAI = new GoogleGenerativeAI(apiKey);
      const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const result = await model.generateContent(prompt);
      textResponse = result.response.text().trim();
    }

    let parsed;
    try {
      // Strip markdown code fences if present
      let clean = textResponse;
      if (clean.startsWith('```')) {
        clean = clean.replace(/```json\n?/, '').replace(/```\n?$/, '').trim();
      }
      parsed = JSON.parse(clean);
    } catch {
      parsed = {
        classification: 'Analysis Error',
        risk_score: 50,
        red_flags: ['Could not parse AI response'],
        explanation: textResponse,
        soc_report: 'Error generating structured report.',
      };
    }

    return Response.json(parsed);
  } catch (error) {
    console.error('Analysis error:', error);
    return Response.json({ error: error.message || 'Analysis failed' }, { status: 500 });
  }
}

