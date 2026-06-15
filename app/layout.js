import './globals.css'

export const metadata = {
  title: 'PhishNet AI - Phishing Email Detector',
  description: 'AI-powered phishing email detection using Google Gemini. Analyze emails for phishing attempts instantly.',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>{children}</body>
    </html>
  )
}
