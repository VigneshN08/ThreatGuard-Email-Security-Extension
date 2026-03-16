// The backend API endpoint.
// !! IMPORTANT: Previously used for remote analysis. We now run
// a local rule-based engine for real-time detection inside Gmail.
const API_URL = 'https://api.your-threatguard-backend.com/analyze';

// Listen for messages from the content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    try {
      const threat = calculateThreat(message.data || {});
      const row = buildThreatGuardRow(message.data || {}, threat);

      // Persist this detection so the dashboard can consume it
      chrome.storage.local.get({ liveDetections: [] }, (data) => {
        const existing = Array.isArray(data.liveDetections) ? data.liveDetections : [];
        const updated = [row, ...existing].slice(0, 500); // keep last N
        chrome.storage.local.set({ liveDetections: updated }, () => {
          // Notify any open dashboard tabs
          chrome.runtime.sendMessage({ type: 'LIVE_DETECTION_ADDED', row });
        });
      });

      // Map rule-based result into the structure expected by content.js
      const level = threat.level || 'Low';
      let status_id = 'SAFE';
      if (level === 'High') status_id = 'DANGEROUS';
      else if (level === 'Medium') status_id = 'WARNING';

      const summary = `Phishing risk: ${level} (${threat.score})`;
      const findings = (threat.flags || []).map(flag => ({
        type: 'Rule',
        severity: level,
        description: flag,
        concern: ''
      }));

      sendResponse({ status_id, summary, findings, level, score: threat.score });
    } catch (error) {
      console.error('ThreatGuard Error (local analysis):', error);
      sendResponse({ status_id: 'ERROR', summary: 'Local analysis failed.', findings: [] });
    }

    // Return true to indicate you will send an asynchronous response
    return true;
  }
});

/**
 * Rule-Based Scoring Engine
 * This function calculates a "threat score" and assigns a level
 * and primary threat category.
 * @param {object} emailData - { sender, replyTo, subject, body, bodyHtml, attachments }
 * @returns {object} - { level: 'Low'|'Medium'|'High', score: number, flags: string[], category?: string, recommended_action?: string }
 */
function calculateThreat(emailData) {
  let score = 0;
  const flags = [];

  const sender = String(emailData.sender || '');
  const replyTo = String(emailData.replyTo || sender);
  const subject = String(emailData.subject || '');
  const body = String(emailData.body || '');
  const bodyHtml = String(emailData.bodyHtml || '');
  const attachments = Array.isArray(emailData.attachments) ? emailData.attachments : [];

  // Track category contributions so we can pick a primary threat type
  const categoryScores = {};
  const categoryInfo = {};

  function bumpCategory(key, pts, description, action) {
    categoryScores[key] = (categoryScores[key] || 0) + pts;
    if (!categoryInfo[key]) {
      categoryInfo[key] = { description, action };
    }
  }

  // --- Rule 1: Sender Mismatch / Domain Spoofing (High-Risk) ---
  try {
    const senderDomain = sender.split('@')[1]?.replace('>', '');
    const replyToDomain = replyTo.split('@')[1]?.replace('>', '');
    if (senderDomain && replyToDomain && senderDomain !== replyToDomain) {
      score += 30;
      flags.push(`Sender Mismatch: 'From' (${senderDomain}) does not match 'Reply-To' (${replyToDomain}).`);
      bumpCategory('Domain Spoofing', 25, 'Sender domain does not match reply-to domain (possible spoofing).', 'Block sender and mark as phishing.');
    }
  } catch (e) {
    // Ignore parsing errors for unusual sender formats
  }

  // Additional domain spoofing heuristic: suspicious brand-like domains
  try {
    const senderDomain = sender.split('@')[1]?.replace('>', '') || '';
    const lowered = senderDomain.toLowerCase();
    const brandHints = ['microsoft', 'paypal', 'google', 'apple', 'bank', 'amazon'];
    brandHints.forEach(brand => {
      if (lowered.includes(brand) && !lowered.endsWith(brand + '.com') && lowered !== brand + '.com') {
        score += 15;
        flags.push(`Suspicious Sender Domain: ${senderDomain} imitates brand "${brand}".`);
        bumpCategory('Domain Spoofing', 15, 'Sender domain imitates a well-known brand.', 'Block sender and mark as phishing.');
      }
    });
  } catch (e) {
    // best-effort only
  }

  // --- Rule 2: Urgency Keywords (Medium-Risk) ---
  const urgencyWords = [
    'action required', 'urgent', 'verify your account', 'account suspended',
    'password expiry', 'security alert', 'immediate response'
  ];
  const subjectLower = subject.toLowerCase();
  for (const word of urgencyWords) {
    if (subjectLower.includes(word)) {
      score += 15;
      flags.push(`Urgent Language: Subject contains "${word}".`);
      bumpCategory('Urgent Account Verification', 10, 'Email attempts to create urgency around account access.', 'Warn user and treat as potential phishing.');
      break;
    }
  }

  // --- Rule 3: Generic Greeting (Low-Risk) ---
  const bodyLower = body.toLowerCase();
  const genericGreetings = ['dear customer', 'dear user', 'valued member', 'hi user'];
  for (const greeting of genericGreetings) {
    if (bodyLower.startsWith(greeting)) {
      score += 10;
      flags.push(`Generic Greeting: Email starts with "${greeting}".`);
      break;
    }
  }

  // --- Rule 4: Link contains IP Address (High-Risk) ---
  const ipLinkRegex = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g;
  if (ipLinkRegex.test(body)) {
    score += 25;
    flags.push('High-Risk Link: A link in the email body points directly to an IP address.');
    bumpCategory('Malicious Link', 20, 'Email contains links directly to IP addresses.', 'Quarantine email and warn user.');
  }

  // --- Rule 5: Insecure Links (Medium-Risk) ---
  const insecureLinkRegex = /http:\/\//g;
  // Treat any http:// link as a signal, even if https:// also appears (Gmail often rewrites links)
  if (insecureLinkRegex.test(body)) {
    score += 15;
    flags.push('Insecure Link: Email contains `http://` links, which are not encrypted.');
    bumpCategory('Malicious Link', 15, 'Email contains unencrypted (http) links.', 'Quarantine email and warn user.');
  }

  // --- Rule 6: URL Shorteners (Low-Risk) ---
  const shorteners = ['bit.ly', 't.co', 'tinyurl.com'];
  for (const shortener of shorteners) {
    if (body.includes(shortener)) {
      score += 20; // slightly higher weight so shorteners contribute more to risk
      flags.push(`Link Obfuscation: Contains a URL shortener (${shortener}).`);
      bumpCategory('Malicious Link', 15, 'Email uses URL shorteners which can hide malicious destinations.', 'Quarantine email and alert user.');
      break;
    }
  }

  // --- Rule 7: Credential Harvesting / Fake Login Page (Medium/High) ---
  try {
    const urlMatch = body.match(/https?:\/\/\S+/);
    if (urlMatch) {
      let host = '';
      try {
        const u = new URL(urlMatch[0]);
        host = u.hostname.toLowerCase();
      } catch (e) {
        // ignore URL parsing errors
      }

      const loginHints = ['login', 'sign in', 'signin', 'verify your account', 'reset your password', 'confirm your account'];
      const brandWords = ['bank', 'paypal', 'microsoft', 'google', 'apple', 'amazon'];
      const comboText = (subject + ' ' + body).toLowerCase();

      const hasLoginHint = loginHints.some(h => comboText.includes(h));
      const hasBrandWord = brandWords.some(b => comboText.includes(b) || host.includes(b));
      if (hasLoginHint && (hasBrandWord || host.includes('secure') || host.includes('myaccount'))) {
        score += 25;
        flags.push('Credential Harvesting: Link appears to lead to a fake login or account verification page.');
        bumpCategory('Credential Harvesting', 30, 'Email directs user to a fake login or account verification page.', 'Warn user and blacklist the destination domain.');
      }
    }
  } catch (e) {
    // best-effort only
  }

  // --- Rule 8: Malware Delivery via Attachment (High) ---
  if (attachments.length) {
    const riskyExts = ['.exe','.scr','.js','.vbs','.bat','.cmd','.msi','.iso','.zip','.rar','.docm','.xlsm','.pptm'];
    attachments.forEach(name => {
      const lower = String(name).toLowerCase();
      const hit = riskyExts.find(ext => lower.endsWith(ext));
      if (hit) {
        score += 30;
        flags.push(`Suspicious Attachment: ${name} (${hit}) may contain malware.`);
        bumpCategory('Malware Attachment', 35, 'Email contains a potentially malicious attachment.', 'Block attachment and run antivirus scan.');
      }
    });
  }

  // --- Rule 9: Fake Job Offer / Recruitment Scam (Medium/High) ---
  const jobPhrases = ['remote job','six figure','salary','per year','apply now','we found your profile','hiring urgently','work from home'];
  const hasJobSign = jobPhrases.some(p => bodyLower.includes(p) || subjectLower.includes(p));
  if (hasJobSign) {
    score += 20;
    flags.push('Fraudulent Offer: Email resembles a fake job or recruitment offer.');
    bumpCategory('Fake Job Offer', 20, 'Email resembles a fraudulent job offer or recruitment scam.', 'Report and block sender.');
  }

  // --- Rule 10: Business Email Compromise (BEC) patterns (High) ---
  const becPhrases = ['wire transfer','urgent payment','bank details','swift code','gift cards','itunes cards','amazon gift cards'];
  const hasBecPhrase = becPhrases.some(p => bodyLower.includes(p) || subjectLower.includes(p));
  if (hasBecPhrase) {
    score += 30;
    flags.push('BEC Pattern: Email requests urgent payment, wire transfer, or gift cards.');
    bumpCategory('Business Email Compromise', 40, 'Email uses BEC-style language about payments or transfers.', 'Verify sender identity and escalate to security team.');
  }

  // --- Rule 11: Tracking Pixel / Privacy Tracking (Low) ---
  if (bodyHtml) {
    const html = bodyHtml.toLowerCase();
    const tinyImgRegex = /<img[^>]+(width\s*=\s*"?1"?[^>]*height\s*=\s*"?1"?|height\s*=\s*"?1"?[^>]*width\s*=\s*"?1"?)/;
    if (tinyImgRegex.test(html) || html.includes('tracking') && html.includes('<img')) {
      score += 5;
      flags.push('Tracking Pixel: Email embeds tiny images likely used for tracking opens.');
      bumpCategory('Tracking / Privacy', 5, 'Email embeds tracking pixels to monitor user behavior.', 'Block remote images and mark as marketing/spam.');
    }
  }

  let level = 'Low';
  if (score >= 50) level = 'High';
  else if (score >= 20) level = 'Medium';

  // Pick primary category by highest category score, if any
  let primaryCategory = undefined;
  let recommendedAction = undefined;
  let maxCatScore = 0;
  Object.keys(categoryScores).forEach(key => {
    if (categoryScores[key] > maxCatScore) {
      maxCatScore = categoryScores[key];
      primaryCategory = key;
      recommendedAction = categoryInfo[key]?.action;
    }
  });

  // Category-specific overrides: Malware Attachment is always at least High
  if (categoryScores['Malware Attachment'] && level !== 'High') {
    level = 'High';
    if (score < 50) score = 50;
  }

  return { level, score, flags, category: primaryCategory, recommended_action: recommendedAction };
}

/**
 * Build a ThreatGuard-compatible row so the dashboard can
 * treat live Gmail detections just like Dataset.csv entries.
 */
function buildThreatGuardRow(emailData, result) {
  const now = new Date().toISOString();
  const body = String(emailData.body || '');

  // Extract first URL (if any)
  const urlMatch = body.match(/https?:\/\/\S+/);
  const url = urlMatch ? urlMatch[0] : '';
  const urlLen = url.length;

  const isHttps = url.startsWith('https://') ? 1 : url.startsWith('http://') ? 0 : '';
  const tldMatch = url.match(/\.([a-zA-Z0-9\-]{2,})[\/\s]?/);
  const tld = tldMatch ? tldMatch[1].toLowerCase() : '';

  let label = 0;
  let status_id = 'SAFE';
  let severity = 'Low';

  if (result.level === 'High') {
    label = 1; status_id = 'DANGEROUS'; severity = 'Critical';
  } else if (result.level === 'Medium') {
    label = 1; status_id = 'WARNING'; severity = 'Medium';
  }

  const type = result.category
    ? result.category
    : label === 1
      ? 'Gmail Live Phishing'
      : 'Gmail Live Safe';

  return {
    __id: `live-${Date.now()}`,
    received_at: now,
    sender: String(emailData.sender || ''),
    subject: String(emailData.subject || ''),
    link: url,
    url_len: String(urlLen || ''),
    is_https: String(isHttps),
    tld,
    label: String(label),
    status_id,
    severity,
    type,
    threat_category: result.category || '',
    recommended_action: result.recommended_action || '',
    risk_score: String(result.score || '')
  };
}