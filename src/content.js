// A simple flag to prevent the script from running multiple times
if (!window.threatGuardInjected) {
  window.threatGuardInjected = true;

  console.log('ThreatGuard: Content script loaded into Gmail.');

  // This is the core logic: watch for changes in the Gmail DOM
  const observer = new MutationObserver(handleMutation);

  // Start observing the main document body
  // You should find a more specific, stable element if possible
  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  function handleMutation(mutations) {
    // Look for the main email view pane.
    // !! IMPORTANT: These selectors are EXAMPLES. Gmail's classes are
    // obfuscated (e.g., "a3s", "adA") and will change. You must find
    // selectors that work reliably, often using [role] attributes.
    const emailViewSelector = 'div[role="listitem"]'; 
    const emailHeaderSelector = 'h2.hP'; // Example selector for subject

    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Check if a new email view was added
          const emailView = node.matches(emailViewSelector) ? node : node.querySelector(emailViewSelector);

          if (emailView && !emailView.dataset.threatGuardAnalyzed) {
            emailView.dataset.threatGuardAnalyzed = 'true'; // Mark as processed
            analyzeEmail(emailView);
          }
        }
      }
    }
  }

  function analyzeEmail(emailView) {
    console.log('ThreatGuard: New email view detected, analyzing...');

    // 1. Scrape data (selectors are examples and may need tweaking)
    const sender = emailView.querySelector('span[email]')?.innerText || '';
    const replyTo = emailView.querySelector('span.hb')?.innerText || sender;
    const subject = emailView.querySelector('h2.hP')?.innerText || '';
    const bodyEl = emailView.querySelector('.a3s'); // Gmail body container
    const bodyText = bodyEl ? bodyEl.innerText || bodyEl.textContent || '' : '';
    const bodyHtml = bodyEl ? bodyEl.innerHTML || '' : '';

    // Attempt to collect attachment filenames (best-effort selectors)
    const attachmentEls = document.querySelectorAll('div.aQH span.aV3, div.aQH span.aVn');
    const attachments = Array.from(attachmentEls).map(el => el.textContent || '').filter(Boolean);

    const emailData = {
      sender,
      replyTo,
      subject,
      body: bodyText,
      bodyHtml,
      attachments,
    };

    // 2. Send data to background script for local rule-based analysis
    chrome.runtime.sendMessage(
      { type: 'ANALYZE_EMAIL', data: emailData },
      (response) => {
        if (response && response.status_id) {
          console.log('ThreatGuard: Analysis complete.', response);
          // Always show a banner so the user sees Safe / Medium / High
          injectWarningBanner(emailView, response);
        } else {
          console.error('ThreatGuard: Invalid response from background.', response);
        }
      }
    );
  }

  /**
   * Injects the HTML warning banner into the email view.
   * @param {Element} emailView - The DOM element containing the email.
   * @param {object} apiResponse - The JSON analysis from your API.
   */
  function injectWarningBanner(emailView, apiResponse) {
    // Remove any existing banners in the current view before injecting a new one
    document.querySelectorAll('.threatguard-banner').forEach((el) => el.remove());

    const banner = document.createElement('div');
    // Add base class and severity class
    banner.className = `threatguard-banner threatguard-banner--${apiResponse.status_id.toLowerCase()}`;
    
    // Build the inner HTML from the API response
    let findingsHTML = apiResponse.findings.map(finding => `
      <div class="threatguard-finding">
        <strong>${finding.type} (Severity: ${finding.severity}):</strong>
        <p>${finding.description}</p>
        <p><strong>Concern:</strong> <code>${finding.concern || 'N/A'}</code></p>
      </div>
    `).join('');

    banner.innerHTML = `
      <div class="threatguard-header">
        <span class="threatguard-icon">🛡️</span>
        <h3>ThreatGuard: ${apiResponse.summary}</h3>
      </div>
      <div class="threatguard-body">
        ${findingsHTML}
      </div>
    `;

    // Prefer to inject directly above the Gmail subject line for visibility
    const subjectEl = document.querySelector('h2.hP');
    if (subjectEl && subjectEl.parentElement) {
      subjectEl.parentElement.prepend(banner);
    } else {
      // Fallback: inject at the top of the email view container
      emailView.prepend(banner);
    }
  }
  window.__tgInjectBanner = (apiResponse) => {
  const view = document.querySelector('div[role="listitem"]') || document.body;
  injectWarningBanner(view, apiResponse);
};

  // Listen for a manual scan trigger from the popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === 'TRIGGER_SCAN') {
      try {
        // Try to find a currently visible email view
        const emailViewSelector = 'div[role="listitem"]';
        const emailView = document.querySelector(emailViewSelector) || document.body;
        // Mark as analyzed so the MutationObserver won't rescan this same view
        if (emailView && emailView.dataset) {
          emailView.dataset.threatGuardAnalyzed = 'true';
        }
        analyzeEmail(emailView);
        sendResponse({ ok: true });
      } catch (e) {
        console.error('ThreatGuard: Scan trigger failed', e);
        sendResponse({ ok: false, error: String(e) });
      }
      return true;
    }
  });
}