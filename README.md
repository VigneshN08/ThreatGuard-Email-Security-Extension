# ThreatGuard Chrome Extension

This folder contains the source code for the ThreatGuard Chrome extension, designed to integrate with Gmail and provide real-time phishing analysis.

## How to Install (for Development)

1.  Clone this repository to your local machine.
2.  Open Google Chrome.
3.  Navigate to `chrome://extensions`.
4.  Enable "Developer mode" in the top-right corner.
5.  Click "Load unpacked".
6.  Select the entire `threatguard-extension` folder.
7.  The extension should now appear in your toolbar.

## ⚠️ Critical Next Steps

This is a **boilerplate** and requires configuration to work.

### 1. Update API Endpoint
-   Open `src/background.js`.
-   Change the `API_URL` constant to point to your deployed backend.
-   Open `manifest.json`.
-   Update the `host_permissions` array to match your API domain.

### 2. Find Gmail DOM Selectors
-   Open `src/content.js`.
-   The selectors in this file (e.g., `div[role="listitem"]`) are **placeholders**.
-   You must manually inspect the Gmail DOM using Chrome DevTools to find stable, reliable selectors for:
    -   The main email-view pane (to know when a new email is opened).
    -   The sender's name/email.
    -   The subject line.
    -   The email body.
-   **This is the hardest part.** Gmail's classes are obfuscated (like `.a3s`) and change often. Look for `data-` attributes or ARIA `role` attributes, which are more stable.

## Screenshots

### Extension Popup
![Popup](screenshotspopup.png)

### Threat Detection Alert
![Alert](screenshotsalert.png)

### Security Dashboard
![Dashboard](screenshotsdashboard.png)

### Threat Report
![Report](screenshotsreport.png)
