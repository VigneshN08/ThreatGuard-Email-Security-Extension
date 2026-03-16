document.getElementById('dashboard-link').addEventListener('click', () => {
  const dashboardUrl = chrome.runtime.getURL('dashboard/index.html');
  chrome.tabs.create({ url: dashboardUrl });
});

document.getElementById('scan-email').addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) return;
    chrome.tabs.sendMessage(tab.id, { type: 'TRIGGER_SCAN' }, (resp) => {
      // Optional: could show status in popup later
    });
  } catch (e) {
    // noop
  }
});