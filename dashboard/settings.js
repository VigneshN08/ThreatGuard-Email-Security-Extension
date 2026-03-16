// Settings page logic with simple local persistence
const STORE_KEY = 'tg_settings';

function $(id){ return document.getElementById(id); }

const els = {
  tabs: () => document.querySelectorAll('.tg-tab'),
  tabRisk: () => $('tab-risk'),
  tabAlerts: () => $('tab-alerts'),
  tabApi: () => $('tab-api'),
  thrLow: () => $('thrLow'),
  thrMed: () => $('thrMed'),
  thrHigh: () => $('thrHigh'),
  saveRisk: () => $('saveRisk'),
  emailAlertsOn: () => document.querySelector('input[name="emailAlerts"][value="enabled"]'),
  emailAlertsOff: () => document.querySelector('input[name="emailAlerts"][value="disabled"]'),
  emailRecipient: () => $('emailRecipient'),
  alertHigh: () => $('alertHigh'),
  alertMed: () => $('alertMed'),
  alertLow: () => $('alertLow'),
  saveAlerts: () => $('saveAlerts'),
  apiKey: () => $('apiKey'),
  regenKey: () => $('regenKey'),
  rateLimit: () => $('rateLimit'),
  saveApi: () => $('saveApi'),
};

function loadSettings(){
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if(!raw) return defaultSettings();
    return JSON.parse(raw);
  } catch { return defaultSettings(); }
}

function saveSettings(s){ localStorage.setItem(STORE_KEY, JSON.stringify(s)); }

function defaultSettings(){
  return {
    risk: { low: 0.30, medium: 0.70, high: 0.90 },
    alerts: { enabled: true, recipient: 'admin@company.com', high: true, med: true, low: false },
    api: { key: '*******************', rateLimit: 1000 },
  };
}

function initTabs(){
  els.tabs().forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));
}

function switchTab(name){
  els.tabs().forEach(btn => btn.classList.toggle('active', btn.dataset.tab===name));
  els.tabRisk().style.display = name==='risk' ? 'grid' : 'none';
  els.tabAlerts().style.display = name==='alerts' ? 'grid' : 'none';
  els.tabApi().style.display = name==='api' ? 'grid' : 'none';
}

function render(s){
  // Risk
  els.thrLow().value = s.risk.low;
  els.thrMed().value = s.risk.medium;
  els.thrHigh().value = s.risk.high;

  // Alerts
  (s.alerts.enabled ? els.emailAlertsOn() : els.emailAlertsOff()).checked = true;
  els.emailRecipient().value = s.alerts.recipient;
  els.alertHigh().checked = !!s.alerts.high;
  els.alertMed().checked = !!s.alerts.med;
  els.alertLow().checked = !!s.alerts.low;

  // API
  els.apiKey().value = s.api.key;
  els.rateLimit().value = s.api.rateLimit;
}

function bindActions(s){
  els.saveRisk().addEventListener('click', () => {
    s.risk.low = clamp(parseFloat(els.thrLow().value), 0, 1);
    s.risk.medium = clamp(parseFloat(els.thrMed().value), 0, 1);
    s.risk.high = clamp(parseFloat(els.thrHigh().value), 0, 1);
    saveSettings(s);
    toast('Risk thresholds saved.');
  });

  els.saveAlerts().addEventListener('click', () => {
    s.alerts.enabled = els.emailAlertsOn().checked;
    s.alerts.recipient = els.emailRecipient().value.trim();
    s.alerts.high = els.alertHigh().checked;
    s.alerts.med = els.alertMed().checked;
    s.alerts.low = els.alertLow().checked;
    saveSettings(s);
    toast('Alert settings saved.');
  });

  els.regenKey().addEventListener('click', () => {
    const key = genKey();
    els.apiKey().value = key;
  });

  els.saveApi().addEventListener('click', () => {
    s.api.key = els.apiKey().value.trim();
    s.api.rateLimit = parseInt(els.rateLimit().value || '0', 10) || 0;
    saveSettings(s);
    toast('API settings saved.');
  });
}

function clamp(v, min, max){ if(isNaN(v)) return min; return Math.max(min, Math.min(max, v)); }
function genKey(){
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function toast(msg){
  // Minimal inline toast
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = 'position:fixed;bottom:16px;right:16px;background:#14234a;color:#e6ebff;padding:8px 12px;border:1px solid #2a3c6e;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,.4);z-index:9999;';
  document.body.appendChild(el);
  setTimeout(()=>el.remove(), 1600);
}

function init(){
  initTabs();
  const s = loadSettings();
  render(s);
  bindActions(s);
}

init();
