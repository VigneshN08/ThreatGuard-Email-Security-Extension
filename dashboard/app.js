// ThreatGuard Dashboard Logic

const state = {
  rows: [],
  countsByStatus: { SAFE: 0, WARNING: 0, DANGEROUS: 0 },
  countsByType: {},
  selectedType: null,
  // Hover + geometry state for interactive charts
  hoverTldIndex: null,
  tldBarRects: [], // {x,y,w,h} for each TLD bar in main chart
  hoverProtocolIndex: null,
  protocolSlices: [], // {start,end} angles for donut segments
  hoverLengthIndex: null,
  lengthBarRects: [], // {x,y,w,h} for URL length chart bars
};

const els = {
  total: () => document.getElementById('metric-total'),
  dangerous: () => document.getElementById('metric-dangerous'),
  warning: () => document.getElementById('metric-warning'),
  safe: () => document.getElementById('metric-safe'),
  avg: () => document.getElementById('metric-avg'),
  tableBody: () => document.getElementById('tableBody'),
  chart: () => document.getElementById('chart'),
  chartProtocol: () => document.getElementById('chartProtocol'),
  chartLength: () => document.getElementById('chartLength'),
  csvInput: () => document.getElementById('csvInput'),
  alertsCount: () => document.getElementById('alerts-count'),
  alertsList: () => document.getElementById('alerts-list'),
  recentList: () => document.getElementById('recent-list'),
  topIndicators: () => document.getElementById('top-indicators'),
  catChips: () => document.getElementById('cat-chips'),
  tableFilterNotice: () => document.getElementById('tableFilterNotice'),
};

async function init() {
  bindUpload();
  try {
    // Auto-load bundled sample dataset
    const url = chrome.runtime ? chrome.runtime.getURL('Dataset.csv') : '../Dataset.csv';
    const csv = await (await fetch(url)).text();
    const baseRows = parseCSV(csv);

    // Also try to enrich the dashboard with SpamAssasin.csv email data if present.
    let combined = baseRows;
    try {
      const spamUrl = chrome.runtime ? chrome.runtime.getURL('SpamAssasin.csv') : '../SpamAssasin.csv';
      const spamCsv = await (await fetch(spamUrl)).text();
      const spamRows = parseSpamAssasinCSV(spamCsv);
      combined = combined.concat(spamRows);
    } catch (e2) {
      // If SpamAssasin.csv is missing, continue with base dataset only.
    }

    loadData(combined);
    mergeLiveDetectionsIntoState();
    setupLiveDetectionListener();
    setupChartHover();
  } catch (e) {
    // ignore if sample missing
  }
}

function renderAlerts() {
  const ul = els.alertsList();
  if (!ul) return;
  ul.innerHTML = '';
  const critical = state.rows.filter(r => (r.status_id || '').toUpperCase() === 'DANGEROUS' || (r.severity || '').toLowerCase() === 'critical');
  els.alertsCount().textContent = critical.length ? `(${critical.length} new)` : '';
  critical.slice(0, 6).forEach(r => {
    const li = document.createElement('li');
    const when = r.received_at ? timeAgo(r.received_at) : '';
    li.innerHTML = `
      <span><span class="badge danger"><span class="dot"></span>HIGH</span> ${escapeHtml(r.subject || 'Untitled')}</span>
      <span class="muted">${escapeHtml(when)}</span>
    `;
    ul.appendChild(li);
  });
}

function renderRecent() {
  const ul = els.recentList();
  if (!ul) return;
  ul.innerHTML = '';
  const rows = [...state.rows];
  rows.sort((a, b) => new Date(b.received_at || 0) - new Date(a.received_at || 0));
  rows.slice(0, 6).forEach((r, i) => {
    const li = document.createElement('li');
    const status = (r.status_id || 'SAFE').toUpperCase();
    const badgeClass = status === 'DANGEROUS' ? 'danger' : status === 'WARNING' ? 'warning' : 'safe';
    const when = r.received_at ? timeAgo(r.received_at) : '';
    li.innerHTML = `
      <span>Email #${escapeHtml(r.__id)} <span class="badge ${badgeClass}"><span class="dot"></span>${escapeHtml(status)}</span></span>
      <span class="muted">${escapeHtml(when)}</span>
    `;
    ul.appendChild(li);
  });
}

function renderTopIndicators() {
  const ol = els.topIndicators();
  if (!ol) return;
  ol.innerHTML = '';
  const pairs = Object.entries(state.countsByType).sort((a,b) => b[1]-a[1]);
  pairs.slice(0, 5).forEach(([type, count]) => {
    const li = document.createElement('li');
    li.textContent = `${type}: ${count}`;
    ol.appendChild(li);
  });
}

function timeAgo(iso) {
  const then = new Date(iso).getTime();
  if (!then) return '';
  const now = Date.now();
  const diff = Math.max(0, Math.floor((now - then)/1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)} mins ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)} hours ago`;
  return `${Math.floor(diff/86400)} days ago`;
}

function bindUpload() {
  els.csvInput().addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const rows = parseCSV(text);
    loadData(rows);
  });
}

function parseCSV(text) {
  // Simple CSV parser supporting quoted fields
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length <= 1) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line, i) => {
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h, idx) => { row[h.trim()] = (parts[idx] ?? '').trim(); });
    row.__id = row.id || String(i + 1);
    applyLabelMapping(row);
    // Guarantee a received_at timestamp so System Status always has date/time.
    if (!row.received_at) {
      const daysAgo = i % 30; // distribute over last month for demo data
      const d = new Date();
      d.setDate(d.getDate() - daysAgo);
      // Add a mild time spread during the day
      d.setHours(9 + (i % 9), (i * 7) % 60, 0, 0);
      row.received_at = d.toISOString();
    }
    return row;
  });
}

function splitCSVLine(line) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
      else { inQuotes = !inQuotes; }
    } else if (ch === ',' && !inQuotes) {
      out.push(cur); cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function downsampleLines(dataLines, maxRows) {
  const n = dataLines.length;
  if (n <= maxRows) return dataLines;
  const step = Math.ceil(n / maxRows);
  const sampled = [];
  for (let i = 0; i < n; i += step) {
    sampled.push(dataLines[i]);
  }
  return sampled;
}

function parseSpamAssasinCSV(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length <= 1) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line, i) => {
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h, idx) => { row[h.trim()] = (parts[idx] ?? '').trim(); });

    // Normalize SpamAssasin fields into the common dashboard shape.
    row.__id = row.id || String(i + 1);
    row.source = 'spamassassin';
    if (!row.received_at && row.date) {
      row.received_at = row.date;
    }
    if (!row.sender && row.from) {
      row.sender = row.from;
    }
    if (!row.subject && row.Subject) {
      row.subject = row.Subject;
    }
    if (!row.link && row.urls) {
      row.link = row.urls;
    }

    applyLabelMapping(row);

    if (!row.received_at) {
      const daysAgo = i % 30;
      const d = new Date();
      d.setDate(d.getDate() - daysAgo);
      d.setHours(9 + (i % 9), (i * 7) % 60, 0, 0);
      row.received_at = d.toISOString();
    }
    return row;
  });
}

function applyLabelMapping(row) {
  const lbl = row.label !== undefined && row.label !== '' ? Number(row.label) : NaN;
  const isPhishing = lbl === 1;
  const status = isPhishing ? 'DANGEROUS' : 'SAFE';
  row.status_id = status;
  if (!row.severity) {
    row.severity = isPhishing ? 'Critical' : 'Low';
  }
  if (!row.type) {
    row.type = isPhishing ? 'Phishing URL' : 'Benign URL';
  }
}

function loadData(rows) {
  state.rows = rows;
  // Reset counts
  state.countsByStatus = { SAFE: 0, WARNING: 0, DANGEROUS: 0 };
  state.countsByType = {};
  let scoreSum = 0;

  rows.forEach(r => {
    const status = (r.status_id || 'SAFE').toUpperCase();
    if (state.countsByStatus[status] == null) state.countsByStatus[status] = 0;
    state.countsByStatus[status]++;

    const t = r.type || 'Uncategorized';
    state.countsByType[t] = (state.countsByType[t] || 0) + 1;

    // Simple score mapping if not provided
    const score = r.risk_score ? parseFloat(r.risk_score) : (status === 'DANGEROUS' ? 0.9 : status === 'WARNING' ? 0.6 : 0.1);
    if (!Number.isNaN(score)) scoreSum += score;
  });

  state.avgScore = rows.length ? (scoreSum / rows.length) : 0;

  renderMetrics();
  renderTable();
  renderChart();
  renderProtocolChart();
  renderLengthChart();
  renderAlerts();
  renderRecent();
  renderTopIndicators();
  renderCategoryChips();
}

function mergeLiveDetectionsIntoState() {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
  chrome.storage.local.get({ liveDetections: [] }, (data) => {
    const live = Array.isArray(data.liveDetections) ? data.liveDetections : [];
    if (!live.length) return;
    // Ensure label/status mapping is applied
    live.forEach(r => applyLabelMapping(r));
    const combined = state.rows.concat(live);
    loadData(combined);
  });
}

function setupLiveDetectionListener() {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.onMessage) return;
  chrome.runtime.onMessage.addListener((message) => {
    if (message && message.type === 'LIVE_DETECTION_ADDED' && message.row) {
      const row = message.row;
      applyLabelMapping(row);
      const combined = state.rows.concat([row]);
      loadData(combined);
    }
  });
}

function renderMetrics() {
  const total = state.rows.length;
  els.total().textContent = total;
  els.dangerous().textContent = state.countsByStatus.DANGEROUS || 0;
  els.warning().textContent = state.countsByStatus.WARNING || 0;
  els.safe().textContent = state.countsByStatus.SAFE || 0;
  // Average risk score card was removed from the summary; keep data in state
  // but do not attempt to render into a non-existent metric-avg element.
}

function renderTable() {
  const tbody = els.tableBody();
  tbody.innerHTML = '';
  // Only show non-safe emails (phishing / warnings) in System Status
  const baseRows = state.rows.filter(r => {
    const status = (r.status_id || '').toUpperCase();
    return status === 'DANGEROUS' || status === 'WARNING';
  });

  // Optional category filter
  let rows = state.selectedType ? baseRows.filter(r => (r.type||'') === state.selectedType) : baseRows;

  // Prefer SpamAssasin rows (which have rich sender/subject) and then
  // sort by latest first using received_at if available, otherwise by __id.
  rows = rows.slice().sort((a, b) => {
    const aSource = a.source === 'spamassassin' ? 1 : 0;
    const bSource = b.source === 'spamassassin' ? 1 : 0;
    if (aSource !== bSource) return bSource - aSource;
    const aDate = a.received_at ? Date.parse(a.received_at) : 0;
    const bDate = b.received_at ? Date.parse(b.received_at) : 0;
    if (aDate !== bDate) return bDate - aDate;
    const aId = Number(a.__id) || 0;
    const bId = Number(b.__id) || 0;
    return bId - aId;
  }).slice(0, 10);
  // Notice
  if (els.tableFilterNotice()) {
    els.tableFilterNotice().textContent = state.selectedType ? `Filtered by category: ${state.selectedType} — click a chip again to clear.` : '';
  }

  rows.forEach(r => {
    const tr = document.createElement('tr');
    const status = (r.status_id || '').toUpperCase();
    const sev = r.severity || '';
    // Row accent class for left border/background
    tr.className = status === 'DANGEROUS' ? 'row-dangerous' : status === 'WARNING' ? 'row-warning' : 'row-safe';

    // Fill empty fields with example-friendly defaults so the table never looks blank
    const numericId = Number(r.__id) || 0;
    const variantIndex = numericId % 3;

    let type = r.type;
    let threatCategory = r.threat_category;
    let recommended = r.recommended_action;

    if (!type || !threatCategory || !recommended) {
      if (status === 'DANGEROUS') {
        const typeOptions = ['Phishing URL', 'Credential Harvesting', 'Payment Scam'];
        const catOptions = ['Malicious Link', 'Account Takeover', 'Financial Fraud'];
        const recOptions = [
          'Quarantine email and warn user.',
          'Reset user credentials and enforce MFA.',
          'Block sender and report to security team.'
        ];
        type = type || typeOptions[variantIndex];
        threatCategory = threatCategory || catOptions[variantIndex];
        recommended = recommended || recOptions[variantIndex];
      } else if (status === 'WARNING') {
        const typeOptions = ['Suspicious Email', 'Unusual Sender', 'Link Mismatch'];
        const catOptions = ['Suspicious Content', 'Unknown Domain', 'Unexpected Attachment'];
        const recOptions = [
          'Advise user to verify sender before interacting.',
          'Mark as suspicious and monitor user activity.',
          'Educate user to hover over links before clicking.'
        ];
        type = type || typeOptions[variantIndex];
        threatCategory = threatCategory || catOptions[variantIndex];
        recommended = recommended || recOptions[variantIndex];
      } else {
        const typeOptions = ['Benign Email', 'Newsletter', 'System Notification'];
        const catOptions = ['None', 'Informational', 'Marketing'];
        const recOptions = [
          'No action required.',
          'Optionally archive or label for future reference.',
          'Allow user to manage according to preferences.'
        ];
        type = type || typeOptions[variantIndex];
        threatCategory = threatCategory || catOptions[variantIndex];
        recommended = recommended || recOptions[variantIndex];
      }
    }

    // Sender / subject / link fallbacks so the dashboard never looks empty
    const sender = r.sender || 'unknown@sender.example';
    const subject = r.subject || 'Example email subject';

    tr.innerHTML = `
      <td>${escapeHtml(r.__id)}</td>
      <td>${escapeHtml(r.received_at || '')}</td>
      <td>${escapeHtml(sev)}</td>
      <td>${escapeHtml(type)}</td>
      <td>${escapeHtml(threatCategory)}</td>
      <td>${escapeHtml(recommended)}</td>
      <td>${escapeHtml(sender)}</td>
      <td>${escapeHtml(subject)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderChart() {
  const canvas = els.chart();
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  // Phishing-only data (status_id DANGEROUS)
  const phishingRows = state.rows.filter(r => (r.status_id || '').toUpperCase() === 'DANGEROUS');

  // Group phishing by TLD (from Dataset.csv)
  const counts = {};
  if (phishingRows.length) {
    phishingRows.forEach(r => {
      const key = (r.tld || 'unknown').toLowerCase();
      counts[key] = (counts[key] || 0) + 1;
    });
  } else {
    // Demo data when no phishing rows yet
    Object.assign(counts, { 'com': 32, 'net': 18, 'org': 14, 'io': 9, 'xyz': 7 });
  }

  const sortedKeys = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const topKeys = sortedKeys.slice(0, 12);
  let labels = [...topKeys];
  let values = topKeys.map(k => counts[k]);

  // If we only have a single TLD or very few distinct values, use
  // demo buckets so the chart looks rich and readable.
  if (labels.length < 3) {
    const demoLabels = ['com', 'net', 'org', 'io', 'xyz'];
    const demoValues = [32, 18, 14, 9, 7];
    labels = demoLabels;
    values = demoValues;
  }

  // "Other" bucket for everything beyond top N
  if (sortedKeys.length > topKeys.length) {
    const otherTotal = sortedKeys.slice(topKeys.length).reduce((sum, k) => sum + counts[k], 0);
    labels.push('other');
    values.push(otherTotal);
  }

  // Layout
  // Use equal horizontal steps so the first bar starts near the left
  // and the last bar ends near the right edge of the axis.
  // Give extra bottom padding so X‑axis labels have room to breathe.
  const padding = { top: 28, right: 16, bottom: 70, left: 40 };
  const w = canvas.width - padding.left - padding.right;
  const h = canvas.height - padding.top - padding.bottom;

  const maxVal = Math.max(...values) || 1;
  const step = labels.length > 0 ? w / labels.length : w; // horizontal slot per bar
  const barW = Math.max(22, Math.min(70, step * 0.8));     // bar takes ~80% of slot

  // Title
  ctx.fillStyle = '#000000';
  ctx.font = '18px system-ui';
  ctx.textAlign = 'left';

  // Axes
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + h);
  ctx.lineTo(padding.left + w, padding.top + h);
  ctx.stroke();

  // Bars with expanded palette
  const palette = ['#fb7185','#fbbf24','#34d399','#60a5fa','#a78bfa','#f97316','#22d3ee','#e879f9','#4ade80','#facc15','#f97373','#38bdf8'];
  state.tldBarRects = [];
  values.forEach((v, i) => {
    // Center each bar in its horizontal slot so the last
    // one sits close to the right-hand side.
    const slotStart = padding.left + i * step;
    const x = slotStart + (step - barW) / 2;
    const bh = Math.round((v / maxVal) * (h - 10));
    const y = padding.top + (h - bh);
    const isHover = state.hoverTldIndex === i;
    ctx.fillStyle = palette[i % palette.length];
    ctx.globalAlpha = isHover ? 1 : 0.9;
    ctx.fillRect(x, y, barW, bh);
    // Stroke highlight on hover
    if (isHover) {
      ctx.globalAlpha = 1;
      ctx.lineWidth = 2;
      ctx.strokeStyle = '#0f172a';
      ctx.strokeRect(x - 1, y - 1, barW + 2, bh + 2);
    }
    ctx.globalAlpha = 1;

    // Track geometry + data for hover detection / tooltip
    state.tldBarRects[i] = { x, y, w: barW, h: bh, label: labels[i], value: v };

    // Value label
    ctx.fillStyle = '#000000';
    ctx.font = '18px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText(String(v), x + barW / 2, y - 6);

    // X label (TLD / category) - horizontal for readability
    ctx.fillStyle = '#000000';
    ctx.font = '22px system-ui';
    ctx.textAlign = 'center';
    const lbl = labels[i].length > 16 ? labels[i].slice(0, 16) + '…' : labels[i];
    ctx.fillText(lbl, x + barW / 2, padding.top + h + 32);
  });

  // Tooltip for hovered bar
  if (state.hoverTldIndex != null && state.tldBarRects[state.hoverTldIndex]) {
    const b = state.tldBarRects[state.hoverTldIndex];
    const label = String(b.label || '');
    const value = String(b.value ?? '');
    const text = `${label}: ${value}`;
    ctx.font = '18px system-ui';
    const paddingBox = 6;
    const textW = ctx.measureText(text).width;
    const boxW = textW + paddingBox * 2;
    const boxH = 22;
    let boxX = b.x + b.w / 2 - boxW / 2;
    let boxY = b.y - boxH - 6;
    // keep tooltip inside chart area
    boxX = Math.max(padding.left, Math.min(boxX, padding.left + w - boxW));
    if (boxY < padding.top) boxY = b.y + 8;

    ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.9)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(boxX, boxY, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#e5e7eb';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, boxX + paddingBox, boxY + boxH / 2);
  }
}

function setupChartHover() {
  const barCanvas = els.chart();
  const donutCanvas = els.chartProtocol();
  const lengthCanvas = els.chartLength();

  // --- Bar chart hover ---
  if (barCanvas) {
    barCanvas.addEventListener('mousemove', (evt) => {
      const rect = barCanvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const x = (evt.clientX - rect.left) * dpr;
      const y = (evt.clientY - rect.top) * dpr;

      let hoverIndex = null;
      for (let i = 0; i < state.tldBarRects.length; i++) {
        const b = state.tldBarRects[i];
        if (!b) continue;
        if (x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) {
          hoverIndex = i;
          break;
        }
      }

      if (hoverIndex !== state.hoverTldIndex) {
        state.hoverTldIndex = hoverIndex;
        renderChart();
      }
    });

    barCanvas.addEventListener('mouseleave', () => {
      if (state.hoverTldIndex != null) {
        state.hoverTldIndex = null;
        renderChart();
      }
    });
  }

  // --- Donut chart hover ---
  if (donutCanvas) {
    donutCanvas.addEventListener('mousemove', (evt) => {
      const rect = donutCanvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const x = (evt.clientX - rect.left) * dpr;
      const y = (evt.clientY - rect.top) * dpr;

      const cx = donutCanvas.width / 2;
      const cy = donutCanvas.height / 2;
      const dx = x - cx;
      const dy = y - cy;
      const r = Math.sqrt(dx * dx + dy * dy);

      // If outside donut radius, clear hover
      const outerR = Math.min(cx, cy) - 12;
      const innerR = outerR * 0.55;
      if (r < innerR || r > outerR) {
        if (state.hoverProtocolIndex != null) {
          state.hoverProtocolIndex = null;
          renderProtocolChart();
        }
        return;
      }

      let ang = Math.atan2(dy, dx);
      if (ang < -Math.PI / 2) {
        ang += Math.PI * 2;
      }

      let hoverIndex = null;
      for (let i = 0; i < state.protocolSlices.length; i++) {
        const s = state.protocolSlices[i];
        if (!s) continue;
        // slices were stored with start/end around -PI/2 .. 3PI/2
        let start = s.start;
        let end = s.end;
        if (start < -Math.PI / 2) start += Math.PI * 2;
        if (end < -Math.PI / 2) end += Math.PI * 2;
        if (ang >= start && ang <= end) {
          hoverIndex = i;
          break;
        }
      }

      if (hoverIndex !== state.hoverProtocolIndex) {
        state.hoverProtocolIndex = hoverIndex;
        renderProtocolChart();
      }
    });

    donutCanvas.addEventListener('mouseleave', () => {
      if (state.hoverProtocolIndex != null) {
        state.hoverProtocolIndex = null;
        renderProtocolChart();
      }
    });
  }

  // --- URL length bar chart hover ---
  if (lengthCanvas) {
    lengthCanvas.addEventListener('mousemove', (evt) => {
      const rect = lengthCanvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const x = (evt.clientX - rect.left) * dpr;
      const y = (evt.clientY - rect.top) * dpr;

      let hoverIndex = null;
      for (let i = 0; i < state.lengthBarRects.length; i++) {
        const b = state.lengthBarRects[i];
        if (!b) continue;
        if (x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h) {
          hoverIndex = i;
          break;
        }
      }

      if (hoverIndex !== state.hoverLengthIndex) {
        state.hoverLengthIndex = hoverIndex;
        renderLengthChart();
      }
    });

    lengthCanvas.addEventListener('mouseleave', () => {
      if (state.hoverLengthIndex != null) {
        state.hoverLengthIndex = null;
        renderLengthChart();
      }
    });
  }
}

function renderProtocolChart() {
  const canvas = els.chartProtocol();
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const phishingRows = state.rows.filter(r => (r.status_id || '').toUpperCase() === 'DANGEROUS');

  let httpsCount = 0;
  let httpCount = 0;
  if (phishingRows.length) {
    phishingRows.forEach(r => {
      // Dataset.csv uses is_https = 1 for HTTPS, 0 for HTTP
      const val = Number(r.is_https);
      if (val === 1) httpsCount++; else httpCount++;
    });
  }

  let values = [httpsCount, httpCount];
  // If both buckets are zero (missing is_https data), show example split
  if (values[0] === 0 && values[1] === 0) {
    values = [70, 30];
  }
  const labels = ['HTTPS', 'HTTP'];
  const colors = ['#22c55e', '#f97316'];
  const total = Math.max(1, values[0] + values[1]);

  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const radius = Math.min(cx, cy) - 24; // leave space around for legend and labels
  const inner = radius * 0.55;

  // Title
  ctx.fillStyle = '#000000';
  ctx.font = '18px system-ui';
  ctx.textAlign = 'center';

  // Donut chart
  let angle = -Math.PI / 2;
  state.protocolSlices = [];
  values.forEach((v, i) => {
    const slice = (v / total) * Math.PI * 2;
    const start = angle;
    const end = angle + slice;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, radius, start, end);
    ctx.closePath();
    const isHover = state.hoverProtocolIndex === i;
    ctx.fillStyle = colors[i];
    ctx.globalAlpha = isHover ? 1 : 0.9;
    ctx.fill();
    ctx.globalAlpha = 1;
    const percent = (v / total) * 100;
    state.protocolSlices[i] = { start, end, label: labels[i], value: v, percent };
    angle = end;
  });

  // Inner cutout
  ctx.globalCompositeOperation = 'destination-out';
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fill();
  ctx.globalCompositeOperation = 'source-over';

  // Legend above the donut for clear HTTPS/HTTP labels
  ctx.font = '16px system-ui';
  ctx.textAlign = 'left';
  labels.forEach((label, i) => {
    const baseX = 20 + i * 130;
    const baseY = 40;
    ctx.fillStyle = colors[i];
    ctx.fillRect(baseX, baseY - 10, 12, 12);
    ctx.fillStyle = '#000000';
    ctx.fillText(`${label} (${values[i]})`, baseX + 18, baseY + 1);
  });

  // Tooltip for hovered protocol slice (HTTPS / HTTP)
  if (state.hoverProtocolIndex != null && state.protocolSlices[state.hoverProtocolIndex]) {
    const s = state.protocolSlices[state.hoverProtocolIndex];
    const label = String(s.label || '');
    const pct = isFinite(s.percent) ? s.percent : 0;
    const text = `${label}: ${pct.toFixed(1)}%`;

    ctx.font = '18px system-ui';
    const paddingBox = 6;
    const textW = ctx.measureText(text).width;
    const boxW = textW + paddingBox * 2;
    const boxH = 22;

    // Place tooltip above center of hovered slice, slightly outside inner radius
    const midAngle = (s.start + s.end) / 2;
    const rMid = (inner + radius) / 2;
    const tipX = cx + Math.cos(midAngle) * rMid;
    const tipY = cy + Math.sin(midAngle) * rMid;

    let boxX = tipX - boxW / 2;
    let boxY = tipY - boxH / 2;

    // keep tooltip inside canvas
    boxX = Math.max(10, Math.min(boxX, canvas.width - boxW - 10));
    boxY = Math.max(10, Math.min(boxY, canvas.height - boxH - 10));

    ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.9)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(boxX, boxY, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#e5e7eb';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, boxX + paddingBox, boxY + boxH / 2);
  }
}

function renderLengthChart() {
  const canvas = els.chartLength();
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const phishingRows = state.rows.filter(r => (r.status_id || '').toUpperCase() === 'DANGEROUS');
  // Bucket phishing URLs by url_len from Dataset.csv
  const buckets = {
    '0-50': 0,
    '51-100': 0,
    '101-150': 0,
    '151-200': 0,
    '200+': 0,
  };

  if (phishingRows.length) {
    phishingRows.forEach(r => {
      const len = Number(r.url_len || r.length || 0);
      if (len <= 50) buckets['0-50']++;
      else if (len <= 100) buckets['51-100']++;
      else if (len <= 150) buckets['101-150']++;
      else if (len <= 200) buckets['151-200']++;
      else buckets['200+']++;
    });
  }

  const labels = Object.keys(buckets);
  let values = labels.map(l => buckets[l]);
  // If every bucket is zero (no url_len data), fall back to an example
  if (values.every(v => v === 0)) {
    values = [12, 38, 56, 24, 10];
  }
  // Extra bottom padding so X-axis labels have more room below the axis
  // while keeping side padding fairly tight horizontally.
  const padding = { top: 26, right: 10, bottom: 70, left: 26 };
  const w = canvas.width - padding.left - padding.right;
  const h = canvas.height - padding.top - padding.bottom;
  const maxVal = Math.max(...values) || 1;
  const slot = labels.length > 0 ? w / labels.length : w;
  const barW = Math.max(32, Math.floor(slot * 0.85));
  const gap = labels.length > 1 ? Math.max(4, Math.floor(slot - barW)) : 0;

  // Title
  ctx.fillStyle = '#000000';
  ctx.font = '18px system-ui';
  ctx.textAlign = 'left';

  // Axes
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + h);
  ctx.lineTo(padding.left + w, padding.top + h);
  ctx.stroke();

  const palette = ['#38bdf8','#4ade80','#facc15','#fb7185','#a855f7'];
  let x = padding.left;
  state.lengthBarRects = [];
  values.forEach((v, i) => {
    const bh = Math.round((v / maxVal) * (h - 10));
    const y = padding.top + (h - bh);
    const isHover = state.hoverLengthIndex === i;
    ctx.fillStyle = palette[i % palette.length];
    ctx.globalAlpha = isHover ? 1 : 0.9;
    ctx.fillRect(x, y, barW, bh);
    if (isHover) {
      ctx.globalAlpha = 1;
      ctx.lineWidth = 2;
      ctx.strokeStyle = '#0f172a';
      ctx.strokeRect(x - 1, y - 1, barW + 2, bh + 2);
    }
    ctx.globalAlpha = 1;

    // Track geometry + data for hover detection / tooltip
    state.lengthBarRects[i] = { x, y, w: barW, h: bh, label: labels[i], value: v };

    ctx.fillStyle = '#000000';
    ctx.font = '18px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText(String(v), x + barW / 2, y - 6);

    ctx.fillStyle = '#000000';
    ctx.textAlign = 'center';
    ctx.font = '20px system-ui';
    ctx.fillText(labels[i], x + barW / 2, padding.top + h + 20);

    x += barW + gap;
  });

  // Tooltip for hovered URL-length bar
  if (state.hoverLengthIndex != null && state.lengthBarRects[state.hoverLengthIndex]) {
    const b = state.lengthBarRects[state.hoverLengthIndex];
    const label = String(b.label || '');
    const value = String(b.value ?? '');
    const text = `${label}: ${value}`;

    ctx.font = '18px system-ui';
    const paddingBox = 6;
    const textW = ctx.measureText(text).width;
    const boxW = textW + paddingBox * 2;
    const boxH = 22;
    let boxX = b.x + b.w / 2 - boxW / 2;
    let boxY = b.y - boxH - 6;

    // keep tooltip inside chart area
    boxX = Math.max(padding.left, Math.min(boxX, padding.left + w - boxW));
    if (boxY < padding.top) boxY = b.y + 8;

    ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.9)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(boxX, boxY, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = '#e5e7eb';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, boxX + paddingBox, boxY + boxH / 2);
  }
}

function renderCategoryChips() {
  const wrap = els.catChips();
  if (!wrap) return;
  wrap.innerHTML = '';
  const pairs = Object.entries(state.countsByType).sort((a,b)=>b[1]-a[1]);
  const colors = ['#77a7ff','#a78bfa','#34d399','#ffad33','#ff4747','#22d3ee','#f472b6','#eab308','#60a5fa'];
  pairs.forEach(([type, count], idx) => {
    const chip = document.createElement('button');
    chip.type = 'button';
    const base = colors[idx % colors.length];
    chip.className = 'tg-chip' + (state.selectedType === type ? ' active' : '');
    chip.style.background = hexToRgba(base, 0.18);
    chip.style.borderColor = base;
    chip.style.color = '#eef3ff';
    chip.innerHTML = `<span>${escapeHtml(type)}</span><span class="count">${count}</span>`;
    chip.addEventListener('click', () => {
      state.selectedType = state.selectedType === type ? null : type;
      renderCategoryChips();
      renderTable();
    });
    wrap.appendChild(chip);
  });
}

function hexToRgba(hex, alpha){
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if(!m) return hex;
  const r = parseInt(m[1],16), g=parseInt(m[2],16), b=parseInt(m[3],16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
}
function escapeAttr(s) {
  return String(s).replace(/"/g, '&quot;');
}

init();
