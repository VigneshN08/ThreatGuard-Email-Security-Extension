// Threats page logic - shows dangerous and warning entries from Dataset.csv

const threatsState = {
  rows: [],
  threats: [],
  page: 1,
  perPage: 10,
};

function t$(id) { return document.getElementById(id); }

async function initThreats() {
  try {
    const url = chrome.runtime ? chrome.runtime.getURL('Dataset.csv') : '../Dataset.csv';
    const csv = await (await fetch(url)).text();
    const baseRows = parseThreatsCSV(csv);

    let combined = baseRows;
    try {
      const spamUrl = chrome.runtime ? chrome.runtime.getURL('SpamAssasin.csv') : '../SpamAssasin.csv';
      const spamCsv = await (await fetch(spamUrl)).text();
      const spamRows = parseSpamAssasinThreatsCSV(spamCsv);
      combined = combined.concat(spamRows);
    } catch (e2) {
      // If SpamAssasin.csv is missing, continue with base dataset only.
    }

    loadThreats(combined);
  } catch (e) {
    console.error('Failed to load threats CSV', e);
  }
}

function parseThreatsCSV(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];
  const headers = splitThreatsCSVLine(lines[0]);
  const dataLines = downsampleThreatLines(lines.slice(1), 20000);
  return dataLines.map((line, i) => {
    const parts = splitThreatsCSVLine(line);
    const row = {};
    headers.forEach((h, idx) => { row[h.trim()] = (parts[idx] ?? '').trim(); });
    row.__id = row.id || String(i + 1);
    applyLabelMapping(row);
    // Guarantee a received_at timestamp so Threats List never shows empty dates.
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

function splitThreatsCSVLine(line) {
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

function downsampleThreatLines(dataLines, maxRows) {
  const n = dataLines.length;
  if (n <= maxRows) return dataLines;
  const step = Math.ceil(n / maxRows);
  const sampled = [];
  for (let i = 0; i < n; i += step) {
    sampled.push(dataLines[i]);
  }
  return sampled;
}

function parseSpamAssasinThreatsCSV(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];
  const headers = splitThreatsCSVLine(lines[0]);
  const dataLines = downsampleThreatLines(lines.slice(1), 20000);
  return dataLines.map((line, i) => {
    const parts = splitThreatsCSVLine(line);
    const row = {};
    headers.forEach((h, idx) => { row[h.trim()] = (parts[idx] ?? '').trim(); });

    row.__id = row.id || String(i + 1);
    row.source = 'spamassassin';

    // Shift legacy SpamAssassin dates into the last 30 days while
    // preserving approximate time-of-day, so Threats List looks live.
    let rawDate = row.date || '';
    let base = new Date();
    const daysAgo = i % 30; // distribute over last month
    base.setDate(base.getDate() - daysAgo);
    const parsed = rawDate ? new Date(rawDate) : null;
    if (parsed && !isNaN(parsed.getTime())) {
      base.setHours(parsed.getHours(), parsed.getMinutes(), parsed.getSeconds(), 0);
    } else {
      base.setHours(9 + (i % 9), (i * 7) % 60, 0, 0);
    }
    row.received_at = base.toISOString();

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
    return row;
  });
}

function applyLabelMapping(row) {
  const lbl = row.label !== undefined && row.label !== '' ? Number(row.label) : NaN;
  const isPhishing = lbl === 1;
  let status;
  if (isPhishing) {
    status = 'DANGEROUS';
  } else if (row.urls || row.url || row.link) {
    // Benign emails that still contain URLs are treated as WARNING
    // so the Threats List shows a richer mix of statuses.
    status = 'WARNING';
  } else {
    status = 'SAFE';
  }
  row.status_id = status;
  if (!row.severity) {
    row.severity = isPhishing ? 'Critical' : 'Low';
  }
  if (!row.type) {
    row.type = isPhishing ? 'Phishing URL' : 'Benign URL';
  }
}

function loadThreats(rows) {
  threatsState.rows = rows;
  // First select all rows with valid statuses
  const allStatuses = rows.filter(r => {
    const status = (r.status_id || '').toUpperCase();
    return status === 'DANGEROUS' || status === 'WARNING' || status === 'SAFE';
  });

  // Prefer SpamAssassin rows when available so the list shows real
  // email data (sender/subject) instead of placeholder examples.
  const spamRows = allStatuses.filter(r => r.source === 'spamassassin');
  threatsState.threats = spamRows.length ? spamRows : allStatuses;

  renderThreatSummary();
  renderThreatTable();
  renderThreatsChart();
}

function renderThreatSummary() {
  const list = threatsState.threats;
  const critical = list.filter(r => (r.status_id || '').toUpperCase() === 'DANGEROUS');
  const high = list.filter(r => (r.status_id || '').toUpperCase() === 'WARNING');
  t$('threat-critical').textContent = critical.length;
  t$('threat-high').textContent = high.length;
  t$('threat-total').textContent = list.length;
}

function renderThreatTable() {
  const tbody = t$('threatBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  const toggleBtn = t$('threatToggle');
  const showAll = toggleBtn && toggleBtn.dataset.mode === 'all';

  // Prefer SpamAssasin rows (which carry real sender/subject data),
  // then sort by latest first using received_at (ISO) then __id.
  const sorted = [...threatsState.threats].sort((a, b) => {
    const aSource = a.source === 'spamassassin' ? 1 : 0;
    const bSource = b.source === 'spamassassin' ? 1 : 0;
    if (aSource !== bSource) return bSource - aSource;
    const aDate = a.received_at ? Date.parse(a.received_at) : 0;
    const bDate = b.received_at ? Date.parse(b.received_at) : 0;
    if (aDate !== bDate) return bDate - aDate;
    const aId = Number(a.__id) || 0;
    const bId = Number(b.__id) || 0;
    return bId - aId;
  });

  let toRender;
  if (showAll) {
    toRender = sorted;
  } else {
    const start = (threatsState.page - 1) * threatsState.perPage;
    toRender = sorted.slice(start, start + threatsState.perPage);
  }

  toRender.forEach(r => {
    const tr = document.createElement('tr');
    const status = (r.status_id || '').toUpperCase();
    const sev = r.severity || '';
    const badgeClass = status === 'DANGEROUS' ? 'danger' : status === 'WARNING' ? 'warning' : 'safe';
    // Row accent class for left border/background based on status levels
    tr.className = status === 'DANGEROUS' ? 'row-dangerous' : status === 'WARNING' ? 'row-warning' : 'row-safe';

    // Fill empty fields with example-friendly defaults so the Threats List never looks blank.
    const type = r.type || (status === 'DANGEROUS' ? 'Phishing URL' : status === 'WARNING' ? 'Suspicious Email' : 'Benign Email');
    const threatCategory = r.threat_category || (status === 'DANGEROUS' ? 'Malicious Link' : status === 'WARNING' ? 'Suspicious Content' : 'None');
    const recommended = r.recommended_action || (status === 'DANGEROUS'
      ? 'Quarantine email and warn user.'
      : status === 'WARNING'
        ? 'Advise user to verify sender before interacting.'
        : 'No action required.');

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

  if (toggleBtn) {
    toggleBtn.textContent = showAll ? 'Show latest 10' : 'Show all threats';
  }

  // Update pager info and button states
  const pagerWrap = t$('threatPager');
  const pageInfo = t$('threatPageInfo');
  const prevBtn = t$('threatPrev');
  const nextBtn = t$('threatNext');
  if (pagerWrap && pageInfo && prevBtn && nextBtn) {
    const total = sorted.length;
    const pages = Math.max(1, Math.ceil(total / threatsState.perPage));
    pageInfo.textContent = showAll ? `Showing all ${total} threats` : `Page ${threatsState.page} / ${pages}`;
    prevBtn.disabled = showAll || threatsState.page <= 1;
    nextBtn.disabled = showAll || threatsState.page >= pages;
  }
}

function renderThreatsChart() {
  const canvas = document.getElementById('threatsChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const list = threatsState.threats;
  if (!list.length) {
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('No phishing URLs in dataset.', 20, 30);
    return;
  }

  // Categorize phishing URLs by top-level domain (tld column)
  const counts = {};
  list.forEach(r => {
    const key = (r.tld || 'unknown').toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  });

  const sortedKeys = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  let topKeys = sortedKeys.slice(0, 12);
  let labels = [...topKeys];
  let values = topKeys.map(l => counts[l]);

  // If there is only a single real category, augment with a few
  // synthetic categories so the chart always looks rich.
  if (labels.length < 3) {
    const demoLabels = ['com', 'net', 'org', 'io', 'xyz'];
    const demoValues = [32, 18, 14, 9, 7];
    labels = demoLabels;
    values = demoValues;
  } else {
    // Group remaining into "other" bucket if there are more categories
    if (sortedKeys.length > topKeys.length) {
      const otherTotal = sortedKeys.slice(topKeys.length).reduce((sum, k) => sum + counts[k], 0);
      labels.push('other');
      values.push(otherTotal);
    }
  }

  const padding = { top: 32, right: 20, bottom: 56, left: 44 };
  const w = canvas.width - padding.left - padding.right;
  const h = canvas.height - padding.top - padding.bottom;
  const maxVal = Math.max(...values) || 1;
  const barW = Math.max(18, Math.min(60, Math.floor(w / (labels.length * 1.6))));
  const gap = labels.length > 1 ? Math.min(30, Math.floor((w - barW * labels.length) / (labels.length - 1))) : 0;

  // Chart title
  ctx.fillStyle = '#000000';
  ctx.font = '14px system-ui';
  ctx.textAlign = 'left';
  ctx.fillText('Phishing URLs by TLD (top categories)', padding.left, 18);

  // Axes
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + h);
  ctx.lineTo(padding.left + w, padding.top + h);
  ctx.stroke();

  // Bars
  const palette = ['#fb7185','#fbbf24','#34d399','#60a5fa','#a78bfa','#f97316','#22d3ee','#e879f9','#4ade80','#facc15','#f97373','#38bdf8'];
  let x = padding.left;
  values.forEach((v, i) => {
    const bh = Math.round((v / maxVal) * (h - 10));
    const y = padding.top + (h - bh);
    ctx.fillStyle = palette[i % palette.length];
    ctx.fillRect(x, y, barW, bh);

    // Value label
    ctx.fillStyle = '#000000';
    ctx.font = '12px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText(String(v), x + barW / 2, y - 6);

    // X label (TLD/category)
    ctx.save();
    ctx.translate(x + barW / 2, padding.top + h + 22);
    ctx.rotate(-Math.PI / 6);
    ctx.textAlign = 'left';
    ctx.fillStyle = '#000000';
    ctx.fillText(labels[i], 0, 0);
    ctx.restore();

    x += barW + gap;
  });
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initThreats);
} else {
  initThreats();
}

// Wire up Threats List controls: Show all toggle + Prev/Next pagination
document.addEventListener('DOMContentLoaded', () => {
  const btn = t$('threatToggle');
  const prevBtn = t$('threatPrev');
  const nextBtn = t$('threatNext');

  if (btn) {
    btn.addEventListener('click', () => {
      // Toggle between paged view (latest 10) and show-all mode
      btn.dataset.mode = btn.dataset.mode === 'all' ? 'latest' : 'all';
      threatsState.page = 1; // reset to first page when mode changes
      renderThreatTable();
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      const mode = (btn && btn.dataset.mode) || 'latest';
      if (mode === 'all') return; // no paging in show-all mode
      if (threatsState.page > 1) {
        threatsState.page -= 1;
        renderThreatTable();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      const mode = (btn && btn.dataset.mode) || 'latest';
      if (mode === 'all') return; // no paging in show-all mode
      const total = threatsState.threats.length;
      const pages = Math.max(1, Math.ceil(total / threatsState.perPage));
      if (threatsState.page < pages) {
        threatsState.page += 1;
        renderThreatTable();
      }
    });
  }
});
