// Alerts page logic using bundled Dataset.csv
const state = {
  rows: [],
  filtered: [],
  page: 1,
  perPage: 8,
  severity: 'ALL',
  search: '',
  from: '',
  to: '',
  // Track selected alerts across pages by their __id so that
  // pagination does not clear the user's selection.
  selected: new Set(),
};

function $(id){ return document.getElementById(id); }

async function init(){
  const url = chrome.runtime ? chrome.runtime.getURL('Dataset.csv') : '../Dataset.csv';
  const csv = await (await fetch(url)).text();
  const baseRows = parseCSV(csv);

  let combined = baseRows;
  try {
    const spamUrl = chrome.runtime ? chrome.runtime.getURL('SpamAssasin.csv') : '../SpamAssasin.csv';
    const spamCsv = await (await fetch(spamUrl)).text();
    const spamRows = parseSpamAssasinCSV(spamCsv);
    // Prefer real SpamAssassin email rows when available so Alerts
    // shows only live-looking data instead of dummy Dataset.csv rows.
    if (spamRows.length) {
      combined = spamRows;
    }
  } catch (e) {
    // If SpamAssasin.csv is missing, continue with base dataset only.
  }

  state.rows = combined;
  bindControls();
  applyFilters();
}

function bindControls(){
  document.querySelectorAll('input[name="severity"]').forEach(r => {
    r.addEventListener('change', () => { state.severity = r.value; state.page = 1; applyFilters(); });
  });
  $('search').addEventListener('input', (e) => { state.search = e.target.value.toLowerCase(); state.page = 1; applyFilters(); });
  $('from').addEventListener('change', (e) => { state.from = e.target.value; state.page = 1; applyFilters(); });
  $('to').addEventListener('change', (e) => { state.to = e.target.value; state.page = 1; applyFilters(); });
  $('selectAll').addEventListener('click', selectAll);
  $('export').addEventListener('click', exportAll);
  const prevBtn = $('prevPage');
  const nextBtn = $('nextPage');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (state.page > 1) {
        state.page -= 1;
        renderList();
        renderPager();
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      const total = state.filtered.length;
      const pages = Math.max(1, Math.ceil(total/state.perPage));
      if (state.page < pages) {
        state.page += 1;
        renderList();
        renderPager();
      }
    });
  }
}

function parseCSV(text){
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(lines.length <= 1) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line,i)=>{
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h,idx)=> row[h.trim()] = (parts[idx]||'').trim());
    row.__id = row.id || String(i+1);
    applyLabelMapping(row);
    // Prefer real timestamps from common date fields and only
    // fall back to synthetic dates when nothing is available.
    if (!row.received_at) {
      if (row.date) {
        row.received_at = row.date;
      } else if (row.timestamp) {
        row.received_at = row.timestamp;
      } else if (row.time) {
        row.received_at = row.time;
      } else {
        // Spread synthetic dates over recent days for demo purposes.
        const daysAgo = i % 14; // within last 2 weeks
        const d = new Date();
        d.setDate(d.getDate() - daysAgo);
        row.received_at = d.toISOString();
      }
    }
    return row;
  });
}

function splitCSVLine(line){
  const out=[]; let cur=''; let q=false; for(let i=0;i<line.length;i++){const c=line[i]; if(c==='"'){ if(q && line[i+1]==='"'){cur+='"'; i++;} else {q=!q;} } else if(c===',' && !q){ out.push(cur); cur=''; } else { cur+=c; }} out.push(cur); return out; }

function downsampleLines(dataLines, maxRows){
  const n = dataLines.length;
  if(n <= maxRows) return dataLines;
  const step = Math.ceil(n / maxRows);
  const sampled = [];
  for(let i=0;i<n;i+=step){ sampled.push(dataLines[i]); }
  return sampled;
}

// Parse SpamAssasin.csv and normalize legacy dates into the recent past
// so that Alerts date filters behave like a real-time feed.
function parseSpamAssasinCSV(text){
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(lines.length <= 1) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line,i)=>{
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h,idx)=> row[h.trim()] = (parts[idx]||'').trim());

    row.__id = row.id || String(i+1);
    // Prefer original SpamAssassin date for time-of-day, but shift
    // the calendar date into the last 30 days so UI filters feel live.
    let rawDate = row.date || '';
    let base = new Date();
    const daysAgo = i % 30; // spread across last 30 days
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

function applyLabelMapping(row){
  const lbl = row.label !== undefined && row.label !== '' ? Number(row.label) : NaN;
  const isPhishing = lbl === 1;
  let status;
  if (isPhishing) {
    status = 'DANGEROUS';
  } else if (row.urls || row.url || row.link) {
    // Benign emails that still contain URLs are treated as WARNING
    // so the Alerts list shows a richer mix of severities.
    status = 'WARNING';
  } else {
    status = 'SAFE';
  }
  row.status_id = status;
  if (!row.severity) {
    row.severity = isPhishing ? 'Critical' : (status === 'WARNING' ? 'Medium' : 'Low');
  }
  if (!row.type) {
    row.type = isPhishing ? 'Phishing URL' : 'Benign URL';
  }
}

function applyFilters(){
  const fromTs = state.from ? new Date(state.from).getTime() : null;
  const toTs = state.to ? new Date(state.to).getTime() : null;
  let filtered = state.rows.filter(r => {
    const status = (r.status_id||'').toUpperCase();
    if(state.severity !== 'ALL' && status !== state.severity) return false;
    const hay = (r.subject||'')+' '+(r.sender||'');
    if(state.search && hay.toLowerCase().indexOf(state.search) === -1) return false;
    const ts = r.received_at ? new Date(r.received_at).getTime() : null;
    if(fromTs && (!ts || ts < fromTs)) return false;
    if(toTs && (!ts || ts > toTs + 24*3600*1000 - 1)) return false;
    return true;
  });

  // Prefer SpamAssassin rows (which carry rich sender/subject) and
  // then sort newest first so real email alerts appear at the top.
  filtered = filtered.slice().sort((a, b) => {
    const aSource = a.source === 'spamassassin' ? 1 : 0;
    const bSource = b.source === 'spamassassin' ? 1 : 0;
    if (aSource !== bSource) return bSource - aSource;
    const aDate = a.received_at ? new Date(a.received_at).getTime() : 0;
    const bDate = b.received_at ? new Date(b.received_at).getTime() : 0;
    if (aDate !== bDate) return bDate - aDate;
    const aId = Number(a.__id) || 0;
    const bId = Number(b.__id) || 0;
    return bId - aId;
  });

  state.filtered = filtered;
  renderList();
  renderPager();
}

function renderList(){
  const ul = $('alerts');
  ul.innerHTML = '';
  const start = (state.page-1)*state.perPage;
  const pageRows = state.filtered.slice(start, start + state.perPage);
  pageRows.forEach((r, idx) => {
    const li = document.createElement('li');
    // Track the index into filtered so exportAll can map selections
    li.dataset.index = String(start + idx);
    const status = (r.status_id||'SAFE').toUpperCase();
    const badgeClass = status==='DANGEROUS'?'danger':status==='WARNING'?'warning':'safe';
    const when = r.received_at ? timeAgo(r.received_at) : '';
    li.innerHTML = `
      <span>
        <input type="checkbox" aria-label="select" style="margin-right:8px;" />
        <span class="badge ${badgeClass}"><span class="dot"></span>${status}</span>
        <strong style="margin-left:8px;">${escapeHtml(r.subject||'Untitled')}</strong>
        <span class="muted" style="margin-left:8px;">From: ${escapeHtml(r.sender||'')}</span>
      </span>
      <span class="muted">${escapeHtml(when)}</span>
    `;
    ul.appendChild(li);

    // Restore selection state for this row if it was previously
    // selected on another page.
    const cb = li.querySelector('input[type="checkbox"]');
    if (cb) {
      cb.checked = state.selected.has(r.__id);
      cb.addEventListener('change', () => {
        if (cb.checked) {
          state.selected.add(r.__id);
        } else {
          state.selected.delete(r.__id);
        }
      });
    }
  });
}

function renderPager(){
  const total = state.filtered.length;
  const pages = Math.max(1, Math.ceil(total/state.perPage));
  const info = $('pageInfo');
  if (info) {
    info.textContent = `Page ${state.page} / ${pages}`;
  }
  const prevBtn = $('prevPage');
  const nextBtn = $('nextPage');
  if (prevBtn) {
    prevBtn.disabled = state.page <= 1;
  }
  if (nextBtn) {
    nextBtn.disabled = state.page >= pages;
  }
}

function selectAll(){
  // Select all alerts currently visible on this page and persist
  // their IDs in state.selected so the choice survives pagination.
  const start = (state.page-1)*state.perPage;
  const pageRows = state.filtered.slice(start, start + state.perPage);
  pageRows.forEach(r => {
    if (r && r.__id != null) {
      state.selected.add(r.__id);
    }
  });
  document.querySelectorAll('#alerts input[type="checkbox"]').forEach(cb => { cb.checked = true; });
}

function exportAll(){
  // Export only selected emails across all pages; if none are
  // selected, fall back to exporting the full filtered set.
  const selectedRows = state.filtered.filter(r => state.selected.has(r.__id));
  const rowsToExport = selectedRows.length ? selectedRows : state.filtered;
  const csv = toCSV(rowsToExport);
  const blob = new Blob([csv], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'alerts_export.csv'; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

function toCSV(rows){
  if(!rows.length) return '';
  const headers = Object.keys(rows[0]).filter(k=>!k.startsWith('__'));
  const lines = [headers.join(',')];
  rows.forEach(r=>{
    lines.push(headers.map(h=>`"${String(r[h]||'').replace(/"/g,'""')}"`).join(','));
  });
  return lines.join('\n');
}

function timeAgo(iso){
  const t = new Date(iso).getTime(); if(!t) return '';
  let s = Math.floor((Date.now()-t)/1000);
  if (s < 0) s = 0; // clamp to avoid negative "-t s ago" glitches
  if(s<60) return `${s}s ago`;
  if(s<3600) return `${Math.floor(s/60)} mins ago`;
  if(s<86400) return `${Math.floor(s/3600)} hours ago`;
  return `${Math.floor(s/86400)} days ago`;
}

function escapeHtml(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

init();
