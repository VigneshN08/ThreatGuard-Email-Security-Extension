// Reports page logic
const state = {
  rows: [],
  countsByStatus: { SAFE: 0, WARNING: 0, DANGEROUS: 0 },
  countsByType: {},
  byDay: {},
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
    combined = combined.concat(spamRows);
  } catch (e) {
    // If SpamAssasin.csv is missing, continue with base dataset only.
  }

  loadData(combined);
  bind();

  // Initialize the date range to a recent window (last 7 days) so
  // the initial charts feel real-time and tied to the controls.
  const toInput = $('to');
  const fromInput = $('from');
  const typeSelect = $('reportType');

  // Default the Reports view to the last one week by forcing the
  // initial report type to weekly. Users can still change this
  // after load, but on first open they see a 7-day window.
  let rt = 'weekly';
  if (typeSelect) {
    typeSelect.value = 'weekly';
  }

  const today = new Date();
  const end = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const start = new Date(end);
  const daysBack = rt === 'monthly' ? 29 : rt === 'weekly' ? 6 : 0;
  start.setDate(start.getDate() - daysBack);

  const fmt = (d) => d.toISOString().slice(0, 10);
  if (fromInput) fromInput.value = fmt(start);
  if (toInput) toInput.value = fmt(end);

  const filteredInitial = filterByDate(state.rows, fromInput?.value, toInput?.value);
  computeAndRender(filteredInitial);
}

function bind(){
  const generateBtn = $('generate');
  if (generateBtn) {
    generateBtn.addEventListener('click', (e)=>{
      e.preventDefault();
      // For demo, recompute with optional date range
      const from = $('from')?.value;
      const to = $('to')?.value;
      const filtered = filterByDate(state.rows, from, to);
      computeAndRender(filtered);
    });
  }

  const dlCsvBtn = $('dlCsv');
  if (dlCsvBtn) dlCsvBtn.addEventListener('click', downloadCsv);

  const dlPdfBtn = $('dlPdf');
  if (dlPdfBtn) dlPdfBtn.addEventListener('click', ()=>alert('PDF export stub. Connect to server-side PDF later.'));

  const emailBtn = $('emailReport');
  if (emailBtn) emailBtn.addEventListener('click', ()=>alert('Email report stub. Wire to backend later.'));

  const typeSelect = $('reportType');
  if (typeSelect) {
    typeSelect.addEventListener('change', onReportTypeChange);
  }
}

function onReportTypeChange(){
  const typeSelect = $('reportType');
  const fromInput = $('from');
  const toInput = $('to');
  const rt = typeSelect ? typeSelect.value : 'daily';

  const today = new Date();
  const end = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const start = new Date(end);
  const daysBack = rt === 'monthly' ? 29 : rt === 'weekly' ? 6 : 0;
  start.setDate(start.getDate() - daysBack);

  const fmt = (d) => d.toISOString().slice(0, 10);
  if (fromInput) fromInput.value = fmt(start);
  if (toInput) toInput.value = fmt(end);

  const filtered = filterByDate(state.rows, fromInput?.value, toInput?.value);
  computeAndRender(filtered);
}

function parseCSV(text){
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(!lines.length) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line,i)=>{
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h,idx)=> row[h.trim()] = (parts[idx]||'').trim());
    row.__id = row.id || String(i+1);

    // Apply label mapping first so severity / type are consistent.
    applyLabelMapping(row);

    // Normalize Dataset.csv dates into the last 30 days, similar to
    // how we treat SpamAssassin, so that the Reports page behaves
    // like it is operating on recent, real-time data regardless of
    // how old the original CSV timestamps are.
    const daysAgo = i % 30;
    const base = new Date();
    base.setDate(base.getDate() - daysAgo);

    let parsed = null;
    const rawDate = row.date || row.timestamp || row.time || '';
    if (rawDate) {
      const d = new Date(rawDate);
      if (!isNaN(d.getTime())) parsed = d;
    }

    if (parsed) {
      base.setHours(parsed.getHours(), parsed.getMinutes(), parsed.getSeconds(), 0);
    } else {
      base.setHours(9 + (i % 9), (i * 7) % 60, 0, 0);
    }

    row.received_at = base.toISOString();
    return row;
  });
}

function splitCSVLine(line){ const out=[]; let cur=''; let q=false; for(let i=0;i<line.length;i++){const c=line[i]; if(c==='"'){ if(q && line[i+1]==='"'){cur+='"'; i++;} else {q=!q;} } else if(c===',' && !q){ out.push(cur); cur=''; } else { cur+=c; }} out.push(cur); return out; }

function downsampleLines(dataLines, maxRows){
  const n = dataLines.length;
  if(n <= maxRows) return dataLines;
  const step = Math.ceil(n / maxRows);
  const sampled = [];
  for(let i=0;i<n;i+=step){ sampled.push(dataLines[i]); }
  return sampled;
}

// Parse SpamAssasin.csv and normalize its historical dates into the
// last 30 days so that the Reports date range and trend charts behave
// like they are operating on recent data.
function parseSpamAssasinCSV(text){
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(!lines.length) return [];
  const headers = splitCSVLine(lines[0]);
  const dataLines = downsampleLines(lines.slice(1), 20000);
  return dataLines.map((line,i)=>{
    const parts = splitCSVLine(line);
    const row = {};
    headers.forEach((h,idx)=> row[h.trim()] = (parts[idx]||'').trim());

    row.__id = row.id || String(i+1);

    // Shift legacy SpamAssassin dates into the last 30 days while
    // preserving approximate time-of-day, so reports feel real-time.
    let rawDate = row.date || '';
    let base = new Date();
    const daysAgo = i % 30;
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
  const status = isPhishing ? 'DANGEROUS' : 'SAFE';
  row.status_id = status;
  if(!row.severity){ row.severity = isPhishing ? 'Critical' : 'Low'; }
  if(!row.type){ row.type = isPhishing ? 'Phishing URL' : 'Benign URL'; }
}

function loadData(rows){
  // Keep the raw combined dataset here; actual rendering should
  // always happen through computeAndRender() using either the
  // full set or a date-filtered subset so that the charts and
  // executive summary truly reflect the selected time window.
  state.rows = rows;
}

function filterByDate(rows, from, to){
  const fromTs = from ? new Date(from).getTime() : null;
  const toTs = to ? new Date(to).getTime() : null;
  return rows.filter(r=>{
    const ts = r.received_at ? new Date(r.received_at).getTime() : null;
    if(fromTs && (!ts || ts < fromTs)) return false;
    if(toTs && (!ts || ts > toTs + 24*3600*1000 - 1)) return false;
    return true;
  });
}

function computeAndRender(rows){
  state.countsByStatus = { SAFE: 0, WARNING: 0, DANGEROUS: 0 };
  state.countsByType = {};
  state.byDay = {};

  const typeSelect = $('reportType');
  const rt = typeSelect ? typeSelect.value : 'daily';

  rows.forEach(r=>{
    const s = (r.status_id||'SAFE').toUpperCase();
    if(state.countsByStatus[s]==null) state.countsByStatus[s]=0;
    state.countsByStatus[s]++;

    const t = r.type || 'Uncategorized';
    state.countsByType[t] = (state.countsByType[t]||0)+1;

    // For the Threat Trends chart, focus on dangerous / high severity
    // traffic and bucket it by day/week/month based on report type.
    const sev = (r.severity || '').toLowerCase();
    const isDangerous = s === 'DANGEROUS' || sev === 'critical' || sev === 'high';
    if (isDangerous) {
      const raw = (r.received_at||'').slice(0,10);
      if (!raw) return;
      let bucketKey = raw;
      if (rt === 'weekly') {
        const d = new Date(raw);
        if (!isNaN(d.getTime())) {
          const day = d.getDay();
          d.setDate(d.getDate() - day); // week start
          bucketKey = d.toISOString().slice(0,10);
        }
      } else if (rt === 'monthly') {
        bucketKey = raw.slice(0,7); // YYYY-MM
      }
      state.byDay[bucketKey] = (state.byDay[bucketKey]||0)+1;
    }
  });

  renderSummary(rows);
  renderRiskPie();
  renderTrendLine();
}

function renderSummary(rows){
  const total = rows.length;
  const high = state.countsByStatus.DANGEROUS || 0;
  $('sum-total').textContent = total;
  $('sum-high').textContent = high;
  // Accuracy and FP are static demo metrics in HTML; could compute if we have labels
}

function renderRiskPie(){
  const canvas = $('riskPie'); const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,canvas.width,canvas.height);
  const values = [state.countsByStatus.DANGEROUS||0, state.countsByStatus.WARNING||0, state.countsByStatus.SAFE||0];
  const colors = ['#ef4444','#f59e0b','#10b981'];
  const totalRaw = values.reduce((a,b)=>a+b,0);
  if (totalRaw === 0) {
    // No data for this range – show a friendly message instead of
    // an empty pie so users know the date filter is active.
    ctx.fillStyle = '#94a3b8';
    ctx.font = '13px system-ui';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText('No data in selected date range', 20, 24);
    return;
  }
  const total = totalRaw;
  let angle = -Math.PI/2; const cx = canvas.width/2, cy = canvas.height/2, r = Math.min(cx,cy)-10;
  values.forEach((v,i)=>{
    const slice = (v/total) * Math.PI*2;
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,angle,angle+slice); ctx.closePath(); ctx.fillStyle = colors[i]; ctx.fill();
    angle += slice;
  });
  // Legend
  const labels = ['Dangerous','Warning','Safe'];
  ctx.font='12px system-ui'; ctx.fillStyle='#000000';
  labels.forEach((l,i)=>{ ctx.fillStyle=colors[i]; ctx.fillRect(10,10+i*18,10,10); ctx.fillStyle='#000000'; ctx.fillText(`${l} (${values[i]})`, 26, 20+i*18); });
}

function renderTrendLine(){
  const canvas = $('trendLine'); const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,canvas.width,canvas.height);
  const days = Object.keys(state.byDay).sort();
  const vals = days.map(d=>state.byDay[d]);
  if(days.length===0){
    // Explicit feedback when the selected date range has no data
    ctx.fillStyle = '#94a3b8';
    ctx.font = '13px system-ui';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText('No data in selected date range', 20, 24);
    return;
  }
  const padding = {top:20,right:20,bottom:30,left:30};
  const w = canvas.width - padding.left - padding.right;
  const h = canvas.height - padding.top - padding.bottom;
  const max = Math.max(...vals);
  const min = Math.min(...vals);
  const step = w / Math.max(1, days.length-1);

  // Axes
  ctx.strokeStyle='#334155'; ctx.beginPath();
  ctx.moveTo(padding.left, padding.top); ctx.lineTo(padding.left, padding.top+h); ctx.lineTo(padding.left+w, padding.top+h); ctx.stroke();

  // Line
  ctx.strokeStyle='#6aa3ff'; ctx.lineWidth=2; ctx.beginPath();
  vals.forEach((v,i)=>{
    const x = padding.left + step * i;
    // Use min/max normalization so small changes between days
    // are visible even when counts are all relatively high.
    let norm = 0;
    if (max === min) {
      norm = 0.5; // flat mid-line when every day is identical
    } else {
      norm = (v - min) / (max - min);
    }
    const y = padding.top + (h - norm * h);
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  });
  ctx.stroke();

  // Points
  ctx.fillStyle='#93c5fd';
  vals.forEach((v,i)=>{
    const x = padding.left + step * i;
    let norm = 0;
    if (max === min) {
      norm = 0.5;
    } else {
      norm = (v - min) / (max - min);
    }
    const y = padding.top + (h - norm * h);
    ctx.beginPath(); ctx.arc(x,y,3,0,Math.PI*2); ctx.fill();
  });

  // X labels
  ctx.fillStyle='#000000'; ctx.font='11px system-ui'; ctx.textAlign='center';
  days.forEach((d,i)=>{
    const x = padding.left + step * i; ctx.fillText(d.slice(5), x, padding.top+h+18);
  });
}

function renderTopIndicators(){
  // Optional: original design showed a "top indicators" list, but the
  // current reports.html layout does not include that element. Make this
  // a safe no-op so missing markup never breaks chart rendering.
}

function downloadCsv(){
  const headers = ['day','count'];
  const lines = [headers.join(',')];
  Object.keys(state.byDay).sort().forEach(d=>{ lines.push(`${d},${state.byDay[d]}`); });
  const blob = new Blob([lines.join('\n')], {type:'text/csv'});
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'threat_trends.csv'; a.click(); setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

init();
