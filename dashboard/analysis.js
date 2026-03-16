// Email Analysis page interactions
function $(id){ return document.getElementById(id); }

const state = {
  batchRows: [],
  batchPage: 1,
  batchPageSize: 10,
};

const els = {
  subject: () => $('subject'),
  from: () => $('from'),
  body: () => $('body'),
  analyze: () => $('analyze'),
  results: () => $('results'),
  riskBadge: () => $('riskBadge'),
  riskLabel: () => $('riskLabel'),
  confidence: () => $('confidence'),
  indicators: () => $('indicators'),
  model: () => $('model'),
  batchCsv: () => $('batchCsv'),
  batchResults: () => $('batchResults'),
  batchTableBody: () => $('batchTableBody'),
  batchPrev: () => $('batchPrev'),
  batchNext: () => $('batchNext'),
  batchPageInfo: () => $('batchPageInfo'),
};

function init(){
  els.analyze().addEventListener('click', onAnalyze);
  if (els.batchCsv()) {
    els.batchCsv().addEventListener('change', onBatchCsv);
  }
  if (els.batchPrev()) {
    els.batchPrev().addEventListener('click', ()=>changeBatchPage(-1));
  }
  if (els.batchNext()) {
    els.batchNext().addEventListener('click', ()=>changeBatchPage(1));
  }
}

function onAnalyze(){
  const subject = els.subject().value.trim();
  const from = els.from().value.trim();
  const body = els.body().value.trim();
  // Very simple heuristic demo; replace with real API call later
  const risk = scoreEmail({subject, from, body});
  renderResults(risk);
}

function onBatchCsv(e){
  const file = e.target.files?.[0];
  if(!file) return;
  file.text().then(text => {
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (!lines.length) return;
    const headers = lines[0].split(',');
    const idx = {
      subject: headers.indexOf('subject'),
      sender: headers.indexOf('sender'),
    };
    let total = 0, count = 0;
    const perRows = [];
    lines.slice(1).forEach((line, i) => {
      const cols = splitCSVLine(line);
      const subject = idx.subject >= 0 ? (cols[idx.subject] || '') : '';
      const from = idx.sender >= 0 ? (cols[idx.sender] || '') : '';
      const res = scoreEmail({subject, from, body: ''});
      total += res.score; count++;
      perRows.push({
        id: i + 1,
        from,
        subject,
        level: res.level,
        score: res.score,
      });
    });
    if (!count) return;
    const avg = total / count;
    const level = avg>0.6?'DANGEROUS': avg>0.3?'WARNING':'SAFE';
    renderResults({
      level,
      score: avg,
      confidence: 0.8,
      indicators: ['Batch CSV analyzed'],
      model: { phishing: avg, spam: Math.max(0, 0.3-(avg/2)), legit: Math.max(0, 1-avg) }
    });

    state.batchRows = perRows;
    state.batchPage = 1;
    renderBatchTablePage();
  });
}

function changeBatchPage(delta){
  const totalPages = Math.max(1, Math.ceil(state.batchRows.length / state.batchPageSize));
  state.batchPage = Math.min(totalPages, Math.max(1, state.batchPage + delta));
  renderBatchTablePage();
}

function renderBatchTablePage(){
  const section = els.batchResults();
  const tbody = els.batchTableBody();
  const prevBtn = els.batchPrev();
  const nextBtn = els.batchNext();
  const info = els.batchPageInfo();
  if (!section || !tbody) return;

  const totalRows = state.batchRows.length;
  if (!totalRows){
    section.style.display = 'none';
    return;
  }

  const totalPages = Math.max(1, Math.ceil(totalRows / state.batchPageSize));
  const page = Math.min(totalPages, Math.max(1, state.batchPage));
  const start = (page - 1) * state.batchPageSize;
  const end = Math.min(start + state.batchPageSize, totalRows);

  tbody.innerHTML = '';
  state.batchRows.slice(start, end).forEach(r => {
    const tr = document.createElement('tr');
    const level = (r.level || '').toUpperCase();
    const badgeClass = level === 'DANGEROUS' ? 'danger' : level === 'WARNING' ? 'warning' : 'safe';
    tr.innerHTML = `
      <td>${r.id}</td>
      <td>${escapeHtml(r.from || '')}</td>
      <td>${escapeHtml(r.subject || '')}</td>
      <td><span class="badge ${badgeClass}"><span class="dot"></span>${level || '-'}</span></td>
      <td>${r.score != null ? r.score.toFixed(2) : '-'}</td>
    `;
    tbody.appendChild(tr);
  });

  section.style.display = '';
  if (info) {
    info.textContent = `Page ${page} of ${totalPages}`;
  }
  if (prevBtn) prevBtn.disabled = page <= 1;
  if (nextBtn) nextBtn.disabled = page >= totalPages;
}

function splitCSVLine(line){
  const out=[]; let cur=''; let q=false;
  for(let i=0;i<line.length;i++){
    const c=line[i];
    if(c==='"'){
      if(q && line[i+1]==='"'){cur+='"'; i++;}
      else {q=!q;}
    } else if(c===',' && !q){
      out.push(cur); cur='';
    } else {
      cur+=c;
    }
  }
  out.push(cur); return out;
}

function escapeHtml(str){
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scoreEmail({subject, from, body}){
  const s = (subject + ' ' + body).toLowerCase();
  let score = 0;
  if(/urgent|verify|suspended|account|action required|password/.test(s)) score += 0.4;
  if(/http:\/\//.test(s) || /https:\/\//.test(s)) score += 0.2;
  if(/.xyz|.ru|.top/.test(s)) score += 0.1;
  if(/support@|no-reply@/.test(from)) score += 0.1;
  if(score>1) score = 1;
  const level = score > 0.6 ? 'DANGEROUS' : score > 0.3 ? 'WARNING' : 'SAFE';
  const indicators = [];
  if(/urgent|verify|suspended|account|action required|password/.test(s)) indicators.push('Urgent/Verification language');
  if(/http:\/\//.test(s) || /https:\/\//.test(s)) indicators.push('Contains URLs');
  if(/.xyz|.ru|.top/.test(s)) indicators.push('Suspicious TLD');
  return { level, score, confidence: 0.9, indicators, model: { phishing: score, spam: Math.max(0, 0.3-(score/2)), legit: Math.max(0, 1-score) } };
}

function renderResults(r){
  els.results().style.display = '';
  const badge = els.riskBadge();
  badge.className = 'badge ' + (r.level==='DANGEROUS'?'danger': r.level==='WARNING'?'warning':'safe');
  els.riskLabel().textContent = `${r.level} (${r.score.toFixed(2)})`;
  els.confidence().textContent = `${Math.round((r.confidence||0)*100)}%`;

  const ind = els.indicators(); ind.innerHTML = '';
  (r.indicators||[]).forEach(t=>{ const li=document.createElement('li'); li.textContent = t; ind.appendChild(li); });

  const model = els.model(); model.innerHTML = '';
  const m = r.model || {}; const entries = [['Phishing Probability', m.phishing], ['Spam Probability', m.spam], ['Legitimate', m.legit]];
  entries.forEach(([k,v])=>{ const li=document.createElement('li'); li.textContent = `${k}: ${v!=null ? Math.round(v*100)+'%' : '-'}`; model.appendChild(li); });
}

init();
