/* ================= NKAMG Scanner 共享渲染库 (index / scan 两页共用) ================= */
'use strict';

/* ---------- 全局状态 ---------- */
let MAX_UPLOAD_MB = 10;   /* 上传上限 (MB), 由 /api/stats 动态同步 */
let STATS_HASH = 0;       /* SHA256 哈希签名条数 (用于未命中提示) */
let STATS_MD5 = 0;        /* MD5 哈希签名条数 (用于未命中提示) */

/* ---------- API 认证 (与后端 api_token 联动) ---------- */
const API_TOKEN = (() => {
  const t = new URLSearchParams(location.search).get('token');
  if (t) localStorage.setItem('nk_api_token', t);
  return localStorage.getItem('nk_api_token') || '';
})();
function authHeaders(extra) {
  const h = Object.assign({}, extra || {});
  if (API_TOKEN) h['Authorization'] = 'Bearer ' + API_TOKEN;
  return h;
}

/* ---------- 文件类型图标 / 判定方法 ---------- */
const ftCatIcons = {
  executable: '\u2699', document: '\u{1F4C4}', archive: '\u{1F4E6}',
  graphics: '\u{1F5BC}', media: '\u{1F3AC}', script: '\u{1F4DD}', mail: '\u2709',
  text: '\u{1F4C6}', disk: '\u{1F4BF}', 'ai-model': '\u{1F916}', data: '\u{1F5C2}',
  binary: '\u{1F576}', other: '\u2753'
};
const FT_METHOD = { 'magic': '魔数匹配', 'magic+ooxml': '魔数+OOXML解析', 'pattern': '模式搜索',
  'tail-magic': '尾部魔数', 'text-detect': '文本检测', 'fallback': '兜底判定',
  'empty': '空文件', 'n/a': '不可用' };

/* ---------- 图标 ---------- */
const ICON_CHECK = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.1V12a10 10 0 1 1-5.9-9.1"/><path d="M22 4L12 14l-3-3"/></svg>';
const ICON_X = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>';
const ICON_WARN = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>';
const ICON_CHECK_SM = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
const ICON_COPY = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const ICON_HASH = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/></svg>';
const ICON_INFO = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>';
const ICON_FINGER = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a10 10 0 0 0-10 10c0 1.8.5 3.6 1.3 5.1L2 22l5-1.2A10 10 0 1 0 12 2z"/><path d="M8 11h.01M12 11h.01M16 11h.01"/></svg>';
const ICON_PACK = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16.5 9.4L7.5 4.2"/><path d="M21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4a2 2 0 0 0 1-1.7z"/><path d="M3.3 7L12 12l8.7-5M12 22V12"/></svg>';
const ICON_PE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 8v8M12 8v8M15 8v3M15 14v.01"/></svg>';
const ICON_NOTE = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/></svg>';

/* 模糊哈希缺失原因 tooltip */
const FZ_TIP = {
  ssdeep: 'CTPH 模糊哈希；需 ≥32B，超过 256KB 上限跳过',
  tlsh: 'Trend Micro 局部敏感哈希；需 ≥50B 且内容复杂度足够',
  imphash: 'PE 导入表哈希；仅 PE 样本',
  authentihash: 'PE Authenticode 哈希（清零 CheckSum+安全目录后 SHA256）；仅 PE 样本'
};

/* ---------- 工具函数 ---------- */
function fmtHex(n) {
  if (n === null || n === undefined) return '-';
  return '0x' + Number(n).toString(16).toUpperCase();
}
function esc(s) { const d = document.createElement('span'); d.textContent = s ?? ''; return d.innerHTML; }
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}
function fmtNum(n) { return (n || 0).toLocaleString('en-US'); }

function copyHash(btn, val) {
  const done = () => {
    btn.classList.add('copied');
    btn.innerHTML = ICON_CHECK_SM;
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = ICON_COPY; }, 1400);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(val).then(done).catch(() => fallbackCopy(val, done));
  } else fallbackCopy(val, done);
}
function fallbackCopy(val, done) {
  const ta = document.createElement('textarea');
  ta.value = val; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta); done();
}

/* ================= 上传扫描 (两段式: /scan 上传 → /api/task/<id> 轮询) ================= */
/* onDone(card, result): 扫描完成/失败后的回调 (result 为合并结果, 失败为 null), 供 scan 页记录历史 */
function upload(file, results, emptyHint, onDone) {
  const card = mkScanCard(file, 'scan');
  if (onDone) card._onDone = onDone;
  pushCard(card, results, emptyHint);

  // 本地预检: 超过上限直接拒绝
  const limitBytes = MAX_UPLOAD_MB * 1024 * 1024;
  if (file.size > limitBytes) {
    renderErr(card, '"' + file.name + '" 为 ' + fmtSize(file.size) + ', 超过上传上限 ' + MAX_UPLOAD_MB + 'MB, 请压缩后重试', '文件过大');
    return;
  }

  const fd = new FormData();
  fd.append('file', file);
  fetch('/scan', { method: 'POST', headers: authHeaders(), body: fd })
    .then(r => r.json()
      .then(d => ({ ok: r.ok, status: r.status, d }))
      .catch(() => ({ ok: false, status: r.status, d: null })))
    .then(({ ok, status, d }) => {
      if (!ok) {
        if (status === 413) renderErr(card, '文件超过上传上限 ' + MAX_UPLOAD_MB + 'MB, 请压缩后重试', '文件过大');
        else if (d && d.error) renderErr(card, d.error);
        else renderErr(card, '请求失败 (HTTP ' + status + '), 请稍后重试');
        return;
      }
      if (d.error) { renderErr(card, d.error); return; }
      renderPhase1(card, d.result);
      if (d.status === 'phase2' && d.task_id) pollTask(card, d.task_id, true);
      else render(card, d.result);
    })
    .catch(e => renderErr(card, '网络错误: ' + e.message));
}

/* 轮询后台任务: phase1Shown=true 表示阶段1已渲染过 (POST /scan 直接返回),
   false 表示需在 phase2 期间用接口返回的 result 渲染阶段1 (从 URL ?task= 接管) */
function pollTask(card, taskId, phase1Shown) {
  fetch('/api/task/' + taskId, { headers: authHeaders() })
    .then(r => r.json())
    .then(d => {
      if (d.error) {
        if (phase1Shown) finalizePhase1(card, d.error);
        else renderErr(card, d.error);
      }
      else if (d.status === 'done') render(card, d.result);
      else if (d.status === 'error') renderErr(card, '深度分析失败: ' + d.error);
      else {
        if (d.result && !phase1Shown) renderPhase1(card, d.result);
        setTimeout(() => pollTask(card, taskId, true), 600);
      }
    })
    .catch(() => setTimeout(() => pollTask(card, taskId, phase1Shown), 1200));
}

/* 按 task_id 接管后台任务并渲染 (scan 页从 URL ?task= 进入时使用, 复用两段式轮询;
   无需重新上传, 服务端任务记录 + /api/task 轮询即可完整展示渐进式结果) */
function followTask(taskId, name, size, results, emptyHint, onDone) {
  const card = mkScanCard({ name: name || ('任务 ' + taskId), size: size || 0 }, 'scan');
  if (onDone) card._onDone = onDone;
  pushCard(card, results, emptyHint);
  pollTask(card, taskId, false);
}

/* ================= 结果卡片构建 ================= */
function mkScanCard(file, mode) {
  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML =
    '<div class="banner scanning">' +
      '<div class="banner-icon"><span class="spinner"></span></div>' +
      '<div class="banner-text">' +
        '<div class="banner-title">正在扫描…</div>' +
        '<div class="banner-sub"><b>' + esc(file.name) + '</b>' + (file.size ? ' · ' + fmtSize(file.size) : '') + '</div>' +
      '</div>' +
      '<div class="banner-ring ring-wrap" style="display:none"><svg class="ring" width="54" height="54" viewBox="0 0 54 54"></svg><div class="ring-label">检测引擎</div></div>' +
    '</div>' +
    '<div class="tabs">' +
      '<button class="tab active" data-tab="detections">检测结果<span class="cnt" id="detCnt">0</span></button>' +
      '<button class="tab" data-tab="details">详细信息</button>' +
    '</div>' +
    '<div class="panel panel-detections active"></div>' +
    '<div class="panel panel-details"></div>';
  card.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => switchTab(card, b.dataset.tab)));
  return card;
}

function switchTab(card, name) {
  card.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  card.querySelector('.panel-detections').classList.toggle('active', name === 'detections');
  card.querySelector('.panel-details').classList.toggle('active', name === 'details');
}

/* 阶段1: 哈希 + 类型 + 签名库命中立即展示 */
function renderPhase1(card, d) {
  const banner = card.querySelector('.banner');
  const detPanel = card.querySelector('.panel-detections');
  const detPanelD = card.querySelector('.panel-details');

  const hashHits = d.detections.filter(x => x.engine === 'Hash DB');
  const verdictColor = hashHits.length ? 'detected' : 'scanning';

  banner.className = 'banner ' + verdictColor;
  if (hashHits.length) {
    banner.querySelector('.banner-icon').innerHTML = ICON_X;
    banner.querySelector('.banner-title').textContent = hashHits.length + ' 个引擎将此文件标记为恶意';
    banner.querySelector('.banner-sub').innerHTML =
      '<b>' + esc(d.filename) + '</b> · ' + esc(d.size_human) + ' · ' + esc(d.file_type);
    banner.querySelector('.ring-wrap').style.display = '';
    setRing(card, hashHits.length, 1, 'detected');
  } else {
    banner.querySelector('.banner-icon').innerHTML = '<span class="spinner"></span>';
    banner.querySelector('.banner-title').textContent = '正在扫描…';
    banner.querySelector('.banner-sub').innerHTML =
      '<b>' + esc(d.filename) + '</b> · ' + esc(d.size_human) + ' · ' + esc(d.file_type);
    banner.querySelector('.ring-wrap').style.display = 'none';
  }

  /* 检测结果 tab: 哈希命中 + YARA pending */
  let rows = '';
  rows += engRow('h', 'H', 'Hash DB', hashHits,
    '<span class="spinner" style="width:14px;height:14px"></span> <span>YARA 规则匹配中…</span>');
  detPanel.innerHTML = '<div class="det-table">' + rows + '</div>' +
    '<div class="pending"><span class="spinner"></span>YARA 规则匹配 · 模糊哈希 · 查壳分析进行中…</div>';
  card.querySelector('#detCnt').textContent = hashHits.length;

  /* 详细信息 tab: 类型 + 哈希立即可见 */
  detPanelD.innerHTML = ftypeRow(d) + '<div class="dsec"><div class="dsec-head">' + ICON_HASH + '文件哈希</div>' +
    '<div class="dsec-body">' + hashRows(d) + '</div></div>' +
    '<div class="pending" style="margin-top:16px"><span class="spinner"></span>深度分析（模糊哈希 / PE 元数据 / 查壳）完成后更新…</div>';
}

function finalizePhase1(card, msg) {
  const p = card.querySelector('.panel-detections .pending');
  if (p) p.innerHTML = '&#9888; 深度分析结果不可用: ' + esc(msg);
}

/* 完整结果渲染 (阶段2 完成后) */
function render(card, d) {
  card.classList.remove('updated');
  void card.offsetWidth;
  card.classList.add('updated');

  const banner = card.querySelector('.banner');
  banner.className = 'banner ' + (d.clean ? 'clean' : 'detected');
  banner.querySelector('.banner-icon').innerHTML = d.clean ? ICON_CHECK : ICON_X;
  banner.querySelector('.banner-title').textContent =
    d.clean ? '未发现已知威胁' : d.detections.length + ' 个引擎将此文件标记为恶意';
  banner.querySelector('.banner-sub').innerHTML =
    '<b>' + esc(d.filename) + '</b> · ' + esc(d.size_human) + ' · ' + esc(d.file_type);

  /* 检测环: n/m (参与引擎数) */
  const n = d.detections.length;
  const m = d.scanners.length || 1;
  banner.querySelector('.ring-wrap').style.display = '';
  setRing(card, n, m, d.clean ? 'clean' : 'detected');

  /* 检测结果 tab */
  card.querySelector('#detCnt').textContent = n;
  card.querySelector('.panel-detections').innerHTML = detectionsTable(d) + scanInfoLine(d);
  card.querySelector('.panel-details').innerHTML = ftypeRow(d) + detailsBlocks(d);

  switchTab(card, 'detections');
  if (card._onDone) card._onDone(card, d);
}

/* ================= 检测结果表 ================= */
function engRow(iconCls, letter, label, hits, extraHtml) {
  const hasHits = hits && hits.length;
  let cell;
  if (hasHits) {
    cell = hits.map(x =>
      '<div style="padding:4px 0"><div class="det-name">' + esc(x.name) +
      (x.engine === 'Hash DB' ? '<span class="badge">' + (x.detail && x.detail.startsWith('MD5') ? 'MD5' : 'SHA256') + '</span>' :
       x.engine === 'Fuzzy Hash DB' && x.fuzzy ? '<span class="badge">' + Object.keys(x.fuzzy).filter(k => x.fuzzy[k]).join('+') + '</span>' : '') + '</div>' +
      (x.detail ? '<div class="det-detail">' + esc(x.detail) + '</div>' : '') +
      (x.fuzzy ? '<div class="det-detail" style="color:var(--text-faint)">' + fuzzySummary(x.fuzzy) + '</div>' : '') + '</div>').join('');
  } else if (extraHtml) {
    cell = '<div class="det-verdict pending">' + extraHtml + '</div>';
  } else {
    cell = '<div class="det-verdict ok">' + ICON_CHECK_SM + '未检测到</div>';
  }
  return '<div class="det-row' + (hasHits ? ' hit' : '') + '" style="display:flex;align-items:center;gap:14px;padding:13px 14px;border-bottom:1px solid var(--border-soft)">' +
    '<div class="engine-cell"><span class="e-icon ' + iconCls + '">' + letter + '</span>' + esc(label) + '</div>' +
    '<div style="flex:1;min-width:0">' + cell + '</div></div>';
}

/* Fuzzy 命中的 5 字段概要 (ssdeep 截断为 40 字符, 其余完整) */
function fuzzySummary(fz) {
  const items = [];
  if (fz.ssdeep) items.push('ssdeep: ' + (fz.ssdeep.length > 40 ? fz.ssdeep.slice(0, 40) + '…' : fz.ssdeep));
  if (fz.vhash) items.push('vhash: ' + fz.vhash);
  if (fz.authentihash) items.push('authentihash: ' + fz.authentihash);
  if (fz.imphash) items.push('imphash: ' + fz.imphash);
  if (fz.rich_header_hash) items.push('rich_header_hash: ' + fz.rich_header_hash);
  return items.join(' · ');
}

function detectionsTable(d) {
  const dets = d.detections || [];
  const yaraAvailable = (d.scanners || []).some(s => /YARA/i.test(s));
  const hashHits = dets.filter(x => x.engine === 'Hash DB');
  const yaraHits = dets.filter(x => x.engine === 'YARA');
  const fuzzyHits = dets.filter(x => x.engine === 'Fuzzy Hash DB');

  let html = '<div class="det-table">';
  html += engRow('h', 'H', 'Hash DB', hashHits);
  if (fuzzyHits.length) html += engRow('f', 'F', 'Fuzzy Hash DB', fuzzyHits);
  if (yaraAvailable) html += engRow('y', 'Y', 'YARA', yaraHits);
  /* 加壳启发 (辅助信息) */
  const pk = (d.static_info || {}).packer;
  if (pk && pk.detected && pk.packers && pk.packers.length) {
    html += '<div class="det-row hit" style="display:flex;align-items:center;gap:14px;padding:13px 14px;border-bottom:1px solid var(--border-soft)">' +
      '<div class="engine-cell"><span class="e-icon p">P</span>加壳启发</div>' +
      '<div style="flex:1"><div class="det-name">' + pk.packers.map(p => esc(p.name)).join(' / ') + '</div>' +
      '<div class="det-detail">启发评分 ' + pk.packed_score + ' / 100</div></div></div>';
  }
  html += '</div>';
  return html;
}

function scanInfoLine(d) {
  return '<div class="scan-info">耗时 ' + esc(d.elapsed_ms) + ' ms' +
    (d.static_ms ? '<span class="sep">·</span> 静态分析 ' + esc(d.static_ms) + ' ms' : '') +
    '<span class="sep">·</span> 参与引擎:' +
    (d.scanners || []).map(s => '<span class="engine-chip">' + esc(s) + '</span>').join('') + '</div>';
}

/* ================= 详细信息 ================= */
function ftypeRow(d) {
  const fti = d.file_type_info || {};
  const cat = fti.category || 'other';
  const methodName = FT_METHOD[fti.method] || fti.method || '';
  return '<div class="ftype-row">' +
    '<span class="ft-icon">' + (ftCatIcons[cat] || ftCatIcons.other) + '</span>' +
    '<span class="ft-name">' + esc(fti.name || d.file_type) + '</span>' +
    '<span class="ft-cat ' + cat + '">' + esc(cat) + '</span>' +
    (fti.cl_type && fti.cl_type !== 'CL_TYPE_ANY' ? '<span class="ft-code">' + esc(fti.cl_type) + '</span>' : '') +
    (methodName ? '<span class="ft-method">' + methodName + '</span>' : '') +
    '</div>';
}

function hashRows(d) {
  const rows = [
    ['SHA256', d.sha256], ['SHA1', d.sha1], ['MD5', d.md5]
  ];
  return rows.map(([label, val]) =>
    '<div class="hash-row"><span class="h-label">' + label + '</span>' +
    '<span class="h-val">' + esc(val) + '</span>' +
    '<button class="copy-btn" title="复制" onclick="copyHash(this,\'' + esc(val) + '\')">' + ICON_COPY + '</button></div>').join('');
}

function detailsBlocks(d) {
  const si = d.static_info;
  let html = '<div class="detail-grid">';
  html += '<div class="dsec"><div class="dsec-head">' + ICON_HASH + '文件哈希</div><div class="dsec-body">' + hashRows(d) + '</div></div>';

  html += '<div class="dsec"><div class="dsec-head">' + ICON_INFO + '基本信息</div><div class="dsec-body"><div class="kv">' +
    '<span class="k">文件类型</span><span class="v">' + esc(d.file_type) + '</span>' +
    '<span class="k">大小</span><span class="v">' + esc(d.size_human) + ' (' + fmtSize(d.size) + ')</span>' +
    '<span class="k">扫描耗时</span><span class="v">' + esc(d.elapsed_ms) + ' ms' + (d.static_ms ? '（含静态 ' + esc(d.static_ms) + ' ms）' : '') + '</span>' +
    '<span class="k">参与引擎</span><span class="v">' + (d.scanners || []).map(esc).join(' + ') + '</span>' +
    '</div></div></div>';

  /* 模糊哈希 */
  if (si && si.fuzzy) {
    const fz = si.fuzzy;
    const keys = ['ssdeep', 'tlsh', 'imphash', 'authentihash'];
    html += '<div class="dsec"><div class="dsec-head">' + ICON_FINGER + '模糊哈希</div><div class="dsec-body"><div class="fuzzy">' +
      keys.map(k => {
        const v = fz[k];
        if (v) return '<span class="k">' + k + '</span><span class="v">' + esc(v) + '</span>';
        return '<span class="k">' + k + '</span><span class="v na" title="' + esc(FZ_TIP[k] || '不可用') + '">-</span>';
      }).join('') + '</div></div></div>';
  }

  /* 壳检测 */
  if (si && si.packer) html += packerBlock(si.packer);

  /* PE 元数据 */
  if (si && si.pe) html += peBlock(si.pe);

  /* 说明 */
  const notes = (si && si.notes) || [];
  if (d.phase2_note) notes.unshift({ __raw: d.phase2_note });
  if (notes.length) {
    html += '<div class="dsec"><div class="dsec-head">' + ICON_NOTE + '说明</div><div class="dsec-body"><div class="notes">' +
      notes.map(n => '<div>' + (n.__raw !== undefined ? esc(n.__raw) : esc(n)) + '</div>').join('') + '</div></div></div>';
  }
  html += '</div>';
  return html;
}

function packerBlock(pk) {
  let html = '<div class="dsec"><div class="dsec-head">' + ICON_PACK + '壳 / Packer 识别</div><div class="dsec-body"><div class="pk-head">';
  if (pk.detected && pk.packers.length) {
    html += pk.packers.map(p =>
      '<span class="pk-badge ' + esc(p.confidence || 'low') + '">' + esc(p.name) +
      ' <i>' + esc(p.confidence || '') + '</i></span>').join('');
    html += '<span class="pk-score">加壳评分 ' + pk.packed_score + ' / 100</span>';
  } else {
    html += '<span class="pk-clean">' + ICON_CHECK_SM + '未检测到已知壳</span>';
    if (pk.packed_score > 0) html += '<span class="pk-score">启发评分 ' + pk.packed_score + ' / 100</span>';
  }
  if (pk.yara_rules_loaded > 0) {
    const yTip = pk.yara_error ? ('规则加载警告: ' + pk.yara_error) : '外部 YARA 扩展壳库规则';
    html += '<span class="pk-yara' + (pk.yara_error ? ' err' : '') + '" title="' + esc(yTip) + '">外部规则 <b>' + pk.yara_rules_loaded + '</b> 条</span>';
  }
  html += '</div>';
  (pk.packers || []).forEach(p => {
    if (p.signals && p.signals.length)
      html += '<div class="pk-sig"><b>' + esc(p.name) + '</b> ' + p.signals.map(esc).join('；') + '</div>';
  });
  if (pk.heuristics && pk.heuristics.length)
    html += '<div class="pk-heu">' + pk.heuristics.map(h =>
      '<span title="启发式信号">' + esc(h.label) + '</span>').join('') + '</div>';
  html += '</div></div>';
  return html;
}

function peBlock(pe) {
  let html = '<div class="dsec"><div class="dsec-head">' + ICON_PE + 'PE 元数据</div><div class="dsec-body">';
  html += '<div class="pe-grid">' +
    '<div><div class="k">Machine</div><div class="v">' + esc(pe.machine) + '</div></div>' +
    '<div><div class="k">架构</div><div class="v">' + (pe.is_64bit ? '64-bit' : '32-bit') + '</div></div>' +
    '<div><div class="k">编译时间</div><div class="v">' + esc(pe.timestamp || '-') + '</div></div>' +
    '<div><div class="k">Subsystem</div><div class="v">' + esc(pe.subsystem) + '</div></div>' +
    '<div><div class="k">入口点</div><div class="v">' + esc(pe.entry_point) + '</div></div>' +
    '<div><div class="k">ImageBase</div><div class="v">' + esc(pe.image_base) + '</div></div>' +
    '</div>';
  if (pe.sections && pe.sections.length) {
    html += '<table class="pe-tbl"><tr><th>节区</th><th>VirtualSize</th><th>RawSize</th><th>Flags</th></tr>' +
      pe.sections.map(s =>
        '<tr><td>' + esc(s.name) + '</td><td class="sz">' + fmtHex(s.vsize) + '</td>' +
        '<td class="sz">' + fmtHex(s.rsize) + '</td><td>' + esc(s.flags) + '</td></tr>').join('') + '</table>';
  }
  if (pe.imports && pe.imports.length) {
    html += '<div class="imports">' + pe.imports.map(i => {
      const shown = i.funcs.slice(0, 8);
      const more = i.funcs.length > 8 ? ' … 等 ' + i.funcs.length + ' 个' : '';
      return '<div class="imp-dll"><b>' + esc(i.dll) + '</b> <span class="imp-fn">' + shown.map(esc).join(', ') + more + '</span></div>';
    }).join('') + '</div>';
  }
  html += '</div></div>';
  return html;
}

/* ================= 检测环 (SVG) ================= */
function setRing(card, n, m, kind) {
  const svg = card.querySelector('.ring');
  const C = 2 * Math.PI * 22;
  const frac = m > 0 ? n / m : 0;
  const color = kind === 'clean' ? '#34d17b' : '#f2555d';
  svg.innerHTML =
    '<circle cx="27" cy="27" r="22" fill="none" stroke="#262e3d" stroke-width="6"/>' +
    '<circle cx="27" cy="27" r="22" fill="none" stroke="' + color + '" stroke-width="6" ' +
      'stroke-dasharray="' + C.toFixed(1) + '" stroke-dashoffset="' + (C * (1 - frac)).toFixed(1) + '" ' +
      'stroke-linecap="round" transform="rotate(-90 27 27)" style="transition:stroke-dashoffset .6s ease"/>' +
    '<text x="27" y="31.5" text-anchor="middle" font-size="13" font-weight="700" ' +
      'font-family="Cascadia Code,Consolas,monospace" fill="' + color + '">' + n + '/' + m + '</text>';
}

/* ================= 错误 / 工具 ================= */
function renderErr(card, msg, title) {
  const banner = card.querySelector('.banner');
  banner.className = 'banner error';
  banner.querySelector('.banner-icon').innerHTML = ICON_WARN;
  banner.querySelector('.banner-title').textContent = title || '扫描失败';
  banner.querySelector('.banner-sub').innerHTML = esc(msg);
  const tabs = card.querySelector('.tabs'); if (tabs) tabs.style.display = 'none';
  const det = card.querySelector('.panel-detections'); if (det) det.classList.add('active');
  const dtd = card.querySelector('.panel-details'); if (dtd) dtd.style.display = 'none';
  if (det) det.innerHTML = '<div class="det-verdict pending" style="gap:8px">' + ICON_WARN +
    '<span style="color:var(--amber)">' + esc(msg) + '</span></div>';
  if (card._onDone) card._onDone(card, null);
}

function mkErrCard(title, msg) {
  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML =
    '<div class="banner error"><div class="banner-icon">' + ICON_WARN + '</div>' +
    '<div class="banner-text"><div class="banner-title">' + esc(title) + '</div>' +
    '<div class="banner-sub">' + esc(msg) + '</div></div></div>';
  return card;
}

function pushCard(card, results, emptyHint) {
  results.prepend(card);
  if (emptyHint) emptyHint.style.display = 'none';
}

/* ================= 哈希查询 (VT 搜索框 / scan 最近扫描复用) ================= */
/* 支持 32 位 hex (MD5) 与 64 位 hex (SHA256), 由后端 /api/hash/<h> 按长度路由到对应库 */
function lookupHashCard(raw, results, emptyHint, displayName) {
  const v = (raw || '').trim().toLowerCase();
  if (!v) return;
  let algo = null, label = '';
  if (/^[0-9a-f]{32}$/.test(v)) { algo = 'md5'; label = 'MD5'; }
  else if (/^[0-9a-f]{64}$/.test(v)) { algo = 'sha256'; label = 'SHA256'; }
  if (!algo) {
    pushCard(mkErrCard('无效的哈希', '请输入 32 位 (MD5) 或 64 位 (SHA256) 十六进制哈希（0-9 / a-f），例如：' +
      'a'.repeat(32) + ' 或 ' + 'a'.repeat(64)), results, emptyHint);
    return;
  }
  const card = mkScanCard({ name: displayName || (v + '.' + algo), size: 0 }, 'query');
  card.querySelector('.banner-title').textContent = '正在查询签名库…';
  card.querySelector('.banner-sub').innerHTML = label + ' <b>' + v + '</b>';
  pushCard(card, results, emptyHint);
  fetch('/api/hash/' + v, { headers: authHeaders() })
    .then(r => r.json())
    .then(d => {
      if (d.error) { renderErr(card, d.error); return; }
      if (d.hit) {
        card.querySelector('.banner').className = 'banner detected';
        card.querySelector('.banner-icon').innerHTML = ICON_X;
        card.querySelector('.banner-title').textContent = d.detections.length + ' 个引擎将此哈希标记为恶意';
        card.querySelector('.banner-sub').innerHTML = label + ' <b>' + v + '</b> · 命中签名库';
        const t = card.querySelector('.tabs'); t.style.display = 'none';
        card.querySelector('.panel-details').innerHTML =
          '<div class="det-table">' + d.detections.map(x => {
            const isFuzzy = x.engine === 'Fuzzy Hash DB';
            return '<div class="det-row hit" style="display:flex;justify-content:space-between;padding:12px 14px;border-bottom:1px solid rgba(242,85,93,.14)">' +
              '<div style="min-width:0"><div class="det-name">' + esc(x.name) +
              (isFuzzy && x.fuzzy ? '<span class="badge">' + Object.keys(x.fuzzy).filter(k => x.fuzzy[k]).join('+') + '</span>' : '') + '</div>' +
              '<div class="det-detail">' + esc(x.detail || '') + '</div>' +
              (isFuzzy && x.fuzzy ? '<div class="det-detail" style="color:var(--text-faint)">' + fuzzySummary(x.fuzzy) + '</div>' : '') + '</div>' +
              '<span class="engine-cell" style="flex:none"><span class="e-icon ' + (isFuzzy ? 'f' : 'h') + '">' + (isFuzzy ? 'F' : 'H') + '</span> ' +
              (isFuzzy ? 'Fuzzy Hash DB' : 'Hash DB') + '<span class="badge">' + (isFuzzy ? '' : label) + '</span></span></div>';
          }).join('') +
          '</div>';
        card.querySelector('.ring-wrap').style.display = '';
        setRing(card, d.detections.length, 1, 'detected');
      } else {
        card.querySelector('.banner').className = 'banner clean';
        card.querySelector('.banner-icon').innerHTML = ICON_CHECK;
        card.querySelector('.banner-title').textContent = '未在签名库中找到此哈希';
        card.querySelector('.banner-sub').innerHTML = label + ' <b>' + v + '</b> · 该样本尚未被标记';
        const t = card.querySelector('.tabs'); t.style.display = 'none';
        const total = label === 'MD5' ? (STATS_MD5 || 0) : (STATS_HASH || 0);
        card.querySelector('.panel-details').innerHTML =
          '<div class="det-verdict ok" style="gap:8px">' + ICON_CHECK_SM +
          '<span>签名库（' + fmtNum(total) + ' 条 ' + label + '）中不存在此哈希，未命中任何已知恶意签名。</span></div>';
        card.querySelector('.ring-wrap').style.display = 'none';
      }
    })
    .catch(e => renderErr(card, '网络错误: ' + e.message));
}

/* ================= 统计 / 引擎状态加载 ================= */
function loadStats(onStats) {
  fetch('/api/stats', { headers: authHeaders() }).then(r => r.json()).then(s => {
  MAX_UPLOAD_MB = s.max_upload_mb || 10;
  STATS_HASH = s.hash_signatures || 0;
  STATS_MD5 = s.md5_signatures || 0;

  const maxMb = document.getElementById('maxMb'); if (maxMb) maxMb.textContent = MAX_UPLOAD_MB;
  const hc = document.getElementById('hashCount'); if (hc) hc.textContent = fmtNum(s.hash_signatures);
  const mc = document.getElementById('md5Count'); if (mc) mc.textContent = s.md5_available ? fmtNum(s.md5_signatures) : 'N/A';
  const fc = document.getElementById('fuzzyCount'); if (fc) fc.textContent = s.fuzzy_available ? fmtNum(s.fuzzy_signatures) : 'N/A';
  const yc = document.getElementById('yaraCount'); if (yc) yc.textContent = s.yara_available ? fmtNum(s.yara_rules) : 'N/A';
  const pc = document.getElementById('pkCount'); if (pc) pc.textContent = s.packer_yara_available ? fmtNum(s.packer_yara_rules) : 'N/A';
    const st = s.storage || {};
    const ds = document.getElementById('dbSize'); if (ds) ds.textContent = st.db_size_mb ? st.db_size_mb.toFixed(0) + ' MB' : '-';

    const pill = document.getElementById('enginePill');
    const txt = document.getElementById('engineText');
    if (pill && txt) {
      const ok = s.yara_available && s.packer_yara_available;
      pill.classList.add(ok ? 'ok' : 'warn');
      txt.textContent = ok ? '引擎正常' : (s.yara_available ? '壳库降级' : 'YARA 降级');
    }
    if (onStats) onStats(s);
  }).catch(() => {});
}
