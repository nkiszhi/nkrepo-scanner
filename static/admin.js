/* ================= 哈希管理页面行为 ================= */
'use strict';
/* 复用 app.js 的 esc / fmtNum / loadStats; 会话认证走 cookie (同源自动带凭据) */

const toastEl = document.getElementById('toast');
function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toastEl._t);
  toastEl._t = setTimeout(() => toastEl.classList.remove('show'), 2600);
}

/* 哈希校验: 32hex(MD5) / 64hex(SHA256) */
function validHash(v) {
  v = (v || '').trim().toLowerCase();
  return /^[0-9a-f]{32}$/.test(v) || /^[0-9a-f]{64}$/.test(v) ? v : null;
}

/* 把 JSON 错误/结果渲染进 result-box */
function setBox(el, cls, html) {
  el.innerHTML = '<div class="' + cls + '">' + html + '</div>';
}
function setErr(el, msg) { setBox(el, 'result-err', esc(msg)); }
function setInfo(el, html) { setBox(el, 'result-info', html); }
function setOk(el, html) { setBox(el, 'result-ok', html); }

/* ---------- 添加哈希 ---------- */
const addHash = document.getElementById('addHash');
const addSize = document.getElementById('addSize');
const addName = document.getElementById('addName');
const addBtn = document.getElementById('addBtn');
const addResult = document.getElementById('addResult');

addBtn.addEventListener('click', () => {
  const h = validHash(addHash.value);
  if (!h) { setErr(addResult, '哈希格式无效：需 32 位(MD5) 或 64 位(SHA256) 十六进制'); return; }
  addBtn.disabled = true;
  fetch('/api/admin/hash', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash: h, size: addSize.value.trim() || '*', name: addName.value.trim() })
  }).then(r => r.json().then(d => ({ ok: r.ok, d })))
    .then(({ ok, d }) => {
      if (!ok || d.error) { setErr(addResult, d.error || ('请求失败 (HTTP)')); return; }
      const algo = d.hash_algo ? d.hash_algo.toUpperCase() : '';
      setOk(addResult, (d.added ? '已新增 1 条 ' : '该签名已存在，未重复插入 ')
        + '<span class="mono">' + algo + '</span>' + renderHashKV(d.hash, algo, d.total));
      addHash.value = ''; addSize.value = ''; addName.value = '';
      loadStats();
    }).catch(e => setErr(addResult, '网络错误: ' + e.message))
    .finally(() => addBtn.disabled = false);
});

/* ---------- 查询 / 删除 ---------- */
const qHash = document.getElementById('qHash');
const lookupBtn = document.getElementById('lookupBtn');
const delBtn = document.getElementById('delBtn');
const qResult = document.getElementById('qResult');

lookupBtn.addEventListener('click', () => {
  const h = validHash(qHash.value);
  if (!h) { setErr(qResult, '哈希格式无效：需 32 位(MD5) 或 64 位(SHA256) 十六进制'); return; }
  lookupBtn.disabled = true;
  fetch('/api/admin/hash/' + h).then(r => r.json().then(d => ({ ok: r.ok, d })))
    .then(({ ok, d }) => {
      if (!ok || d.error) { setErr(qResult, d.error || '请求失败'); return; }
      const algo = d.hash_algo ? d.hash_algo.toUpperCase() : '';
      if (d.hit) {
        setInfo(qResult, '<b>命中签名库</b>' + renderHashKV(d.hash, algo, null)
          + '<div style="margin-top:8px">' + (d.detections || []).map(x =>
            '<div class="det-line"><div class="dn">' + esc(x.name) + '</div>'
            + '<div class="dd">' + esc(x.detail || '') + '</div></div>').join('') + '</div>');
      } else {
        setInfo(qResult, '未在签名库中找到此哈希' + renderHashKV(d.hash, algo, null));
      }
    }).catch(e => setErr(qResult, '网络错误: ' + e.message))
    .finally(() => lookupBtn.disabled = false);
});

delBtn.addEventListener('click', () => {
  const h = validHash(qHash.value);
  if (!h) { setErr(qResult, '哈希格式无效：需 32 位(MD5) 或 64 位(SHA256) 十六进制'); return; }
  if (!confirm('确认从签名库删除该哈希？\n' + h)) return;
  delBtn.disabled = true;
  fetch('/api/admin/hash/' + h, { method: 'DELETE' }).then(r => r.json().then(d => ({ ok: r.ok, d })))
    .then(({ ok, d }) => {
      if (!ok || d.error) { setErr(qResult, d.error || '请求失败'); return; }
      const algo = d.hash_algo ? d.hash_algo.toUpperCase() : '';
      setOk(qResult, (d.deleted ? '已删除 1 条 ' : '该哈希不在库中，未删除 ')
        + '<span class="mono">' + algo + '</span>' + renderHashKV(d.hash, algo, d.total));
      qHash.value = '';
      loadStats();
    }).catch(e => setErr(qResult, '网络错误: ' + e.message))
    .finally(() => delBtn.disabled = false);
});

/* ---------- 批量导入 ---------- */
const dz = document.getElementById('dz');
const fi = document.getElementById('fi');
const impResult = document.getElementById('impResult');

function importFiles(files) {
  const arr = [...files];
  if (!arr.length) return;
  let pending = arr.length;
  impResult.innerHTML = '';
  arr.forEach(f => {
    const box = document.createElement('div');
    setInfo(box, '<b>' + esc(f.name) + '</b> 导入中…');
    impResult.appendChild(box);
    const fd = new FormData();
    fd.append('file', f);
    fetch('/api/admin/import', { method: 'POST', body: fd })
      .then(r => r.json().then(d => ({ ok: r.ok, d })))
      .then(({ ok, d }) => {
        if (!ok || d.error) { setErr(box, esc(f.name) + ' 导入失败: ' + (d.error || '请求失败')); return; }
        let msg = '<b>' + esc(d.saved) + '</b> 导入完成';
        if (d.type === 'hash') {
          msg += '（SHA256 +' + fmtNum(d.sha256_added) + '，MD5 +' + fmtNum(d.md5_added) + '）';
          msg += '<div class="kv2"><span class="k">SHA256 总数</span><span class="v">' + fmtNum(d.sha256_total) + '</span>'
            + '<span class="k">MD5 总数</span><span class="v">' + fmtNum(d.md5_total) + '</span></div>';
        } else if (d.type === 'yara') {
          msg += '（YARA +' + fmtNum(d.yara_added) + ' 条）';
          msg += '<div class="kv2"><span class="k">YARA 总数</span><span class="v">' + fmtNum(d.yara_total) + '</span></div>';
        }
        setOk(box, msg);
      }).catch(e => setErr(box, esc(f.name) + ' 网络错误: ' + e.message))
      .finally(() => {
        if (--pending === 0) loadStats();
      });
  });
}

dz.addEventListener('click', e => { if (e.target.id !== 'fi') fi.click(); });
dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('over'); });
dz.addEventListener('dragleave', () => dz.classList.remove('over'));
dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('over'); importFiles(e.dataTransfer.files); });
fi.addEventListener('change', () => { importFiles(fi.files); fi.value = ''; });

/* ---------- 公共渲染片段 ---------- */
function renderHashKV(hash, algo, total) {
  let h = '<div class="kv2"><span class="k">' + esc(algo || '哈希') + '</span><span class="v">' + esc(hash) + '</span>';
  if (total !== null && total !== undefined) {
    h += '<span class="k">库总数</span><span class="v">' + fmtNum(total) + '</span>';
  }
  h += '</div>';
  return h;
}

/* 启动时加载统计 */
loadStats();
