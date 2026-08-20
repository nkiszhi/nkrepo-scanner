# nkrepo-scanner 检测流程分析与优化建议

## 一、检测流水线全景

```
POST /scan (上传文件)
  │
  ├─ 缓存查询 (SHA256 → scan_cache/<sha256>.json)
  │    ├─ 命中 → 秒回结果 (~1ms)
  │    └─ 未命中 ↓
  │
  ├─ 阶段1 (同步, 毫秒级)
  │    ├─ 三哈希计算 (MD5 + SHA1 + SHA256)
  │    ├─ 文件类型识别 (ClamAV FTM 魔数表)
  │    ├─ SHA256 签名库查询 (Bloom 过滤 → SQLite 点查)
  │    ├─ MD5 签名库查询 (独立分片库)
  │    └─ → 立即返回 phase1 结果给前端
  │
  └─ 阶段2 (后台线程, 秒级)
       ├─ YARA 规则匹配 (1433+ 规则文件, 串行, 10s 超时)
       ├─ 静态信息提取 (ssdeep/tlsh/imphash/authentihash + PE 元数据)
       ├─ 壳/保护器识别 (DIE + PEiD + 外部 YARA, 纯 Python 熵计算)
       ├─ 模糊哈希库查询 (5 表: ssdeep/vhash/authentihash/imphash/rich_header_hash)
       └─ 合并结果 + 写入缓存 JSON → 前端轮询 /api/task 获取
```

**签名库规模**: SHA256 库 62,587,049 条 (256 hex 分片) · MD5 库 540,176 条 · YARA 1,433+ 规则文件

---

## 二、性能瓶颈分析 (按严重程度)

### P0-1: YARA 1433+ 规则文件串行匹配

**位置**: `scanner.py` L1648, `YaraScanner.scan_data()`

**问题**: 每个规则文件独立编译为一个 `Rules` 对象，匹配时 `for r in self.rulesets` 逐个串行调用 `r.match(data=data, timeout=10)`。1433+ 个规则集意味着 YARA 初始化开销被重复支付 1433 次（编译规则缓存、模块初始化、内存分配等），且无法利用 YARA 内部的并行匹配优化。

**影响**: 阶段2 的最大耗时来源。即使每条规则匹配仅需 1ms，1433 次累计也在秒级。

**优化方案**: 启动时用 `yara.compile(filepaths=...)` 合并为**单一 Rules 对象**（每文件独立 namespace，规则名冲突互不干扰），匹配时只需一次调用。

```python
# 当前 (scanner.py L1613-1630): 逐文件编译 + 串行匹配
def load_rules(self, filepath):
    r = yara.compile(filepath=filepath)  # 每文件一个 Rules 对象
    self.rulesets.append(r)               # 累积到列表

def scan_data(self, data):
    for r in self.rulesets:              # 串行遍历全部 rulesets
        matches = r.match(data=data, timeout=10)
        ...

# 优化: 合并编译 + 单次匹配
class YaraScanner:
    def __init__(self):
        self._compiled = None       # 合并编译的单一 Rules 对象
        self._pending = {}           # 待编译: {filename: filepath}

    def load_rules(self, filepath):
        fname = os.path.basename(filepath)
        self._pending[fname] = filepath
        self._compiled = None  # 标记需重编译

    def _ensure_compiled(self):
        if self._compiled is None and self._pending:
            self._compiled = yara.compile(filepaths=self._pending)
            self.rule_count = sum(...)  # 从编译结果统计

    def scan_data(self, data):
        self._ensure_compiled()
        if not self._compiled:
            return []
        matches = self._compiled.match(data=data, timeout=30)  # 单次匹配
        return self._format_matches(matches)
```

**预期收益**: 匹配从 1433 次 YARA 调用降为 1 次，阶段2 耗时预计降低 60-80%。

---

### P0-2: SHA256 重复计算

**位置**: `app.py` L496 + `scanner.py` L1775

**问题**: `/scan` POST 处理函数中先调用 `hashlib.sha256(data).hexdigest()` 计算缓存 key（app.py L496），随后 `scanner.scan_phase1(data)` 内部又调用 `compute_hashes_bytes(data)` 再算一遍 SHA256（连同 MD5 和 SHA1）。同一份数据的 SHA256 被计算了两次。

**优化方案**: 在 `app.py` 中一次性计算全部哈希，传给 scanner。

```python
# app.py /scan POST:
from scanner import compute_hashes_bytes
md5_hex, sha1_hex, sha256_hex = compute_hashes_bytes(data)
# 缓存查询直接用 sha256_hex (不再单独算)
cached = None if rescan else _load_cached_result(sha256_hex)
# ...
# 阶段1 改为接受预计算哈希
phase1 = scanner.scan_phase1(data, filename=f.filename, hashes=(md5_hex, sha1_hex, sha256_hex))
```

```python
# scanner.py _phase1 改造:
def _phase1(self, data, filename, hashes=None):
    if hashes:
        md5, sha1, sha256 = hashes
    else:
        md5, sha1, sha256 = compute_hashes_bytes(data)
    # ...
```

**预期收益**: 阶段1 减少 1 次 SHA256 全文件扫描，对 10MB 文件约省 15-30ms。

---

### P1-1: SHA1 哈希无用计算

**位置**: `scanner.py` L1775, `compute_hashes_bytes()`

**问题**: `compute_hashes_bytes` 同时计算 MD5、SHA1、SHA256 三个哈希。但签名库仅存储 SHA256 和 MD5，SHA1 从不参与任何查询。每次扫描白白消耗一次哈希计算的 CPU。

**优化方案**: 移除 SHA1 计算（或改为按需计算）。

```python
# 当前:
def compute_hashes_bytes(data):
    md5 = hashlib.md5(data)
    sha1 = hashlib.sha1(data)    # 从不使用
    sha256 = hashlib.sha256(data)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

# 优化: 延迟或移除 SHA1
def compute_hashes_bytes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, None, sha256  # SHA1 仅在需要时计算
```

**注意**: 如果未来需要 SHA1 签名库支持，可保留但加条件判断。当前移除可减少约 33% 哈希计算 CPU。

---

### P1-2: 纯 Python 逐字节熵计算

**位置**: `packer.py` L186-190, `_section_entropy()`

**问题**: 熵计算使用 `for b in chunk: counts[b] += 1` 纯 Python 循环逐字节统计字节频率。对于 4MB 采样上限，单节循环约 4,194,304 次迭代，实测耗时可达数秒。多节叠加更严重。

**优化方案**: 用 `collections.Counter` 或 `numpy.bincount` 替代。

```python
# 方案 A: collections.Counter (纯 Python, ~5x 加速)
from collections import Counter
def _section_entropy(data, sec, size=None):
    off = sec.PointerToRawData
    if size is None:
        size = sec.SizeOfRawData
    chunk = data[off:off + size]
    if not chunk:
        return 0.0
    counts = Counter(chunk)
    n = len(chunk)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)

# 方案 B: numpy (推荐, ~100x 加速)
import numpy as np
def _section_entropy(data, sec, size=None):
    off = sec.PointerToRawData
    if size is None:
        size = sec.SizeOfRawData
    chunk = np.frombuffer(data[off:off + size], dtype=np.uint8)
    if len(chunk) == 0:
        return 0.0
    counts = np.bincount(chunk, minlength=256).astype(np.float64)
    n = len(chunk)
    nonzero = counts[counts > 0]
    return float(-np.sum((nonzero / n) * np.log2(nonzero / n)))
```

**预期收益**: 4MB 节熵计算从 ~3s 降至 ~30ms (numpy) 或 ~600ms (Counter)。

---

### P1-3: `data.lower()` 整文件副本

**位置**: `packer.py` L361

**问题**: 对 ≤32MB 的文件，`data.lower()` 创建一份完整的全文件小写副本用于 magic 字符串搜索。32MB 文件会产生 32MB 额外内存分配 + GC 压力。

**优化方案**: 改用 `bytes.find()` 的大小写不敏感搜索，或预编译 magic 为正则。

```python
# 当前 (packer.py L360-361):
overlay_low = overlay.lower() if overlay else b""
file_low = data.lower() if len(data) <= MAGIC_FILE_SEARCH_BYTES else None
for family, magic in MAGIC_STRINGS:
    lm = magic.lower()
    if overlay_low and lm in overlay_low:   # overlay 较小, 可接受
        ...
    elif file_low is not None and len(magic) >= 5 and lm in file_low:
        ...

# 优化: 不做整文件副本, 改用预编译正则 (大小写不敏感)
import re as _re
_MAGIC_RES = [
    (family, _re.compile(_re.escape(magic), _re.IGNORECASE))
    for family, magic in MAGIC_STRINGS
]

for family, pat in _MAGIC_RES:
    if overlay and pat.search(overlay):
        exact.append(...)
    elif len(data) <= MAGIC_FILE_SEARCH_BYTES and len(magic) >= 5:
        m = pat.search(data)  # 无需 .lower(), 正则自带 IGNORECASE
        if m:
            exact.append(...)
```

**预期收益**: 消除 32MB 内存副本，降低 GC 压力，PE 查壳阶段内存峰值减半。

---

### P2-1: FUZZY_MAX_BYTES = 256KB 过低

**位置**: `staticinfo.py` L39

**问题**: ssdeep/tlsh 的计算上限设为 256KB，但绝大多数真实 PE 文件（含恶意样本）远超此大小。注释说明原因是纯 Python 实现逐字节处理耗时失控（1MB ≈ 24s）。这导致模糊哈希匹配对实际样本形同虚设。

**优化方案**: 
- **短期**: 将上限提升至 1-2MB，接受 20-30s 耗时（在后台线程不影响响应）
- **长期**: 替换 `ppdeep` 为 C 扩展 `ssdeep` 或 `pyssdeep`，可将 1MB 耗时从 24s 降至 <100ms

```python
# 短期: 提升上限 (后台线程可接受较长耗时)
FUZZY_MAX_BYTES = 2 * 1024 * 1024  # 2MB

# 长期: 安装 C 扩展
# pip install ssdeep  (libfuzzy C 绑定)
# import ssdeep
# h = ssdeep.hash(data)  # 1MB ≈ 50ms
```

---

### P2-2: 缓存命中时同步写回 JSON 阻塞响应

**位置**: `app.py` L505-506

**问题**: 缓存命中时，`_append_history()` + `_save_cached_result()` 在 HTTP 请求处理线程中同步执行，阻塞响应返回。高并发下多个请求同时写 JSON 会造成磁盘 I/O 排队。

**优化方案**: 将 history 追加改为异步写入。

```python
# 当前 (app.py L504-506):
_append_history(cached_result, f.filename, submitted_at)
_save_cached_result(sha256_hex, cached_result)  # 同步阻塞

# 优化: 异步写回 (不阻塞响应)
import threading
def _async_save_history(sha, result):
    threading.Thread(target=_save_cached_result, args=(sha, result), daemon=True).start()

_append_history(cached_result, f.filename, submitted_at)
_async_save_history(sha256_hex, cached_result)  # 后台写, 立即返回
```

---

## 三、正确性与并发安全问题

### C1: LRU 连接淘汰导致检测静默漏报 (严重)

**位置**: `scanner.py` L509-518, `_query_shard()`

**问题**: 当 LRU 缓存淘汰了一个分片连接时（`max_open_shards` 限制），`_conn_locks.pop(old_id)` 移除了对应的锁。如果在 `_ro_conn()` 返回连接和 `_query_shard()` 获取锁之间，该连接恰好被另一个线程的 LRU 淘汰，`_conn_locks.get(shard_id)` 返回 `None`，查询静默返回 `None`（即"未命中"）。**这意味着在并发负载下，已知恶意哈希可能逃逸检测。**

**修复方案**: 在 `_ro_conn()` 内持锁期间同时获取锁引用，返回 `(conn, lock)` 元组；或使用引用计数替代 LRU pop。

```python
def _query_shard(self, shard_id, sql, params=()):
    conn = self._ro_conn(shard_id)
    if conn is None:
        return None
    # 获取锁引用 (即使连接被 LRU 淘汰, 锁对象仍可用)
    with self._cache_lock:
        lock = self._conn_locks.get(shard_id)
    if lock is None:
        # 连接刚被淘汰: 保守起见重新打开临时连接查询
        path = self._shard_path(shard_id)
        if not os.path.exists(path):
            return None
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        try:
            return conn.execute(sql, params).fetchone()
        finally:
            conn.close()
    with lock:
        return conn.execute(sql, params).fetchone()
```

---

### C2: status="done" 先于缓存写入

**位置**: `app.py` L562-572

**问题**: `_run_phase2()` 中先设 `task["status"] = "done"`，然后才调 `_save_cached_result()`。在此间隙，如果有其他请求访问 `/api/file/<sha256>`，会得到 404（缓存尚未写入）。前端详情页已有 1.2s 重试机制缓解，但根本原因应修复。

**修复方案**: 先写缓存，再标记 done。

```python
def _run_phase2():
    with P2_SEM:
        try:
            p2 = scanner.scan_phase2(data, filename=f.filename)
            # 先合并 + 写缓存
            merged = scanner.merge_phases(task["phase1"], p2)
            if p2.get("note"):
                merged["phase2_note"] = p2["note"]
            merged["submitted_at"] = submitted_at
            merged["history"] = history
            merged["scanned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            _save_cached_result(sha256_hex, merged)
            # 再标记完成 (确保缓存已落盘)
            task["phase2"] = p2
            task["status"] = "done"
        except Exception as e:
            task["error"] = str(e)
            task["status"] = "error"
```

---

### C3: scan_cache/ 目录无界增长

**位置**: `app.py` L238

**问题**: `scan_cache/` 目录无 LRU 淘汰、无 TTL、无容量上限。长期运行后磁盘耗尽。

**修复方案**: 添加定期清理（基于文件 mtime 的 LRU 淘汰）。

```python
CACHE_MAX_FILES = 10000
CACHE_MAX_AGE_DAYS = 30

def _cache_cleanup():
    """清理过期/超量缓存文件 (惰性调用)"""
    files = []
    for f in os.listdir(RESULTS_CACHE_DIR):
        path = os.path.join(RESULTS_CACHE_DIR, f)
        if f.endswith(".json"):
            files.append((path, os.path.getmtime(path)))
    files.sort(key=lambda x: x[1])  # 按时间升序
    # 删过期的
    now = time.time()
    for path, mtime in files:
        if now - mtime > CACHE_MAX_AGE_DAYS * 86400:
            os.remove(path)
    # 删超量的 (保留最新的 CACHE_MAX_FILES 个)
    for path, _ in files[:-CACHE_MAX_FILES]:
        os.remove(path)
```

---

### C4: 后台线程闭包持有 data

**位置**: `app.py` L545

**问题**: `_run_phase2()` 闭包捕获 `data`（完整文件内容）。4 个并发线程各持 10MB 数据 = 40MB 额外驻留，直到 phase2 完成。

**影响**: 中等。对本地单机使用影响不大，但高并发场景需关注。

**优化方向**: 对 >1MB 的文件，phase1 只返回哈希值，phase2 从 `data` 改为按需引用（如 `memoryview(data)`），或考虑将大文件落盘后用 `mmap` 访问。

---

### C5: pefile.PE(data) 重复解析 3 次

**位置**: `staticinfo.py` L92 + L142 + `packer.py` L326

**问题**: 同一 PE 数据被 `pefile.PE(data=data)` 解析了 3 次：
1. `compute_imphash()` → `pefile.PE(data=data)`
2. `compute_pe_meta()` → `pefile.PE(data=data)`
3. `packer.detect_packer()` → `pefile.PE(data=data)`

每次 `pefile.PE()` 都重新解析 PE 头、节表、导入表等，对含大量导入项的 PE 文件耗时可观。

**优化方案**: 在 `compute_static_info()` 中统一解析一次 PE 实例，传入各子函数。

```python
def compute_static_info(data):
    pe_obj = None
    if _is_pe(data):
        try:
            pe_obj = pefile.PE(data=data)
        except Exception:
            pe_obj = None
    
    # 全部子函数复用同一 PE 实例
    if pe_obj:
        fuzzy["imphash"] = pe_obj.get_imphash()
        fuzzy["authentihash"] = compute_authentihash(data)  # 纯字节操作, 不需 PE 实例
        pe_meta = _extract_pe_meta(pe_obj)     # 从已有实例提取
        packer_result = _detect_packer(data, pe_obj)  # 传入已有实例
    ...
```

---

## 四、架构级优化建议

### A1: YARA 规则编译缓存

当前每次服务启动都重新编译全部 YARA 规则。可编译后序列化到磁盘（`.yar.cache`），启动时直接加载编译结果，将冷启动从数十秒降至秒级。

### A2: 哈希查询路径用 mmap 替代内存读取

对 ≤10MB 文件当前全量读入内存。可改用 `mmap.mmap()` 映射文件，哈希/YARA 直接对映射区域操作，避免大文件内存复制。

### A3: 结果缓存改为 SQLite

当前 `scan_cache/` 每个文件一个 JSON。大量文件时文件系统 inode 压力大、目录遍历慢。可改为单个 SQLite 缓存库（`scan_cache.db`），按 SHA256 主键存储 JSON 文本，自带索引和事务保护。

### A4: pefile 懒加载

非 PE 文件不需要 `pefile` 模块。可将 `import pefile` 改为函数内懒导入，减少非 PE 扫描的初始化开销。

---

## 五、优先级排序

| 优先级 | 编号 | 问题 | 改动量 | 预期收益 |
|--------|------|------|--------|----------|
| 紧急 | C1 | LRU 锁竞态导致漏报 | 小 | 修复正确性 |
| 高 | P0-1 | YARA 串行匹配 | 中 | 阶段2 提速 60-80% |
| 高 | P0-2 | SHA256 重复计算 | 小 | 阶段1 提速 ~30% |
| 高 | C2 | 缓存写入顺序 | 小 | 修复竞态 |
| 中 | P1-1 | SHA1 无用计算 | 小 | 哈希阶段 CPU -33% |
| 中 | P1-2 | 熵计算纯 Python | 小 | PE 查壳提速 100x |
| 中 | P1-3 | data.lower() 副本 | 小 | 内存峰值 -50% |
| 中 | C5 | pefile 重复解析 | 中 | PE 分析提速 ~3x |
| 中 | C3 | 缓存无界增长 | 小 | 防磁盘耗尽 |
| 低 | P2-1 | 模糊哈希上限 | 小 | 提升检出率 |
| 低 | P2-2 | 缓存命中同步写 | 小 | 高并发响应延迟降低 |
| 低 | C4 | 后台线程内存驻留 | 大 | 高并发内存优化 |
