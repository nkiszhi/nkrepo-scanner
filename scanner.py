"""
NKREPO Scanner - 轻量级静态恶意软件扫描核心引擎
仅实现两类静态检测: 哈希签名 (兼容 ClamAV .hdb 格式) + YARA 规则

哈希签名存储采用三层架构, 支持千万级签名库:
  1. Bloom 预过滤器  - 常驻内存位图, 快速排除"肯定不在库"的查询 (~1.2MB/百万条 @1% 误判率)
  2. SQLite 持久层   - hash 以 BLOB 主键存储 (WITHOUT ROWID), 支持增量导入, 容量到亿级
  3. 内存排序数组    - 可选, 签名数低于阈值时启动加载, 二分查找免去 SQL 开销
     (阈值默认 300 万, 超过则只走 Bloom + SQLite, 与 ClamAV 的排序数组思路一致)
"""
import hashlib
import math
import os
import sqlite3
import struct
import threading
import time

import filetype as ft

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

CHUNK_SIZE = 1024 * 1024  # 1MB 分块读取, 支持大文件

VALID_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_ALGO_BY_BYTES = {16: "MD5", 20: "SHA1", 32: "SHA256"}


def compute_hashes(file_path):
    """一次性分块计算文件的 MD5 / SHA1 / SHA256"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def guess_file_type(file_path):
    """通过魔数判断文件类型 (兼容旧接口, 返回显示名)

    实际逻辑在 filetype.py 中实现, 移植自 ClamAV 的 FTM 魔数签名表:
      固定偏移魔数 (type-0) → 模式搜索 (type-1: PE/SFX/HTML) → 尾部魔数 (DMG) → 文本编码检测
    """
    try:
        head, tail = ft.read_head_tail(file_path)
        return ft.detect_file_type(head, tail)["name"]
    except OSError:
        return "未知"


# ============================================================
# Bloom 过滤器 (纯 Python, 双哈希Double Hashing 实现)
# ============================================================
class BloomFilter:
    """确定性 Bloom 过滤器: 宁可误报绝不漏报, 适配安全检测场景"""

    MAGIC = b"NKB1"

    def __init__(self, expected_items=1_000_000, fp_rate=0.01):
        expected = max(1, expected_items)
        self.m = math.ceil(-(expected * math.log(fp_rate)) / (math.log(2) ** 2))
        self.k = max(1, min(16, round(self.m / expected * math.log(2))))
        self.fp_rate = fp_rate
        self.n = 0  # 已插入元素数
        self.bits = bytearray((self.m + 7) // 8)

    def _positions(self, digest):
        # blake2b 输出确定性双哈希 (跨进程/跨重启一致)
        h1, h2 = struct.unpack("<II", hashlib.blake2b(digest, digest_size=8).digest())
        h2 |= 1
        m = self.m
        return [(h1 + i * h2) % m for i in range(self.k)]

    def add(self, digest):
        for p in self._positions(digest):
            self.bits[p >> 3] |= 1 << (p & 7)
        self.n += 1

    def __contains__(self, digest):
        bits = self.bits
        for p in self._positions(digest):
            if not (bits[p >> 3] >> (p & 7)) & 1:
                return False
        return True

    @property
    def mem_bytes(self):
        return len(self.bits)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.MAGIC)
            f.write(struct.pack("<QQd", self.m, self.k, self.fp_rate))
            f.write(struct.pack("<Q", self.n))
            f.write(bytes(self.bits))

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            if f.read(4) != cls.MAGIC:
                raise ValueError("bloom 文件头无效")
            m, k, fp = struct.unpack("<QQd", f.read(24))
            n = struct.unpack("<Q", f.read(8))[0]
            bits = bytearray(f.read())
        bf = cls.__new__(cls)
        bf.m, bf.k, bf.fp_rate, bf.n = m, k, fp, n
        bf.bits = bits
        return bf


# ============================================================
# 哈希签名库 (SQLite + Bloom + 可选内存排序数组)
# ============================================================
class HashSignatureDB:
    """千万级哈希签名库

    - 存储: SQLite, 表 sigs(h BLOB PRIMARY KEY, size, name) WITHOUT ROWID
      h 存二进制摘要 (比 hex 省一半), 算法由长度自动判定 (16=MD5/20=SHA1/32=SHA256)
    - 导入: .hdb/.hsb 明文文件只是"导入格式", 增量 INSERT OR IGNORE, 已导入文件不重复导
    - 查询: Bloom 先排除 → (命中候选时) 排序数组二分或 SQL 点查
    """

    def __init__(self, db_path, bloom_fp_rate=0.01, max_mem_digests=3_000_000):
        self.db_path = db_path
        self.bloom_path = db_path + ".bloom"
        self.bloom_fp_rate = bloom_fp_rate
        self.max_mem_digests = max_mem_digests
        self._lock = threading.RLock()
        self.source_files = []

        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA cache_size=-65536")  # 64MB 页缓存
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS sigs("
            " h BLOB PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)"
        )
        self.db.commit()

        self._count = self._db_count()
        self.bloom = None
        self.mem_arrays = None  # {摘要字节数: bytes 排序块}
        self._load_bloom()

    # ---------- 内部 ----------
    def _db_count(self):
        return self.db.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]

    def _load_bloom(self):
        """加载持久化 Bloom; 若与当前签名数不匹配则标记待重建 (在 finalize 中执行)"""
        if os.path.exists(self.bloom_path):
            try:
                bf = BloomFilter.load(self.bloom_path)
                if bf.n == self._count:
                    self.bloom = bf
                    return
            except Exception:
                pass
        # count 为 0 时不建 Bloom; 否则留给 finalize() 重建
        self.bloom = None

    def already_imported(self, filename):
        with self._lock:
            row = self.db.execute(
                "SELECT 1 FROM imported_files WHERE name=?", (filename,)
            ).fetchone()
            return row is not None

    # ---------- 导入 ----------
    def import_hdb(self, filepath, batch=50_000):
        """导入 .hdb/.hsb 明文签名文件 (增量, 幂等), 返回新插入条数"""
        basename = os.path.basename(filepath)
        buf = []
        start = time.time()
        with self._lock:
            before = self.db.total_changes
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    h = parts[0].strip().lower()
                    if len(h) not in VALID_HASH_LENGTHS:
                        continue
                    try:
                        digest = bytes.fromhex(h)
                    except ValueError:
                        continue
                    size_field = parts[1].strip()
                    size = None if size_field == "*" else int(size_field)
                    name = parts[2].strip()
                    buf.append((digest, size, name))
                    if len(buf) >= batch:
                        self.db.executemany(
                            "INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)", buf
                        )
                        buf.clear()
            if buf:
                self.db.executemany(
                    "INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)", buf
                )
            inserted = self.db.total_changes - before
            self.db.execute(
                "INSERT OR IGNORE INTO imported_files(name) VALUES(?)", (basename,)
            )
            self.db.commit()
        self._count = self._db_count()
        if basename not in self.source_files:
            self.source_files.append(basename)
        return inserted

    # 旧接口兼容
    def load_hdb(self, filepath):
        return self.import_hdb(filepath)

    def finalize(self):
        """导入完成后调用: 重建过期 Bloom, 重载内存排序数组。返回状态 dict"""
        status = {}
        with self._lock:
            if self._count > 0 and (self.bloom is None or self.bloom.n != self._count):
                t0 = time.time()
                bf = BloomFilter(self._count, self.bloom_fp_rate)
                cur = self.db.execute("SELECT h FROM sigs")
                while True:
                    rows = cur.fetchmany(100_000)
                    if not rows:
                        break
                    for (h,) in rows:
                        bf.add(h)
                bf.save(self.bloom_path)
                self.bloom = bf
                status["bloom_rebuilt_s"] = round(time.time() - t0, 1)
            self.mem_arrays = None
            if 0 < self._count <= self.max_mem_digests:
                t0 = time.time()
                arrays = {}
                cur = self.db.execute("SELECT h FROM sigs ORDER BY h")  # 主键序
                while True:
                    rows = cur.fetchmany(100_000)
                    if not rows:
                        break
                    for (h,) in rows:
                        arrays.setdefault(len(h), bytearray()).extend(h)
                self.mem_arrays = {ln: bytes(b) for ln, b in arrays.items()}
                status["mem_arrays_loaded_s"] = round(time.time() - t0, 1)
        return status

    # ---------- 查询 ----------
    @staticmethod
    def _bisect_blob(blob, item_len, digest):
        """在按主键序拼接的二进制大块上做二分查找"""
        lo, hi = 0, len(blob) // item_len
        while lo < hi:
            mid = (lo + hi) // 2
            chunk = blob[mid * item_len:(mid + 1) * item_len]
            if chunk < digest:
                lo = mid + 1
            elif chunk > digest:
                hi = mid
            else:
                return True
        return False

    @property
    def count(self):
        return self._count

    def check(self, file_path, file_size, md5, sha1, sha256):
        """检查文件哈希是否命中签名, 返回命中列表 (接口与旧版一致)"""
        hits = []
        with self._lock:
            for hexh in (md5, sha1, sha256):
                digest = bytes.fromhex(hexh)
                # 第 1 层: Bloom 排除 (干净文件在此全部短路, 零 SQL 开销)
                if self.bloom is not None and digest not in self.bloom:
                    continue
                # 第 2 层: 内存排序数组二分 / 第 3 层: SQLite 点查
                arr = (self.mem_arrays or {}).get(len(digest))
                if arr is not None:
                    if not self._bisect_blob(arr, len(digest), digest):
                        continue
                    row = self.db.execute(
                        "SELECT size, name FROM sigs WHERE h=?", (digest,)
                    ).fetchone()
                else:
                    row = self.db.execute(
                        "SELECT size, name FROM sigs WHERE h=?"
                        " AND (size IS NULL OR size=?)", (digest, file_size)
                    ).fetchone()
                if row is None:
                    continue
                sig_size, name = row
                if sig_size is not None and sig_size != file_size:
                    continue  # 大小不符, 视为未命中 (降低碰撞误报)
                algo = HASH_ALGO_BY_BYTES[len(digest)]
                hits.append({
                    "engine": "Hash DB",
                    "type": "hash",
                    "name": name,
                    "detail": f"{algo} 命中: {hexh}",
                })
        return hits

    # ---------- 统计 ----------
    def stats(self):
        bloom_info = None
        if self.bloom is not None:
            bloom_info = {
                "items": self.bloom.n,
                "mem_mb": round(self.bloom.mem_bytes / 1048576, 2),
                "hash_funcs": self.bloom.k,
                "fp_rate": self.bloom.fp_rate,
            }
        mem_arrays_info = None
        if self.mem_arrays:
            mem_arrays_info = {
                ln: f"{len(b) // ln:,} 条 / {len(b) / 1048576:.1f}MB"
                for ln, b in self.mem_arrays.items()
            }
        db_size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                db_size += os.path.getsize(self.db_path + suffix)
            except OSError:
                pass
        tier = "sqlite"
        if self.bloom is not None and self.mem_arrays:
            tier = "bloom+memarray+sqlite"
        elif self.bloom is not None:
            tier = "bloom+sqlite"
        elif self.mem_arrays:
            tier = "memarray+sqlite"
        return {
            "count": self._count,
            "tier": tier,
            "bloom": bloom_info,
            "mem_arrays": mem_arrays_info,
            "db_size_mb": round(db_size / 1048576, 1),
        }

    def close(self):
        with self._lock:
            self.db.close()


# ============================================================
# YARA 扫描器 (不变)
# ============================================================
class YaraScanner:
    """YARA 规则扫描器"""

    def __init__(self):
        self.rules = None
        self.rule_count = 0
        self.source_files = []
        self.error = None if YARA_AVAILABLE else "yara-python 未安装, YARA 引擎不可用"

    def load_rules(self, filepath):
        """编译并加载 .yar 规则文件"""
        if not YARA_AVAILABLE:
            return 0
        try:
            self.rules = yara.compile(filepath=filepath)
        except yara.Error as e:
            self.error = f"YARA 规则编译失败: {e}"
            return 0
        count = self._count_rules(filepath)
        self.rule_count = count
        self.source_files.append(os.path.basename(filepath))
        return count

    @staticmethod
    def _count_rules(filepath):
        """统计规则文件中的 rule 数量"""
        count = 0
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("rule ") or stripped == "rule":
                    count += 1
        return count

    def scan(self, file_path):
        """扫描文件, 返回命中列表"""
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path, timeout=10)
        except yara.TimeoutError:
            return [{
                "engine": "YARA",
                "type": "error",
                "name": "YaraScanTimeout",
                "detail": "规则匹配超时 (10s)",
            }]
        except yara.Error as e:
            return [{
                "engine": "YARA",
                "type": "error",
                "name": "YaraScanError",
                "detail": str(e),
            }]
        hits = []
        for m in matches:
            strings = []
            for s in m.strings:
                # yara-python 4.x: s 是 StringMatch 对象
                identifier = getattr(s, "identifier", None) or str(s)
                strings.append(str(identifier))
            hits.append({
                "engine": "YARA",
                "type": "yara",
                "name": m.rule,
                "detail": ("匹配串: " + ", ".join(strings[:5])) if strings else "规则命中",
                "meta": {k: str(v) for k, v in (m.meta or {}).items()},
            })
        return hits


# ============================================================
# 统一扫描器
# ============================================================
class Scanner:
    """统一扫描器: 哈希签名 + YARA"""

    def __init__(self, hash_db, yara_scanner):
        self.hash_db = hash_db
        self.yara_scanner = yara_scanner

    def scan_file(self, file_path, filename=None):
        """扫描单个文件, 返回完整结果 dict"""
        start = time.time()
        file_size = os.path.getsize(file_path)
        md5, sha1, sha256 = compute_hashes(file_path)

        # 文件类型识别 (ClamAV FTM 机制: 魔数 → 模式 → 尾部魔数 → 文本检测)
        ftype = {"name": "未知", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "n/a"}
        try:
            head, tail = ft.read_head_tail(file_path)
            ftype = ft.detect_file_type(head, tail, filename)
        except OSError:
            pass

        detections = []
        detections.extend(self.hash_db.check(file_path, file_size, md5, sha1, sha256))
        detections.extend(self.yara_scanner.scan(file_path))

        elapsed_ms = round((time.time() - start) * 1000, 1)
        return {
            "filename": filename or os.path.basename(file_path),
            "size": file_size,
            "size_human": _human_size(file_size),
            "file_type": ftype["name"],          # 显示名 (向后兼容)
            "file_type_info": ftype,             # 结构化: name/cl_type/category/method
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "clean": len(detections) == 0,
            "verdict": "CLEAN" if not detections else "DETECTED",
            "detections": detections,
            "elapsed_ms": elapsed_ms,
            "scanners": ["Hash DB (md5/sha1/sha256)"]
                         + (["YARA"] if YARA_AVAILABLE and self.yara_scanner.rules else []),
        }


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
