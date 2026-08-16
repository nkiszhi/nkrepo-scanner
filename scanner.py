"""
NKREPO Scanner - 轻量级静态恶意软件扫描核心引擎
仅实现两类静态检测: 哈希签名 (兼容 ClamAV .hdb 格式) + YARA 规则

哈希签名存储采用两层架构, 支持千万级签名库:
  1. Bloom 预过滤器 - 常驻内存位图, 快速排除"肯定不在库"的查询 (~1.2MB/百万条 @1% 误判率)
  2. 前缀分片 SQLite - 按哈希前 2 个 hex 字符(首字节)拆成 256 个独立小库,
     查询时只懒加载前缀匹配的那 1 个分片 (只读连接 + LRU 缓存),
     单分片体量仅为全库 1/256, 点查与增量导入互不干扰
"""
import hashlib
import math
import os
import sqlite3
import struct
import threading
import time
from collections import OrderedDict

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
# 哈希签名库 (Bloom + 256 前缀分片 SQLite)
# ============================================================
class HashSignatureDB:
    """千万级哈希签名库 (前缀分片存储)

    - 分片: 哈希 hex 的前 2 个字符 (= 摘要首字节) 决定归属, 共 256 个小库
      signatures.db.shards/00.db ... ff.db, 每片表 sigs(h BLOB PK, size, name) WITHOUT ROWID
      MD5/SHA1/SHA256 签名按各自哈希前缀路由, 查询三种算法时分别定位对应分片
    - 元数据: signatures.db.shards/_meta.db 存 imported_files 与各分片计数
    - 查询: Bloom 先排除 → (候选时) 只打开前缀匹配的 1 个分片做只读点查,
      连接懒加载 + LRU 缓存 (默认上限 64), 冷启动零分片加载
    - 迁移: 检测到旧版单一 signatures.db 时自动分片迁移, 原文件保留为 .migrated
    """

    def __init__(self, db_path, bloom_fp_rate=0.01, max_open_shards=64):
        self.db_path = db_path
        self.shard_dir = db_path + ".shards"
        self.meta_path = os.path.join(self.shard_dir, "_meta.db")
        self.bloom_path = db_path + ".bloom"
        self.bloom_fp_rate = bloom_fp_rate
        self.max_open_shards = max(4, max_open_shards)
        self._lock = threading.RLock()
        self.source_files = []

        os.makedirs(self.shard_dir, exist_ok=True)
        self.meta = self._open_rw(self.meta_path)
        self._init_meta_schema(self.meta)

        # 旧版单库自动迁移 (一次性)
        if os.path.exists(db_path):
            self._migrate_legacy(db_path)

        self._conns = OrderedDict()  # prefix -> 只读连接 (LRU)
        self._count = self._load_count()
        self.source_files = [
            r[0] for r in self.meta.execute("SELECT name FROM imported_files")
        ]
        self.bloom = None
        self._load_bloom()

    # ---------- 连接管理 ----------
    @staticmethod
    def _open_rw(path):
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @staticmethod
    def _init_meta_schema(conn):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS shard_counts(prefix TEXT PRIMARY KEY, cnt INTEGER NOT NULL)"
        )
        conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        conn.commit()

    @staticmethod
    def _shard_path(shard_dir, prefix):
        return os.path.join(shard_dir, prefix + ".db")

    def _ro_conn(self, prefix):
        """获取分片只读连接 (懒加载 + LRU 淘汰); 分片文件不存在则返回 None"""
        conn = self._conns.get(prefix)
        if conn is not None:
            self._conns.move_to_end(prefix)
            return conn
        path = self._shard_path(self.shard_dir, prefix)
        if not os.path.exists(path):
            return None  # 该前缀无签名, 无需建库
        conn = sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, check_same_thread=False
        )
        self._conns[prefix] = conn
        while len(self._conns) > self.max_open_shards:
            _, old = self._conns.popitem(last=False)
            try:
                old.close()
            except sqlite3.Error:
                pass
        return conn

    # ---------- 计数 ----------
    def _load_count(self):
        """优先读分片计数缓存; 缓存失效(未标记)时逐片重数"""
        valid = self.meta.execute(
            "SELECT v FROM meta WHERE k='counts_valid'"
        ).fetchone()
        if valid and valid[0] == "1":
            row = self.meta.execute("SELECT SUM(cnt) FROM shard_counts").fetchone()
            return row[0] or 0
        total = 0
        counts = []
        for i in range(256):
            prefix = "%02x" % i
            path = self._shard_path(self.shard_dir, prefix)
            if not os.path.exists(path):
                continue
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                cnt = conn.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
            except sqlite3.Error:
                cnt = 0
            conn.close()
            counts.append((prefix, cnt))
            total += cnt
        with self.meta:
            self.meta.executemany(
                "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)", counts
            )
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')"
            )
        return total

    # ---------- 旧库迁移 ----------
    def _migrate_legacy(self, legacy_path):
        """把旧版单一 signatures.db 的签名按前缀拆入 256 分片"""
        try:
            legacy = sqlite3.connect(legacy_path)  # rw 打开以恢复可能存在的 WAL
            tables = {
                r[0] for r in legacy.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "sigs" not in tables:
                legacy.close()
                os.replace(legacy_path, legacy_path + ".migrated")
                return
            t0 = time.time()
            total = 0
            counts = []
            for i in range(256):
                prefix = "%02x" % i
                shard = self._open_rw(self._shard_path(self.shard_dir, prefix))
                shard.execute(
                    "CREATE TABLE IF NOT EXISTS sigs("
                    " h BLOB PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID"
                )
                before = shard.total_changes
                if i < 255:
                    cur = legacy.execute(
                        "SELECT h,size,name FROM sigs WHERE h>=? AND h<?",
                        (bytes([i]), bytes([i + 1])),
                    )
                else:
                    cur = legacy.execute(
                        "SELECT h,size,name FROM sigs WHERE h>=?", (b"\xff",)
                    )
                while True:
                    rows = cur.fetchmany(50_000)
                    if not rows:
                        break
                    shard.executemany(
                        "INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)", rows
                    )
                shard.commit()
                inserted = shard.total_changes - before
                shard.close()
                if inserted:
                    counts.append((prefix, inserted))
                    total += inserted
            # 迁移导入记录
            try:
                names = [r[0] for r in legacy.execute("SELECT name FROM imported_files")]
                with self.meta:
                    self.meta.executemany(
                        "INSERT OR IGNORE INTO imported_files(name) VALUES(?)",
                        [(n,) for n in names],
                    )
            except sqlite3.Error:
                pass
            legacy.close()
            with self.meta:
                self.meta.executemany(
                    "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                    counts,
                )
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')"
                )
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('migrated_from','1')"
                )
            os.replace(legacy_path, legacy_path + ".migrated")
            for suffix in ("-wal", "-shm"):
                try:
                    os.remove(legacy_path + suffix)
                except OSError:
                    pass
            print(f"[NKREPO] 旧单库已迁移至 256 分片: {total:,} 条, "
                  f"耗时 {time.time() - t0:.1f}s (备份: {legacy_path}.migrated)")
        except Exception as e:
            print(f"[NKREPO] 旧库迁移失败(将按空分片库启动): {e}")

    # ---------- Bloom ----------
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
            row = self.meta.execute(
                "SELECT 1 FROM imported_files WHERE name=?", (filename,)
            ).fetchone()
            return row is not None

    # ---------- 导入 ----------
    def import_hdb(self, filepath, batch=50_000):
        """导入 .hdb/.hsb 明文签名文件 (增量, 幂等), 返回新插入条数"""
        basename = os.path.basename(filepath)
        pending = {}  # prefix -> [(digest, size, name)]
        start = time.time()
        with self._lock:
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
                    pending.setdefault(digest[:1].hex(), []).append((digest, size, name))
            inserted = 0
            count_updates = []
            for prefix, rows in pending.items():
                shard = self._open_rw(self._shard_path(self.shard_dir, prefix))
                shard.execute(
                    "CREATE TABLE IF NOT EXISTS sigs("
                    " h BLOB PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID"
                )
                before = shard.total_changes
                for i in range(0, len(rows), batch):
                    shard.executemany(
                        "INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)",
                        rows[i:i + batch],
                    )
                shard.commit()
                delta = shard.total_changes - before
                cnt = shard.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                shard.close()
                inserted += delta
                count_updates.append((cnt, prefix))
            with self.meta:
                self.meta.executemany(
                    "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                    [(p, c) for c, p in count_updates],
                )
                self.meta.execute(
                    "INSERT OR IGNORE INTO imported_files(name) VALUES(?)", (basename,)
                )
            self._count += inserted
        if basename not in self.source_files:
            self.source_files.append(basename)
        return inserted

    # 旧接口兼容
    def load_hdb(self, filepath):
        return self.import_hdb(filepath)

    def finalize(self):
        """导入完成后调用: 按需重建 Bloom。返回状态 dict"""
        status = {}
        with self._lock:
            if self._count > 0 and (self.bloom is None or self.bloom.n != self._count):
                t0 = time.time()
                bf = BloomFilter(self._count, self.bloom_fp_rate)
                for i in range(256):
                    prefix = "%02x" % i
                    path = self._shard_path(self.shard_dir, prefix)
                    if not os.path.exists(path):
                        continue
                    conn = self._ro_conn(prefix)
                    cur = conn.execute("SELECT h FROM sigs")
                    while True:
                        rows = cur.fetchmany(100_000)
                        if not rows:
                            break
                        for (h,) in rows:
                            bf.add(h)
                bf.save(self.bloom_path)
                self.bloom = bf
                status["bloom_rebuilt_s"] = round(time.time() - t0, 1)
        return status

    # ---------- 查询 ----------
    @property
    def count(self):
        return self._count

    def check(self, file_path, file_size, md5, sha1, sha256):
        """检查文件哈希是否命中签名, 返回命中列表 (接口与旧版一致)

        每个哈希按自身前 2 个 hex 字符定位 1 个分片, 只对该分片做点查
        """
        hits = []
        with self._lock:
            for hexh in (md5, sha1, sha256):
                digest = bytes.fromhex(hexh)
                # 第 1 层: Bloom 排除 (干净文件在此全部短路, 零 SQL 开销)
                if self.bloom is not None and digest not in self.bloom:
                    continue
                # 第 2 层: 前缀分片点查 (只加载 hex 前 2 位匹配的那个分片)
                conn = self._ro_conn(digest[:1].hex())
                if conn is None:
                    continue
                row = conn.execute(
                    "SELECT size, name FROM sigs WHERE h=?", (digest,)
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
        shard_files = [
            f for f in os.listdir(self.shard_dir)
            if len(f) == 5 and f.endswith(".db")  # "00.db" ~ "ff.db"
        ]
        shard_sizes = []
        for f in shard_files:
            for suffix in ("", "-wal", "-shm"):
                try:
                    shard_sizes.append(os.path.getsize(os.path.join(self.shard_dir, f + suffix)))
                except OSError:
                    pass
        db_size = sum(shard_sizes)
        try:
            db_size += os.path.getsize(self.meta_path)
        except OSError:
            pass
        tier = "bloom+sharded-sqlite" if self.bloom is not None else "sharded-sqlite"
        return {
            "count": self._count,
            "tier": tier,
            "bloom": bloom_info,
            "shards": {
                "total": len(shard_files),
                "open_conns": len(self._conns),
                "max_open": self.max_open_shards,
            },
            "db_size_mb": round(db_size / 1048576, 1),
        }

    def close(self):
        with self._lock:
            for conn in self._conns.values():
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._conns.clear()
            self.meta.close()


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
