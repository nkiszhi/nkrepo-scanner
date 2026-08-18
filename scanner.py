"""
NKAMG Scanner - 轻量级静态恶意软件扫描核心引擎
仅实现两类静态检测: 哈希签名 (兼容 ClamAV .hdb 格式) + YARA 规则

哈希签名存储采用 "Bloom shard 驱动的动态分片" 架构, 支持千万级签名库:
  1. 分片数 N 完全由 config.json 的 bloom.shards 决定 (任意正整数, 如 16/64/256/1024):
     路由规则 = int.from_bytes(digest[:4], 'big') % N, 不再依赖"哈希前 2 字符=固定 256 片"
  2. Bloom 过滤器同样按 N 分片: 每个 SQLite 分片配一个独立位图
     (签名库.bloom/{shard_id:04d}.bloom), 懒加载 + LRU 缓存, 冷启动零加载,
     内存随查询按需增长
  3. 查询: 路由到分片 → 该分片 Bloom 排除 → (候选时) 打开该分片 SQLite 只读点查;
     并发模型: 查询路径无全局锁 (Bloom 查询期只读无锁 + SQLite 连接级串行锁,
     不同分片并行); v3 起签名库仅存 SHA256, 查询单次点查即短路
  4. 布局一致性: meta 表记录 layout 版本与 shard_count; 检测到旧 hex 前缀布局
     (16/256/4096) 或修改 N 时启动自动重分片, 旧数据备份不丢失
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
import staticinfo

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

CHUNK_SIZE = 1024 * 1024  # 1MB 分块读取, 支持大文件

VALID_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_ALGO_BY_BYTES = {16: "MD5", 20: "SHA1", 32: "SHA256"}

# 哈希算法规格表: HashSignatureDB 按 hash_algo 参数化 (md5/sha256 两个独立并列库)
#   hex_len  = 十六进制长度, bytes = 摘要字节数, col = 主键列名, label = 显示名
HASH_SPECS = {
    "md5":    {"hex_len": 32, "bytes": 16, "col": "md5",    "label": "MD5"},
    "sha1":   {"hex_len": 40, "bytes": 20, "col": "sha1",   "label": "SHA1"},
    "sha256": {"hex_len": 64, "bytes": 32, "col": "sha256", "label": "SHA256"},
}

# sigs 表 sha256 主键结构 (v3):
#   sha256 BLOB PRIMARY KEY       唯一主键, 库内仅存 SHA256 签名 (32B)
#   size/name TEXT                签名元数据
#   md5/sha1 BLOB                 同文件其它标准哈希列 (无数据源时 NULL, 预留)
#   ssdeep/tlsh/sdhash/mvhash TEXT  4 个 fuzzy hash 列 (暂无数据源, 预留)
SIGS_COLS = "sha256,size,name,md5,sha1,ssdeep,tlsh,sdhash,mvhash"
SIGS_DDL = (
    "CREATE TABLE IF NOT EXISTS sigs("
    " sha256 BLOB PRIMARY KEY,"
    " size INTEGER, name TEXT,"
    " md5 BLOB, sha1 BLOB,"
    " ssdeep TEXT, tlsh TEXT, sdhash TEXT, mvhash TEXT) WITHOUT ROWID"
)
SIGS_INSERT = (
    "INSERT OR IGNORE INTO sigs(" + SIGS_COLS + ")"
    " VALUES(?,?,?,?,?,?,?,?,?)"
)

# 字节长度 -> 哈希类型; v3 起库内仅接受 SHA256 (32B)
def _sigs_row(sha256_digest, size, name):
    """把 (sha256_digest,size,name) 映射为 9 列新结构行; 非 32B 抛 ValueError"""
    if len(sha256_digest) != 32:
        raise ValueError(f"仅支持 SHA256 签名 (32B), 收到 {len(sha256_digest)}B")
    return (sha256_digest, size, name,
            None, None,        # md5 / sha1 (预留)
            None, None, None, None)  # ssdeep/tlsh/sdhash/mvhash (预留)


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


def compute_hashes_bytes(data):
    """从内存缓冲一次性计算 MD5 / SHA1 / SHA256 (内存复用扫描: 文件只读一遍)"""
    md5 = hashlib.md5(data)
    sha1 = hashlib.sha1(data)
    sha256 = hashlib.sha256(data)
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

    # (digest → positions) 实例级 LRU 缓存: 重复样本/重复请求命中高, 省掉 blake2b+求模
    _POS_CACHE_MAX = 4096

    def _positions(self, digest):
        # blake2b 输出确定性双哈希 (跨进程/跨重启一致)
        cache = self.__dict__.get("_pos_cache")
        if cache is None:
            cache = self._pos_cache = OrderedDict()
        pos = cache.get(digest)
        if pos is None:
            h1, h2 = struct.unpack(
                "<II", hashlib.blake2b(digest, digest_size=8).digest()
            )
            h2 |= 1
            m = self.m
            pos = tuple((h1 + i * h2) % m for i in range(self.k))
            cache[digest] = pos
            if len(cache) > self._POS_CACHE_MAX:
                cache.popitem(last=False)
        else:
            cache.move_to_end(digest)
        return pos

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
# 哈希签名库 (Bloom shard 驱动的动态分片 SQLite)
# ============================================================
class HashSignatureDB:
    """千万级哈希签名库 (动态分片)

    - 分片数 N 由 config 中 bloom.shards 决定, 任意正整数:
      路由规则 = int.from_bytes(digest[:4], 'big') % N → 均匀分布到 0000.db ~ (N-1).db
      v3 起库内仅存 SHA256 签名, 按 sha256 摘要路由并点查对应分片
    - Bloom 按同样的 N 分片: {db_path}.bloom/{shard_id:04d}.bloom, 与 SQLite 分片
      一一对应, 懒加载 + LRU 缓存, 冷启动零加载, 内存随查询按需增长
    - 查询: 路由 → 分片 Bloom 排除 (干净文件短路, 零 SQL) → 分片 SQLite 只读点查
    - 布局: meta 记录 layout/shard_count; 旧 hex 前缀布局 (16/256/4096) 或 N 变更
      时自动重分片, 旧数据备份到 .shards.legacy/
    """

    LAYOUT_MODULO = "modulo"
    LAYOUT_HEX = "hex"
    HEX_COUNTS = {1: 16, 2: 256, 3: 4096}  # hex 前缀长度 → 分片数 (旧布局)

    def __init__(self, db_path, shard_count=4, bloom_fp_rate=0.01,
                 max_open_shards=4, hash_algo="sha256"):
        if hash_algo not in HASH_SPECS:
            raise ValueError(f"不支持的哈希算法: {hash_algo} (可选: {list(HASH_SPECS)})")
        self.hash_algo = hash_algo
        _spec = HASH_SPECS[hash_algo]
        self.pk_col = _spec["col"]          # 主键列名 (md5 / sha256)
        self.pk_hex_len = _spec["hex_len"]  # 主键十六进制长度 (32 / 64)
        self.pk_bytes = _spec["bytes"]      # 主键摘要字节数 (16 / 32)
        self.hash_label = _spec["label"]    # 显示名 (MD5 / SHA256)
        self.shard_count = max(1, int(shard_count))
        self.db_path = db_path
        self.shard_dir = db_path + ".shards"
        self.meta_path = os.path.join(self.shard_dir, "_meta.db")
        self.bloom_dir = db_path + ".bloom"   # 分片 Bloom 位图目录
        self.bloom_fp_rate = bloom_fp_rate
        self.max_open_shards = max(4, max_open_shards)
        # 主键结构: sha256 库保留 v3 九列 (含预留 md5/sha1/fuzzy 列, 历史结构不破坏);
        # md5 独立并列库用三列精简结构 (主键即 md5, 与 SHA256 库互不干扰)
        if hash_algo == "sha256":
            self._ddl = SIGS_DDL
            self._insert_sql = SIGS_INSERT
        else:
            self._ddl = (
                f"CREATE TABLE IF NOT EXISTS sigs({self.pk_col} BLOB PRIMARY KEY,"
                " size INTEGER, name TEXT) WITHOUT ROWID"
            )
            self._insert_sql = (
                f"INSERT OR IGNORE INTO sigs({self.pk_col},size,name)"
                " VALUES(?,?,?)"
            )
        self._lock = threading.RLock()       # 写路径互斥 (import_hdb / finalize / close)
        self._cache_lock = threading.Lock()  # _conns/_blooms 字典 LRU 操作的细粒度锁
        self._retired = []                   # LRU 淘汰的连接, 延迟到 close() 统一关闭
        self.source_files = []

        # 旧版单一 Bloom 文件 (signatures.db.bloom) 与新版 bloom 目录同名,
        # 存在时先备份为 .bloom.legacy, 避免 makedirs 冲突
        if os.path.isfile(db_path + ".bloom") and not os.path.isdir(self.bloom_dir):
            try:
                os.replace(db_path + ".bloom", db_path + ".bloom.legacy")
            except OSError:
                pass
        os.makedirs(self.shard_dir, exist_ok=True)
        os.makedirs(self.bloom_dir, exist_ok=True)
        self.meta = self._open_rw(self.meta_path)
        self._init_meta_schema(self.meta)

        # 旧版单一 SQLite 库自动迁移 (一次性)
        if os.path.exists(db_path):
            self._migrate_legacy(db_path)

        # 布局一致性: 旧 hex 前缀布局或 shard_count 变更 → 自动重分片
        self._sync_layout()

        self._conns = OrderedDict()    # shard_id(int) -> 只读 SQLite 连接 (LRU)
        self._conn_locks = {}          # shard_id(int) -> 连接级串行锁 (Python sqlite3 不允许同连接并发 execute)
        self._blooms = OrderedDict()   # shard_id(int) -> BloomFilter (LRU)
        self._bloom_dirty = set()      # 需要重建 bloom 的分片
        self._count = self._load_count()
        self.source_files = [
            r[0] for r in self.meta.execute("SELECT name FROM imported_files")
        ]
        self._scan_bloom()

    # ---------- 行映射 (按 hash_algo) ----------
    def _row_for_insert(self, digest, size, name):
        """把 (digest,size,name) 映射为本库插入行; sha256 库为 v3 九列, md5 库为三列"""
        if self.hash_algo == "sha256":
            return _sigs_row(digest, size, name)  # 9 列 (含预留列)
        if len(digest) != self.pk_bytes:
            raise ValueError(
                f"仅支持 {self.hash_label} 签名 ({self.pk_bytes}B), 收到 {len(digest)}B")
        return (digest, size, name)              # 3 列独立结构

    # ---------- 路由与命名 ----------
    @staticmethod
    def _route(digest, shard_count):
        """路由: 取摘要前 4 字节对 N 取模 → 分片序号 (任意 N 均匀分布)"""
        return int.from_bytes(digest[:4], "big") % shard_count

    def _shard_id(self, digest):
        return self._route(digest, self.shard_count)

    @staticmethod
    def _shard_name(shard_id):
        return "%04d" % shard_id  # 十进制 4 位定长: 0000 ~ N-1 (N <= 9999)

    def _shard_path(self, shard_id):
        return os.path.join(self.shard_dir, self._shard_name(shard_id) + ".db")

    def _bloom_path(self, shard_id):
        return os.path.join(self.bloom_dir, self._shard_name(shard_id) + ".bloom")

    # ---------- 分片布局检测与同步 ----------
    def _layout_shard_files(self):
        """当前布局下的分片文件名列表 (modulo: 4 位十进制, 排除 _meta.db)"""
        return [
            f for f in os.listdir(self.shard_dir)
            if f.endswith(".db") and f != "_meta.db"
            and len(f) == 7 and f[:-3].isdigit()
        ]

    def _count_modulo_files(self):
        return len(self._layout_shard_files())

    def _detect_layout(self):
        """扫描分片目录推断已有布局; 空目录返回 None → (layout, shard_count)"""
        for f in os.listdir(self.shard_dir):
            if f == "_meta.db" or not f.endswith(".db"):
                continue
            stem = f[:-3]
            if stem == "resharding":
                continue
            if len(stem) == 4 and stem.isdigit():
                return self.LAYOUT_MODULO, self._count_modulo_files()
            if len(stem) in self.HEX_COUNTS and all(c in "0123456789abcdef" for c in stem):
                return self.LAYOUT_HEX, self.HEX_COUNTS[len(stem)]
        return None

    def _sync_layout(self):
        """确保分片布局与配置一致 (layout=modulo, shard_count=配置值); 不一致则重分片"""
        row = self.meta.execute(
            "SELECT v FROM meta WHERE k='layout'"
        ).fetchone()
        crow = self.meta.execute(
            "SELECT v FROM meta WHERE k='shard_count'"
        ).fetchone()
        if row is None:
            detected = self._detect_layout()
            if detected is not None:
                layout, old_count = detected
            else:
                layout, old_count = self.LAYOUT_MODULO, self.shard_count
            with self.meta:
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('layout',?)", (layout,))
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('shard_count',?)",
                    (str(old_count),))
        else:
            layout = row[0]
            old_count = int(crow[0]) if crow else self.shard_count

        if layout != self.LAYOUT_MODULO or old_count != self.shard_count:
            self._reshard(layout, old_count)

    def _reshard(self, old_layout, old_count):
        """把已有分片数据按当前路由规则重分布; 旧布局备份到 .shards.legacy/"""
        t0 = time.time()
        new_dir = self.shard_dir + ".resharding"
        os.makedirs(new_dir, exist_ok=True)
        total = 0
        # 枚举旧分片文件 (不依赖命名规则, 兼容 hex/modulo 两种布局)
        old_files = [
            f for f in os.listdir(self.shard_dir)
            if f.endswith(".db") and f != "_meta.db"
        ]
        for f in old_files:
            src = os.path.join(self.shard_dir, f)
            try:
                src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
            except sqlite3.Error:
                continue
            pending = {}
            try:
                cur = src_conn.execute(
                    "SELECT " + ("sha256,size,name,md5,sha1,"
                                 "ssdeep,tlsh,sdhash,mvhash" if self.hash_algo == "sha256"
                                 else f"{self.pk_col},size,name")
                    + " FROM sigs")
                while True:
                    rows = cur.fetchmany(50_000)
                    if not rows:
                        break
                    for row in rows:  # 9 列整行透传 (结构已在迁移时统一为 v3)
                        sid = self._route(row[0], self.shard_count)
                        pending.setdefault(sid, []).append(row)
            except sqlite3.Error:
                pass
            src_conn.close()
            for sid, rows in pending.items():
                shard = self._open_rw(
                    os.path.join(new_dir, self._shard_name(sid) + ".db"))
                shard.execute(self._ddl)
                shard.executemany(self._insert_sql, rows)
                shard.commit()
                shard.close()
                total += len(rows)
        # 旧分片移入备份目录, 新分片就位
        backup_dir = self.shard_dir + ".legacy"
        os.makedirs(backup_dir, exist_ok=True)
        for f in old_files:
            for name in (f, f + "-wal", f + "-shm", f + "-journal"):
                try:
                    os.replace(os.path.join(self.shard_dir, name),
                               os.path.join(backup_dir, name))
                except OSError:
                    pass
        for f in os.listdir(new_dir):
            os.replace(os.path.join(new_dir, f), os.path.join(self.shard_dir, f))
        try:
            os.rmdir(new_dir)
        except OSError:
            pass
        # 分片 Bloom 全部失效, 清理待重建 (旧单文件 bloom 已在上层备份)
        for f in os.listdir(self.bloom_dir):
            if f.endswith(".bloom"):
                try:
                    os.remove(os.path.join(self.bloom_dir, f))
                except OSError:
                    pass
        with self.meta:
            self.meta.execute("DELETE FROM shard_counts")
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','0')")
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('layout',?)",
                (self.LAYOUT_MODULO,))
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('shard_count',?)",
                (str(self.shard_count),))
        print(f"[NKAMG] 分片重排: {old_layout}({old_count}) → "
              f"modulo({self.shard_count}), {total:,} 条, "
              f"耗时 {time.time() - t0:.1f}s (旧布局备份: {backup_dir})")

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

    def _ro_conn(self, shard_id):
        """获取分片只读连接 (懒加载 + LRU 淘汰); 分片文件不存在则返回 None

        线程安全: 每个连接配一把串行锁 (_conn_locks) —— Python sqlite3 允许连接
        跨线程使用 (check_same_thread=False), 但多个线程不能同时在同一连接上
        execute; 连接级锁使同一连接串行、不同连接并行 (并发度 = min(分片数, LRU 上限))。
        仅字典 LRU 操作处加细粒度 _cache_lock; 被淘汰的连接移入 _retired 延迟关闭,
        避免正在查询中的连接被中途 close。
        """
        with self._cache_lock:
            conn = self._conns.get(shard_id)
            if conn is not None:
                self._conns.move_to_end(shard_id)
                return conn
            path = self._shard_path(shard_id)
            if not os.path.exists(path):
                return None  # 该分片无签名, 无需建库
            conn = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, check_same_thread=False
            )
            try:
                conn.execute("PRAGMA query_only=ON")  # 双保险: 只读连接拒绝任何写
            except sqlite3.Error:
                pass
            self._conns[shard_id] = conn
            self._conn_locks[shard_id] = threading.Lock()
            while len(self._conns) > self.max_open_shards:
                old_id, old = self._conns.popitem(last=False)
                self._conn_locks.pop(old_id, None)  # 淘汰分片的锁随之移除
                self._retired.append(old)
            return conn

    def _query_shard(self, shard_id, sql, params=()):
        """分片连接点查 (连接级串行锁; 连接被淘汰瞬间保守跳过)"""
        conn = self._ro_conn(shard_id)
        if conn is None:
            return None
        lock = self._conn_locks.get(shard_id)
        if lock is None:
            return None  # 连接刚被 LRU 淘汰, 保守跳过 (宁可不查不误报)
        with lock:
            return conn.execute(sql, params).fetchone()

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
        for sid in range(self.shard_count):
            path = self._shard_path(sid)
            if not os.path.exists(path):
                continue
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                cnt = conn.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
            except sqlite3.Error:
                cnt = 0
            conn.close()
            counts.append((self._shard_name(sid), cnt))
            total += cnt
        with self.meta:
            self.meta.executemany(
                "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)", counts
            )
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')"
            )
        return total

    # ---------- 旧单库迁移 ----------
    def _migrate_legacy(self, legacy_path):
        """把旧版单一 signatures.db 的签名按当前路由规则拆入分片"""
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
            skipped = 0
            pending = {}
            cur = legacy.execute("SELECT h,size,name FROM sigs")  # 旧库为 v1 三列
            while True:
                rows = cur.fetchmany(100_000)
                if not rows:
                    break
                for h, size, name in rows:
                    try:
                        row9 = self._row_for_insert(h, size, name)  # 按本库主键映射
                    except ValueError:
                        skipped += 1
                        continue
                    sid = self._route(h, self.shard_count)
                    pending.setdefault(sid, []).append(row9)
            # 迁移导入记录
            try:
                names = [r[0] for r in legacy.execute("SELECT name FROM imported_files")]
            except sqlite3.Error:
                names = []
            legacy.close()
            total = 0
            count_updates = []
            for sid, rows in pending.items():
                shard = self._open_rw(self._shard_path(sid))
                shard.execute(self._ddl)
                before = shard.total_changes
                for i in range(0, len(rows), 50_000):
                    shard.executemany(self._insert_sql, rows[i:i + 50_000])
                shard.commit()
                inserted = shard.total_changes - before
                cnt = shard.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                shard.close()
                total += inserted
                count_updates.append((self._shard_name(sid), cnt))
            with self.meta:
                self.meta.executemany(
                    "INSERT OR IGNORE INTO imported_files(name) VALUES(?)",
                    [(n,) for n in names],
                )
                self.meta.executemany(
                    "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                    count_updates,
                )
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')"
                )
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('migrated_from','1')"
                )
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('layout',?)",
                    (self.LAYOUT_MODULO,))
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('shard_count',?)",
                    (str(self.shard_count),))
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('schema_version',?)",
                    ("3" if self.hash_algo == "sha256" else "1",))
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('primary_key',?)",
                    (self.pk_col,))
            os.replace(legacy_path, legacy_path + ".migrated")
            for suffix in ("-wal", "-shm"):
                try:
                    os.remove(legacy_path + suffix)
                except OSError:
                    pass
            skip_note = (f", 跳过非 {self.hash_label} {skipped:,} 条" if skipped else "")
            print(f"[NKAMG] 旧单库已迁移至 {self.shard_count} 分片: {total:,} 条"
                  f"{skip_note}, 耗时 {time.time() - t0:.1f}s (备份: {legacy_path}.migrated)")
        except Exception as e:
            print(f"[NKAMG] 旧库迁移失败(将按空分片库启动): {e}")

    # ---------- Bloom (按分片懒加载) ----------
    @staticmethod
    def _bloom_stored_n(path):
        """只读 bloom 文件头返回存储的元素数 n; 无效文件返回 None"""
        try:
            with open(path, "rb") as f:
                if f.read(4) != BloomFilter.MAGIC:
                    return None
                f.read(24)  # m, k, fp
                return struct.unpack("<Q", f.read(8))[0]
        except OSError:
            return None

    def _scan_bloom(self):
        """校验各分片 bloom 文件与签名数是否一致; 缺失/不一致 → 标记 dirty (finalize 重建)"""
        try:
            rows = self.meta.execute(
                "SELECT prefix, cnt FROM shard_counts WHERE cnt > 0"
            ).fetchall()
        except sqlite3.Error:
            rows = []
        for prefix, cnt in rows:
            try:
                sid = int(prefix)
            except ValueError:
                continue
            path = self._bloom_path(sid)
            if self._bloom_stored_n(path) == cnt:
                continue
            self._bloom_dirty.add(sid)

    def _load_bloom_shard(self, shard_id):
        """懒加载某分片的 Bloom (LRU); 文件缺失或无效 → 返回 None (不排除, 保守)

        查询期位图只读: 加载后调用方无锁读 bf.bits 是安全的 (引用替换/淘汰
        都不原地修改位图); 此处仅对字典 LRU 操作加 _cache_lock。
        """
        with self._cache_lock:
            bf = self._blooms.get(shard_id)
            if bf is not None:
                self._blooms.move_to_end(shard_id)
                return bf
            path = self._bloom_path(shard_id)
            if not os.path.exists(path):
                return None
            try:
                bf = BloomFilter.load(path)
            except Exception:
                self._bloom_dirty.add(shard_id)
                return None
            self._blooms[shard_id] = bf
            while len(self._blooms) > self.max_open_shards:
                self._blooms.popitem(last=False)
            return bf

    def already_imported(self, filename):
        with self._lock:
            row = self.meta.execute(
                "SELECT 1 FROM imported_files WHERE name=?", (filename,)
            ).fetchone()
            return row is not None

    # ---------- 导入 ----------
    def import_hdb(self, filepath, batch=50_000):
        """导入 .hdb/.hsb 明文签名文件 (增量, 幂等), 返回新插入条数

        仅接受与本库主键等长的哈希行 (sha256 库收 64hex, md5 库收 32hex),
        其它合法长度 (32/40/64hex) 计数跳过。
        """
        basename = os.path.basename(filepath)
        pending = {}  # shard_id -> [(digest, size, name)]
        skipped = 0   # 非本库长度的合法哈希行
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
                    if len(h) == self.pk_hex_len:
                        pass
                    elif len(h) in VALID_HASH_LENGTHS:  # 其它长度 (md5/sha1/sha256): 计数跳过
                        skipped += 1
                        continue
                    else:
                        continue
                    try:
                        digest = bytes.fromhex(h)
                    except ValueError:
                        continue
                    size_field = parts[1].strip()
                    size = None if size_field == "*" else int(size_field)
                    name = parts[2].strip()
                    # 仅本库主键长度的签名入库, 按摘要前缀路由分片
                    pending.setdefault(
                        self._route(digest, self.shard_count), []
                    ).append(self._row_for_insert(digest, size, name))
            inserted = 0
            count_updates = []
            dirty = set()
            for sid, rows in pending.items():
                shard = self._open_rw(self._shard_path(sid))
                shard.execute(self._ddl)
                before = shard.total_changes
                for i in range(0, len(rows), batch):
                    shard.executemany(self._insert_sql, rows[i:i + batch])
                shard.commit()
                delta = shard.total_changes - before
                cnt = shard.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                shard.close()
                inserted += delta
                count_updates.append((self._shard_name(sid), cnt))
                dirty.add(sid)
            with self.meta:
                self.meta.executemany(
                    "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                    count_updates,
                )
                self.meta.execute(
                    "INSERT OR IGNORE INTO imported_files(name) VALUES(?)", (basename,)
                )
            self._count += inserted
            self._bloom_dirty |= dirty  # 新增签名的分片 bloom 失效, 待 finalize 重建
        if basename not in self.source_files:
            self.source_files.append(basename)
        if skipped:
            print(f"[NKAMG] 导入 {basename}: 跳过 {skipped:,} 条非 {self.hash_label} 签名"
                  f" (本库主键为 {self.hash_label})")
        return inserted

    # 旧接口兼容
    def load_hdb(self, filepath):
        return self.import_hdb(filepath)

    def finalize(self):
        """导入/迁移完成后调用: 重建标记为 dirty 的分片 Bloom (增量)。返回状态 dict"""
        status = {}
        with self._lock:
            dirty = list(self._bloom_dirty)
            if self._count > 0 and dirty:
                t0 = time.time()
                rebuilt = 0
                for sid in dirty:
                    path = self._shard_path(sid)
                    if not os.path.exists(path):
                        continue
                    conn = self._ro_conn(sid)
                    if conn is None:
                        continue
                    lock = self._conn_locks.get(sid)
                    if lock is None:
                        continue
                    with lock:  # 连接级串行锁: 避免与并发查询交叉执行
                        cnt = conn.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                        if cnt == 0:
                            continue
                        bf = BloomFilter(cnt, self.bloom_fp_rate)
                        cur = conn.execute(
                            f"SELECT {self.pk_col} FROM sigs")
                        while True:
                            rows = cur.fetchmany(100_000)
                            if not rows:
                                break
                            for (h,) in rows:
                                bf.add(h)
                    bf.save(self._bloom_path(sid))
                    with self._cache_lock:
                        self._blooms[sid] = bf  # 引用替换, 查询中的旧引用不受影响
                    rebuilt += 1
                self._bloom_dirty.clear()
                status["bloom_rebuilt"] = rebuilt
                status["bloom_rebuilt_s"] = round(time.time() - t0, 1)
        return status

    # ---------- 查询 ----------
    @property
    def count(self):
        return self._count

    def check_hash(self, hash_hex, file_size=None):
        """按本库主键哈希十六进制查询 (md5 库收 32hex, sha256 库收 64hex)。

        Bloom 排除短路 + 单分片 SQLite 点查; file_size=None 时跳过大小校验
        (哈希查询场景调用方只有哈希没有文件)。返回命中列表, 结构与 check 一致。
        """
        hits = []
        if not hash_hex or len(hash_hex) != self.pk_hex_len:
            return hits
        try:
            digest = bytes.fromhex(hash_hex)
        except ValueError:
            return hits
        shard_id = self._route(digest, self.shard_count)
        bf = self._load_bloom_shard(shard_id)
        if bf is not None and digest not in bf:
            return hits
        row = self._query_shard(
            shard_id, f"SELECT size, name FROM sigs WHERE {self.pk_col}=?", (digest,)
        )
        if row is None:
            return hits
        sig_size, name = row
        if file_size is not None and sig_size is not None and sig_size != file_size:
            return hits
        hits.append({
            "engine": "Hash DB",
            "type": "hash",
            "name": name,
            "size": sig_size,
            "detail": f"{self.hash_label} 命中: {hash_hex}",
        })
        return hits

    def check(self, file_path, file_size, md5, sha1, sha256):
        """检查文件哈希是否命中签名, 返回命中列表 (接口与旧版一致)

        v3 起签名库仅存 SHA256 签名 (主键即 sha256), 查询只对 sha256 摘要做
        一次 Bloom 排除 + SQLite 点查即短路; md5/sha1 参数保留仅为兼容接口,
        库内无对应数据必然未命中。

        并发安全 (P0 优化): 查询路径不再持全局锁 ——
          · Bloom 位图查询期只读 (加载/淘汰只做引用替换, 不原地改位图) → 无锁读
          · 分片连接 check_same_thread=False, SQLite serialized 模式可跨线程并发读
          · 仅 _conns/_blooms 字典 LRU 操作在 _load_bloom_shard/_ro_conn 内部加细粒度锁
        """
        hits = []
        if not sha256:
            return hits
        digest = bytes.fromhex(sha256)
        shard_id = self._route(digest, self.shard_count)
        # 第 1 层: 该分片 Bloom 排除 (干净文件短路, 零 SQL 开销)
        bf = self._load_bloom_shard(shard_id)
        if bf is not None and digest not in bf:
            return hits
        # 第 2 层: 该分片 SQLite 点查 (只加载路由匹配的那个分片)
        row = self._query_shard(
            shard_id, "SELECT size, name FROM sigs WHERE sha256=?", (digest,)
        )
        if row is None:
            return hits
        sig_size, name = row
        # 大小校验 (降低碰撞误报): 仅当调用方提供了 file_size 时比对;
        # file_size=None (如 /api/hash/ 哈希查询, 调用方只有哈希没有文件) 跳过该校验
        if file_size is not None and sig_size is not None and sig_size != file_size:
            return hits
        hits.append({
            "engine": "Hash DB",
            "type": "hash",
            "name": name,
            "size": sig_size,
            "detail": f"SHA256 命中: {sha256}",
        })
        return hits

    # ---------- 统计 ----------
    def stats(self):
        # 并发快照: 遍历 LRU 字典前先加锁, 避免迭代中被其它线程淘汰
        with self._cache_lock:
            bloom_items = list(self._blooms.values())
            open_conns = len(self._conns)
        bloom_info = None
        if bloom_items:
            total_mem = sum(b.mem_bytes for b in bloom_items)
            bloom_info = {
                "shards_configured": self.shard_count,
                "shards_loaded": len(bloom_items),
                "mem_mb": round(total_mem / 1048576, 2),
                "hash_funcs": bloom_items[-1].k,
                "fp_rate": self.bloom_fp_rate,
            }
        shard_files = self._layout_shard_files()
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
        tier = ("bloom-shards+sharded-sqlite"
                if self._blooms else "sharded-sqlite")
        return {
            "count": self._count,
            "tier": tier,
            "bloom": bloom_info,
            "shards": {
                "configured": self.shard_count,
                "total": len(shard_files),
                "open_conns": open_conns,
                "max_open": self.max_open_shards,
            },
            "db_size_mb": round(db_size / 1048576, 1),
        }

    def close(self):
        with self._lock:
            with self._cache_lock:
                conns = list(self._conns.values()) + self._retired
                self._conns.clear()
                self._conn_locks.clear()
                self._retired = []
                self._blooms.clear()
            for conn in conns:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
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
        """扫描文件, 返回命中列表 (路径版本: YARA 自行读盘)"""
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path, timeout=10)
        except yara.TimeoutError:
            return self._timeout_hit()
        except yara.Error as e:
            return self._error_hit(e)
        return self._format_matches(matches)

    def scan_data(self, data):
        """扫描内存缓冲, 返回命中列表 (与 scan 等价, 但复用调用方已读入的数据,
        避免哈希/类型识别后 YARA 再次读盘 → 文件只读一遍)"""
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data, timeout=10)
        except yara.TimeoutError:
            return self._timeout_hit()
        except yara.Error as e:
            return self._error_hit(e)
        return self._format_matches(matches)

    @staticmethod
    def _timeout_hit():
        return [{
            "engine": "YARA",
            "type": "error",
            "name": "YaraScanTimeout",
            "detail": "规则匹配超时 (10s)",
        }]

    @staticmethod
    def _error_hit(e):
        return [{
            "engine": "YARA",
            "type": "error",
            "name": "YaraScanError",
            "detail": str(e),
        }]

    @staticmethod
    def _format_matches(matches):
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

    # 一次性读入内存的上限: 超过则退回分块+路径扫描, 防大文件占满内存
    INLINE_LIMIT = 64 * 1024 * 1024

    def __init__(self, hash_db, yara_scanner, md5_db=None):
        self.hash_db = hash_db
        self.yara_scanner = yara_scanner
        self.md5_db = md5_db  # 独立 MD5 分片库 (可选); 命中并入 detections

    def scan_file(self, file_path, filename=None):
        """扫描单个文件 (兼容接口)。

        <=64MB 一次性读入内存, 哈希 / 类型识别 / YARA 从同一份缓冲取 (文件只读一遍);
        更大文件退回 _scan_large 分块路径。
        """
        file_size = os.path.getsize(file_path)
        if file_size <= self.INLINE_LIMIT:
            with open(file_path, "rb") as f:
                data = f.read()
            return self._scan_common(
                data, filename or os.path.basename(file_path), file_size
            )
        return self._scan_large(file_path, filename)

    def scan_bytes(self, data, filename=None):
        """直接扫描内存数据 (Web 上传路径: 全程不落盘, 零额外磁盘 IO)"""
        return self._scan_common(data, filename or "unnamed", len(data))

    def scan_phase1(self, data, filename=None):
        """两段式扫描·阶段1 (Web 上传): 哈希 + 文件类型 + 哈希签名库命中, 毫秒级立即返回"""
        return self._phase1(data, filename or "unnamed")

    def scan_phase2(self, data, filename=None):
        """两段式扫描·阶段2 (Web 上传, 后台线程): YARA 规则 + 静态信息/模糊哈希 + 查壳"""
        return self._phase2(data, filename or "unnamed")

    def merge_phases(self, p1, p2):
        """两段式扫描·合并: 阶段1 + 阶段2 → 完整扫描结果 (供轮询接口拼装)"""
        return self._merge_phases(p1, p2)

    def _scan_common(self, data, filename, file_size):
        """内存复用核心 (同步完整扫描): 哈希 → 类型识别 → 签名库 → YARA → 静态信息

        供 scan_file / scan_bytes 兼容使用, 等价于 _phase1 + _phase2 顺序合并;
        Web 上传路径改用 scanner.scan_phase1 / scan_phase2 两段式 (哈希先返回, 深度分析动态更新)。
        """
        p1 = self._phase1(data, filename)
        p2 = self._phase2(data, filename)
        return self._merge_phases(p1, p2)

    def _phase1(self, data, filename):
        """阶段 1 (快速, 同步返回): 哈希 → 文件类型 → 哈希签名库命中

        只做 O(1) 哈希计算 + Bloom/SQLite 点查, 毫秒级返回;
        返回结构带 phase="hash" 标记, detections 仅含 Hash DB 命中。
        """
        start = time.time()
        md5, sha1, sha256 = compute_hashes_bytes(data)
        file_size = len(data)

        # 文件类型识别 (ClamAV FTM 机制: 魔数 → 模式 → 尾部魔数 → 文本检测)
        ftype = {"name": "未知", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "n/a"}
        try:
            head = data[:ft.MAGIC_BUFFER_SIZE]
            tail = (data[-512:] if len(data) > ft.MAGIC_BUFFER_SIZE + 512 else b"")
            ftype = ft.detect_file_type(head, tail, filename)
        except Exception:
            pass

        detections = list(self.hash_db.check(None, file_size, md5, sha1, sha256))
        if self.md5_db is not None:
            detections.extend(self.md5_db.check_hash(md5, file_size))
        elapsed_ms = round((time.time() - start) * 1000, 1)
        return {
            "filename": filename or "unnamed",
            "size": file_size,
            "size_human": _human_size(file_size),
            "file_type": ftype["name"],          # 显示名 (向后兼容)
            "file_type_info": ftype,             # 结构化: name/cl_type/category/method
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "detections": detections,            # 仅 Hash DB 命中
            "clean": len(detections) == 0,
            "verdict": "CLEAN" if not detections else "DETECTED",
            "scanners": ["Hash DB (md5/sha1/sha256)"],
            "elapsed_ms": elapsed_ms,            # 阶段1耗时
            "static_info": None,
            "static_ms": 0.0,
            "phase": "hash",
        }

    def _phase2(self, data, filename):
        """阶段 2 (深度, 后台执行): YARA 规则匹配 + 静态信息/模糊哈希 + 查壳

        返回合并阶段 1 所需的补充字段: detections(YARA) / static_info / static_ms / elapsed_ms / scanners。
        """
        start = time.time()
        detections = list(self.yara_scanner.scan_data(data))

        # 静态信息与模糊哈希 (ssdeep/tlsh/imphash/authentihash + PE 元数据 + 壳检测)
        static_start = time.time()
        static_info = staticinfo.compute_static_info(data)
        static_ms = round((time.time() - static_start) * 1000, 1)

        elapsed_ms = round((time.time() - start) * 1000, 1)
        scanners = (["YARA"] if YARA_AVAILABLE and self.yara_scanner.rules else [])
        return {
            "detections": detections,            # 仅 YARA 命中
            "static_info": static_info,
            "static_ms": static_ms,
            "elapsed_ms": elapsed_ms,            # 阶段2耗时
            "scanners": scanners,
        }

    def _merge_phases(self, p1, p2):
        """合并阶段 1/2 结果 → 完整扫描结果 (返回结构与原 _scan_common 一致)"""
        detections = p1["detections"] + p2["detections"]
        return {
            "filename": p1["filename"],
            "size": p1["size"],
            "size_human": p1["size_human"],
            "file_type": p1["file_type"],        # 显示名 (向后兼容)
            "file_type_info": p1["file_type_info"],
            "md5": p1["md5"],
            "sha1": p1["sha1"],
            "sha256": p1["sha256"],
            "static_info": p2["static_info"],     # fuzzy: ssdeep/tlsh/imphash/authentihash; pe: PE 元数据; packer: 壳检测
            "static_ms": p2["static_ms"],
            "clean": len(detections) == 0,
            "verdict": "CLEAN" if not detections else "DETECTED",
            "detections": detections,
            "elapsed_ms": round(p1["elapsed_ms"] + p2["elapsed_ms"], 1),
            "scanners": p1["scanners"] + p2["scanners"],
            "phase": "done",
        }

    def _scan_large(self, file_path, filename=None):
        """大文件退回路径: 分块哈希 + 头尾类型识别 + YARA 路径扫描 (与旧版一致)"""
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
        if self.md5_db is not None:
            detections.extend(self.md5_db.check_hash(md5, file_size))
        detections.extend(self.yara_scanner.scan(file_path))

        # 大文件路径: 不计算模糊哈希/静态信息 (避免超大文件纯 Python 计算失控)
        static_info = None
        static_ms = 0.0

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
            "static_info": static_info,          # 大文件路径不计算
            "static_ms": static_ms,
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
