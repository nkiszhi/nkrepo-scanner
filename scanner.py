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
import tlsh as tlsh_module

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import ppdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

# TLSH 模块为纯 Python 自研, 始终可用
TLSH_AVAILABLE = True
tlsh_diff = tlsh_module.diff  # 距离计算函数 (越小越相似)

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
#   size/name                    签名元数据
#   md5 BLOB                     同文件 MD5 (无数据源时 NULL, 预留; 保留以兼容查询)
SIGS_COLS = "sha256,size,name,md5"
SIGS_DDL = (
    "CREATE TABLE IF NOT EXISTS sigs("
    " sha256 BLOB PRIMARY KEY,"
    " size INTEGER, name TEXT,"
    " md5 BLOB) WITHOUT ROWID"
)
SIGS_INSERT = (
    "INSERT OR IGNORE INTO sigs(" + SIGS_COLS + ")"
    " VALUES(?,?,?,?)"
)

# 字节长度 -> 哈希类型; v3 起库内仅接受 SHA256 (32B)
def _sigs_row(sha256_digest, size, name):
    """把 (sha256_digest,size,name) 映射为 4 列新结构行; 非 32B 抛 ValueError"""
    if len(sha256_digest) != 32:
        raise ValueError(f"仅支持 SHA256 签名 (32B), 收到 {len(sha256_digest)}B")
    return (sha256_digest, size, name, None)  # md5 (预留, NULL)


def compute_hashes(file_path):
    """一次性分块计算文件的 MD5 / SHA1 / SHA256 (SHA1 供 Web 文件哈希展示)"""
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
    """从内存缓冲一次性计算 MD5 / SHA1 / SHA256 (SHA1 供 Web 文件哈希展示)"""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha1, sha256


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


def _type_suspicion_signals(filename, ftype):
    """文件类型可疑信号 → detections 条目 (接入检测表展示)

    两类信号 (均不影响原有哈希/YARA 判定, 独立成行):
      · PE 头部结构校验失败 (伪装/损坏的 PE, filetype 增强返回 suspect 字段)
      · 扩展名与魔数识别结果不一致 (如 .jpg 扩展名 + PE 内容, 疑似伪装)
    """
    signals = []
    if not isinstance(ftype, dict):
        return signals
    suspect = ftype.get("suspect")
    if suspect:
        signals.append({
            "engine": "FileType",
            "type": "suspicious",
            "name": "文件结构异常",
            "detail": suspect,
        })
    mismatch = ft.check_extension_mismatch(filename, ftype)
    if mismatch:
        signals.append({
            "engine": "FileType",
            "type": "suspicious",
            "name": "扩展名与内容不一致",
            "detail": mismatch,
        })
    return signals


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

    - 分片路由由 layout 参数决定:
      modulo (默认): int.from_bytes(digest[:4], 'big') % N → 0000.db ~ (N-1).db
      hex:           digest[0] → 00.db ~ ff.db (固定 256 片, 按 SHA256 前两字符直查)
    - Bloom 按同样的分片数: {db_path}.bloom/{shard_id}.bloom, 与 SQLite 分片
      一一对应, 懒加载 + LRU 缓存, 冷启动零加载, 内存随查询按需增长
    - 查询: 路由 → 分片 Bloom 排除 (干净文件短路, 零 SQL) → 分片 SQLite 只读点查
    - 布局: meta 记录 layout/shard_count; 布局或 N 变更时自动重分片, 旧数据备份到 .shards.legacy/
    """

    LAYOUT_MODULO = "modulo"
    LAYOUT_HEX = "hex"
    HEX_COUNTS = {1: 16, 2: 256, 3: 4096}  # hex 前缀长度 → 分片数 (旧布局)

    def __init__(self, db_path, shard_count=4, bloom_fp_rate=0.01,
                 max_open_shards=4, hash_algo="sha256",
                 ddl=None, insert_sql=None, row_cols=None,
                 layout=LAYOUT_MODULO):
        """hash_algo 决定主键列 (sha256/md5); ddl/insert_sql/row_cols 可覆盖默认表结构
        (FuzzySignatureDB 用它定制 8 列模糊哈希结构; 默认 None = 按 hash_algo 的标准结构)

        layout 决定分片路由与命名:
          modulo: 摘要前4字节 % N → 4位十进制分片名 (0000~N-1), 任意 N 均匀分布
          hex:    摘要首字节 → 2位十六进制分片名 (00~ff), 固定 256 片, 按 SHA256 前缀直查
        """
        if hash_algo not in HASH_SPECS:
            raise ValueError(f"不支持的哈希算法: {hash_algo} (可选: {list(HASH_SPECS)})")
        self.hash_algo = hash_algo
        _spec = HASH_SPECS[hash_algo]
        self.pk_col = _spec["col"]          # 主键列名 (md5 / sha256)
        self.pk_hex_len = _spec["hex_len"]  # 主键十六进制长度 (32 / 64)
        self.pk_bytes = _spec["bytes"]      # 主键摘要字节数 (16 / 32)
        self.hash_label = _spec["label"]    # 显示名 (MD5 / SHA256)
        self.layout = layout
        if layout == self.LAYOUT_HEX:
            self.shard_count = 256           # hex 布局固定 256 片 (2 字符前缀)
        else:
            self.shard_count = max(1, int(shard_count))
        self.db_path = db_path
        self.shard_dir = db_path + ".shards"
        self.meta_path = os.path.join(self.shard_dir, "_meta.db")
        self.bloom_dir = db_path + ".bloom"   # 分片 Bloom 位图目录
        self.bloom_fp_rate = bloom_fp_rate
        self.max_open_shards = max(4, max_open_shards)
        # 表结构: sha256 库四列 (sha256 主键 + size/name + 预留 md5), md5 库三列;
        # 亦可通过构造参数 ddl/insert_sql/row_cols 定制 (FuzzySignatureDB 8 列模糊哈希结构)。
        # row_cols 供 _reshard 整行透传 SELECT 用, 须与 insert_sql 列数一致。
        if ddl is not None:
            self._ddl = ddl
        elif hash_algo == "sha256":
            self._ddl = SIGS_DDL
        else:
            self._ddl = (
                f"CREATE TABLE IF NOT EXISTS sigs({self.pk_col} BLOB PRIMARY KEY,"
                " size INTEGER, name TEXT) WITHOUT ROWID"
            )
        if insert_sql is not None:
            self._insert_sql = insert_sql
        elif hash_algo == "sha256":
            self._insert_sql = SIGS_INSERT
        else:
            self._insert_sql = (
                f"INSERT OR IGNORE INTO sigs({self.pk_col},size,name)"
                " VALUES(?,?,?)"
            )
        self._row_cols = row_cols or (
            "sha256,size,name,md5" if hash_algo == "sha256" else f"{self.pk_col},size,name"
        )
        self._lock = threading.RLock()       # 写路径互斥 (import_hdb / finalize / close)
        self._cache_lock = threading.Lock()  # _conns/_blooms 字典 LRU 操作的细粒度锁
        self._retired = []                   # LRU 淘汰的连接, 延迟到 close() 统一关闭
        self.source_files = []

        # 旧版单一 Bloom 文件 (sha256.db.bloom 单文件) 与新版 bloom 目录同名,
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
        """把 (digest,size,name) 映射为本库插入行; sha256 库为四列, md5 库为三列"""
        if self.hash_algo == "sha256":
            return _sigs_row(digest, size, name)  # 4 列 (含预留 md5)
        if len(digest) != self.pk_bytes:
            raise ValueError(
                f"仅支持 {self.hash_label} 签名 ({self.pk_bytes}B), 收到 {len(digest)}B")
        return (digest, size, name)              # 3 列独立结构

    # ---------- 路由与命名 ----------
    def _route(self, digest, shard_count=None):
        """路由: hex 布局取首字节 (0-255, 对应 00~ff 前缀); modulo 布局取前4字节对N取模"""
        if self.layout == self.LAYOUT_HEX:
            return digest[0]
        n = shard_count or self.shard_count
        return int.from_bytes(digest[:4], "big") % n

    def _shard_id(self, digest):
        return self._route(digest)

    def _shard_name(self, shard_id):
        if self.layout == self.LAYOUT_HEX:
            return "%02x" % shard_id   # 2 位十六进制: 00 ~ ff
        return "%04d" % shard_id       # 十进制 4 位定长: 0000 ~ N-1

    def _shard_path(self, shard_id):
        return os.path.join(self.shard_dir, self._shard_name(shard_id) + ".db")

    def _bloom_path(self, shard_id):
        return os.path.join(self.bloom_dir, self._shard_name(shard_id) + ".bloom")

    # ---------- 分片布局检测与同步 ----------
    def _layout_shard_files(self):
        """当前目录下的分片文件名列表 (modulo: 4位十进制, hex: 2位十六进制; 排除 _meta.db)"""
        result = []
        for f in os.listdir(self.shard_dir):
            if not f.endswith(".db") or f == "_meta.db":
                continue
            stem = f[:-3]
            if len(stem) == 4 and stem.isdigit():
                result.append(f)        # modulo 布局: 0000~9999
            elif len(stem) == 2 and all(c in "0123456789abcdef" for c in stem):
                result.append(f)        # hex 布局: 00~ff
        return result

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

        if layout != self.layout or old_count != self.shard_count:
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
                    f"SELECT {self._row_cols} FROM sigs")
                while True:
                    rows = cur.fetchmany(50_000)
                    if not rows:
                        break
                    for row in rows:  # 整行透传 (列数 = _row_cols, 与 _insert_sql 一致)
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
                (self.layout,))
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('shard_count',?)",
                (str(self.shard_count),))
        print(f"[NKAMG] 分片重排: {old_layout}({old_count}) → "
              f"{self.layout}({self.shard_count}), {total:,} 条, "
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
        """分片连接点查 (连接级串行锁; 连接被淘汰瞬间开临时连接补查, 不漏报)"""
        conn = self._ro_conn(shard_id)
        if conn is None:
            return None
        with self._cache_lock:
            lock = self._conn_locks.get(shard_id)
        if lock is None:
            # 连接刚被 LRU 淘汰: 开临时只读连接补查, 确保不漏报 (C1 修复)
            path = self._shard_path(shard_id)
            if not os.path.exists(path):
                return None
            tmp_conn = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, check_same_thread=False)
            try:
                return tmp_conn.execute(sql, params).fetchone()
            finally:
                tmp_conn.close()
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
        """把旧版单一 sha256.db 的签名按当前路由规则拆入分片"""
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
                    (self.layout,))
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
                if self.layout == self.LAYOUT_HEX:
                    sid = int(prefix, 16)   # hex 前缀: "0a" → 10
                else:
                    sid = int(prefix)       # modulo 前缀: "0001" → 1
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
                    # "*" 和 "0" 均归一化为 None (不限大小): 否则 size=0 的签名在文件扫描时永远无法通过大小校验
                    size = None if size_field in ("*", "0") else int(size_field)
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
                    if self.rebuild_bloom_shard(sid) is not None:
                        rebuilt += 1
                self._bloom_dirty.clear()
                status["bloom_rebuilt"] = rebuilt
                status["bloom_rebuilt_s"] = round(time.time() - t0, 1)
        return status

    # ---------- 单条写入 (管理接口: 增 / 删) ----------
    def rebuild_bloom_shard(self, sid):
        """重建单个分片的 Bloom 位图 (从该分片 SQLite 全量重算并落盘)。返回 bf 或 None。

        用于: ① 新增哈希后该分片尚无 bloom 文件 (首条入库)；② finalize() 增量重建 dirty 分片。
        已存在 bloom 的分片不会走到这里 (add_hash 直接复用并追加)。
        """
        path = self._shard_path(sid)
        if not os.path.exists(path):
            return None
        conn = self._ro_conn(sid)
        if conn is None:
            return None
        lock = self._conn_locks.get(sid)
        if lock is None:
            return None
        with lock:
            cnt = conn.execute(f"SELECT COUNT(*) FROM sigs").fetchone()[0]
            if cnt == 0:
                return None
            bf = BloomFilter(cnt, self.bloom_fp_rate)
            cur = conn.execute(f"SELECT {self.pk_col} FROM sigs")
            while True:
                rows = cur.fetchmany(100_000)
                if not rows:
                    break
                for (h,) in rows:
                    bf.add(h)
        bf.save(self._bloom_path(sid))
        with self._cache_lock:
            self._blooms[sid] = bf
        return bf

    def add_hash(self, hash_hex, size, name):
        """新增单条哈希签名 (hash:size:name), 自动按主键长度路由到 SHA256/MD5 库。

        写入对应分片 SQLite + 更新计数 + 增量更新 Bloom (命中即被后续查询发现)。
        返回新增条数 (0 表示已存在, 1 表示新增)。哈希长度须与本库主键等长
        (sha256 库 64hex / md5 库 32hex), 否则抛 ValueError。
        """
        h = (hash_hex or "").strip().lower()
        if len(h) != self.pk_hex_len:
            raise ValueError(
                f"需要 {self.pk_hex_len} 位 {self.hash_label} 十六进制, 收到 {len(h)} 位")
        try:
            digest = bytes.fromhex(h)
        except ValueError:
            raise ValueError("非法的十六进制哈希")
        # "*", "" 和 0 均归一化为 None (不限大小), 与 import_hdb 行为一致
        size_field = None if size in (None, "*", "", 0, "0") else int(size)
        name_field = (name or "").strip() or "unknown"
        with self._lock:
            sid = self._route(digest)
            shard = self._open_rw(self._shard_path(sid))
            shard.execute(self._ddl)
            before = shard.total_changes
            shard.execute(self._insert_sql, self._row_for_insert(digest, size_field, name_field))
            inserted = shard.total_changes - before
            shard.commit()
            if inserted:
                cnt = shard.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                with self.meta:
                    self.meta.execute(
                        "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                        (self._shard_name(sid), cnt))
                    self.meta.execute(
                        "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')")
                self._count += inserted
                # Bloom: 已有位图则追加并落盘; 否则首次全量重建 (含本条)
                bf = self._load_bloom_shard(sid)
                if bf is None:
                    bf = self.rebuild_bloom_shard(sid)
                if bf is not None:
                    bf.add(digest)
                    bf.save(self._bloom_path(sid))
                    with self._cache_lock:
                        self._blooms[sid] = bf
            return inserted

    def delete_hash(self, hash_hex):
        """删除单条哈希签名, 返回删除条数 (0 表示不存在)。

        仅从 SQLite 移除; Bloom 位图不回收该位 (布隆过滤器不可删除, 残留位只会造成
        无害的假阳性 → SQLite 点查返回空 → 正确判定为未命中)。计数与分片计数同步更新。
        """
        h = (hash_hex or "").strip().lower()
        if len(h) != self.pk_hex_len:
            raise ValueError(
                f"需要 {self.pk_hex_len} 位 {self.hash_label} 十六进制, 收到 {len(h)} 位")
        try:
            digest = bytes.fromhex(h)
        except ValueError:
            raise ValueError("非法的十六进制哈希")
        with self._lock:
            sid = self._route(digest)
            if not os.path.exists(self._shard_path(sid)):
                return 0
            shard = self._open_rw(self._shard_path(sid))
            before = shard.total_changes
            shard.execute(f"DELETE FROM sigs WHERE {self.pk_col}=?", (digest,))
            deleted = shard.total_changes - before
            shard.commit()
            if deleted:
                cnt = shard.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
                with self.meta:
                    self.meta.execute(
                        "INSERT OR REPLACE INTO shard_counts(prefix,cnt) VALUES(?,?)",
                        (self._shard_name(sid), cnt))
                    self.meta.execute(
                        "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')")
                self._count -= deleted
            return deleted

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
            "engine": "MD5 Hash DB",
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
            "engine": "SHA256 Hash DB",
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
# 模糊哈希签名库 (FuzzySignatureDB): 5 表独立结构
# 每种 fuzzy hash 独立成表, 以 fuzzy hash 本身为主键 (不再是 sha256)
# 数据源 ClamAV 8 字段 hdb 行: sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash
# ============================================================
FUZZY_TYPES = ["vhash", "authentihash", "imphash", "rich_header_hash"]

# 每种 fuzzy hash 的表定义: 表名 / 列名 / SQL 类型 / DDL / INSERT / SELECT 列
FUZZY_TABLE_SPECS = {
    "vhash": {
        "col": "vhash", "sql_type": "BLOB", "label": "VHash",
        "table": "sigs_vhash",
        "ddl": "CREATE TABLE IF NOT EXISTS sigs_vhash("
               " vhash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB)"
               " WITHOUT ROWID",
        "insert": "INSERT OR IGNORE INTO sigs_vhash(vhash,size,name,sha256) VALUES(?,?,?,?)",
        "cols": "vhash,size,name,sha256",
    },
    "authentihash": {
        "col": "authentihash", "sql_type": "BLOB", "label": "Authentihash",
        "table": "sigs_authentihash",
        "ddl": "CREATE TABLE IF NOT EXISTS sigs_authentihash("
               " authentihash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB)"
               " WITHOUT ROWID",
        "insert": "INSERT OR IGNORE INTO sigs_authentihash(authentihash,size,name,sha256) VALUES(?,?,?,?)",
        "cols": "authentihash,size,name,sha256",
    },
    "imphash": {
        "col": "imphash", "sql_type": "BLOB", "label": "Imphash",
        "table": "sigs_imphash",
        "ddl": "CREATE TABLE IF NOT EXISTS sigs_imphash("
               " imphash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB)"
               " WITHOUT ROWID",
        "insert": "INSERT OR IGNORE INTO sigs_imphash(imphash,size,name,sha256) VALUES(?,?,?,?)",
        "cols": "imphash,size,name,sha256",
    },
    "rich_header_hash": {
        "col": "rich_header_hash", "sql_type": "BLOB", "label": "RichHeaderHash",
        "table": "sigs_rich_header_hash",
        "ddl": "CREATE TABLE IF NOT EXISTS sigs_rich_header_hash("
               " rich_header_hash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB)"
               " WITHOUT ROWID",
        "insert": "INSERT OR IGNORE INTO sigs_rich_header_hash(rich_header_hash,size,name,sha256) VALUES(?,?,?,?)",
        "cols": "rich_header_hash,size,name,sha256",
    },
}


def _hex_to_blob(s):
    """hex 字符串 → BLOB 字节 (偶数长度纯 hex); 空/非法/奇数长度返回 None"""
    if not s:
        return None
    s = s.strip().lower()
    if len(s) % 2 or not all(c in "0123456789abcdef" for c in s):
        return None
    return bytes.fromhex(s)


class FuzzySignatureDB:
    """4 表模糊哈希签名库 (每种 fuzzy hash 独立成表, 以 fuzzy hash 为主键)。

    每个 hex 分片文件 (00.db ~ ff.db) 包含 4 张表:
      sigs_vhash(vhash BLOB PK, size, name, sha256 BLOB)
      sigs_authentihash(authentihash BLOB PK, size, name, sha256 BLOB)
      sigs_imphash(imphash BLOB PK, size, name, sha256 BLOB)
      sigs_rich_header_hash(rich_header_hash BLOB PK, size, name, sha256 BLOB)

    注意: ssdeep 已独立到 SsdeepLibrary (单文件 SQLite, 无 bloom, 无分片)。
    路由: BLOB 类型取首字节 → 00~ff 分片。
    Bloom 按类型 × 分片: {shard}_{type}.bloom, 懒加载 + LRU 缓存。
    数据源: ClamAV 8 字段 hdb 行, 每个非空 fuzzy 字段独立写入对应表。
    """

    LAYOUT_HEX = "hex"

    def __init__(self, db_path, shard_count=4, bloom_fp_rate=0.01,
                 max_open_shards=16, layout="hex"):
        self.db_path = db_path
        self.shard_dir = db_path + ".shards"
        self.bloom_dir = db_path + ".bloom"
        self.meta_path = os.path.join(self.shard_dir, "_meta.db")
        self.bloom_fp_rate = bloom_fp_rate
        self.max_open_shards = max(4, max_open_shards)
        self.layout = layout
        self.shard_count = 256 if layout == self.LAYOUT_HEX else max(1, int(shard_count))

        os.makedirs(self.shard_dir, exist_ok=True)
        os.makedirs(self.bloom_dir, exist_ok=True)

        self._lock = threading.RLock()
        self._cache_lock = threading.Lock()

        # Meta DB
        self.meta = self._open_rw(self.meta_path)
        self._init_meta()

        # LRU caches: 连接按 shard_id 共享 (5 表在同一文件), bloom 按 (type, shard_id)
        self._conns = OrderedDict()
        self._conn_locks = {}
        self._blooms = OrderedDict()    # (fuzzy_type, shard_id) -> BloomFilter
        self._bloom_dirty = set()       # {(fuzzy_type, shard_id)}
        self._retired = []

        self._counts = self._load_counts()
        self.source_files = [
            r[0] for r in self.meta.execute("SELECT name FROM imported_files")
        ]
        self._scan_bloom()

    # ---------- Meta ----------
    @staticmethod
    def _open_rw(path):
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_meta(self):
        self.meta.execute(
            "CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)")
        self.meta.execute(
            "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        self.meta.execute(
            "CREATE TABLE IF NOT EXISTS fuzzy_counts("
            " type TEXT, prefix TEXT, cnt INTEGER NOT NULL,"
            " PRIMARY KEY(type, prefix))")
        self.meta.commit()
        self.meta.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('layout','hex')")
        self.meta.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('shard_count','256')")
        self.meta.execute(
            "INSERT OR IGNORE INTO meta(k,v) VALUES('schema_version','4')")
        self.meta.commit()

    # ---------- 路由 ----------
    def _route(self, fuzzy_type, value):
        """Route fuzzy hash value → shard_id (0-255). BLOB: blob[0]"""
        return value[0]

    def _bloom_key(self, fuzzy_type, value):
        """Bloom 用的字节: BLOB → 原始字节"""
        return value

    def _shard_name(self, shard_id):
        return "%02x" % shard_id

    def _shard_path(self, shard_id):
        return os.path.join(self.shard_dir, self._shard_name(shard_id) + ".db")

    def _bloom_path(self, fuzzy_type, shard_id):
        return os.path.join(self.bloom_dir,
                            f"{self._shard_name(shard_id)}_{fuzzy_type}.bloom")

    # ---------- 连接管理 (5 表共享同一 shard 连接) ----------
    def _ro_conn(self, shard_id):
        """获取分片只读连接 (懒加载 + LRU); 5 表共用同一连接"""
        with self._cache_lock:
            conn = self._conns.get(shard_id)
            if conn is not None:
                self._conns.move_to_end(shard_id)
                return conn
            path = self._shard_path(shard_id)
            if not os.path.exists(path):
                return None
            conn = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, check_same_thread=False)
            try:
                conn.execute("PRAGMA query_only=ON")
            except sqlite3.Error:
                pass
            self._conns[shard_id] = conn
            self._conn_locks[shard_id] = threading.Lock()
            while len(self._conns) > self.max_open_shards:
                old_id, old = self._conns.popitem(last=False)
                self._conn_locks.pop(old_id, None)
                self._retired.append(old)
            return conn

    def _query_shard(self, shard_id, sql, params=()):
        conn = self._ro_conn(shard_id)
        if conn is None:
            return None
        with self._cache_lock:
            lock = self._conn_locks.get(shard_id)
        if lock is None:
            # 连接刚被 LRU 淘汰: 开临时只读连接补查, 确保不漏报 (C1 修复)
            path = self._shard_path(shard_id)
            if not os.path.exists(path):
                return None
            tmp_conn = sqlite3.connect(
                f"file:{path}?mode=ro", uri=True, check_same_thread=False)
            try:
                return tmp_conn.execute(sql, params).fetchone()
            finally:
                tmp_conn.close()
        with lock:
            return conn.execute(sql, params).fetchone()

    # ---------- 计数 ----------
    def _load_counts(self):
        """从 meta 的 fuzzy_counts 表加载各类型计数; 缓存失效则逐片重数"""
        valid = self.meta.execute(
            "SELECT v FROM meta WHERE k='counts_valid'").fetchone()
        if valid and valid[0] == "1":
            rows = self.meta.execute(
                "SELECT type, SUM(cnt) FROM fuzzy_counts GROUP BY type").fetchall()
            return {t: (c or 0) for t, c in rows}
        counts = {t: 0 for t in FUZZY_TYPES}
        count_rows = []
        for sid in range(self.shard_count):
            path = self._shard_path(sid)
            if not os.path.exists(path):
                continue
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            prefix = self._shard_name(sid)
            for ftype in FUZZY_TYPES:
                spec = FUZZY_TABLE_SPECS[ftype]
                try:
                    cnt = conn.execute(
                        f"SELECT COUNT(*) FROM {spec['table']}").fetchone()[0]
                except sqlite3.Error:
                    cnt = 0
                counts[ftype] += cnt
                if cnt > 0:
                    count_rows.append((ftype, prefix, cnt))
            conn.close()
        with self.meta:
            self.meta.execute("DELETE FROM fuzzy_counts")
            self.meta.executemany(
                "INSERT OR REPLACE INTO fuzzy_counts(type,prefix,cnt) VALUES(?,?,?)",
                count_rows)
            self.meta.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')")
        return counts

    @property
    def count(self):
        return sum(self._counts.values())

    def already_imported(self, filename):
        with self._lock:
            row = self.meta.execute(
                "SELECT 1 FROM imported_files WHERE name=?", (filename,)).fetchone()
            return row is not None

    # ---------- Bloom ----------
    @staticmethod
    def _bloom_stored_n(path):
        try:
            with open(path, "rb") as f:
                if f.read(4) != BloomFilter.MAGIC:
                    return None
                f.read(24)
                return struct.unpack("<Q", f.read(8))[0]
        except OSError:
            return None

    def _scan_bloom(self):
        """校验各 (type, shard) bloom 与计数是否一致; 不一致标记 dirty"""
        rows = self.meta.execute(
            "SELECT type, prefix, cnt FROM fuzzy_counts WHERE cnt > 0").fetchall()
        for ftype, prefix, cnt in rows:
            try:
                sid = int(prefix, 16)
            except ValueError:
                continue
            path = self._bloom_path(ftype, sid)
            if self._bloom_stored_n(path) != cnt:
                self._bloom_dirty.add((ftype, sid))

    def _load_bloom(self, fuzzy_type, shard_id):
        """懒加载 (type, shard) 的 Bloom (LRU)"""
        with self._cache_lock:
            key = (fuzzy_type, shard_id)
            bf = self._blooms.get(key)
            if bf is not None:
                self._blooms.move_to_end(key)
                return bf
            path = self._bloom_path(fuzzy_type, shard_id)
            if not os.path.exists(path):
                return None
            try:
                bf = BloomFilter.load(path)
            except Exception:
                self._bloom_dirty.add(key)
                return None
            self._blooms[key] = bf
            while len(self._blooms) > self.max_open_shards:
                self._blooms.popitem(last=False)
            return bf

    # ---------- 导入 ----------
    def import_hdb(self, filepath, batch=50_000):
        """导入 ClamAV 8 字段 hdb 文件, 每个非空 fuzzy 字段独立写入对应表。

        行格式: sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash
        每个 fuzzy hash 按自身值路由到 00~ff 分片, 写入对应表 (INSERT OR IGNORE 去重)。
        """
        basename = os.path.basename(filepath)
        start = time.time()
        with self._lock:
            # pending: {(fuzzy_type, shard_id): [(hash_value, size, name, sha256_blob)]}
            pending = {}
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 8:
                        continue
                    h = parts[0].strip().lower()
                    if len(h) != 64:
                        continue
                    try:
                        sha256_blob = bytes.fromhex(h)
                    except ValueError:
                        continue
                    size_field = parts[1].strip()
                    try:
                        # "*" 和 "0" 均归一化为 None (不限大小), 与 HashSignatureDB.import_hdb 一致
                        size = None if size_field in ("*", "0") else int(size_field)
                    except ValueError:
                        size = None
                    name = parts[2].strip()
                    vhash_blob = _hex_to_blob(parts[4])
                    auth_blob = _hex_to_blob(parts[5])
                    imp_blob = _hex_to_blob(parts[6])
                    rich_blob = _hex_to_blob(parts[7])
                    # 分发到 4 个表 (ssdeep 已独立到 SsdeepLibrary)
                    fuzzy_values = {
                        "vhash": vhash_blob,
                        "authentihash": auth_blob,
                        "imphash": imp_blob,
                        "rich_header_hash": rich_blob,
                    }
                    for ftype, val in fuzzy_values.items():
                        if val is None:
                            continue
                        sid = self._route(ftype, val)
                        pending.setdefault((ftype, sid), []).append(
                            (val, size, name, sha256_blob))
            inserted = 0
            count_updates = []
            dirty = set()
            for (ftype, sid), rows in pending.items():
                spec = FUZZY_TABLE_SPECS[ftype]
                shard = self._open_rw(self._shard_path(sid))
                # 确保所有 5 张表都存在
                for ft in FUZZY_TYPES:
                    shard.execute(FUZZY_TABLE_SPECS[ft]["ddl"])
                before = shard.total_changes
                for i in range(0, len(rows), batch):
                    shard.executemany(spec["insert"], rows[i:i + batch])
                shard.commit()
                delta = shard.total_changes - before
                cnt = shard.execute(
                    f"SELECT COUNT(*) FROM {spec['table']}").fetchone()[0]
                shard.close()
                inserted += delta
                count_updates.append((ftype, self._shard_name(sid), cnt))
                dirty.add((ftype, sid))
            with self.meta:
                self.meta.executemany(
                    "INSERT OR REPLACE INTO fuzzy_counts(type,prefix,cnt) VALUES(?,?,?)",
                    count_updates)
                self.meta.execute(
                    "INSERT OR IGNORE INTO imported_files(name) VALUES(?)", (basename,))
                self.meta.execute(
                    "INSERT OR REPLACE INTO meta(k,v) VALUES('counts_valid','1')")
            self._counts = self._load_counts()
            self._bloom_dirty |= dirty
        if basename not in self.source_files:
            self.source_files.append(basename)
        return inserted

    # ---------- Finalize ----------
    def finalize(self):
        """导入完成后调用: 重建标记为 dirty 的 (type, shard) Bloom"""
        status = {}
        with self._lock:
            dirty = list(self._bloom_dirty)
            if dirty:
                t0 = time.time()
                rebuilt = 0
                for ftype, sid in dirty:
                    path = self._shard_path(sid)
                    if not os.path.exists(path):
                        continue
                    conn = self._ro_conn(sid)
                    if conn is None:
                        continue
                    lock = self._conn_locks.get(sid)
                    if lock is None:
                        continue
                    spec = FUZZY_TABLE_SPECS[ftype]
                    with lock:
                        cnt = conn.execute(
                            f"SELECT COUNT(*) FROM {spec['table']}").fetchone()[0]
                        if cnt == 0:
                            continue
                        bf = BloomFilter(cnt, self.bloom_fp_rate)
                        cur = conn.execute(
                            f"SELECT {spec['col']} FROM {spec['table']}")
                        while True:
                            rows = cur.fetchmany(100_000)
                            if not rows:
                                break
                            for (h,) in rows:
                                bf.add(self._bloom_key(ftype, h))
                    bf.save(self._bloom_path(ftype, sid))
                    with self._cache_lock:
                        self._blooms[(ftype, sid)] = bf
                    rebuilt += 1
                self._bloom_dirty.clear()
                status["bloom_rebuilt"] = rebuilt
                status["bloom_rebuilt_s"] = round(time.time() - t0, 1)
        return status

    # ---------- 查询 ----------
    def check_fuzzy(self, fuzzy_type, hash_value, file_size=None):
        """按 fuzzy hash 值查询对应表。hash_value: ssdeep 传 str, BLOB 类型传 bytes。"""
        hits = []
        if fuzzy_type not in FUZZY_TABLE_SPECS:
            return hits
        spec = FUZZY_TABLE_SPECS[fuzzy_type]
        sid = self._route(fuzzy_type, hash_value)
        bf = self._load_bloom(fuzzy_type, sid)
        bloom_key = self._bloom_key(fuzzy_type, hash_value)
        if bf is not None and bloom_key not in bf:
            return hits
        row = self._query_shard(
            sid,
            f"SELECT size, name, sha256 FROM {spec['table']} WHERE {spec['col']}=?",
            (hash_value,))
        if row is None:
            return hits
        sig_size, name, sha256_blob = row
        if file_size is not None and sig_size is not None and sig_size != file_size:
            return hits
        sha256_hex = sha256_blob.hex() if sha256_blob else None
        hits.append({
            "engine": "Fuzzy Hash DB",
            "type": "fuzzy",
            "name": name,
            "size": sig_size,
            "detail": f"{spec['label']} 命中",
            "fuzzy_type": fuzzy_type,
            "sha256": sha256_hex,
        })
        return hits

    def check_by_computed_hashes(self, imphash_hex=None,
                                 authentihash_hex=None, file_size=None):
        """批量查询: 用 staticinfo 计算出的 fuzzy hash 查各表, 返回命中列表
        (ssdeep 精确匹配由 SsdeepLibrary.check_exact 处理, 不在此查询)"""
        hits = []
        if imphash_hex:
            try:
                hits.extend(self.check_fuzzy("imphash", bytes.fromhex(imphash_hex), file_size))
            except ValueError:
                pass
        if authentihash_hex:
            try:
                hits.extend(self.check_fuzzy("authentihash", bytes.fromhex(authentihash_hex), file_size))
            except ValueError:
                pass
        return hits

    # ---------- 统计 ----------
    def stats(self):
        with self._cache_lock:
            bloom_items = list(self._blooms.values())
            open_conns = len(self._conns)
        bloom_info = None
        if bloom_items:
            total_mem = sum(b.mem_bytes for b in bloom_items)
            bloom_info = {
                "shards_configured": self.shard_count,
                "types": len(FUZZY_TYPES),
                "loaded": len(bloom_items),
                "mem_mb": round(total_mem / 1048576, 2),
                "fp_rate": self.bloom_fp_rate,
            }
        shard_files = [
            f for f in os.listdir(self.shard_dir)
            if f.endswith(".db") and f != "_meta.db"
            and len(f) == 5 and all(c in "0123456789abcdef" for c in f[:2])
        ]
        db_size = 0
        for f in shard_files:
            for suffix in ("", "-wal", "-shm"):
                try:
                    db_size += os.path.getsize(os.path.join(self.shard_dir, f + suffix))
                except OSError:
                    pass
        try:
            db_size += os.path.getsize(self.meta_path)
        except OSError:
            pass
        return {
            "count": self.count,
            "counts_by_type": dict(self._counts),
            "tier": "fuzzy-5table-sharded-sqlite" if self._blooms else "sharded-sqlite",
            "bloom": bloom_info,
            "shards": {
                "configured": self.shard_count,
                "total": len(shard_files),
                "types": len(FUZZY_TYPES),
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
# TLSH 自增长相似度库 (纯 Python, 单文件 SQLite)
# ============================================================
class TlshLibrary:
    """TLSH 自增长相似度检索库

    数据来源: 每次精确哈希命中 (SHA256/MD5) 的样本自动入库累积;
    无预置 TLSH 数据 (hdb 中不含 TLSH 字段)。
    检索: 将查询 TLSH 与库内全部 TLSH 逐一做 diff (纯 Python, 距离越小越相似),
          返回距离 ≤ threshold 的 top_k 条 (按距离升序)。

    表结构: tlsh (主键) / sha256 (BLOB 二进制, 32 字节) / size / name — 仅 4 字段,
    sha256 存储格式与 ssdeep 库一致。
    线程安全: 写入 (insert) 用 threading.Lock 保护; 读取 (search) 用只读连接,
    与写入连接隔离, 无锁竞争。
    """

    TLSH_SIM_THRESHOLD = 40    # 距离阈值 (≤ threshold 视为相似; 0=完全相同)
    TLSH_SIM_TOP_K = 10        # 返回距离最小的前 N 条
    TLSH_MAX_ENTRIES = 50000   # 库容量上限 (自增长, 超限淘汰最旧)

    def __init__(self, db_path, threshold=None, top_k=None, max_entries=None):
        self.db_path = db_path
        self.threshold = self.TLSH_SIM_THRESHOLD if threshold is None else threshold
        self.top_k = self.TLSH_SIM_TOP_K if top_k is None else top_k
        self.max_entries = self.TLSH_MAX_ENTRIES if max_entries is None else max_entries
        self._lock = threading.Lock()
        self._conn = None
        self._count = -1  # -1 = 未加载
        self._init_db()

    def _init_db(self):
        """创建数据库与表 (首次启动自动建表; 旧表结构自动迁移)"""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # 旧表迁移: 含旧字段 (first_seen/hit_count) 或 sha256 非 BLOB 列 → 删除重建
        cols = self._conn.execute("PRAGMA table_info(tlsh_entries)").fetchall()
        if cols:
            col_types = {c[1]: c[2] for c in cols}
            if ("first_seen" in col_types or "hit_count" in col_types
                    or col_types.get("sha256") != "BLOB"):
                self._conn.execute("DROP TABLE tlsh_entries")

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS tlsh_entries (
                tlsh       TEXT PRIMARY KEY,
                sha256     BLOB,
                size       INTEGER,
                name       TEXT
            )
        """)
        self._conn.commit()
        self._count = self._conn.execute(
            "SELECT COUNT(*) FROM tlsh_entries"
        ).fetchone()[0]

    @property
    def count(self):
        if self._count < 0:
            return 0
        return self._count

    def insert(self, tlsh_hex, sha256_hex, name, size):
        """插入/更新一条 TLSH 记录 (自增长, 线程安全)

        已存在 (同 tlsh) → 更新 sha256/size/name; 不存在 → 新增。
        超过 max_entries 时淘汰 ROWID 最旧 (最先插入) 的条目。
        """
        if not tlsh_hex or not sha256_hex:
            return
        # hex → BLOB (32 字节 vs 64 字符, 节省 50% 空间, 与 ssdeep 库一致)
        try:
            sha256_blob = bytes.fromhex(sha256_hex)
        except (ValueError, TypeError):
            sha256_blob = None
        with self._lock:
            try:
                cur = self._conn.execute(
                    "SELECT 1 FROM tlsh_entries WHERE tlsh = ?", (tlsh_hex,)
                )
                if cur.fetchone():
                    # 已存在 → 更新关联信息
                    self._conn.execute(
                        "UPDATE tlsh_entries SET sha256 = ?, size = ?, name = ? "
                        "WHERE tlsh = ?",
                        (sha256_blob, size, name or "unknown", tlsh_hex),
                    )
                else:
                    # 新条目 → 插入
                    self._conn.execute(
                        "INSERT INTO tlsh_entries (tlsh, sha256, size, name) "
                        "VALUES (?, ?, ?, ?)",
                        (tlsh_hex, sha256_blob, size, name or "unknown"),
                    )
                    self._count += 1
                    # 淘汰最旧条目 (ROWID 最小 = 最先插入)
                    if self._count > self.max_entries:
                        self._conn.execute(
                            "DELETE FROM tlsh_entries WHERE rowid = "
                            "(SELECT MIN(rowid) FROM tlsh_entries)"
                        )
                        self._count -= 1
                self._conn.commit()
            except sqlite3.Error:
                pass

    def check_exact(self, tlsh_hex):
        """精确匹配 TLSH 签名 (主键查询, 走索引)"""
        if not tlsh_hex:
            return []
        conn = sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False
        )
        try:
            row = conn.execute(
                "SELECT size, name, LOWER(hex(sha256)) FROM tlsh_entries WHERE tlsh = ?",
                (tlsh_hex,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return []
        sig_size, name, sha256_hex = row
        return [{
            "engine": "TLSH Hash DB",
            "type": "fuzzy",
            "name": name,
            "size": sig_size,
            "detail": "TLSH 命中",
            "fuzzy_type": "tlsh",
            "sha256": sha256_hex,
        }]

    def delete(self, tlsh_hex):
        """删除一条 TLSH 记录; 返回删除条数 (0/1)"""
        if not tlsh_hex:
            return 0
        with self._lock:
            try:
                cur = self._conn.execute(
                    "DELETE FROM tlsh_entries WHERE tlsh = ?", (tlsh_hex,)
                )
                self._conn.commit()
                deleted = cur.rowcount
                if deleted:
                    self._count = max(self._count - 1, 0)
                return deleted
            except sqlite3.Error:
                return 0

    def search(self, query_tlsh, threshold=None, top_k=None):
        """检索与 query_tlsh 距离 ≤ threshold 的库内条目, 按距离升序取 top_k

        返回 [{engine, type, name, size, sha256, score, tlsh, detail}, ...]
        其中 score = TLSH 距离 (越小越相似, 与 ssdeep score 语义相反)。
        """
        if not query_tlsh:
            return []
        threshold = self.threshold if threshold is None else threshold
        top_k = self.top_k if top_k is None else top_k

        # 用只读连接 (与写入连接隔离, 无锁竞争)
        conn = sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False
        )
        try:
            rows = conn.execute(
                "SELECT tlsh, LOWER(hex(sha256)), size, name FROM tlsh_entries"
            ).fetchall()
        finally:
            conn.close()

        if not rows:
            return []

        scored = []
        for lib_tlsh, lib_sha256, lib_size, lib_name in rows:
            if lib_tlsh == query_tlsh:
                continue  # 跳过自身 (刚入库的条目)
            distance = tlsh_diff(query_tlsh, lib_tlsh)
            if distance < 0:
                continue  # 无效 TLSH, 跳过
            if distance <= threshold:
                scored.append((distance, {
                    "engine": "TLSH Hash DB",
                    "type": "fuzzy-similar",
                    "name": lib_name or "unknown",
                    "size": lib_size,
                    "sha256": lib_sha256 or "",
                    "score": distance,
                    "tlsh": lib_tlsh,
                    "detail": f"TLSH 距离 {distance} (越小越相似)",
                }))
        scored.sort(key=lambda x: x[0])
        return [hit for _, hit in scored[:top_k]]

    def stats(self):
        """返回库统计信息"""
        return {
            "count": self.count,
            "threshold": self.threshold,
            "top_k": self.top_k,
            "max_entries": self.max_entries,
        }

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# ============================================================
# SSDeep 自增长相似度检索库 (单文件 SQLite, 无 bloom, 无分片)
# ============================================================
class SsdeepLibrary:
    """SSDeep 自增长相似度检索库

    数据来源:
      1. 从 hdb 文件批量导入 (build_ssdeep_db.py / build_fuzzy_db.py)
      2. 每次精确哈希命中 (SHA256/MD5) 的样本自动入库累积 (自增长)
    检索: 与库内 ssdeep 签名做 ppdeep.compare 模糊匹配 (得分 0-100, 越高越相似)。

    表结构: ssdeep (主键) / sha256 (BLOB 二进制, 32 字节) / size / name — 仅 4 字段。
    不使用分片 Bloom filter — ssdeep 为变长 TEXT 主键, 精确查询走主键索引;
    相似度检索走 GLOB 前缀 + 7-gram 预过滤 + ppdeep.compare, 无需 Bloom 预筛。
    线程安全: 写入 (insert/import_hdb) 用 threading.Lock 保护;
    读取 (search/check_exact) 用只读连接, 与写入连接隔离, 无锁竞争。
    """

    SSDEEP_SIM_THRESHOLD = 50   # 相似度阈值 (0-100, ssdeep 官方: >=50 高度可能相关)
    SSDEEP_SIM_TOP_K = 5        # 返回得分最高的前 N 条
    SSDEEP_SIM_LIMIT = 500      # 每候选块大小最多取多少行
    SSDEEP_MAX_ENTRIES = 50000 # 库容量上限 (自增长, 超限淘汰最旧)

    def __init__(self, db_path, threshold=None, top_k=None, max_entries=None):
        self.db_path = db_path
        self.threshold = self.SSDEEP_SIM_THRESHOLD if threshold is None else threshold
        self.top_k = self.SSDEEP_SIM_TOP_K if top_k is None else top_k
        self.max_entries = self.SSDEEP_MAX_ENTRIES if max_entries is None else max_entries
        self._lock = threading.Lock()
        self._conn = None
        self._count = -1  # -1 = 未加载
        self._imported_files = set()
        self._init_db()

    def _init_db(self):
        """创建数据库与表 (首次启动自动建表; 旧表结构自动迁移)"""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # 旧表迁移: 如果存在含 first_seen/hit_count 列的旧表, 删除重建
        cols = self._conn.execute("PRAGMA table_info(ssdeep_entries)").fetchall()
        if cols:
            col_names = {c[1] for c in cols}
            if "first_seen" in col_names or "hit_count" in col_names:
                self._conn.execute("DROP TABLE ssdeep_entries")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS ssdeep_entries (
                ssdeep     TEXT PRIMARY KEY,
                sha256     BLOB,
                size       INTEGER,
                name       TEXT
            )
        """)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)"
        )
        self._conn.commit()
        self._count = self._conn.execute(
            "SELECT COUNT(*) FROM ssdeep_entries"
        ).fetchone()[0]
        self._imported_files = {
            r[0] for r in self._conn.execute(
                "SELECT name FROM imported_files"
            ).fetchall()
        }

    @property
    def count(self):
        if self._count < 0:
            return 0
        return self._count

    @property
    def source_files(self):
        return sorted(self._imported_files)

    def already_imported(self, basename):
        return basename in self._imported_files

    # ---------- ssdeep 格式辅助 ----------

    @staticmethod
    def _ssdeep_to_standard(value):
        """归一化为标准 ssdeep 格式 (块大小:hash1:hash2, 冒号分隔)。
        接受两种输入:
          · 标准格式 (ppdeep.hash 输出, 冒号分隔) —— 直接返回
          · ClamAV 格式 (12-hash1-hash2, 短横线分隔) —— 前两个 '-' 替换为 ':'
        ssdeep hash 字符集不含 '-'/':', 分隔符可安全识别; 非法返回 None。"""
        if not value:
            return None
        if ":" in value:
            parts = value.split(":")
            if len(parts) >= 3 and parts[0].isdigit():
                return f"{parts[0]}:{parts[1]}:{parts[2]}"
            return None
        parts = value.split("-")
        if len(parts) < 3:
            return None
        block = parts[0]
        if not block.isdigit():
            return None
        return f"{block}:{parts[1]}:{parts[2]}"

    @staticmethod
    def _ssdeep_strip(s):
        """压缩连续重复字符 (与 ppdeep._strip_sequences 语义一致)"""
        if len(s) <= 3:
            return s
        out = [s[0], s[1], s[2]]
        for i in range(3, len(s)):
            if s[i] != s[i - 1] or s[i] != s[i - 2] or s[i] != s[i - 3]:
                out.append(s[i])
        return "".join(out)

    @staticmethod
    def _ssdeep_grams7(s):
        """7-gram 集合 (ppdeep._common_substring 的 ROLL_WINDOW=7); 长度 <7 返回空集"""
        if len(s) < 7:
            return set()
        return {s[i:i + 7] for i in range(len(s) - 6)}

    # ---------- 导入 ----------

    def import_hdb(self, filepath, batch=50_000):
        """从 ClamAV 8 字段 hdb 文件导入 ssdeep 签名。

        行格式: sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash
        仅提取 ssdeep 字段 (parts[3]); sha256 存为 BLOB 二进制 (32 字节)。
        INSERT OR IGNORE 去重, 幂等可续导。
        """
        basename = os.path.basename(filepath)
        if self.already_imported(basename):
            return 0
        pending = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 8:
                    continue
                h = parts[0].strip().lower()
                if len(h) != 64:
                    continue
                try:
                    sha256_blob = bytes.fromhex(h)
                except ValueError:
                    continue
                size_field = parts[1].strip()
                try:
                    size = None if size_field in ("*", "0") else int(size_field)
                except ValueError:
                    size = None
                name = parts[2].strip()
                ssdeep_val = parts[3].strip() or None
                if ssdeep_val:
                    # 归一化为标准格式 (冒号分隔), 与 insert() 保持一致
                    std = self._ssdeep_to_standard(ssdeep_val)
                    if std:
                        ssdeep_val = std
                    pending.append((ssdeep_val, sha256_blob, size, name))

        inserted = 0
        with self._lock:
            for i in range(0, len(pending), batch):
                chunk = pending[i:i + batch]
                before = self._conn.total_changes
                self._conn.executemany(
                    "INSERT OR IGNORE INTO ssdeep_entries(ssdeep, sha256, size, name) "
                    "VALUES(?,?,?,?)",
                    chunk,
                )
                self._conn.commit()
                inserted += self._conn.total_changes - before
            self._count = self._conn.execute(
                "SELECT COUNT(*) FROM ssdeep_entries"
            ).fetchone()[0]
            self._conn.execute(
                "INSERT OR IGNORE INTO imported_files(name) VALUES(?)", (basename,))
            self._conn.commit()
            self._imported_files.add(basename)
        return inserted

    # ---------- 写入 (自增长) ----------

    def insert(self, ssdeep_val, sha256_hex, name, size):
        """插入/更新一条 ssdeep 记录 (自增长, 线程安全)

        sha256_hex: 64 位 hex 字符串, 内部转为 BLOB 二进制存储 (节省 50% 空间)。
        ssdeep_val 归一化为标准格式 (块大小:hash1:hash2, 冒号分隔) 后存储,
        确保 insert (ppdeep 标准格式) 与 import_hdb (ClamAV 短横线格式) 数据一致,
        精确匹配与 GLOB 前缀检索均能命中。
        已存在 (同 ssdeep) → 更新 sha256/size/name; 不存在 → 新增。
        超过 max_entries 时淘汰 ROWID 最旧 (最先插入) 的条目。
        """
        if not ssdeep_val or not sha256_hex:
            return
        # 归一化为标准格式 (冒号分隔), 统一存储格式
        std = self._ssdeep_to_standard(ssdeep_val)
        if std:
            ssdeep_val = std
        # hex → BLOB (32 字节 vs 64 字符, 节省 50% 空间)
        try:
            sha256_blob = bytes.fromhex(sha256_hex)
        except (ValueError, TypeError):
            sha256_blob = None
        with self._lock:
            try:
                cur = self._conn.execute(
                    "SELECT 1 FROM ssdeep_entries WHERE ssdeep = ?", (ssdeep_val,)
                )
                if cur.fetchone():
                    self._conn.execute(
                        "UPDATE ssdeep_entries SET sha256 = ?, size = ?, name = ? "
                        "WHERE ssdeep = ?",
                        (sha256_blob, size, name or "unknown", ssdeep_val),
                    )
                else:
                    self._conn.execute(
                        "INSERT INTO ssdeep_entries (ssdeep, sha256, size, name) "
                        "VALUES (?, ?, ?, ?)",
                        (ssdeep_val, sha256_blob, size, name or "unknown"),
                    )
                    self._count += 1
                    if self._count > self.max_entries:
                        self._conn.execute(
                            "DELETE FROM ssdeep_entries WHERE rowid = "
                            "(SELECT MIN(rowid) FROM ssdeep_entries)"
                        )
                        self._count -= 1
                self._conn.commit()
            except sqlite3.Error:
                pass

    # ---------- 精确匹配 ----------

    def check_exact(self, ssdeep_value, file_size=None):
        """精确匹配 ssdeep 签名 (主键查询, 走索引)"""
        if not ssdeep_value:
            return []
        conn = sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False
        )
        try:
            row = conn.execute(
                "SELECT size, name, LOWER(hex(sha256)) FROM ssdeep_entries WHERE ssdeep = ?",
                (ssdeep_value,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return []
        sig_size, name, sha256_hex = row
        if file_size is not None and sig_size is not None and sig_size != file_size:
            return []
        return [{
            "engine": "SSDeep Hash DB",
            "type": "fuzzy",
            "name": name,
            "size": sig_size,
            "detail": "SSDeep 命中",
            "fuzzy_type": "ssdeep",
            "sha256": sha256_hex,
        }]

    def delete(self, ssdeep_val):
        """删除一条 ssdeep 记录 (按归一化后的标准格式匹配); 返回删除条数 (0/1)"""
        if not ssdeep_val:
            return 0
        std = self._ssdeep_to_standard(ssdeep_val)
        if std:
            ssdeep_val = std
        with self._lock:
            try:
                cur = self._conn.execute(
                    "DELETE FROM ssdeep_entries WHERE ssdeep = ?", (ssdeep_val,)
                )
                self._conn.commit()
                deleted = cur.rowcount
                if deleted:
                    self._count = max(self._count - 1, 0)
                return deleted
            except sqlite3.Error:
                return 0

    # ---------- 相似度检索 ----------

    def search(self, query_ssdeep, file_size=None, threshold=None, top_k=None):
        """ssdeep 相似度检索: 与库中 ssdeep 签名做 ppdeep.compare 模糊匹配 (得分 0-100)。

        候选筛选 (避免全库逐条比对, 控制检索量):
          1. 解析查询块大小 B; 候选块大小 ∈ {B//2, B, B*2}
          2. 文件大小 ±2 倍过滤
          3. GLOB 'B:*' (ssdeep 主键前缀索引, 标准冒号格式) + size 过滤 + LIMIT
          4. 7-gram 预过滤: 无公共 7 子串的候选 compare 必然得 0, 直接跳过
        返回得分 >= threshold 的命中, 按得分降序取 top_k。
        """
        if not SSDEEP_AVAILABLE or not query_ssdeep:
            return []
        threshold = self.SSDEEP_SIM_THRESHOLD if threshold is None else threshold
        top_k = self.SSDEEP_SIM_TOP_K if top_k is None else top_k

        query_std = self._ssdeep_to_standard(query_ssdeep)
        if query_std is None:
            return []
        try:
            q_block = int(query_std.split(":", 1)[0])
        except ValueError:
            return []
        _qb, _qh1, _qh2 = query_std.split(":", 2)
        q_s1 = self._ssdeep_strip(_qh1)
        q_s2 = self._ssdeep_strip(_qh2)
        q_g1 = self._ssdeep_grams7(q_s1)
        q_g2 = self._ssdeep_grams7(q_s2)
        cand_blocks = sorted({b for b in (q_block, q_block // 2, q_block * 2) if b > 0})
        if file_size is not None and file_size > 0:
            size_lo, size_hi = file_size // 2, file_size * 2
        else:
            size_lo, size_hi = None, None

        conn = sqlite3.connect(
            f"file:{self.db_path}?mode=ro", uri=True, check_same_thread=False
        )
        try:
            scored = []
            for bsize in cand_blocks:
                sql = ("SELECT ssdeep, size, name, LOWER(hex(sha256)) FROM ssdeep_entries"
                       " WHERE ssdeep GLOB ?")
                params = [f"{bsize}:*"]
                if size_lo is not None:
                    sql += " AND (size IS NULL OR size BETWEEN ? AND ?)"
                    params += [size_lo, size_hi]
                sql += " LIMIT ?"
                params.append(self.SSDEEP_SIM_LIMIT)
                try:
                    rows = conn.execute(sql, params).fetchall()
                except sqlite3.Error:
                    continue
                for clam_val, sig_size, name, sha256_hex in rows:
                    std = self._ssdeep_to_standard(clam_val)
                    if std is None or std == query_std:
                        continue
                    try:
                        c_block, c_h1, c_h2 = std.split(":", 2)
                        c_block = int(c_block)
                    except ValueError:
                        continue
                    # 7-gram 预过滤
                    if c_block == q_block:
                        if not (q_g1 & self._ssdeep_grams7(self._ssdeep_strip(c_h1))
                                or q_g2 & self._ssdeep_grams7(self._ssdeep_strip(c_h2))):
                            continue
                    elif q_block == c_block * 2:
                        if not (q_g1 & self._ssdeep_grams7(self._ssdeep_strip(c_h2))):
                            continue
                    elif c_block == q_block * 2:
                        if not (q_g2 & self._ssdeep_grams7(self._ssdeep_strip(c_h1))):
                            continue
                    else:
                        continue
                    try:
                        score = ppdeep.compare(query_std, std)
                    except Exception:
                        continue
                    if score >= threshold:
                        scored.append((score, {
                            "engine": "SSDeep Hash DB",
                            "type": "fuzzy-similar",
                            "name": name or "unknown",
                            "size": sig_size,
                            "sha256": sha256_hex,
                            "score": score,
                            "ssdeep": clam_val,
                            "detail": f"ssdeep 相似度 {score}/100",
                        }))
        finally:
            conn.close()
        scored.sort(key=lambda x: -x[0])
        return [hit for _, hit in scored[:top_k]]

    # ---------- 统计 ----------

    def stats(self):
        db_size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                db_size += os.path.getsize(self.db_path + suffix)
            except OSError:
                pass
        return {
            "count": self.count,
            "threshold": self.threshold,
            "top_k": self.top_k,
            "max_entries": self.max_entries,
            "db_size_mb": round(db_size / 1048576, 2),
            "sources": len(self._imported_files),
        }

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# ============================================================
# YARA 扫描器 (合并编译 + 单次匹配)
# ============================================================
class YaraScanner:
    """YARA 规则扫描器 (合并编译优化)

    启动时收集全部 .yar 文件路径, 首次匹配前用 yara.compile(filepaths=...)
    合并为**单一 Rules 对象** (每文件独立 namespace, 规则名冲突互不干扰),
    匹配时只需一次 .match() 调用, 避免 1433+ 次串行编译/匹配的初始化开销。

    旧实现逐文件编译为独立 Rules 对象, 匹配时 for r in rulesets 串行调用,
    每次重复支付 YARA 初始化开销; 合并后从 N 次降为 1 次。
    """

    def __init__(self):
        self._pending = {}           # {filename: filepath} 待批量编译
        self._compiled = None        # 合并编译的单一 Rules 对象
        self._compile_lock = threading.Lock()
        self.rule_count = 0          # 累计规则条数
        self.source_files = []       # 成功加载的文件名列表
        self.errors = []             # [(文件名, 错误), ...] 编译失败的文件
        self.error = None if YARA_AVAILABLE else "yara-python 未安装, YARA 引擎不可用"

    @property
    def rules(self):
        """触发延迟编译, 返回合并后的单一 Rules 对象 (无则 None)"""
        self._ensure_compiled()
        return self._compiled

    @property
    def rulesets(self):
        """向后兼容: 返回 [compiled] 或 []"""
        self._ensure_compiled()
        return [self._compiled] if self._compiled else []

    def load_rules(self, filepath):
        """收集 .yar/.yara 文件路径, 标记需重新编译 (实际编译延迟到首次匹配)

        不再逐文件预编译 (旧实现); 批量编译在 _ensure_compiled 中一次性完成,
        坏文件在批量编译失败后逐个排查。
        """
        if not YARA_AVAILABLE:
            return 0
        fname = os.path.basename(filepath)
        with self._compile_lock:
            self._pending[fname] = filepath
            self._compiled = None  # 标记需重新编译
        count = self._count_rules(filepath)
        self.rule_count += count
        if fname not in self.source_files:
            self.source_files.append(fname)
        return count

    def warmup(self):
        """启动时预编译全部规则 (避免首次扫描延迟)"""
        self._ensure_compiled()

    def _ensure_compiled(self):
        """延迟批量编译: 用 yara.compile(filepaths=...) 合并全部规则为单一 Rules"""
        if self._compiled is not None or not self._pending:
            return
        with self._compile_lock:
            if self._compiled is not None:  # double-check
                return
            pending_copy = dict(self._pending)
            # 尝试一次性合并编译 (每文件独立 namespace, 规则名冲突互不干扰)
            try:
                self._compiled = yara.compile(filepaths=pending_copy)
                self.errors = []
                return
            except yara.Error:
                pass
            # 合并编译失败: 逐文件编译找出坏文件, 好文件批量重编译
            good = {}
            new_errors = []
            for fname, fpath in pending_copy.items():
                try:
                    yara.compile(filepath=fpath)
                    good[fname] = fpath
                except yara.Error as e:
                    new_errors.append((fname, str(e)))
                except (MemoryError, OSError) as e:
                    new_errors.append((fname, f"编译资源不足: {e}"))
            self.errors = new_errors
            if good:
                try:
                    self._compiled = yara.compile(filepaths=good)
                except yara.Error as e:
                    self.error = f"YARA 批量编译失败: {e}"

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
        self._ensure_compiled()
        if not self._compiled:
            return []
        try:
            matches = self._compiled.match(file_path, timeout=30)
        except yara.TimeoutError:
            return self._timeout_hit()
        except yara.Error:
            return []
        return self._format_matches(matches)

    def scan_data(self, data):
        """扫描内存缓冲, 返回命中列表 (单次 .match 调用, 复用调用方已读入的数据)"""
        self._ensure_compiled()
        if not self._compiled:
            return []
        try:
            matches = self._compiled.match(data=data, timeout=30)
        except yara.TimeoutError:
            return self._timeout_hit()
        except yara.Error:
            return []
        return self._format_matches(matches)

    @staticmethod
    def _timeout_hit():
        return [{
            "engine": "YARA",
            "type": "error",
            "name": "YaraScanTimeout",
            "detail": "规则匹配超时 (30s)",
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

    def __init__(self, hash_db, yara_scanner, md5_db=None, fuzzy_db=None,
                 tlsh_library=None, ssdeep_library=None):
        self.hash_db = hash_db
        self.yara_scanner = yara_scanner
        self.md5_db = md5_db  # 独立 MD5 分片库 (可选); 命中并入 detections
        self.fuzzy_db = fuzzy_db  # 模糊哈希库 (4 表: vhash/authentihash/imphash/rich_header_hash)
        self.tlsh_library = tlsh_library  # TLSH 自增长相似度库 (可选); 检测始终执行, hash_hit 时入库
        self.ssdeep_library = ssdeep_library  # SSDeep 自增长相似度库 (可选); 检测始终执行, hash_hit 时入库

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

    def scan_phase1(self, data, filename=None, hashes=None):
        """两段式扫描·阶段1 (Web 上传): 哈希 + 文件类型 + 哈希签名库命中, 毫秒级立即返回

        hashes: 可选 (md5, sha1, sha256) 预计算哈希元组, 传入则不再重算 (P0-2)。
        """
        return self._phase1(data, filename or "unnamed", hashes=hashes)

    def scan_phase2(self, data, filename=None, hash_hit=False,
                     sha256=None, hash_hit_name=None):
        """两段式扫描·阶段2 (Web 上传, 后台线程): YARA 规则 + 静态信息/模糊哈希 + 查壳

        hash_hit: 阶段1 是否命中 SHA256/MD5 哈希签名 (仅控制 ssdeep/TLSH 自增长入库, 不控制检测)。
        sha256: 阶段1 计算的 SHA256 (用于 ssdeep/TLSH 库入库关联; 不传则 phase2 内部重算)。
        hash_hit_name: 哈希命中对应的恶意名称 (用于 ssdeep/TLSH 库入库标注; 可选)。
        """
        return self._phase2(data, filename or "unnamed", hash_hit=hash_hit,
                            sha256=sha256, hash_hit_name=hash_hit_name)

    def merge_phases(self, p1, p2):
        """两段式扫描·合并: 阶段1 + 阶段2 → 完整扫描结果 (供轮询接口拼装)"""
        return self._merge_phases(p1, p2)

    def _scan_common(self, data, filename, file_size):
        """内存复用核心 (同步完整扫描): 哈希 → 类型识别 → 签名库 → YARA → 静态信息

        供 scan_file / scan_bytes 兼容使用, 等价于 _phase1 + _phase2 顺序合并;
        Web 上传路径改用 scanner.scan_phase1 / scan_phase2 两段式 (哈希先返回, 深度分析动态更新)。
        """
        p1 = self._phase1(data, filename)
        hash_hit = any(d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB")
                       for d in p1["detections"])
        # 获取哈希命中名称 (用于 ssdeep/TLSH 库入库标注)
        hit_name = None
        for d in p1["detections"]:
            if d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB"):
                hit_name = d.get("name")
                break
        p2 = self._phase2(data, filename, hash_hit=hash_hit,
                          sha256=p1.get("sha256"), hash_hit_name=hit_name)
        return self._merge_phases(p1, p2)

    def _phase1(self, data, filename, hashes=None):
        """阶段 1 (快速, 同步返回): 哈希 → 文件类型 → 哈希签名库命中

        只做 O(1) 哈希计算 + Bloom/SQLite 点查, 毫秒级返回;
        hashes 参数可传入预计算的 (md5, sha1, sha256) 避免重算 (P0-2);
        返回结构带 phase="hash" 标记, detections 仅含 Hash DB 命中。
        """
        start = time.time()
        if hashes:
            md5, sha1, sha256 = hashes
        else:
            md5, sha1, sha256 = compute_hashes_bytes(data)
        file_size = len(data)

        # 文件类型识别 (ClamAV FTM 机制: 魔数 → 模式 → 尾部魔数 → 文本检测)
        # 增强: ZIP 中央目录解析 / PE 结构校验 / libmagic 兜底 (data 传入完整缓冲)
        ftype = {"name": "未知", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "n/a"}
        try:
            head = data[:ft.MAGIC_BUFFER_SIZE]
            tail = (data[-512:] if len(data) > ft.MAGIC_BUFFER_SIZE + 512 else b"")
            ftype = ft.detect_file_type(head, tail, filename, data=data)
        except Exception:
            pass

        # 文件类型可疑信号 → 接入 detections:
        #   · PE 头结构校验失败 (伪装/损坏的 PE)
        #   · 扩展名与魔数识别结果不一致 (如 .jpg 扩展名 + PE 内容)
        type_signals = _type_suspicion_signals(filename, ftype)

        detections = list(self.hash_db.check(None, file_size, md5, sha1, sha256))
        if self.md5_db is not None:
            detections.extend(self.md5_db.check_hash(md5, file_size))
        detections.extend(type_signals)
        # 模糊哈希查询移至 phase2: 需先计算 ssdeep/imphash/authentihash 才能按值查询
        elapsed_ms = round((time.time() - start) * 1000, 1)
        return {
            "filename": filename or "unnamed",
            "size": file_size,
            "size_human": _human_size(file_size),
            "file_type": ftype["name"],          # 显示名 (向后兼容)
            "file_type_info": ftype,             # 结构化: name/cl_type/category/method[/suspect]
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "detections": detections,            # Hash DB 命中 + 文件类型可疑信号
            "clean": len(detections) == 0,
            "verdict": "CLEAN" if not detections else "DETECTED",
            "scanners": ["SHA256 Hash DB", "MD5 Hash DB"] + (["FileType Analysis"] if type_signals else []),
            "elapsed_ms": elapsed_ms,            # 阶段1耗时
            "static_info": None,
            "static_ms": 0.0,
            "phase": "hash",
        }

    def _phase2(self, data, filename, hash_hit=False, sha256=None, hash_hit_name=None):
        """阶段 2 (深度, 后台执行): YARA 规则匹配 + 静态信息/模糊哈希 + 查壳

        返回合并阶段 1 所需的补充字段: detections(YARA + Fuzzy Hash + SSDeep + TLSH) / static_info / static_ms / elapsed_ms / scanners。
        hash_hit: 阶段1 是否命中 SHA256/MD5 哈希签名; 仅控制 ssdeep/TLSH 自增长入库,
        不影响检测——SSDeep 相似度检索与 TLSH 相似度检测始终执行 (与 SHA256/MD5 精确哈希并行)。
        sha256: 阶段1 的 SHA256 (用于 ssdeep/TLSH 库入库关联; 不传则内部重算)。
        hash_hit_name: 哈希命中名称 (用于 ssdeep/TLSH 库入库标注)。
        """
        start = time.time()
        detections = list(self.yara_scanner.scan_data(data))

        # 静态信息与模糊哈希 (ssdeep/tlsh/imphash/authentihash + PE 元数据 + 壳检测)
        static_start = time.time()
        static_info = staticinfo.compute_static_info(data)
        static_ms = round((time.time() - static_start) * 1000, 1)

        fuzzy_info = static_info.get("fuzzy", {}) if static_info else {}

        # 模糊哈希签名库查询: imphash/authentihash 查 FuzzySignatureDB 4 表
        if self.fuzzy_db is not None:
            fuzzy_hits = self.fuzzy_db.check_by_computed_hashes(
                imphash_hex=fuzzy_info.get("imphash"),
                authentihash_hex=fuzzy_info.get("authentihash"),
                file_size=len(data),
            )
            detections.extend(fuzzy_hits)

        # SSDeep 检测 (精确匹配 + 相似度检索) + 自增长入库 (独立库, 无 bloom, 无分片)
        # 检测始终执行, 与 SHA256/MD5 精确哈希并行, 不再由哈希命中结果决定是否启动;
        # 自增长入库仅在精确哈希命中时执行, 保持库内仅累积已知恶意样本
        ssdeep_val = fuzzy_info.get("ssdeep")
        if ssdeep_val and self.ssdeep_library is not None:
            # 精确匹配 (主键索引, O(1))
            exact_hits = self.ssdeep_library.check_exact(ssdeep_val, file_size=len(data))
            detections.extend(exact_hits)
            # 相似度检索 (始终执行)
            sim_hits = self.ssdeep_library.search(
                ssdeep_val, file_size=len(data))
            detections.extend(sim_hits)
            # 入库 (自增长): 仅在精确哈希命中时
            if hash_hit:
                _sha = sha256
                if not _sha:
                    _sha = hashlib.sha256(data).hexdigest()
                self.ssdeep_library.insert(
                    ssdeep_val, _sha, hash_hit_name or "unknown", len(data)
                )

        # TLSH 相似度检测 (始终执行) + 自增长入库 (仅在精确哈希命中时)
        tlsh_val = fuzzy_info.get("tlsh")
        if tlsh_val and self.tlsh_library is not None:
            tlsh_hits = self.tlsh_library.search(tlsh_val)
            detections.extend(tlsh_hits)
            if hash_hit:
                _sha = sha256
                if not _sha:
                    _sha = hashlib.sha256(data).hexdigest()
                self.tlsh_library.insert(
                    tlsh_val, _sha, hash_hit_name or "unknown", len(data)
                )

        elapsed_ms = round((time.time() - start) * 1000, 1)
        scanners = (["YARA"] if YARA_AVAILABLE and self.yara_scanner.rules else [])
        if self.ssdeep_library is not None and ssdeep_val:
            scanners.append("SSDeep Hash DB")
        if self.tlsh_library is not None and tlsh_val:
            scanners.append("TLSH Hash DB")
        return {
            "detections": detections,
            "static_info": static_info,
            "static_ms": static_ms,
            "elapsed_ms": elapsed_ms,
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
        # 大文件路径仅头尾缓冲: ZIP 中央目录/PE 深度校验自动退回, 扩展名校验仍生效
        ftype = {"name": "未知", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "n/a"}
        try:
            head, tail = ft.read_head_tail(file_path)
            ftype = ft.detect_file_type(head, tail, filename)
        except OSError:
            pass

        # 文件类型可疑信号 (扩展名不一致 / 头缓冲内可校验的 PE 异常)
        type_signals = _type_suspicion_signals(filename, ftype)

        detections = []
        detections.extend(self.hash_db.check(file_path, file_size, md5, sha1, sha256))
        if self.md5_db is not None:
            detections.extend(self.md5_db.check_hash(md5, file_size))
        detections.extend(self.yara_scanner.scan(file_path))
        detections.extend(type_signals)

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
            "scanners": ["SHA256 Hash DB", "MD5 Hash DB"]
                         + (["YARA"] if YARA_AVAILABLE and self.yara_scanner.rules else [])
                         + (["FileType Analysis"] if type_signals else []),
        }


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
