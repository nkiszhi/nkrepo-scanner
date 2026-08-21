"""
NKAMG Scanner - Web 服务入口
启动: python app.py  →  http://127.0.0.1:5000 (地址/端口可由 config.json 修改)
"""
import json
import os
import re
import hashlib
import hmac
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from functools import wraps

from flask import Flask, jsonify, render_template, request, redirect, url_for, abort, session
from werkzeug.exceptions import RequestEntityTooLarge

from scanner import (FuzzySignatureDB, HashSignatureDB, Scanner,
                     SsdeepLibrary, TlshLibrary, YaraScanner, compute_hashes_bytes)
import packer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_DIR = os.path.join(BASE_DIR, "signatures")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# 默认配置 (config.json 中的同名键会覆盖对应项)
DEFAULT_CONFIG = {
    "bloom": {
        "shards": 4,               # Bloom Filter 分片数, 同时驱动 SQLite 动态分片数 (任意正整数)
        "fp_rate": 0.01,           # Bloom 误判率
    },
    "sha256": {
        "layout": "hex",           # SHA256 库分片布局: "hex" = 按前两字符分 256 片; "modulo" = 取模分 N 片
        "max_open_shards": 16,     # 256 片时建议增大 LRU 缓存上限, 减少频繁换页
    },
    "md5": {
        "layout": "hex",           # MD5 库分片布局: "hex" = 按前两字符分 256 片; "modulo" = 取模分 N 片
        "max_open_shards": 16,     # 256 片时建议增大 LRU 缓存上限, 减少频繁换页
    },
    "fuzzy": {
        "layout": "hex",           # 模糊哈希库分片布局: "hex" = 按首字节分 256 片; 5 表共享分片文件
        "max_open_shards": 16,     # LRU 缓存上限 (连接 × bloom)
    },
    "hash_db": {
        "max_open_shards": 4,      # 分片 SQLite 连接 / Bloom 位图懒加载 LRU 上限
    },
    "server": {
        "host": "127.0.0.1",
        "port": 5000,
        "max_upload_mb": 10,
        "uploads_dir": "uploads",  # 上传样本目录: /scan 上传时按 SHA256 去重保存原始字节与扫描报告 (uploads/<sha256> 与 .json 同目录), 供"重新扫描"读取; 相对项目根目录或绝对路径, 启动时自动创建
        # 安全加固: 认证 / 限流 / 深度分析资源上限 (以下均为中危 DoS 缓解, 见 README「安全」章节)
        "api_token": "",            # 留空 = 匿名本地模式; 配置任意字符串后, /scan /api/task /api/stats
                                    # 需携带 Authorization: Bearer <token> 或 ?token=<token> (前端首次带 ?token= 访问即记住)
        "scan_rate_limit": 30,      # 每 IP 每分钟最多 /scan 次数 (0 = 不限); 防恶意刷扫描耗尽 CPU
        "phase2_max_mb": 32,        # 阶段2 深度分析(模糊哈希/PE元数据/查壳)的样本大小上限; 超过仅执行 YARA (10s 超时),
                                    # 防超大文件纯 Python 逐字节分析 (熵/模糊哈希) 打满 CPU
        "phase2_concurrency": 4,    # 阶段2 后台线程并发上限 (信号量, 超限排队), 控制 CPU 峰值
    },
    "packer": {
        "rules_dir": "packer_rules",      # 外部 YARA 扩展壳库目录 (相对项目根目录或绝对路径)
        "max_yara_bytes": 16777216,       # 外部规则匹配的样本大小上限 (16MB)
    },
    "tlsh": {
        "threshold": 40,              # TLSH 距离阈值 (≤ threshold 视为相似; 0=完全相同)
        "top_k": 10,                   # 返回距离最小的前 N 条
        "max_entries": 50000,          # 自增长库容量上限 (超限淘汰最旧)
    },
    "admin": {},                          # 管理员凭据 (哈希管理页面登录); config.json 的 admin 节会合并进来
}


def load_config(path=CONFIG_PATH):
    """加载 config.json 并与默认值逐节合并 (忽略以 _ 开头的注释键)"""
    cfg = {k: dict(v) for k, v in DEFAULT_CONFIG.items()}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for section, values in user.items():
                if section not in cfg or not isinstance(values, dict):
                    continue
                for key, val in values.items():
                    if not key.startswith("_"):
                        cfg[section][key] = val
        except (json.JSONDecodeError, OSError) as e:
            print(f"[NKAMG] 配置文件解析失败, 使用默认配置: {e}")
    return cfg


cfg = load_config()
bcfg = cfg["bloom"]
sha256cfg = cfg.get("sha256", {})
hcfg = cfg["hash_db"]
scfg = cfg["server"]
pkcfg = cfg["packer"]

_sha256_layout = str(sha256cfg.get("layout", "modulo")).strip()
_sha256_max_open = int(sha256cfg.get("max_open_shards", hcfg["max_open_shards"]))

md5cfg = cfg.get("md5", {})
_md5_layout = str(md5cfg.get("layout", "modulo")).strip()
_md5_max_open = int(md5cfg.get("max_open_shards", hcfg["max_open_shards"]))

fuzzycfg = cfg.get("fuzzy", {})
_fuzzy_layout = str(fuzzycfg.get("layout", "hex")).strip()
_fuzzy_max_open = int(fuzzycfg.get("max_open_shards", hcfg["max_open_shards"]))

# TLSH 自增长相似度库配置
tlshcfg = cfg.get("tlsh", {})
_tlsh_threshold = int(tlshcfg.get("threshold", 40))
_tlsh_top_k = int(tlshcfg.get("top_k", 10))
_tlsh_max_entries = int(tlshcfg.get("max_entries", 50000))

# SSDeep 自增长相似度库配置
ssdeepcfg = cfg.get("ssdeep", {})
_ssdeep_threshold = int(ssdeepcfg.get("threshold", 50))
_ssdeep_top_k = int(ssdeepcfg.get("top_k", 5))
_ssdeep_max_entries = int(ssdeepcfg.get("max_entries", 50000))

# 上传目录: 从配置读取 (server.uploads_dir), 不存在时动态创建。
# /scan 上传时按 SHA256 去重保存样本原始字节 (uploads/<sha256>) 到该目录,
# 供报告页 "重新扫描" 按钮读取重扫; 随缓存 LRU 一起清理 (2026-08-22 调整: 样本并入 uploads/)
_uploads_cfg = str(scfg.get("uploads_dir", "uploads")).strip()
UPLOAD_DIR = _uploads_cfg if os.path.isabs(_uploads_cfg) else os.path.join(BASE_DIR, _uploads_cfg)
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _sample_path(sha256_hex):
    """样本文件路径: uploads/<sha256> (小写十六进制)"""
    return os.path.join(UPLOAD_DIR, str(sha256_hex).strip().lower())


def _save_sample(sha256_hex, data):
    """按 SHA256 去重保存样本字节 (原子写: 临时文件 + rename); 失败静默忽略"""
    path = _sample_path(sha256_hex)
    if os.path.isfile(path):
        return
    tmp = path + ".tmp." + uuid.uuid4().hex[:8]
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 - 样本保存失败不影响扫描主流程
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _remove_sample_for_cache(cache_json_path):
    """缓存被 LRU 淘汰时同步删除同名样本 (uploads/<sha256>), 防目录无限增长"""
    name = os.path.basename(cache_json_path)
    if name.endswith(".json"):
        try:
            sample = _sample_path(name[:-5])
            if os.path.isfile(sample):
                os.remove(sample)
        except OSError:
            pass
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(scfg["max_upload_mb"]) * 1024 * 1024

# 会话密钥: 用于管理员登录态 Cookie 签名; 默认空时随机生成 (重启即失效, 仅本地兜底)
_secret_key = str(scfg.get("secret_key", "")).strip()
if not _secret_key:
    import secrets as _secrets
    _secret_key = _secrets.token_hex(24)
    print("[NKAMG] 未配置 server.secret_key, 已生成临时会话密钥 (重启失效, 建议在 config.json 配置)")
app.secret_key = _secret_key

# ---------- 管理员凭据 (哈希管理页面登录) ----------
# 检测功能 (/ /scan /api/*) 无需登录; 仅 /admin/hash 与 /api/admin/* 需登录。
# 密码以 SHA-256(salt:password) 形式存储, 明文不出现在配置中。
ADMIN_CFG = cfg.get("admin", {}) or {}
ADMIN_USER = str(ADMIN_CFG.get("username", "")).strip() or "admin"
ADMIN_SALT = str(ADMIN_CFG.get("salt", "")).strip()
ADMIN_PW_HASH = str(ADMIN_CFG.get("password_hash", "")).strip().lower()

# ---------- 初始化扫描引擎 ----------
# 哈希签名持久化在动态分片 SQLite (signatures/sha256.db.shards/),
# layout=hex 时按 SHA256 前两字符分 256 片 (00~ff), layout=modulo 时按取模分 N 片
# Bloom 位图按同样分片数懒加载
hash_db = HashSignatureDB(
    os.path.join(SIG_DIR, "sha256.db"),
    shard_count=int(bcfg["shards"]),
    bloom_fp_rate=float(bcfg["fp_rate"]),
    max_open_shards=_sha256_max_open,
    layout=_sha256_layout,
)
# 独立 MD5 分片库 (与 SHA256 库并列): 由 build_md5_db.py 构建 (signatures/md5.db.shards/),
# layout=hex 时按 MD5 前两字符分 256 片 (00~ff), layout=modulo 时按取模分 N 片
# 这里只读实例化; 若分片未构建则降级为 None, 不影响 sha256 功能
md5_db = None
_md5_base = os.path.join(SIG_DIR, "md5.db")
if os.path.isdir(_md5_base + ".shards"):
    md5_db = HashSignatureDB(
        _md5_base,
        shard_count=int(bcfg["shards"]),
        bloom_fp_rate=float(bcfg["fp_rate"]),
        max_open_shards=_md5_max_open,
        hash_algo="md5",
        layout=_md5_layout,
    )
    print(f"[NKAMG] MD5 库就绪: {md5_db.count:,} 条")
else:
    print("[NKAMG] 未检测到 MD5 分片库, 跳过 (运行 build_md5_db.py 可构建)")
# 模糊哈希签名库 (5 表独立结构): 由 build_fuzzy_db.py 从 hdb/
# 8 字段行提取 5 个模糊哈希, 每种独立成表, 以 fuzzy hash 为主键
# (signatures/fuzzy.db.shards/); 256 hex 分片, 每分片含 5 张表
fuzzy_db = None
_fuzzy_base = os.path.join(SIG_DIR, "fuzzy.db")
if os.path.isdir(_fuzzy_base + ".shards"):
    fuzzy_db = FuzzySignatureDB(
        _fuzzy_base,
        bloom_fp_rate=float(bcfg["fp_rate"]),
        max_open_shards=_fuzzy_max_open,
        layout=_fuzzy_layout,
    )
    print(f"[NKAMG] 模糊哈希库就绪: {fuzzy_db.count:,} 条 ({fuzzy_db._counts})")
else:
    print("[NKAMG] 未检测到模糊哈希分片库, 跳过 (运行 build_fuzzy_db.py 可构建)")
# TLSH 自增长相似度库: 每次精确哈希命中的样本自动入库累积,
# 后续扫描将文件 TLSH 与库内条目做距离比对 (纯 Python, 无预置数据)
tlsh_library = TlshLibrary(
    os.path.join(SIG_DIR, "tlsh_library.db"),
    threshold=_tlsh_threshold,
    top_k=_tlsh_top_k,
    max_entries=_tlsh_max_entries,
)
print(f"[NKAMG] TLSH 自增长库就绪: {tlsh_library.count:,} 条 (阈值={_tlsh_threshold}, top_k={_tlsh_top_k})")
# SSDeep 自增长相似度库: 单文件 SQLite, 无 bloom, 无分片;
# 可从 hdb 文件预导入 + 每次精确哈希命中自增长入库
ssdeep_library = SsdeepLibrary(
    os.path.join(SIG_DIR, "ssdeep_library.db"),
    threshold=_ssdeep_threshold,
    top_k=_ssdeep_top_k,
    max_entries=_ssdeep_max_entries,
)
print(f"[NKAMG] SSDeep 自增长库就绪: {ssdeep_library.count:,} 条 (阈值={_ssdeep_threshold}, top_k={_ssdeep_top_k})")
yara_scanner = YaraScanner()

for fname in sorted(os.listdir(SIG_DIR)):
    path = os.path.join(SIG_DIR, fname)
    if fname.endswith((".hdb", ".hsb")):
        if not hash_db.already_imported(fname):
            added = hash_db.import_hdb(path)
            print(f"[NKAMG] 导入 {fname}: 新增 {added:,} 条")
    elif fname.endswith((".yar", ".yara")):
        yara_scanner.load_rules(path)

# 收集目录: 从第三方仓库 (Neo23x0/signature-base, Yara-Rules/rules,
# InQuest/yara-rules-vt, advanced-threat-research/Yara-Rules 等, 见 README
# 「YARA 规则库」) 递归加载全部 .yar/.yara。每个文件独立编译为一个规则集,
# 全部累积生效 (见 YaraScanner)。
_YARA_SRC = os.path.join(BASE_DIR, "yara_sources")
if os.path.isdir(_YARA_SRC):
    _collected = 0
    for _root, _dirs, _files in os.walk(_YARA_SRC):
        _dirs[:] = [d for d in _dirs if d != ".git"]   # 跳过仓库元数据
        for _fn in sorted(_files):
            if _fn.endswith((".yar", ".yara")):
                yara_scanner.load_rules(os.path.join(_root, _fn))
                _collected += 1
    if _collected:
        print(f"[NKAMG] 已收集第三方 YARA 规则文件: {_collected} 个 (yara_sources/)")

if yara_scanner.rule_count:
    print(f"[NKAMG] YARA 规则: {yara_scanner.rule_count:,} 条 "
          f"({len(yara_scanner.source_files)} 文件"
          + (f", {len(yara_scanner.errors)} 个文件编译失败" if yara_scanner.errors else "")
          + ")")
for _f, _e in yara_scanner.errors[:5]:
    print(f"[NKAMG] YARA 编译警告 [{_f}]: {_e}")

# P0-1: 启动时预编译全部 YARA 规则 (合并为单一 Rules 对象, 避免首次扫描延迟)
yara_scanner.warmup()

finalize_status = hash_db.finalize()
if finalize_status:
    print(f"[NKAMG] 签名库整理: {finalize_status}")

# 外部 YARA 扩展壳库: 读取 config.packer, 加载 packer_rules/ 下全部规则
_pk_rules_dir = str(pkcfg.get("rules_dir", "packer_rules")).strip()
_pk_rules_dir = _pk_rules_dir if os.path.isabs(_pk_rules_dir) else os.path.join(BASE_DIR, _pk_rules_dir)
pk_engine = packer.configure(
    rules_dir=_pk_rules_dir,
    max_yara_bytes=int(pkcfg.get("max_yara_bytes", 16 * 1024 * 1024)),
)
if pk_engine.rule_count:
    print(f"[NKAMG] 壳库 YARA 扩展规则: {pk_engine.rule_count} 条 ({len(pk_engine.source_files)} 文件, {_pk_rules_dir})")
for f, err in pk_engine.errors[:5]:
    print(f"[NKAMG] 壳库规则警告 [{f}]: {err}")

scanner = Scanner(hash_db, yara_scanner, md5_db=md5_db, fuzzy_db=fuzzy_db,
                   tlsh_library=tlsh_library, ssdeep_library=ssdeep_library)

# ---------- 安全加固: API 认证 / 限流 / 阶段2 资源上限 ----------
# M1: api_token 非空则所有 API 需 Bearer/query token (401); 默认空 = 匿名本地模式
API_TOKEN = str(scfg.get("api_token", "")).strip()
# M1: 每 IP 每分钟 /scan 次数上限 (0 = 不限), 滑动窗口内存实现
RATE_LIMIT = int(scfg.get("scan_rate_limit", 30))
_RATE_DQ = defaultdict(deque)
_RATE_LOCK = threading.Lock()
# M3: 阶段2 深度分析大小上限 (超过仅 YARA) + 后台线程并发信号量
P2_MAX_BYTES = int(scfg.get("phase2_max_mb", 32)) * 1024 * 1024
P2_MAX_MB = P2_MAX_BYTES // (1024 * 1024)
P2_CONCURRENCY = max(1, int(scfg.get("phase2_concurrency", 4)))
P2_SEM = threading.Semaphore(P2_CONCURRENCY)

# ---------- 扫描结果缓存 (按文件 SHA256 命名的 JSON, 与样本同存 uploads/) ----------
# 同一文件 (内容相同 → SHA256 相同) 重复扫描时直接返回缓存结果, 跳过两段式扫描;
# 前端可通过 "重新扫描" 按钮 (rescan=1) 强制绕过缓存重新分析并覆盖缓存。
# 报告文件: uploads/<sha256>.json; 样本文件: uploads/<sha256> (同目录并存, 无扩展名冲突)
RESULTS_CACHE_DIR = UPLOAD_DIR
os.makedirs(RESULTS_CACHE_DIR, exist_ok=True)

# 一次性迁移: 旧的 scan_cache/ 报告迁入 uploads/, 保留既有报告链接 (仅移动 uploads/ 中尚未存在的)
_LEGACY_CACHE_DIR = os.path.join(BASE_DIR, "scan_cache")
if os.path.isdir(_LEGACY_CACHE_DIR):
    for _name in os.listdir(_LEGACY_CACHE_DIR):
        if not _name.endswith(".json"):
            continue
        _src = os.path.join(_LEGACY_CACHE_DIR, _name)
        _dst = os.path.join(RESULTS_CACHE_DIR, _name)
        if os.path.isfile(_src) and not os.path.exists(_dst):
            try:
                os.replace(_src, _dst)
            except OSError:
                pass
    try:
        os.rmdir(_LEGACY_CACHE_DIR)   # 迁移干净后空目录被删除; 仍含其它文件则保留
    except OSError:
        pass


def _cache_path(sha256_hex):
    """报告缓存文件路径: uploads/<sha256>.json (小写十六进制, 防大小写歧义)"""
    return os.path.join(RESULTS_CACHE_DIR, str(sha256_hex).strip().lower() + ".json")


def _load_cached_result(sha256_hex):
    """读取缓存结果; 不存在或损坏返回 None"""
    path = _cache_path(sha256_hex)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# 提交历史上限: 超过后保留最近的条目 (防止同一文件反复提交撑爆 JSON)
HISTORY_MAX = 100

# ---------- 缓存 LRU 淘汰 (C3) ----------
# 无限增长的缓存目录最终会耗尽磁盘; 惰性清理: 超过 30 天的缓存删除,
# 总量超过 CACHE_MAX_FILES 时按 mtime 从旧到新淘汰, 只保留最近使用的。
CACHE_MAX_FILES = 10000
CACHE_MAX_AGE_DAYS = 30
_cache_cleanup_interval = 3600.0  # 清理节流间隔 (秒), 避免每次扫描都遍历目录
_cache_last_cleanup = 0.0
_cache_cleanup_lock = threading.Lock()


def _append_history(result, filename, submitted_at):
    """向扫描结果 dict 追加一条提交历史 {filename, submitted_at} (原地修改)"""
    hist = result.get("history")
    if not isinstance(hist, list):
        hist = []
    hist.append({"filename": filename, "submitted_at": submitted_at})
    result["history"] = hist[-HISTORY_MAX:]
    return result


def _save_cached_result(sha256_hex, result):
    """写入缓存结果 (临时文件 + 原子替换, 防并发写坏文件)

    Windows 下目标文件被并发读取时 os.replace 可能抛 PermissionError (共享冲突),
    此处短暂重试; 仍失败则退回直接覆写 (非原子但内容完整)。
    """
    path = _cache_path(sha256_hex)
    tmp = path + ".tmp." + uuid.uuid4().hex[:8]
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        for i in range(5):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                time.sleep(0.05 * (i + 1))
        # 重试仍失败: 直接覆写目标文件
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
    except Exception:  # noqa: BLE001 - 缓存写入失败不影响扫描结果
        pass
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _cache_cleanup(force=False):
    """惰性清理扫描缓存: 删除过期文件 (超 CACHE_MAX_AGE_DAYS 天) 并按 mtime LRU
    淘汰超量文件 (保最新 CACHE_MAX_FILES 个)。

    带节流: 距上次清理不足 _cache_cleanup_interval 秒时直接跳过 (force=True 除外),
    防止高频上传时反复遍历目录。清理失败静默忽略, 不影响扫描主流程。
    """
    global _cache_last_cleanup
    now = time.time()
    if not force:
        with _cache_cleanup_lock:
            if now - _cache_last_cleanup < _cache_cleanup_interval:
                return
            _cache_last_cleanup = now
    try:
        entries = []
        for name in os.listdir(RESULTS_CACHE_DIR):
            if not name.endswith(".json"):
                continue
            path = os.path.join(RESULTS_CACHE_DIR, name)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            entries.append((mtime, path))
        if not entries:
            return
        # 1) 删除超过 max age 的过期缓存
        stale_cutoff = now - CACHE_MAX_AGE_DAYS * 86400.0
        keep = [(m, p) for m, p in entries if m >= stale_cutoff]
        expired = [p for m, p in entries if m < stale_cutoff]
        for path in expired:
            try:
                os.remove(path)
            except OSError:
                pass
            _remove_sample_for_cache(path)
        # 2) 超量时按 mtime 从旧到新淘汰 (保留最新 CACHE_MAX_FILES 个)
        if len(keep) > CACHE_MAX_FILES:
            keep.sort(key=lambda e: e[0])
            for _, path in keep[:-CACHE_MAX_FILES]:
                try:
                    os.remove(path)
                except OSError:
                    pass
                _remove_sample_for_cache(path)
    except Exception:  # noqa: BLE001 - 清理失败不影响扫描主流程
        pass


def _launch_phase2(scanner, task, data, filename, submitted_at,
                   sha256_hex, hash_hit, hash_hit_name, history):
    """后台执行阶段 2 (YARA + 静态信息/模糊哈希 + 查壳), 合并后覆盖写缓存, 标记任务完成。

    - task["phase1"] 必须已就绪 (调用方先填充再启动);
    - 合并结果写 uploads/<sha256>.json (重新扫描时即"更新对应的 json 报告");
    - 大样本仅跑 YARA (超 P2_MAX_BYTES), 并发受 P2_SEM 信号量限制。
    """
    def _run():
        with P2_SEM:
            try:
                _t0 = time.time()
                if len(data) > P2_MAX_BYTES:
                    yara_dets = list(scanner.yara_scanner.scan_data(data))
                    p2 = {
                        "detections": yara_dets,
                        "static_info": None,
                        "static_ms": 0.0,
                        "elapsed_ms": round((time.time() - _t0) * 1000, 1),
                        "scanners": (["YARA"] if scanner.yara_scanner.rules else []),
                        "note": f"样本超过阶段2深度分析上限 ({P2_MAX_MB}MB), "
                                f"已跳过模糊哈希/PE元数据/查壳, 仅执行 YARA 规则匹配",
                    }
                else:
                    p2 = scanner.scan_phase2(data, filename=filename,
                                             hash_hit=hash_hit,
                                             sha256=sha256_hex,
                                             hash_hit_name=hash_hit_name)
                # C2 修复: 先合并+写缓存, 再标记 done (消除 gap 期 /api/file 404 窗口)
                try:
                    merged = scanner.merge_phases(task["phase1"], p2)
                    if p2.get("note"):
                        merged["phase2_note"] = p2["note"]
                    merged["submitted_at"] = submitted_at
                    merged["history"] = history
                    merged["scanned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    _save_cached_result(sha256_hex, merged)
                except Exception:  # noqa: BLE001 - 缓存写入失败不影响扫描结果
                    pass
                task["phase2"] = p2
                task["status"] = "done"
            except Exception as e:  # noqa: BLE001 - 后台异常记录到任务, 由轮询端呈现
                task["error"] = str(e)
                task["status"] = "error"
    threading.Thread(target=_run, daemon=True).start()


def _require_auth():
    """api_token 已配置时校验 Authorization: Bearer / ?token=; 未配置放行 (返回 None)"""
    if not API_TOKEN:
        return None
    h = request.headers.get("Authorization", "")
    if h == f"Bearer {API_TOKEN}":
        return None
    if request.args.get("token") == API_TOKEN:
        return None
    return jsonify({"error": "未授权: 缺少或无效的 API token"}), 401


# ---------- 管理员会话认证 (哈希管理页面登录) ----------
# 检测功能 (/ /scan /api/task /api/stats /api/hash) 完全不需要登录;
# 仅 /admin/hash 页面与 /api/admin/* 接口要求管理员登录 (session 标记)。
def is_admin():
    """当前会话是否已登录管理员"""
    return bool(session.get("admin"))


def _check_admin_credentials(user, pw):
    """校验用户名 + 密码; 存储形式 SHA-256(salt:password), 明文不在配置中"""
    if not ADMIN_PW_HASH or not user:
        return False
    if user != ADMIN_USER:
        return False
    calc = hashlib.sha256(f"{ADMIN_SALT}:{pw}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(calc, ADMIN_PW_HASH)  # 常量时间比较, 防计时侧信道


def admin_required(view):
    """装饰器: 仅放行已登录管理员; 未登录 GET 跳转登录页, 其余返回 401 JSON"""
    @wraps(view)
    def _wrapped(*args, **kwargs):
        if not is_admin():
            if request.method == "GET":
                nxt = request.full_path
                return redirect(url_for("admin_login", **({"next": nxt} if nxt else {})))
            return jsonify({"error": "未登录管理员, 请先登录"}), 401
        return view(*args, **kwargs)
    return _wrapped


def _route_hash_db(h):
    """按哈希长度路由到对应库: 64hex→SHA256 库, 32hex→MD5 库(若已构建)"""
    h = (h or "").strip().lower()
    valid = all(c in "0123456789abcdef" for c in h) if h else False
    if len(h) == 64 and valid:
        return hash_db, "sha256"
    if len(h) == 32 and valid:
        return (md5_db if md5_db is not None else None), "md5"
    return None, None


def _rate_limited():
    """每 IP 每分钟 /scan 次数限制 (滑动窗口); 返回 True 表示应拒绝 (429)"""
    if RATE_LIMIT <= 0:
        return False
    key = request.remote_addr or "?"
    now = time.time()
    with _RATE_LOCK:
        dq = _RATE_DQ[key]
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) >= RATE_LIMIT:
            return True
        dq.append(now)
    return False

# ---------- 两段式扫描任务管理 ----------
# Web 上传先返回阶段 1 (哈希/类型/签名库命中, 毫秒级), 阶段 2 (YARA/静态信息/查壳)
# 由后台线程执行, 前端轮询 /api/task/<id> 动态更新 → 类似 VirusTotal 的渐进式结果展示
TASKS_MAX = 100    # 内存中保留的任务上限 (超限淘汰最老)
TASK_TTL = 600     # 任务结果保留秒数 (惰性清理, 轮询过期返回 404)

_tasks = OrderedDict()
_tasks_lock = threading.Lock()


def _task_cleanup():
    """惰性清理过期任务 + 超限淘汰最老任务 (仅 /scan 创建任务时调用)"""
    now = time.time()
    with _tasks_lock:
        expired = [tid for tid, t in _tasks.items() if now - t["ts"] > TASK_TTL]
        for tid in expired:
            _tasks.pop(tid, None)
        while len(_tasks) > TASKS_MAX:
            _tasks.popitem(last=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["GET"])
def scan_page():
    """VirusTotal 风格独立扫描页 (GET /scan); 同名 POST 为上传扫描接口"""
    return render_template("scan.html")


@app.route("/api/stats")
def stats():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    return jsonify({
        "hash_signatures": hash_db.count,
        "md5_signatures": md5_db.count if md5_db else 0,
        "md5_available": md5_db is not None,
        "fuzzy_signatures": fuzzy_db.count if fuzzy_db else 0,
        "fuzzy_available": fuzzy_db is not None,
        "tlsh_entries": tlsh_library.count,
        "tlsh_available": tlsh_library is not None,
        "ssdeep_entries": ssdeep_library.count,
        "ssdeep_available": ssdeep_library is not None,
        "yara_rules": yara_scanner.rule_count,
        "yara_available": yara_scanner.rules is not None,
        "yara_error": yara_scanner.error,
        "packer_yara_rules": pk_engine.rule_count,
        "packer_yara_available": pk_engine.rules is not None,
        "packer_yara_error": "; ".join(f"{f}: {e}" for f, e in pk_engine.errors[:3]) or None,
        "hash_sources": hash_db.source_files,
        "md5_sources": md5_db.source_files if md5_db else [],
        "fuzzy_sources": fuzzy_db.source_files if fuzzy_db else [],
        "yara_sources": yara_scanner.source_files,
        "storage": hash_db.stats(),
        "md5_storage": md5_db.stats() if md5_db else None,
        "fuzzy_storage": fuzzy_db.stats() if fuzzy_db else None,
        "tlsh_storage": tlsh_library.stats() if tlsh_library else None,
        "ssdeep_storage": ssdeep_library.stats() if ssdeep_library else None,
        "max_upload_mb": int(scfg["max_upload_mb"]),  # 前端据此本地预检超限, 给出明确提示
    })


@app.route("/api/hash/<hash>")
def hash_lookup(hash):
    """哈希查询: 32 位 hex → MD5 库, 64 位 hex → SHA256 库; 命中与否均 200, 非法 400。

    VirusTotal 风格首页大搜索框的查询接口 (GET, 幂等), 双库并列查询。
    """
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    h = (hash or "").strip().lower()
    valid = all(c in "0123456789abcdef" for c in h) if h else False
    if len(h) == 32 and valid:  # MD5
        if md5_db is None:
            return jsonify({"error": "MD5 库未构建: 请先运行 build_md5_db.py"}), 503
        hits = list(md5_db.check_hash(h))
        return jsonify({
            "md5": h,
            "hash_algo": "md5",
            "hit": bool(hits),
            "detections": hits,
            "scanner": "Hash DB (md5)",
        })
    if len(h) == 64 and valid:  # SHA256
        hits = list(hash_db.check(None, None, None, None, h))
        # 模糊哈希库不再按 SHA256 查询 (fuzzy hash 是主键, 需按 hash 值查)
        return jsonify({
            "sha256": h,
            "hash_algo": "sha256",
            "hit": bool(hits),
            "detections": hits,
            "scanner": "Hash DB (sha256)",
        })
    return jsonify({"error": "无效的哈希: 需要 32 位 (MD5) 或 64 位 (SHA256) 十六进制字符串"}), 400


# 文件超过 MAX_CONTENT_LENGTH 时 Flask/Werkzeug 抛出 413 RequestEntityTooLarge,
# 默认返回 HTML 错误页 (前端 JSON 解析失败 → 模糊 ERROR)。统一返回明确 JSON 提示。
@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(e):
    limit_mb = int(scfg["max_upload_mb"])
    return jsonify({"error": f"文件过大: 超过上传上限 {limit_mb}MB, 请压缩后重试"}), 413


@app.route("/scan", methods=["POST"])
def scan():
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    if _rate_limited():
        return jsonify({"error": "请求过于频繁, 请稍后再试 (限流)"}), 429
    if "file" not in request.files:
        return jsonify({"error": "未收到文件"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "空文件名"}), 400

    # 直接内存读取扫描 (受 MAX_CONTENT_LENGTH 限制), 全程不落盘
    data = f.read()
    # 文件提交时间 (本机时间): 注入扫描结果, 供前端展示
    submitted_at = time.strftime("%Y-%m-%d %H:%M:%S")

    # P0-2: 一次性计算全部哈希 (供缓存 key + scanner 复用, 不再重算 SHA256)
    md5_hex, sha1_hex, sha256_hex = compute_hashes_bytes(data)

    # 重新扫描支持: 按 SHA256 去重保存样本原始字节 (供报告页"重新扫描"按钮读取); 后台写盘不阻塞响应
    threading.Thread(target=_save_sample, args=(sha256_hex, data), daemon=True).start()

    # C3: 惰性触发缓存清理 (带 1 小时节流, 避免高频上传时反复遍历目录)
    threading.Thread(target=_cache_cleanup, daemon=True).start()

    # ---------- 结果缓存: 按 SHA256 查缓存, 命中直接返回 (跳过两段式扫描) ----------
    # rescan=1 (前端 "重新扫描" 按钮) 强制绕过缓存重新分析, 完成后覆盖缓存。
    rescan = request.form.get("rescan") in ("1", "true", "on")
    cached = None if rescan else _load_cached_result(sha256_hex)
    if cached is not None:
        cached_result = dict(cached)
        # 文件名/提交时间以本次上传为准 (内容相同但文件名可能不同, 其余结果内容一致)
        cached_result["filename"] = f.filename
        cached_result["submitted_at"] = submitted_at
        # 提交历史: 追加本次 {filename, submitted_at} (命中缓存也记录每次提交)
        _append_history(cached_result, f.filename, submitted_at)
        # P2-2: 磁盘写回放到后台线程, 响应立即返回 (高并发时避免磁盘 I/O 排队阻塞)
        # history 已在内存中的 cached_result 追加完毕, 本次响应内容不受异步写回影响
        threading.Thread(
            target=_save_cached_result,
            args=(sha256_hex, cached_result),
            daemon=True,
        ).start()
        return jsonify({
            "task_id": None,
            "status": "done",
            "cached": True,
            "sha256": sha256_hex,
            "result": cached_result,
        })

    # 提交历史: 重新扫描时从既有缓存延续历史 (首次扫描为空), 再追加本次提交
    history = []
    if rescan:
        old = _load_cached_result(sha256_hex)
        if old and isinstance(old.get("history"), list):
            history = list(old["history"])[-HISTORY_MAX:]
    history.append({"filename": f.filename, "submitted_at": submitted_at})

    _task_cleanup()
    task_id = uuid.uuid4().hex[:12]

    # 阶段 1: 哈希 + 文件类型 + 哈希签名库命中 → 立即返回 (毫秒级)
    # P0-2: 传入预计算哈希, scanner 不再重算
    phase1 = scanner.scan_phase1(data, filename=f.filename,
                                 hashes=(md5_hex, sha1_hex, sha256_hex))
    phase1["submitted_at"] = submitted_at   # 提交时间随阶段1结果下发/合并
    # 是否命中 SHA256/MD5 精确哈希: 不再作为 ssdeep/TLSH 检测门控
    # (SSDeep/TLSH 相似度检测始终执行, 与 SHA256/MD5 精确哈希并行),
    # 仅控制 ssdeep/TLSH 自增长库入库 (保持库内仅累积已知恶意样本)
    hash_hit = any(d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB")
                   for d in phase1["detections"])
    # 获取哈希命中名称 (用于 ssdeep/TLSH 库入库标注)
    _hash_hit_name = None
    for d in phase1["detections"]:
        if d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB"):
            _hash_hit_name = d.get("name")
            break
    task = {
        "id": task_id,
        "ts": time.time(),
        "history": history,                 # 提交历史 (含本次提交), 随合并结果返回/入缓存
        "phase1": phase1,
        "phase2": None,
        "status": "phase2",   # 阶段 2 后台执行中
        "error": None,
    }
    with _tasks_lock:
        _tasks[task_id] = task

    # 阶段 2: YARA 规则 + 静态信息/模糊哈希 + 查壳 → 后台线程, 不阻塞上传响应
    # (闭包持有的 data 在线程结束后自动释放, 任务记录中不保留大缓冲)
    _launch_phase2(scanner, task, data, f.filename, submitted_at, sha256_hex,
                   hash_hit, _hash_hit_name, history)
    return jsonify({"task_id": task_id, "status": "phase2", "result": phase1})


@app.route("/api/rescan/<path:sha256_hex>", methods=["POST"])
def api_rescan(sha256_hex):
    """重新扫描: 读取已保存的样本原始字节重跑完整扫描, 覆盖更新 uploads/<sha256>.json 报告

    供报告页 "重新扫描" 按钮调用; 返回两段式 task (阶段2 后台执行), 前端轮询
    /api/task/<id> 后以新结果重新渲染报告。
    """
    if auth_err := _require_auth():
        return auth_err
    if _rate_limited():
        return jsonify({"error": "请求过于频繁, 请稍后再试 (限流)"}), 429
    sha = str(sha256_hex).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        return jsonify({"error": "非法 SHA256 格式"}), 400
    sample_path = _sample_path(sha)
    if not os.path.isfile(sample_path):
        return jsonify({
            "error": "该样本的原始文件未被保留（样本自保存功能启用起才留存），"
                     "请到扫描页重新上传后再重新扫描"
        }), 404
    try:
        with open(sample_path, "rb") as f:
            data = f.read()
    except OSError:
        return jsonify({"error": "样本文件读取失败"}), 500

    # 沿用既有缓存中的文件名与提交历史, 追加本次重扫记录
    old = _load_cached_result(sha)
    filename = (old or {}).get("filename") or "unknown.bin"
    history = []
    if old and isinstance(old.get("history"), list):
        history = list(old["history"])[-HISTORY_MAX:]
    submitted_at = time.strftime("%Y-%m-%d %H:%M:%S")
    history.append({"filename": filename, "submitted_at": submitted_at})

    md5_hex, sha1_hex, sha256_hex2 = compute_hashes_bytes(data)
    phase1 = scanner.scan_phase1(data, filename=filename, hashes=(md5_hex, sha1_hex, sha256_hex2))
    phase1["submitted_at"] = submitted_at
    hash_hit = any(d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB")
                   for d in phase1["detections"])
    _hash_hit_name = None
    for d in phase1["detections"]:
        if d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB"):
            _hash_hit_name = d.get("name")
            break

    _task_cleanup()
    task_id = uuid.uuid4().hex[:12]
    task = {
        "id": task_id,
        "ts": time.time(),
        "history": history,
        "phase1": phase1,
        "phase2": None,
        "status": "phase2",
        "error": None,
    }
    with _tasks_lock:
        _tasks[task_id] = task
    _launch_phase2(scanner, task, data, filename, submitted_at, sha,
                   hash_hit, _hash_hit_name, history)
    return jsonify({"task_id": task_id, "status": "phase2", "result": phase1, "rescanned": True})


@app.route("/api/task/<task_id>")
def task_status(task_id):
    """轮询接口: 阶段 2 完成后返回合并的完整扫描结果 (哈希 + YARA + 静态信息 + 查壳)"""
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        return jsonify({"error": "任务不存在或已过期"}), 404
    if task["status"] == "phase2":
        # 附带阶段1结果: 供从 URL (?task=) 跳转接管的页面立即渲染哈希/类型/签名库命中
        return jsonify({"task_id": task_id, "status": "phase2", "result": task["phase1"]})
    if task["status"] == "error":
        return jsonify({"task_id": task_id, "status": "error", "error": task["error"]})
    result = scanner.merge_phases(task["phase1"], task["phase2"])
    result["submitted_at"] = task["phase1"].get("submitted_at")   # 文件提交时间
    result["history"] = task.get("history") or []                 # 提交历史
    if task["phase2"].get("note"):
        result["phase2_note"] = task["phase2"]["note"]
    return jsonify({"task_id": task_id, "status": "done", "result": result})


# ================= 文件详情页 (VirusTotal 风格 /file/<sha256> 动态路径) =================
# 以文件 SHA256 作为资源唯一标识放入 URL 路径参数; 页面从扫描结果缓存加载完整报告。
def _is_valid_sha256(h):
    """64 位十六进制 (大小写不敏感, 统一转小写)"""
    h = (h or "").strip().lower()
    return h if len(h) == 64 and all(c in "0123456789abcdef" for c in h) else None


@app.route("/file/<file_hash>")
def file_page(file_hash):
    """文件扫描报告详情页: /file/<sha256> (参考 VirusTotal /gui/file/<hash>)"""
    h = _is_valid_sha256(file_hash)
    # 非法哈希仍渲染页面, 由前端给出友好提示 (保持与 VT 一致的体验而非裸 404)
    return render_template("file.html", file_hash=h or (file_hash or ""), valid=bool(h))


@app.route("/api/file/<file_hash>")
def file_report(file_hash):
    """按 SHA256 读取缓存中的扫描报告 (uploads/<sha256>.json); 未扫描过返回 404"""
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    h = _is_valid_sha256(file_hash)
    if not h:
        return jsonify({"error": "无效的哈希: 需要 64 位 (SHA256) 十六进制字符串"}), 400
    cached = _load_cached_result(h)
    if cached is None:
        return jsonify({"found": False, "sha256": h, "error": "该文件尚未在本系统扫描过"}), 404
    return jsonify({"found": True, "sha256": h, "result": cached})


# ================= 管理员登录 / 哈希管理页面 =================
# 检测功能无需登录; 以下路由保护哈希管理页面与对应 API。
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """管理员登录页 (用户名 + 密码); GET 渲染表单, POST 校验后写 session"""
    if is_admin():
        return redirect(url_for("admin_hash"))
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pw = request.form.get("password") or ""
        if _check_admin_credentials(user, pw):
            session["admin"] = True
            nxt = request.args.get("next")
            # 防开放重定向: 仅允许站内相对路径
            if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("admin_hash")
            return redirect(nxt)
        return render_template("login.html", error="用户名或密码错误", username=user)
    return render_template("login.html")


@app.route("/admin/logout")
def admin_logout():
    """退出登录, 清空整个会话 (比 pop 单键更彻底)"""
    session.clear()
    return redirect(url_for("admin_login"))


@app.after_request
def _admin_no_store(resp):
    """管理页面禁止缓存: 防止登出后浏览器从缓存/bfcache 还原管理页, 造成"未退出"假象"""
    if request.path.startswith("/admin"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


@app.route("/admin/hash")
@admin_required
def admin_hash():
    """哈希管理页面 (需登录): 增 / 删 / 查 / 批量导入签名"""
    return render_template("hash_admin.html")


@app.route("/api/admin/hash/<hash>")
@admin_required
def admin_hash_lookup(hash):
    """按哈希查询单条签名 (32hex→MD5 库, 64hex→SHA256 库); 命中与否均 200"""
    db, algo = _route_hash_db(hash)
    if db is None:
        return jsonify({"error": "无效的哈希或对应库未构建: 需要 32 位(MD5) 或 64 位(SHA256) 十六进制"}), 400
    hits = list(db.check_hash(hash))
    return jsonify({"hash": hash, "hash_algo": algo, "hit": bool(hits), "detections": hits})


@app.route("/api/admin/hash", methods=["POST"])
@admin_required
def admin_hash_add():
    """新增单条哈希签名 (hash:size:name); 自动路由 SHA256/MD5 库"""
    data = request.get_json(silent=True) or {}
    h = (data.get("hash") or "").strip().lower()
    size = data.get("size")
    name = (data.get("name") or "").strip()
    db, algo = _route_hash_db(h)
    if db is None:
        return jsonify({"error": "无效的哈希或对应库未构建: 需要 32 位(MD5) 或 64 位(SHA256) 十六进制"}), 400
    try:
        added = db.add_hash(h, size, name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"hash": h, "hash_algo": algo, "added": added, "total": db.count})


@app.route("/api/admin/hash/<hash>", methods=["DELETE"])
@admin_required
def admin_hash_delete(hash):
    """删除单条哈希签名; 返回删除条数"""
    db, algo = _route_hash_db(hash)
    if db is None:
        return jsonify({"error": "无效的哈希或对应库未构建"}), 400
    try:
        deleted = db.delete_hash(hash)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"hash": hash, "hash_algo": algo, "deleted": deleted, "total": db.count})


# ============================================================
# 模糊哈希管理: SSDeep / TLSH (自增长库)
# ============================================================
_SSDEEP_RE = re.compile(r"^\d+[:|-][A-Za-z0-9+/]+[:|-][A-Za-z0-9+/]+$")
_TLSH_RE = re.compile(r"^[0-9a-fA-F]{70}$")
# Trend Micro 官方 libtlsh 原始格式: "T1" + 70 位 hex = 72 字符
# (VirusTotal / MalwareBazaar 存量数据为无前缀 70 位 hex, 本项目同; 校验时兼容并归一化)
# 注意: 值已先 lower(), 故前缀用小写 t 匹配
_TLSH_TM_RE = re.compile(r"^t[0-9a-f][0-9a-f]{70}$")


def _validate_fuzzy(kind, value):
    """校验模糊哈希值格式; 返回 (value, error)"""
    if kind == "ssdeep":
        v = value.strip()
        if not _SSDEEP_RE.match(v):
            return None, "SSDeep 格式无效: 需 <块大小>:<hash1>:<hash2> (或 ClamAV 短横线分隔)"
        return v, None
    if kind == "tlsh":
        v = value.strip().lower()
        if _TLSH_TM_RE.match(v):
            v = v[2:]  # 去掉 T1 前缀 → 70 位 hex (与本项目/VT 存储格式一致)
        if not _TLSH_RE.match(v):
            return None, "TLSH 格式无效: 需 70 位十六进制 (兼容 T1 前缀格式, 如 T1A8...)"
        return v, None
    return None, "未知哈希类型"


@app.route("/api/admin/fuzzy/<kind>/<path:value>")
@admin_required
def admin_fuzzy_lookup(kind, value):
    """查询 SSDeep/TLSH 模糊哈希 (精确匹配); 命中与否均 200"""
    v, err = _validate_fuzzy(kind, value)
    if err:
        return jsonify({"error": err}), 400
    if kind == "ssdeep":
        if ssdeep_library is None:
            return jsonify({"error": "SSDeep 库未构建"}), 503
        hits = ssdeep_library.check_exact(v)
        total = ssdeep_library.count
    else:
        if tlsh_library is None:
            return jsonify({"error": "TLSH 库未构建"}), 503
        hits = tlsh_library.check_exact(v)
        total = tlsh_library.count
    return jsonify({"kind": kind, "value": v, "hit": bool(hits), "total": total, "detections": hits})


@app.route("/api/admin/fuzzy/<kind>", methods=["POST"])
@admin_required
def admin_fuzzy_add(kind):
    """新增一条 SSDeep/TLSH 模糊哈希 {value, sha256, name, size}"""
    data = request.get_json(silent=True) or {}
    v, err = _validate_fuzzy(kind, data.get("value") or "")
    if err:
        return jsonify({"error": err}), 400
    sha256 = (data.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return jsonify({"error": "SHA256 需 64 位十六进制"}), 400
    name = (data.get("name") or "").strip() or "unknown"
    size = data.get("size")
    if kind == "ssdeep":
        if ssdeep_library is None:
            return jsonify({"error": "SSDeep 库未构建"}), 503
        ssdeep_library.insert(v, sha256, name, size)
        total = ssdeep_library.count
    else:
        if tlsh_library is None:
            return jsonify({"error": "TLSH 库未构建"}), 503
        tlsh_library.insert(v, sha256, name, size)
        total = tlsh_library.count
    return jsonify({"kind": kind, "value": v, "added": 1, "total": total})


@app.route("/api/admin/fuzzy/<kind>/<path:value>", methods=["DELETE"])
@admin_required
def admin_fuzzy_delete(kind, value):
    """删除一条 SSDeep/TLSH 模糊哈希; 返回删除条数"""
    v, err = _validate_fuzzy(kind, value)
    if err:
        return jsonify({"error": err}), 400
    if kind == "ssdeep":
        if ssdeep_library is None:
            return jsonify({"error": "SSDeep 库未构建"}), 503
        deleted = ssdeep_library.delete(v)
        total = ssdeep_library.count
    else:
        if tlsh_library is None:
            return jsonify({"error": "TLSH 库未构建"}), 503
        deleted = tlsh_library.delete(v)
        total = tlsh_library.count
    return jsonify({"kind": kind, "value": v, "deleted": deleted, "total": total})


@app.route("/api/admin/import", methods=["POST"])
@admin_required
def admin_import():
    """批量导入签名文件: .hdb/.hsb → 哈希库 (SHA256 + MD5), .yar/.yara → YARA 规则库"""
    if "file" not in request.files:
        return jsonify({"error": "未收到文件"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "空文件名"}), 400
    fname = os.path.basename(f.filename)
    lower = fname.lower()
    if not lower.endswith((".hdb", ".hsb", ".yar", ".yara")):
        return jsonify({"error": "仅支持 .hdb/.hsb (哈希) 或 .yar/.yara (YARA) 文件"}), 400
    dest = os.path.join(SIG_DIR, fname)
    f.save(dest)
    result = {"saved": fname}
    if lower.endswith((".hdb", ".hsb")):
        result["type"] = "hash"
        sha_added = hash_db.import_hdb(dest)
        md5_added = md5_db.import_hdb(dest) if md5_db else 0
        hash_db.finalize()
        if md5_db:
            md5_db.finalize()
        result["sha256_added"] = sha_added
        result["md5_added"] = md5_added
        result["sha256_total"] = hash_db.count
        result["md5_total"] = md5_db.count if md5_db else 0
    else:  # .yar / .yara
        result["type"] = "yara"
        added = yara_scanner.load_rules(dest)
        result["yara_added"] = added
        result["yara_total"] = yara_scanner.rule_count
        if added == 0 and yara_scanner.errors:
            result["error"] = f"规则编译失败: {yara_scanner.errors[-1][1]}"
    return jsonify(result)


if __name__ == "__main__":
    st = hash_db.stats()
    print(f"[NKAMG] 哈希签名: {hash_db.count:,} 条 (存储层: {st['tier']}, "
          f"分片: {st['shards']['configured']}, DB {st['db_size_mb']}MB) "
          f"| YARA 规则: {yara_scanner.rule_count} 条"
          + (f" | MD5 库: {md5_db.count:,} 条" if md5_db else " | MD5 库: 未构建"))
    if yara_scanner.error:
        print(f"[NKAMG] YARA 警告: {yara_scanner.error}")
    # C3: 启动时后台强制清理一次过期/超量缓存
    threading.Thread(target=_cache_cleanup, kwargs={"force": True}, daemon=True).start()
    app.run(host=scfg["host"], port=int(scfg["port"]), debug=False, threaded=True)
