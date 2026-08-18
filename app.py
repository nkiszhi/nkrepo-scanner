"""
NKAMG Scanner - Web 服务入口
启动: python app.py  →  http://127.0.0.1:5000 (地址/端口可由 config.json 修改)
"""
import json
import os
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from scanner import FuzzySignatureDB, HashSignatureDB, Scanner, YaraScanner
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
    "hash_db": {
        "max_open_shards": 4,      # 分片 SQLite 连接 / Bloom 位图懒加载 LRU 上限
    },
    "server": {
        "host": "127.0.0.1",
        "port": 5000,
        "max_upload_mb": 10,
        "uploads_dir": "uploads",  # 上传测试样本目录 (相对项目根目录或绝对路径), 启动时自动创建
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
hcfg = cfg["hash_db"]
scfg = cfg["server"]
pkcfg = cfg["packer"]

# 上传目录: 从配置读取 (server.uploads_dir), 不存在时动态创建; 仅用于放置测试样本, /scan 不落盘
_uploads_cfg = str(scfg.get("uploads_dir", "uploads")).strip()
UPLOAD_DIR = _uploads_cfg if os.path.isabs(_uploads_cfg) else os.path.join(BASE_DIR, _uploads_cfg)
os.makedirs(UPLOAD_DIR, exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(scfg["max_upload_mb"]) * 1024 * 1024

# ---------- 初始化扫描引擎 ----------
# 哈希签名持久化在动态分片 SQLite (signatures/sha256.db.shards/),
# 分片数 = config 中 bloom.shards, Bloom 位图按同样分片数懒加载
hash_db = HashSignatureDB(
    os.path.join(SIG_DIR, "sha256.db"),
    shard_count=int(bcfg["shards"]),
    bloom_fp_rate=float(bcfg["fp_rate"]),
    max_open_shards=int(hcfg["max_open_shards"]),
)
# 独立 MD5 分片库 (与 SHA256 库并列): 由 build_md5_db.py 构建 (signatures/md5.db.shards/),
# 这里只读实例化; 若分片未构建则降级为 None, 不影响 sha256 功能
md5_db = None
_md5_base = os.path.join(SIG_DIR, "md5.db")
if os.path.isdir(_md5_base + ".shards"):
    md5_db = HashSignatureDB(
        _md5_base,
        shard_count=int(bcfg["shards"]),
        bloom_fp_rate=float(bcfg["fp_rate"]),
        max_open_shards=int(hcfg["max_open_shards"]),
        hash_algo="md5",
    )
    print(f"[NKAMG] MD5 库就绪: {md5_db.count:,} 条")
else:
    print("[NKAMG] 未检测到 MD5 分片库, 跳过 (运行 build_md5_db.py 可构建)")
# 模糊哈希增强库 (与 SHA256/MD5 库并列的第三库): 由 build_fuzzy_db.py 从 hdb/
# 8 字段行 (sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash)
# 提取 5 个模糊哈希字段构建 (signatures/fuzzy.db.shards/); 未构建则降级 None
fuzzy_db = None
_fuzzy_base = os.path.join(SIG_DIR, "fuzzy.db")
if os.path.isdir(_fuzzy_base + ".shards"):
    fuzzy_db = FuzzySignatureDB(
        _fuzzy_base,
        shard_count=int(bcfg["shards"]),
        bloom_fp_rate=float(bcfg["fp_rate"]),
        max_open_shards=int(hcfg["max_open_shards"]),
    )
    print(f"[NKAMG] 模糊哈希库就绪: {fuzzy_db.count:,} 条")
else:
    print("[NKAMG] 未检测到模糊哈希分片库, 跳过 (运行 build_fuzzy_db.py 可构建)")
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

scanner = Scanner(hash_db, yara_scanner, md5_db=md5_db, fuzzy_db=fuzzy_db)

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
        if fuzzy_db is not None:
            # 模糊哈希增强: sha256 命中时附加 ssdeep/vhash/authentihash/imphash/rich_header_hash
            hits.extend(fuzzy_db.check_hash(h))
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
    _task_cleanup()
    task_id = uuid.uuid4().hex[:12]

    # 阶段 1: 哈希 + 文件类型 + 哈希签名库命中 → 立即返回 (毫秒级)
    phase1 = scanner.scan_phase1(data, filename=f.filename)
    task = {
        "id": task_id,
        "ts": time.time(),
        "phase1": phase1,
        "phase2": None,
        "status": "phase2",   # 阶段 2 后台执行中
        "error": None,
    }
    with _tasks_lock:
        _tasks[task_id] = task

    # 阶段 2: YARA 规则 + 静态信息/模糊哈希 + 查壳 → 后台线程, 不阻塞上传响应
    # (闭包持有的 data 在线程结束后自动释放, 任务记录中不保留大缓冲)
    # M3: 超过 phase2_max_mb 的样本仅执行 YARA (10s 超时), 跳过纯 Python 深度分析;
    #     并发上限由信号量控制, 超限排队, 防止 CPU 峰值打满
    def _run_phase2():
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
                    p2 = scanner.scan_phase2(data, filename=f.filename)
                task["phase2"] = p2
                task["status"] = "done"
            except Exception as e:  # noqa: BLE001 - 后台异常记录到任务, 由轮询端呈现
                task["error"] = str(e)
                task["status"] = "error"

    threading.Thread(target=_run_phase2, daemon=True).start()
    return jsonify({"task_id": task_id, "status": "phase2", "result": phase1})


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
    if task["phase2"].get("note"):
        result["phase2_note"] = task["phase2"]["note"]
    return jsonify({"task_id": task_id, "status": "done", "result": result})


if __name__ == "__main__":
    st = hash_db.stats()
    print(f"[NKAMG] 哈希签名: {hash_db.count:,} 条 (存储层: {st['tier']}, "
          f"分片: {st['shards']['configured']}, DB {st['db_size_mb']}MB) "
          f"| YARA 规则: {yara_scanner.rule_count} 条"
          + (f" | MD5 库: {md5_db.count:,} 条" if md5_db else " | MD5 库: 未构建"))
    if yara_scanner.error:
        print(f"[NKAMG] YARA 警告: {yara_scanner.error}")
    app.run(host=scfg["host"], port=int(scfg["port"]), debug=False, threaded=True)
