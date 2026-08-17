"""
NKREPO Scanner - Web 服务入口
启动: python app.py  →  http://127.0.0.1:5000 (地址/端口可由 config.json 修改)
"""
import json
import os
import threading
import time
import uuid
from collections import OrderedDict

from flask import Flask, jsonify, render_template, request

from scanner import HashSignatureDB, Scanner, YaraScanner
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
        "max_upload_mb": 50,
        "uploads_dir": "uploads",  # 上传测试样本目录 (相对项目根目录或绝对路径), 启动时自动创建
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
            print(f"[NKREPO] 配置文件解析失败, 使用默认配置: {e}")
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
# 哈希签名持久化在动态分片 SQLite (signatures/signatures.db.shards/),
# 分片数 = config 中 bloom.shards, Bloom 位图按同样分片数懒加载
hash_db = HashSignatureDB(
    os.path.join(SIG_DIR, "signatures.db"),
    shard_count=int(bcfg["shards"]),
    bloom_fp_rate=float(bcfg["fp_rate"]),
    max_open_shards=int(hcfg["max_open_shards"]),
)
yara_scanner = YaraScanner()

for fname in sorted(os.listdir(SIG_DIR)):
    path = os.path.join(SIG_DIR, fname)
    if fname.endswith((".hdb", ".hsb")):
        if not hash_db.already_imported(fname):
            added = hash_db.import_hdb(path)
            print(f"[NKREPO] 导入 {fname}: 新增 {added:,} 条")
    elif fname.endswith((".yar", ".yara")):
        yara_scanner.load_rules(path)

finalize_status = hash_db.finalize()
if finalize_status:
    print(f"[NKREPO] 签名库整理: {finalize_status}")

# 外部 YARA 扩展壳库: 读取 config.packer, 加载 packer_rules/ 下全部规则
_pk_rules_dir = str(pkcfg.get("rules_dir", "packer_rules")).strip()
_pk_rules_dir = _pk_rules_dir if os.path.isabs(_pk_rules_dir) else os.path.join(BASE_DIR, _pk_rules_dir)
pk_engine = packer.configure(
    rules_dir=_pk_rules_dir,
    max_yara_bytes=int(pkcfg.get("max_yara_bytes", 16 * 1024 * 1024)),
)
if pk_engine.rule_count:
    print(f"[NKREPO] 壳库 YARA 扩展规则: {pk_engine.rule_count} 条 ({len(pk_engine.source_files)} 文件, {_pk_rules_dir})")
for f, err in pk_engine.errors[:5]:
    print(f"[NKREPO] 壳库规则警告 [{f}]: {err}")

scanner = Scanner(hash_db, yara_scanner)

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


@app.route("/api/stats")
def stats():
    return jsonify({
        "hash_signatures": hash_db.count,
        "yara_rules": yara_scanner.rule_count,
        "yara_available": yara_scanner.rules is not None,
        "yara_error": yara_scanner.error,
        "packer_yara_rules": pk_engine.rule_count,
        "packer_yara_available": pk_engine.rules is not None,
        "packer_yara_error": "; ".join(f"{f}: {e}" for f, e in pk_engine.errors[:3]) or None,
        "hash_sources": hash_db.source_files,
        "yara_sources": yara_scanner.source_files,
        "storage": hash_db.stats(),
    })


@app.route("/scan", methods=["POST"])
def scan():
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
    def _run_phase2():
        try:
            task["phase2"] = scanner.scan_phase2(data, filename=f.filename)
            task["status"] = "done"
        except Exception as e:  # noqa: BLE001 - 后台异常记录到任务, 由轮询端呈现
            task["error"] = str(e)
            task["status"] = "error"

    threading.Thread(target=_run_phase2, daemon=True).start()
    return jsonify({"task_id": task_id, "status": "phase2", "result": phase1})


@app.route("/api/task/<task_id>")
def task_status(task_id):
    """轮询接口: 阶段 2 完成后返回合并的完整扫描结果 (哈希 + YARA + 静态信息 + 查壳)"""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        return jsonify({"error": "任务不存在或已过期"}), 404
    if task["status"] == "phase2":
        return jsonify({"task_id": task_id, "status": "phase2"})
    if task["status"] == "error":
        return jsonify({"task_id": task_id, "status": "error", "error": task["error"]})
    result = scanner.merge_phases(task["phase1"], task["phase2"])
    return jsonify({"task_id": task_id, "status": "done", "result": result})


if __name__ == "__main__":
    st = hash_db.stats()
    print(f"[NKREPO] 哈希签名: {hash_db.count:,} 条 (存储层: {st['tier']}, "
          f"分片: {st['shards']['configured']}, DB {st['db_size_mb']}MB) "
          f"| YARA 规则: {yara_scanner.rule_count} 条")
    if yara_scanner.error:
        print(f"[NKREPO] YARA 警告: {yara_scanner.error}")
    app.run(host=scfg["host"], port=int(scfg["port"]), debug=False, threaded=True)
