"""
NKREPO Scanner - Web 服务入口
启动: python app.py  →  http://127.0.0.1:5000 (地址/端口可由 config.json 修改)
"""
import json
import os

from flask import Flask, jsonify, render_template, request

from scanner import HashSignatureDB, Scanner, YaraScanner

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

scanner = Scanner(hash_db, yara_scanner)


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

    # 直接内存读取扫描 (受 MAX_CONTENT_LENGTH 限制), 哈希/类型/YARA 复用同一缓冲, 全程不落盘
    data = f.read()
    result = scanner.scan_bytes(data, filename=f.filename)
    return jsonify(result)


if __name__ == "__main__":
    st = hash_db.stats()
    print(f"[NKREPO] 哈希签名: {hash_db.count:,} 条 (存储层: {st['tier']}, "
          f"分片: {st['shards']['configured']}, DB {st['db_size_mb']}MB) "
          f"| YARA 规则: {yara_scanner.rule_count} 条")
    if yara_scanner.error:
        print(f"[NKREPO] YARA 警告: {yara_scanner.error}")
    app.run(host=scfg["host"], port=int(scfg["port"]), debug=False, threaded=True)
