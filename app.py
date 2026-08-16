"""
NKREPO Scanner - Web 服务入口
启动: python app.py  →  http://127.0.0.1:5000
"""
import os
import tempfile

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from scanner import HashSignatureDB, Scanner, YaraScanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_DIR = os.path.join(BASE_DIR, "signatures")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# ---------- 初始化扫描引擎 ----------
# 哈希签名持久化在 SQLite (signatures/signatures.db), .hdb 明文仅作增量导入格式
hash_db = HashSignatureDB(os.path.join(SIG_DIR, "signatures.db"))
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
os.makedirs(UPLOAD_DIR, exist_ok=True)


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

    # 保存到临时文件 (保留原始扩展名便于魔数/类型判断)
    safe_name = secure_filename(f.filename) or "unnamed"
    fd, tmp_path = tempfile.mkstemp(
        suffix="_" + safe_name, dir=UPLOAD_DIR
    )
    try:
        os.close(fd)
        f.save(tmp_path)
        result = scanner.scan_file(tmp_path, filename=f.filename)
        return jsonify(result)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


if __name__ == "__main__":
    st = hash_db.stats()
    print(f"[NKREPO] 哈希签名: {hash_db.count:,} 条 (存储层: {st['tier']}, "
          f"DB {st['db_size_mb']}MB) | YARA 规则: {yara_scanner.rule_count} 条")
    if yara_scanner.error:
        print(f"[NKREPO] YARA 警告: {yara_scanner.error}")
    app.run(host="127.0.0.1", port=5000, debug=False)
