"""
NKAMG Scanner - 千万级签名库基准测试
测量: 启动耗时 / 磁盘与内存占用 / 命中与未命中查询延迟 / 端到端扫描耗时

用法:
  python bench.py                      # 使用现有 signatures.db
  python bench.py --miss 2000 --hits 200
"""
import argparse
import os
import random
import time

from scanner import HashSignatureDB, Scanner, compute_hashes

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "signatures", "signatures.db")
BLOOM_PATH = DB_PATH + ".bloom"


def pct(sorted_ms, p):
    if not sorted_ms:
        return 0.0
    idx = min(len(sorted_ms) - 1, int(len(sorted_ms) * p / 100))
    return sorted_ms[idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--miss", type=int, default=2000, help="未命中查询采样数")
    ap.add_argument("--hits", type=int, default=200, help="命中查询采样数")
    args = ap.parse_args()
    random.seed(2026)

    print("=" * 62)

    # ---------- 启动 (含 Bloom 加载/重建) ----------
    t0 = time.time()
    db = HashSignatureDB(DB_PATH)
    init_s = time.time() - t0
    # 无 Bloom 文件或与签名数不匹配时, 构建并持久化 (一次性开销)
    build_status = db.finalize()
    if build_status:
        print(f"[bench] Bloom 构建 : {build_status}")
    st = db.stats()
    print(f"[bench] 签名总数 : {st['count']:,}")
    print(f"[bench] 启动耗时 : {init_s:.2f}s (含 Bloom 加载)")
    print(f"[bench] 存储层   : {st['tier']}")
    print(f"[bench] SQLite   : {st['db_size_mb']} MB 磁盘")
    if st["bloom"]:
        b = st["bloom"]
        print(f"[bench] Bloom    : {b['shards_loaded']}/{b['shards_configured']} 分片已加载 "
              f"({b['mem_mb']} MB), k={b['hash_funcs']}, fp={b['fp_rate']}")
    if st.get("mem_arrays"):
        print(f"[bench] 排序数组 : {st['mem_arrays']}")
    if st.get("shards"):
        sh = st["shards"]
        print(f"[bench] 分片     : {sh['total']} 个 SQLite 库, "
              f"当前已加载 {sh['open_conns']}/{sh['max_open']} 连接")

    # ---------- 未命中延迟 (干净文件路径: Bloom 短路) ----------
    miss_ms = []
    for _ in range(args.miss):
        r = os.urandom(48)
        import hashlib
        m5, s1, s2 = (hashlib.md5(r).hexdigest(),
                      hashlib.sha1(r).hexdigest(),
                      hashlib.sha256(r).hexdigest())
        t = time.perf_counter()
        db.check("", 12345, m5, s1, s2)
        miss_ms.append((time.perf_counter() - t) * 1000)
    miss_ms.sort()
    print(f"[bench] 未命中(干净文件) : avg {sum(miss_ms)/len(miss_ms):.3f} ms | "
          f"p50 {pct(miss_ms,50):.3f} | p95 {pct(miss_ms,95):.3f}")

    # ---------- 命中延迟 (报毒文件路径: Bloom 通过 + 分片点查) ----------
    # 从随机分片中采样真实签名
    shard_files = [
        f for f in os.listdir(db.shard_dir)
        if len(f) == 7 and f.endswith(".db") and f[:-3].isdigit()
    ]
    sample_rows = []
    random.shuffle(shard_files)
    for sf in shard_files:
        conn = db._ro_conn(int(sf[:-3]))
        if conn is None:
            continue
        sample_rows.extend(conn.execute(
            "SELECT sha256, size FROM sigs LIMIT ?", (args.hits,)
        ).fetchall())
        if len(sample_rows) >= args.hits:
            break
    sample_rows = sample_rows[:args.hits]
    hit_ms = []
    n_hit = 0
    for h, size in sample_rows:  # v3: 库内全为 sha256 (32B)
        hexh = h.hex()
        t = time.perf_counter()
        hits = db.check("", size, "0" * 32, "0" * 40, hexh)
        hit_ms.append((time.perf_counter() - t) * 1000)
        n_hit += len(hits)
    hit_ms.sort()
    print(f"[bench] 命中(报毒文件)   : avg {sum(hit_ms)/len(hit_ms):.3f} ms | "
          f"p50 {pct(hit_ms,50):.3f} | p95 {pct(hit_ms,95):.3f} | 验证命中 {n_hit}/{len(sample_rows)}")

    # ---------- 端到端 (含读文件+三哈希+YARA) ----------
    clean_path = os.path.join(BASE_DIR, "uploads", "clean.txt")
    if os.path.exists(clean_path):
        from scanner import YaraScanner
        ys = YaraScanner()
        ys.load_rules(os.path.join(BASE_DIR, "signatures", "rules.yar"))
        scanner = Scanner(db, ys)
        e2e = []
        for _ in range(30):
            t = time.perf_counter()
            r = scanner.scan_file(clean_path)
            e2e.append((time.perf_counter() - t) * 1000)
        e2e.sort()
        print(f"[bench] 端到端扫描(小文件): avg {sum(e2e)/len(e2e):.2f} ms | "
              f"verdict={r['verdict']}")

    # ---------- 进程内存 ----------
    try:
        import resource
        rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        print(f"[bench] 进程峰值内存    : {rss_mb:.1f} MB")
    except ImportError:
        pass  # Windows 无 resource 模块, 由外部任务管理器观测

    print("=" * 62)
    db.close()


if __name__ == "__main__":
    main()
