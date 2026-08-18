"""
NKAMG Scanner - 千万级合成签名生成器
用确定性随机摘要快速填充 sha256.db, 用于大规模压测。

用法:
  python gen_sigs.py --n 10000000            # 生成 1000 万条 (全部 SHA256, 与库 v3 主键一致)
  python gen_sigs.py --n 1000000 --seed 42
"""
import argparse
import hashlib
import os
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "signatures", "sha256.db")


def gen_digests(n, seed):
    """确定性生成 n 条签名: (digest_bytes, size, name); 全部为 SHA256 (库 v3 主键)"""
    for i in range(n):
        data = f"{seed}:{i}".encode()
        digest = hashlib.sha256(data).digest()      # 32B sha256 主键
        yield (digest, 100 + (i % 900), f"Test.Gen.{seed}.{i:09d}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000_000, help="生成签名条数")
    ap.add_argument("--seed", type=int, default=1, help="随机种子 (决定摘要内容)")
    ap.add_argument("--batch", type=int, default=100_000)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")  # 批量导入期间关闭同步, 结束恢复
    con.execute("PRAGMA cache_size=-131072")
    con.execute(
        "CREATE TABLE IF NOT EXISTS sigs("
        " h BLOB PRIMARY KEY, size INTEGER, name TEXT) WITHOUT ROWID"
    )
    con.execute("CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)")

    before = con.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
    print(f"[gen] 现有签名: {before:,} 条, 开始生成 {args.n:,} 条 ...")

    t0 = time.time()
    buf = []
    inserted = 0
    for row in gen_digests(args.n, args.seed):
        buf.append(row)
        if len(buf) >= args.batch:
            con.executemany(
                "INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)", buf
            )
            inserted += len(buf)
            buf.clear()
            if inserted % 1_000_000 == 0:
                elapsed = time.time() - t0
                print(f"[gen] 已写入 {inserted:,} ({elapsed:.0f}s, "
                      f"{inserted / elapsed:,.0f} rows/s)")
    if buf:
        con.executemany("INSERT OR IGNORE INTO sigs(h,size,name) VALUES(?,?,?)", buf)
        inserted += len(buf)
    con.commit()
    con.execute("PRAGMA synchronous=NORMAL")

    after = con.execute("SELECT COUNT(*) FROM sigs").fetchone()[0]
    elapsed = time.time() - t0
    print(f"[gen] 完成: 写入 {inserted:,} 条, 耗时 {elapsed:.1f}s "
          f"({inserted / elapsed:,.0f} rows/s)")
    print(f"[gen] 库内签名总数: {after:,}")
    print(f"[gen] DB 路径: {DB_PATH}")
    con.close()


if __name__ == "__main__":
    main()
