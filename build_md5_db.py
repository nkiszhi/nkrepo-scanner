#!/usr/bin/env python
"""构建/更新 MD5 独立分片库 (与 SHA256 库并列)。

数据源: extracted/ 下 ClamAV CVD 解包的整文件哈希文件 (.hdb/.hsb)。
  - main.main.hdb / main.main.hsb    (main 库, 周级更新)
  - daily.daily.hdb / daily.daily.hsb (daily 库, 日级更新, 由 extract_cvd.py 解包)
仅提取 32hex (MD5) 行, 经参数化 HashSignatureDB(hash_algo="md5")
幂等导入 signatures/md5.db 分片 (shard_count=4) + 重建 bloom。

增量更新: 下载最新 daily.cvd 并解包后重跑本脚本, 仅新增行入库 (INSERT OR IGNORE)。
用法: python build_md5_db.py
"""
import os

from scanner import HashSignatureDB

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "signatures", "md5.db")
SOURCES = [
    "extracted/main.main.hdb",
    "extracted/main.main.hsb",
    "extracted/daily.daily.hdb",
    "extracted/daily.daily.hsb",
]


def main():
    db = HashSignatureDB(DB, shard_count=4, hash_algo="md5")
    added_total = 0
    for src in SOURCES:
        p = os.path.join(HERE, src)
        if not os.path.exists(p):
            print(f"[NKAMG][MD5] 跳过(缺失): {src}")
            continue
        before = db.count
        n = db.import_hdb(p)
        print(f"[NKAMG][MD5] {src}: +{n:,} 条 (累计 {db.count:,})")
        added_total += n
    print(f"\n[NKAMG][MD5] 本次新增 {added_total:,} 条, 库总条数 {db.count:,}")
    st = db.finalize()
    print(f"[NKAMG][MD5] bloom 重建: {st}")
    print(f"[NKAMG][MD5] stats: {db.stats()}")
    db.close()
    print("[NKAMG][MD5] 完成")


if __name__ == "__main__":
    main()
