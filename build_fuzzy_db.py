#!/usr/bin/env python
"""构建模糊哈希签名库 (FuzzySignatureDB) — 5 表独立结构。

数据源: hdb/ 下 ClamAV 官方 hdb 分桶文件 (00.hdb ~ ff.hdb, 256 个)。
行格式 (8 字段):
  sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash

每种 fuzzy hash 独立成表, 以 fuzzy hash 本身为主键:
  sigs_ssdeep(ssdeep TEXT PK, size, name, sha256 BLOB)
  sigs_vhash(vhash BLOB PK, size, name, sha256 BLOB)
  sigs_authentihash(authentihash BLOB PK, size, name, sha256 BLOB)
  sigs_imphash(imphash BLOB PK, size, name, sha256 BLOB)
  sigs_rich_header_hash(rich_header_hash BLOB PK, size, name, sha256 BLOB)

每个非空 fuzzy 字段按自身值路由到 00~ff 分片, 写入对应表。
256 hex 分片 (layout=hex), 每个分片文件含 5 张表。

幂等导入: INSERT OR IGNORE 去重, 重跑仅新增。
用法: python build_fuzzy_db.py
"""
import argparse
import glob
import os
import sys

from scanner import FuzzySignatureDB

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "signatures", "fuzzy.db")
HDB_DIR = os.path.join(HERE, "hdb")


def main():
    ap = argparse.ArgumentParser(description="构建模糊哈希签名库 (5 表独立结构)")
    ap.add_argument("--hdb-dir", default=HDB_DIR,
                    help=f"hdb 分桶文件目录 (默认: {HDB_DIR})")
    args = ap.parse_args()
    hdb_dir = args.hdb_dir

    files = sorted(glob.glob(os.path.join(hdb_dir, "*.hdb")))
    if not files:
        print(f"[NKAMG][FUZZY] 未找到 hdb 文件: {hdb_dir}")
        sys.exit(1)
    print(f"[NKAMG][FUZZY] 数据源: {len(files)} 个分桶 hdb 文件 ({hdb_dir})")
    db = FuzzySignatureDB(DB, layout="hex")
    added_total = 0
    for p in files:
        if db.already_imported(os.path.basename(p)):
            continue  # 幂等: 已导入过的分桶跳过
        before = db.count
        n = db.import_hdb(p)
        print(f"[NKAMG][FUZZY] {os.path.basename(p)}: +{n:,} 条 "
              f"(累计 {db.count:,}, 耗时见总计时)")
        added_total += n
    print(f"\n[NKAMG][FUZZY] 本次新增 {added_total:,} 条, 库总条数 {db.count:,}")
    print(f"[NKAMG][FUZZY] 各类型计数: {db._counts}")
    st = db.finalize()
    print(f"[NKAMG][FUZZY] bloom 重建: {st}")
    print(f"[NKAMG][FUZZY] stats: {db.stats()}")
    db.close()
    print("[NKAMG][FUZZY] 完成")


if __name__ == "__main__":
    main()
