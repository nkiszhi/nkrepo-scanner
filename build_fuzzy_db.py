#!/usr/bin/env python
"""构建模糊哈希签名库 (FuzzySignatureDB) + SSDeep 独立库 (SsdeepLibrary)。

数据源: hdb/ 下 ClamAV 官方 hdb 分桶文件 (00.hdb ~ ff.hdb, 256 个)。
行格式 (8 字段):
  sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash

FuzzySignatureDB (4 表, 256 hex 分片, bloom filter):
  sigs_vhash(vhash BLOB PK, size, name, sha256 BLOB)
  sigs_authentihash(authentihash BLOB PK, size, name, sha256 BLOB)
  sigs_imphash(imphash BLOB PK, size, name, sha256 BLOB)
  sigs_rich_header_hash(rich_header_hash BLOB PK, size, name, sha256 BLOB)

SsdeepLibrary (单文件 SQLite, 无 bloom, 无分片):
  ssdeep_entries(ssdeep TEXT PK, sha256 BLOB, size, name)
  sha256 存为 BLOB 二进制 (32 字节), 节省 50% 存储空间。

幂等导入: INSERT OR IGNORE 去重, 重跑仅新增。
用法: python build_fuzzy_db.py
"""
import argparse
import glob
import os
import sys

from scanner import FuzzySignatureDB, SsdeepLibrary

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "signatures", "fuzzy.db")
SSDEEP_DB = os.path.join(HERE, "signatures", "ssdeep_library.db")
HDB_DIR = os.path.join(HERE, "hdb")


def main():
    ap = argparse.ArgumentParser(description="构建模糊哈希签名库 (4 表 + SSDeep 独立库)")
    ap.add_argument("--hdb-dir", default=HDB_DIR,
                    help=f"hdb 分桶文件目录 (默认: {HDB_DIR})")
    args = ap.parse_args()
    hdb_dir = args.hdb_dir

    files = sorted(glob.glob(os.path.join(hdb_dir, "*.hdb")))
    if not files:
        print(f"[NKAMG][FUZZY] 未找到 hdb 文件: {hdb_dir}")
        sys.exit(1)
    print(f"[NKAMG][FUZZY] 数据源: {len(files)} 个分桶 hdb 文件 ({hdb_dir})")

    # 1. FuzzySignatureDB (4 表: vhash/authentihash/imphash/rich_header_hash)
    db = FuzzySignatureDB(DB, layout="hex")
    added_total = 0
    for p in files:
        if db.already_imported(os.path.basename(p)):
            continue
        before = db.count
        n = db.import_hdb(p)
        print(f"[NKAMG][FUZZY] {os.path.basename(p)}: +{n:,} 条 "
              f"(累计 {db.count:,})")
        added_total += n
    print(f"\n[NKAMG][FUZZY] FuzzyDB 本次新增 {added_total:,} 条, 库总条数 {db.count:,}")
    print(f"[NKAMG][FUZZY] 各类型计数: {db._counts}")
    st = db.finalize()
    print(f"[NKAMG][FUZZY] bloom 重建: {st}")
    print(f"[NKAMG][FUZZY] FuzzyDB stats: {db.stats()}")
    db.close()

    # 2. SsdeepLibrary (单文件, 无 bloom, sha256 存 BLOB)
    ssdeep_lib = SsdeepLibrary(SSDEEP_DB)
    ssdeep_added = 0
    for p in files:
        if ssdeep_lib.already_imported(os.path.basename(p)):
            continue
        n = ssdeep_lib.import_hdb(p)
        print(f"[NKAMG][SSDEEP] {os.path.basename(p)}: +{n:,} 条 "
              f"(累计 {ssdeep_lib.count:,})")
        ssdeep_added += n
    print(f"\n[NKAMG][SSDEEP] SsdeepLibrary 本次新增 {ssdeep_added:,} 条, "
          f"库总条数 {ssdeep_lib.count:,}")
    print(f"[NKAMG][SSDEEP] stats: {ssdeep_lib.stats()}")
    ssdeep_lib.close()

    print("[NKAMG] 完成")


if __name__ == "__main__":
    main()
