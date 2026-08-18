#!/usr/bin/env python
"""构建模糊哈希增强库 (FuzzySignatureDB) — 与 SHA256/MD5 库并列的第三库。

数据源: hdb/ 下 ClamAV 官方 hdb 分桶文件 (00.hdb ~ ff.hdb, 256 个)。
行格式 (8 字段):
  sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash

提取其中 5 个模糊哈希字段 (ssdeep/vhash/authentihash/imphash/rich_header_hash),
表结构参考 sha256/md5 库: sigs(sha256 BLOB PRIMARY KEY, size, name,
  ssdeep TEXT, vhash/authentihash/imphash/rich_header_hash BLOB) WITHOUT ROWID
只存**至少一个模糊字段非空**的行 (无 fuzzy 信息的行仅存在于 sha256 库即可)。

幂等导入 signatures/fuzzy.db 分片 (shard_count=4) + 重建 bloom。
增量更新: 重新下载 hdb 分桶后重跑本脚本, 仅新增 sha256 主键行入库 (INSERT OR IGNORE)。
用法: python build_fuzzy_db.py
"""
import glob
import os
import sys

from scanner import FuzzySignatureDB

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "signatures", "fuzzy.db")
HDB_DIR = os.path.join(HERE, "hdb")


def main():
    files = sorted(glob.glob(os.path.join(HDB_DIR, "*.hdb")))
    if not files:
        print(f"[NKAMG][FUZZY] 未找到 hdb 文件: {HDB_DIR}")
        sys.exit(1)
    print(f"[NKAMG][FUZZY] 数据源: {len(files)} 个分桶 hdb 文件 ({HDB_DIR})")
    db = FuzzySignatureDB(DB, shard_count=4)
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
    st = db.finalize()
    print(f"[NKAMG][FUZZY] bloom 重建: {st}")
    print(f"[NKAMG][FUZZY] stats: {db.stats()}")
    db.close()
    print("[NKAMG][FUZZY] 完成")


if __name__ == "__main__":
    main()
