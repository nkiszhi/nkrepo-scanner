"""测试 Bloom shard 驱动的动态分片: 任意 N 路由 / 重分片保持命中 / Bloom 分片懒加载"""
import os
import shutil
import sys
import tempfile

from scanner import HashSignatureDB

TEST_HASHES = [
    # sha256 (库 v3 起仅接受 SHA256 主键; 测试约定: 不使用 EICAR 文件, 全部用自造签名)
    ("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 32, "Test.SHA256.c"),
    ("00000abcdeadbeef000000000000000000000000000000000000000000000123", 50, "Test.SHA256.a"),
    (("fffffabcdeadbeef" + "f" * 62)[:61] + "456", 60, "Test.SHA256.b"),
]


def write_hdb(path):
    with open(path, "w") as f:
        for h, size, name in TEST_HASHES:
            f.write(f"{h}:{size}:{name}\n")


def verify(db, tag):
    ok = True
    for h, size, name in TEST_HASHES:
        hits = db.check("", size, "0" * 32, "0" * 40, h)
        if not any(x["name"] == name for x in hits):
            print(f"  [FAIL] {tag} 未命中 {name} ({h[:8]}...)")
            ok = False
    r = os.urandom(32)
    if db.check("", 1, "0" * 32, "0" * 40, r.hex()):
        print(f"  [FAIL] {tag} 随机哈希误命中")
        ok = False
    print(f"  [{'PASS' if ok else 'FAIL'}] {tag}: {len(TEST_HASHES)} 命中 + 无误报")
    return ok


def main():
    tmp = tempfile.mkdtemp(prefix="nkrepo_shard_test_")
    db_path = os.path.join(tmp, "test.db")
    hdb = os.path.join(tmp, "in.hdb")
    write_hdb(hdb)

    all_ok = True
    # 任意 N: 16 / 64 / 256 / 512 (含非 16 的幂, 验证 modulo 路由)
    for shard_count in (256, 64, 512, 16, 256):  # 最后切回默认
        print(f"\n=== bloom.shards = {shard_count} ===")
        db = HashSignatureDB(db_path, shard_count=shard_count)
        if shard_count == 256 and db.count == 0:
            added = db.import_hdb(hdb)
            print(f"  导入 {added} 条")
        st = db.finalize()
        if st:
            print(f"  重建 bloom: {st}")
        st = db.stats()
        print(f"  count={db.count}, 分片文件={st['shards']['total']}, "
              f"open_sqlite={st['shards']['open_conns']}, "
              f"loaded_bloom={st['bloom']['shards_loaded'] if st['bloom'] else 0}, "
              f"tier={st['tier']}")
        all_ok &= verify(db, f"shards={shard_count}")
        # 校验分片文件名统一为 4 位十进制 (modulo 布局)
        files = db._layout_shard_files()
        bad = [f for f in files if len(f) != 7 or not f[:-3].isdigit()]
        if bad:
            print(f"  [FAIL] 布局文件名异常: {bad[:3]}")
            all_ok = False
        # Bloom 分片懒加载: 冷启动后应 0 个已加载 bloom
        db2 = HashSignatureDB(db_path, shard_count=shard_count)
        st2 = db2.stats()
        if st2["bloom"] and st2["bloom"]["shards_loaded"] != 0:
            print(f"  [FAIL] 冷启动应 0 个 bloom 加载, 实际 {st2['bloom']['shards_loaded']}")
            all_ok = False
        # sha256 单次点查短路: 命中样本查询后只加载其所在分片 (1 个), 且命中 1 条
        probe_h, probe_size, probe_name = TEST_HASHES[0]
        hits = db2.check("", probe_size, "0" * 32, "0" * 40, probe_h)
        st2 = db2.stats()
        loaded = st2["bloom"]["shards_loaded"] if st2["bloom"] else 0
        if loaded != 1:
            print(f"  [FAIL] sha256 短路后应只加载 1 个 bloom 分片, 实际 {loaded}")
            all_ok = False
        if len(hits) != 1:
            print(f"  [FAIL] {probe_name} 应命中 1 条, 实际 {len(hits)}")
            all_ok = False
        print(f"  sha256 单次点查: 命中 {len(hits)} 条, 已加载 bloom 分片 {loaded}/1 ✓")
        db2.close()
        db.close()

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + ("ALL PASS" if all_ok else "SOME FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
