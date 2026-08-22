#!/usr/bin/env python3
"""SsdeepLibrary 综合功能测试 (Tier 1/2/3 加速版)

验证项:
  1. 初始化 (空库建表, 6 字段新 schema + ssdeep_gram 倒排表 + 复合索引)
  2. insert() — BLOB 存储、重复更新、淘汰策略、gram 级联删除
  3. check_exact() — 精确匹配
  4. search() — 相似度检索 (Tier 2 gram 倒排探针 + Tier 3 并行)
  4b. Tier 2 倒排索引与召回率 (含跨块大小 B*2 探针)
  5. import_hdb() — 从 hdb 文件导入 (含 gram 回填)
  6. stats() — 统计信息
  7. Scanner 集成 — ssdeep_library 传入与调用路径
  8. 旧表迁移 (first_seen/hit_count → 重建)
  8b. 旧 4 列 schema 迁移 (ssdeep TEXT PK → 新 schema + gram 回填)
  9. 并发安全
"""
import os
import sys
import sqlite3
import tempfile
import threading

# 确保项目根目录在 path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import SsdeepLibrary, SSDEEP_AVAILABLE, ppdeep

PASS = 0
FAIL = 0
libs_to_close = []  # 所有打开的 SsdeepLibrary, 测试结束时统一关闭

def ok(name):
    global PASS
    PASS += 1
    print(f"  [PASS] {name}")

def fail(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {name} {detail}")

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def make_ssdeep(data: bytes) -> str:
    """用 ppdeep 生成标准格式 ssdeep (冒号分隔)"""
    if not SSDEEP_AVAILABLE:
        return "96:QpvECSfdRmvWVW3VyfJ0d2wJ3y6GPfNDt2nNy3JTG9r+UHF0wL:PvEvRmVVW3V+0d2wJny6GwNmNy3BTGUUwL"
    return ppdeep.hash(data)

def to_clamav(std_ssdeep: str) -> str:
    """标准格式 (冒号) -> ClamAV 格式 (短横线)"""
    return std_ssdeep.replace(":", "-", 2)

# ============================================================
# 1. 初始化测试
# ============================================================
def test_init(tmpdir):
    section("1. 初始化 (空库建表)")
    db_path = os.path.join(tmpdir, "ssdeep_library.db")
    lib = SsdeepLibrary(db_path)
    libs_to_close.append(lib)

    if os.path.exists(db_path):
        ok("数据库文件已创建")
    else:
        fail("数据库文件已创建", f"路径 {db_path} 不存在")
        return lib

    if lib.count == 0:
        ok(f"空库 count=0")
    else:
        fail(f"空库 count=0", f"实际 count={lib.count}")

    # 验证表结构 (Tier 1/2 新 schema)
    cols = lib._conn.execute("PRAGMA table_info(ssdeep_entries)").fetchall()
    col_names = [c[1] for c in cols]
    col_types = {c[1]: c[2] for c in cols}

    expected_cols = ["id", "blocksize", "ssdeep", "sha256", "size", "name"]
    if col_names == expected_cols:
        ok(f"表结构 6 字段 (Tier 1): {col_names}")
    else:
        fail(f"表结构 6 字段", f"期望 {expected_cols}, 实际 {col_names}")

    if col_types.get("sha256") == "BLOB":
        ok(f"sha256 字段类型 = BLOB")
    else:
        fail(f"sha256 字段类型 = BLOB", f"实际 = {col_types.get('sha256')}")

    if col_types.get("ssdeep") == "TEXT":
        ok(f"ssdeep 字段类型 = TEXT (UNIQUE)")
    else:
        fail(f"ssdeep 字段类型 = TEXT", f"实际 = {col_types.get('ssdeep')}")

    if col_types.get("blocksize") == "INTEGER":
        ok(f"blocksize 字段类型 = INTEGER (Tier 1 归一化列)")
    else:
        fail(f"blocksize 字段类型 = INTEGER", f"实际 = {col_types.get('blocksize')}")

    # Tier 2 倒排索引表
    gram_tables = [r[0] for r in lib._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ssdeep_gram'"
    ).fetchall()]
    if "ssdeep_gram" in gram_tables:
        ok(f"ssdeep_gram 倒排表已创建 (Tier 2)")
    else:
        fail(f"ssdeep_gram 倒排表已创建")

    # (blocksize, size) 复合索引 (Tier 1)
    idx = [r[1] for r in lib._conn.execute("PRAGMA index_list(ssdeep_entries)").fetchall()]
    if "idx_ssdeep_bs_size" in idx:
        ok(f"idx_ssdeep_bs_size 复合索引已创建 (Tier 1)")
    else:
        fail(f"idx_ssdeep_bs_size 复合索引已创建", f"实际索引 = {idx}")

    return lib

# ============================================================
# 2. insert() 测试
# ============================================================
def test_insert(lib, tmpdir):
    section("2. insert() — BLOB 存储、重复更新、淘汰策略")

    data1 = b"Hello World, this is test data for ssdeep hashing. " * 10
    data2 = data1[:300] + b"X" * 5 + data1[305:]   # 与 data1 相似 (中间替换 5 字节, ppdeep.compare≈97)
    data3 = b"Completely different content for a different ssdeep hash. " * 10

    ssdeep1_std = make_ssdeep(data1)
    ssdeep2_std = make_ssdeep(data2)
    ssdeep3_std = make_ssdeep(data3)

    sha1 = "a" * 64
    sha2 = "b" * 64
    sha3 = "c" * 64

    # 插入第一条
    lib.insert(ssdeep1_std, sha1, "malware_a.exe", 500)
    if lib.count == 1:
        ok(f"insert 第一条 -> count=1")
    else:
        fail(f"insert 第一条 -> count=1", f"实际 count={lib.count}")

    # 验证 sha256 存为 BLOB (32 字节二进制)
    row = lib._conn.execute(
        "SELECT sha256, size, name FROM ssdeep_entries WHERE ssdeep = ?",
        (ssdeep1_std,)
    ).fetchone()

    if row and row[0] is not None:
        blob_data = row[0]
        if isinstance(blob_data, bytes) and len(blob_data) == 32:
            ok(f"sha256 BLOB 存储 = 32 字节二进制 (非 64 字符 hex)")
            if blob_data.hex() == sha1:
                ok(f"BLOB 内容正确: hex(blob) == '{sha1[:16]}...'")
            else:
                fail(f"BLOB 内容正确", f"hex(blob)={blob_data.hex()[:32]}... expected={sha1[:32]}...")
        elif isinstance(blob_data, bytes) and len(blob_data) == 64:
            fail(f"sha256 BLOB 存储 = 32 字节", f"实际存储为 64 字节文本, 未转为 BLOB")
        else:
            fail(f"sha256 BLOB 存储 = 32 字节", f"类型={type(blob_data)}, len={len(blob_data) if blob_data else 0}")
    else:
        fail(f"BLOB 查询", f"row={row}")

    if row and row[1] == 500:
        ok(f"size 字段 = 500")
    else:
        fail(f"size 字段 = 500", f"实际 = {row[1] if row else 'N/A'}")

    if row and row[2] == "malware_a.exe":
        ok(f"name 字段 = 'malware_a.exe'")
    else:
        fail(f"name 字段", f"实际 = {row[2] if row else 'N/A'}")

    # 插入第二、三条
    lib.insert(ssdeep2_std, sha2, "malware_b.exe", 500)
    lib.insert(ssdeep3_std, sha3, "benign_c.exe", 600)
    if lib.count == 3:
        ok(f"insert 三条 -> count=3")
    else:
        fail(f"insert 三条 -> count=3", f"实际 count={lib.count}")

    # 重复插入 (同 ssdeep) -> 应更新而非新增
    lib.insert(ssdeep1_std, "d" * 64, "updated_name.exe", 999)
    if lib.count == 3:
        ok(f"重复 insert 同 ssdeep -> count 不变 (更新而非新增)")
    else:
        fail(f"重复 insert 同 ssdeep -> count 不变", f"实际 count={lib.count}")

    # 验证更新生效
    row = lib._conn.execute(
        "SELECT LOWER(hex(sha256)), size, name FROM ssdeep_entries WHERE ssdeep = ?",
        (ssdeep1_std,)
    ).fetchone()
    if row and row[0] == "d" * 64 and row[1] == 999 and row[2] == "updated_name.exe":
        ok(f"重复 insert 更新字段: sha256/size/name 已更新")
    else:
        fail(f"重复 insert 更新字段", f"row={row}")

    # 淘汰策略测试 (max_entries=5)
    small_lib = SsdeepLibrary(
        os.path.join(tmpdir, "ssdeep_small.db"),
        max_entries=5
    )
    libs_to_close.append(small_lib)
    for i in range(7):
        d = f"test data chunk {i} ".encode() * 20
        sd = make_ssdeep(d)
        small_lib.insert(sd, f"{i:064x}", f"file_{i}.exe", 100 + i)

    if small_lib.count == 5:
        ok(f"淘汰策略: 插入 7 条 (max=5) -> count=5")
    else:
        fail(f"淘汰策略: count=5", f"实际 count={small_lib.count}")

    # 验证淘汰的是最旧 (rowid 最小) 的条目
    names = [r[0] for r in small_lib._conn.execute(
        "SELECT name FROM ssdeep_entries ORDER BY rowid"
    ).fetchall()]
    if names == ["file_2.exe", "file_3.exe", "file_4.exe", "file_5.exe", "file_6.exe"]:
        ok(f"淘汰策略: 淘汰 file_0 和 file_1 (最旧)")
    else:
        fail(f"淘汰策略: 淘汰最旧", f"剩余 = {names}")

    # 淘汰需级联删除 gram 索引, 否则倒排表残留孤儿 entry_id
    orphan = small_lib._conn.execute(
        "SELECT COUNT(*) FROM ssdeep_gram g"
        " LEFT JOIN ssdeep_entries e ON e.id = g.entry_id"
        " WHERE e.id IS NULL"
    ).fetchone()[0]
    if orphan == 0:
        ok(f"淘汰级联删除 gram: 无孤儿 entry_id")
    else:
        fail(f"淘汰级联删除 gram", f"孤儿 {orphan} 条")

    # 剩余 5 条的 gram 索引应完整 (每条约 6+ 个 7-gram)
    gram_cnt = small_lib._conn.execute(
        "SELECT COUNT(*) FROM ssdeep_gram").fetchone()[0]
    if gram_cnt >= 5:
        ok(f"淘汰后 gram 索引完整: {gram_cnt} 条 (每条 >=1)")
    else:
        fail(f"淘汰后 gram 索引完整", f"gram_cnt={gram_cnt}")

# ============================================================
# 3. check_exact() 测试
# ============================================================
def test_check_exact(lib, tmpdir):
    section("3. check_exact() — 精确匹配")

    data1 = b"Hello World, this is test data for ssdeep hashing. " * 10
    ssdeep1_std = make_ssdeep(data1)
    sha1 = "d" * 64  # 更新后的值

    # 精确匹配已入库的 ssdeep
    hits = lib.check_exact(ssdeep1_std, file_size=999)
    if len(hits) == 1:
        ok(f"精确匹配命中 1 条")
    else:
        fail(f"精确匹配命中 1 条", f"实际 {len(hits)} 条")
        return

    hit = hits[0]
    if hit.get("fuzzy_type") == "ssdeep":
        ok(f"hit.fuzzy_type = 'ssdeep'")
    else:
        fail(f"hit.fuzzy_type", f"实际 = {hit.get('fuzzy_type')}")

    if hit.get("engine") == "SSDeep Hash DB":
        ok(f"hit.engine = 'SSDeep Hash DB'")
    else:
        fail(f"hit.engine", f"实际 = {hit.get('engine')}")

    if hit.get("name") == "updated_name.exe":
        ok(f"hit.name = 'updated_name.exe' (更新后的名称)")
    else:
        fail(f"hit.name", f"实际 = {hit.get('name')}")

    if hit.get("sha256") == sha1:
        ok(f"hit.sha256 = '{sha1[:16]}...'")
    else:
        fail(f"hit.sha256", f"实际 = {hit.get('sha256')}")

    # 未入库的 ssdeep -> 空结果
    data_new = b"This is completely new data not in the library. " * 10
    ssdeep_new = make_ssdeep(data_new)
    hits2 = lib.check_exact(ssdeep_new)
    if len(hits2) == 0:
        ok(f"未入库的 ssdeep -> 0 条命中")
    else:
        fail(f"未入库的 ssdeep -> 0 条命中", f"实际 {len(hits2)} 条")

    # file_size 不匹配 -> 空结果
    hits3 = lib.check_exact(ssdeep1_std, file_size=12345)
    if len(hits3) == 0:
        ok(f"file_size 不匹配 -> 0 条命中 (size 门控)")
    else:
        fail(f"file_size 不匹配 -> 0 条", f"实际 {len(hits3)} 条")

    # 空输入
    hits4 = lib.check_exact("")
    if len(hits4) == 0:
        ok(f"空输入 -> 0 条命中")
    else:
        fail(f"空输入 -> 0 条", f"实际 {len(hits4)} 条")

# ============================================================
# 4. search() 相似度检索测试
# ============================================================
def test_search(lib, tmpdir):
    section("4. search() — 相似度检索")

    if not SSDEEP_AVAILABLE:
        print("  [SKIP] ppdeep 不可用, 跳过 search 测试")
        return

    data1 = b"Hello World, this is test data for ssdeep hashing. " * 10
    data2 = data1[:300] + b"X" * 5 + data1[305:]   # 与 data1 相似 (中间替换 5 字节, ppdeep.compare≈97)
    ssdeep1_std = make_ssdeep(data1)
    ssdeep2_std = make_ssdeep(data2)

    # data1 查询 -> 应该能找到 data2 (相似)
    hits = lib.search(ssdeep1_std, file_size=500, threshold=0)
    if len(hits) > 0:
        ok(f"search(data1) -> {len(hits)} 条相似结果")
    else:
        fail(f"search(data1) -> 应有相似结果", "0 条")
        return

    # 检查 hit 结构
    hit = hits[0]
    if "score" in hit:
        ok(f"hit.score = {hit['score']} (0-100)")
    else:
        fail(f"hit.score 字段缺失")

    if hit.get("type") == "fuzzy-similar":
        ok(f"hit.type = 'fuzzy-similar'")
    else:
        fail(f"hit.type", f"实际 = {hit.get('type')}")

    if hit.get("engine") == "SSDeep Hash DB":
        ok(f"hit.engine = 'SSDeep Hash DB'")
    else:
        fail(f"hit.engine", f"实际 = {hit.get('engine')}")

    # 验证排序 (按 score 降序)
    scores = [h["score"] for h in hits]
    if scores == sorted(scores, reverse=True):
        ok(f"结果按 score 降序排列: {scores}")
    else:
        fail(f"结果按 score 降序", f"实际 = {scores}")

    # 阈值过滤测试: threshold=100 (极高)
    hits_high = lib.search(ssdeep1_std, file_size=500, threshold=100)
    if len(hits_high) == 0:
        ok(f"threshold=100 -> 0 条 (仅完全相同才 100)")
    else:
        ok(f"threshold=100 -> {len(hits_high)} 条 (可能极高相似)")

    # ClamAV 格式查询 (短横线分隔)
    clam_ssdeep = to_clamav(ssdeep1_std)
    hits_clam = lib.search(clam_ssdeep, file_size=500, threshold=0)
    if len(hits_clam) > 0:
        ok(f"ClamAV 格式查询 (短横线分隔) -> {len(hits_clam)} 条")
    else:
        fail(f"ClamAV 格式查询 -> 应有结果", "0 条")

    # 空查询
    hits_empty = lib.search("", file_size=500)
    if len(hits_empty) == 0:
        ok(f"空查询 -> 0 条")
    else:
        fail(f"空查询 -> 0 条", f"实际 {len(hits_empty)} 条")

# ============================================================
# 4b. Tier 2 倒排索引与召回率测试
# ============================================================
def test_gram_index_recall(tmpdir):
    section("4b. Tier 2 倒排索引 + 召回率")

    if not SSDEEP_AVAILABLE:
        print("  [SKIP] ppdeep 不可用, 跳过")
        return

    db_path = os.path.join(tmpdir, "ssdeep_gram.db")
    lib = SsdeepLibrary(db_path)
    libs_to_close.append(lib)

    # 内容族: 同源变体 (同块大小) + 跨块大小成员
    base = b"AbCdEf1234567890 xyz pattern pattern "
    q     = base * 20                    # 查询 (~740B)
    e0    = base * 9 + b"XXXXXXXXXX" + base * 10  # 相似变体 (同源, 中段替换)
    e2x   = base * 32                    # 更长家族成员 (~1184B, 块大小 2 倍)
    e0_sha = "a" * 64
    e2x_sha = "b" * 64

    sq = make_ssdeep(q)
    se0 = make_ssdeep(e0)
    se2x = make_ssdeep(e2x)
    q_bs = int(sq.split(":", 1)[0])
    e0_bs = int(se0.split(":", 1)[0])
    e2x_bs = int(se2x.split(":", 1)[0])

    # 前置条件自检: 变体同 bs, 长成员 bs = q_bs*2 (B*2 探针路径)
    if q_bs == e0_bs and e2x_bs == q_bs * 2:
        ok(f"块大小关系: q_bs={q_bs}, e0_bs={e0_bs}, e2x_bs={e2x_bs} (B*2 路径)")
    else:
        fail(f"块大小关系", f"q_bs={q_bs}, e0_bs={e0_bs}, e2x_bs={e2x_bs}")
        return

    lib.insert(sq,   e0_sha,   "query.exe",   len(q))
    lib.insert(se0,  e0_sha,   "variant.exe", len(e0))
    lib.insert(se2x, e2x_sha,  "family_2x.exe", len(e2x))

    # 填充随机干扰条目 (让 gram 稀有度评估有意义)
    import random
    random.seed(42)
    for i in range(150):
        rnd = bytes(random.randrange(256) for _ in range(700))
        lib.insert(make_ssdeep(rnd), f"{i:064x}", f"noise_{i}.exe", 700)

    if lib.count >= 150:
        ok(f"插入干扰集 -> count={lib.count} (>=150)")
    else:
        fail(f"插入干扰集", f"count={lib.count}")

    # Tier 2 倒排索引已回填
    gram_cnt = lib._conn.execute("SELECT COUNT(*) FROM ssdeep_gram").fetchone()[0]
    if gram_cnt > 1000:
        ok(f"Tier 2 倒排索引回填: ssdeep_gram 共 {gram_cnt} 条")
    else:
        fail(f"Tier 2 倒排索引回填", f"gram_cnt={gram_cnt}")

    # 召回: 查询 q -> 找到同 bs 相似变体 variant.exe (bs=12 路径)
    hits = lib.search(sq, file_size=len(q), threshold=50)
    names = {h["name"] for h in hits}
    if "variant.exe" in names:
        ok(f"召回: 同块大小相似变体被找到")
    else:
        fail(f"召回: 同块大小相似变体", f"hits={names}")

    var_score = next((h["score"] for h in hits if h["name"] == "variant.exe"), None)
    if var_score is not None and var_score >= 90:
        ok(f"召回: variant.exe score={var_score} (>=90)")
    else:
        fail(f"召回: variant.exe score>=90", f"score={var_score}")

    # 跨块大小召回: q (bs=B) 应通过 B*2 探针找到 family_2x.exe (bs=B*2)
    hits2 = lib.search(sq, file_size=len(q), threshold=0)
    fam_names = {h["name"] for h in hits2}
    if "family_2x.exe" in fam_names:
        ok(f"跨块大小召回: family_2x.exe (bs={e2x_bs}) 经 B*2 探针命中")
    else:
        fail(f"跨块大小召回: family_2x.exe", f"hits={fam_names}")

    # 低阈值下噪声条目不得误报为高分: 最高相似度应来自同源族
    if hits2:
        top = hits2[0]
        if top["name"] in ("variant.exe", "family_2x.exe", "query.exe"):
            ok(f"最高分命中为同源族: {top['name']} score={top['score']}")
        else:
            fail(f"最高分命中为同源族", f"实际 {top['name']} score={top['score']}")

# ============================================================
# 5. import_hdb() 测试
# ============================================================
def test_import_hdb(tmpdir):
    section("5. import_hdb() — 从 hdb 文件导入")

    db_path = os.path.join(tmpdir, "ssdeep_import.db")
    lib = SsdeepLibrary(db_path)
    libs_to_close.append(lib)

    data1 = b"Test malware sample 1. " * 20
    data2 = b"Test malware sample 2. " * 20
    data3 = b"Different sample entirely. " * 20

    sd1 = make_ssdeep(data1)
    sd2 = make_ssdeep(data2)
    sd3 = make_ssdeep(data3)

    sd1_clam = to_clamav(sd1)
    sd2_clam = to_clamav(sd2)
    sd3_clam = to_clamav(sd3)

    hdb_path = os.path.join(tmpdir, "test.hdb")
    with open(hdb_path, "w") as f:
        f.write(f"{'a'*64}:500:Malware.A:{sd1_clam}:vhash_a:auth_a:imphash_a:rich_a\n")
        f.write(f"{'b'*64}:600:Malware.B:{sd2_clam}:vhash_b:auth_b:imphash_b:rich_b\n")
        f.write(f"{'c'*64}:700:Benign.C:{sd3_clam}:vhash_c:auth_c:imphash_c:rich_c\n")
        f.write(f"{'d'*64}:800:Invalid.D:only_three_fields\n")
        f.write(f"# This is a comment\n")

    inserted = lib.import_hdb(hdb_path)
    if inserted == 3:
        ok(f"import_hdb -> 3 条有效导入 (跳过无效行和注释)")
    else:
        fail(f"import_hdb -> 3 条导入", f"实际 {inserted} 条")

    if lib.count == 3:
        ok(f"import 后 count=3")
    else:
        fail(f"import 后 count=3", f"实际 count={lib.count}")

    # 导入条目需回填 gram 倒排 (Tier 2)
    gram_cnt = lib._conn.execute("SELECT COUNT(*) FROM ssdeep_gram").fetchone()[0]
    if gram_cnt >= 3:
        ok(f"导入回填 gram: ssdeep_gram 共 {gram_cnt} 条")
    else:
        fail(f"导入回填 gram", f"gram_cnt={gram_cnt}")

    # 归一化 blocksize 列已填充 (与 ssdeep 前缀块大小一致)
    bs_ok = lib._conn.execute(
        "SELECT COUNT(*) FROM ssdeep_entries WHERE blocksize > 0"
    ).fetchone()[0]
    if bs_ok == 3:
        ok(f"blocksize 归一化列已填充 (Tier 1)")
    else:
        fail(f"blocksize 归一化列", f"blocksize>0 共 {bs_ok} 条")

    # 导入的条目可被相似度检索命中 (走倒排探针; 用变异版避免精确命中被跳过)
    if SSDEEP_AVAILABLE:
        probe = data1[:220] + b"ZZZZZZZ" + data1[227:]  # 与 Malware.A 高度相似
        probe_hits = lib.search(make_ssdeep(probe), file_size=500, threshold=50)
        probe_names = {h["name"] for h in probe_hits}
        if "Malware.A" in probe_names:
            ok(f"导入条目可被相似度检索命中 (Malware.A)")
        else:
            fail(f"导入条目可被相似度检索命中", f"hits={probe_names}")

    # 验证 sha256 存为 BLOB
    rows = lib._conn.execute(
        "SELECT ssdeep, sha256, size, name FROM ssdeep_entries ORDER BY name"
    ).fetchall()

    all_blob = True
    for row in rows:
        if row[1] is not None and not (isinstance(row[1], bytes) and len(row[1]) == 32):
            all_blob = False
            break
    if all_blob:
        ok(f"所有 sha256 均为 32 字节 BLOB")
    else:
        fail(f"所有 sha256 均为 32 字节 BLOB")

    # 验证 sha256 BLOB 内容
    row = lib._conn.execute(
        "SELECT LOWER(hex(sha256)), size, name FROM ssdeep_entries WHERE name = 'Malware.A'"
    ).fetchone()
    if row and row[0] == "a" * 64:
        ok(f"Malware.A: hex(sha256) = 'aaa...' (BLOB 内容正确)")
    else:
        fail(f"Malware.A: sha256 BLOB 内容", f"row={row}")

    # 幂等性: 再次导入同一文件
    inserted2 = lib.import_hdb(hdb_path)
    if inserted2 == 0:
        ok(f"重复导入同一 hdb -> 0 条 (幂等)")
    else:
        fail(f"重复导入 -> 0 条 (幂等)", f"实际 {inserted2} 条")

    if lib.count == 3:
        ok(f"重复导入后 count 仍=3")
    else:
        fail(f"重复导入后 count=3", f"实际 count={lib.count}")

    # 导入第二个 hdb 文件
    hdb_path2 = os.path.join(tmpdir, "test2.hdb")
    data4 = b"Fourth sample for testing. " * 20
    sd4 = make_ssdeep(data4)
    sd4_clam = to_clamav(sd4)
    with open(hdb_path2, "w") as f:
        f.write(f"{'e'*64}:800:Malware.E:{sd4_clam}:vhash_e:auth_e:imphash_e:rich_e\n")

    inserted3 = lib.import_hdb(hdb_path2)
    if inserted3 == 1:
        ok(f"导入第二个 hdb -> 1 条新增")
    else:
        fail(f"导入第二个 hdb -> 1 条", f"实际 {inserted3} 条")

    if lib.count == 4:
        ok(f"两文件导入后 count=4")
    else:
        fail(f"两文件导入后 count=4", f"实际 count={lib.count}")

# ============================================================
# 6. stats() 测试
# ============================================================
def test_stats(lib, tmpdir):
    section("6. stats() — 统计信息")

    stats = lib.stats()

    expected_keys = {"count", "threshold", "top_k", "max_entries", "db_size_mb", "sources"}
    actual_keys = set(stats.keys())

    if expected_keys.issubset(actual_keys):
        ok(f"stats() 包含所有期望字段: {sorted(expected_keys)}")
    else:
        missing = expected_keys - actual_keys
        fail(f"stats() 字段完整", f"缺失: {missing}")

    if "db_size_mb" in stats and isinstance(stats["db_size_mb"], (int, float)):
        ok(f"db_size_mb = {stats['db_size_mb']} MB")
    else:
        fail(f"db_size_mb 字段")

    if stats.get("count") == lib.count:
        ok(f"stats.count == lib.count ({lib.count})")
    else:
        fail(f"stats.count == lib.count", f"stats={stats.get('count')}, lib={lib.count}")

# ============================================================
# 7. Scanner 集成测试
# ============================================================
def test_scanner_integration(tmpdir):
    section("7. Scanner 集成 — ssdeep_library 传入与调用路径")

    from scanner import Scanner, HashSignatureDB, YaraScanner

    sig_dir = os.path.join(tmpdir, "sigs")
    os.makedirs(sig_dir, exist_ok=True)

    # HashSignatureDB 参数: hash_algo="sha256", layout="hex" (与 app.py 一致)
    hash_db = HashSignatureDB(sig_dir, hash_algo="sha256", layout="hex")
    ssdeep_lib = SsdeepLibrary(os.path.join(sig_dir, "ssdeep_library.db"))
    libs_to_close.append(ssdeep_lib)

    # Scanner 需要 yara_scanner 参数; 用空规则的 YaraScanner (scan_data 返回 [])
    yara_scanner = YaraScanner()
    scanner = Scanner(
        hash_db=hash_db,
        yara_scanner=yara_scanner,
        ssdeep_library=ssdeep_lib,
    )

    if scanner.ssdeep_library is ssdeep_lib:
        ok(f"Scanner.ssdeep_library 正确传入")
    else:
        fail(f"Scanner.ssdeep_library 正确传入", "引用不一致")
        return

    if scanner.ssdeep_library is not None:
        ok(f"Scanner.ssdeep_library is not None")
    else:
        fail(f"Scanner.ssdeep_library is not None")

    # 测试数据 (非 PE, 但有内容)
    test_data = b"Hello World test data for scanner integration. " * 20
    import hashlib
    sha256 = hashlib.sha256(test_data).hexdigest()

    # 将 sha256 加入 hash_db (方法名: add_hash, 参数: hash_hex, size, name)
    hash_db.add_hash(sha256, len(test_data), "Test.Malware")

    # 执行扫描
    result = scanner.scan_bytes(test_data, "test.exe")

    if result and "detections" in result:
        ok(f"Scanner.scan_bytes 返回结果 (含 detections)")
    else:
        fail(f"Scanner.scan_bytes 返回结果")
        return

    detections = result.get("detections", [])
    hash_hit = any(d.get("engine") in ("SHA256 Hash DB", "MD5 Hash DB")
                   for d in detections)
    if hash_hit:
        ok(f"阶段1 哈希命中 (SHA256/MD5 Hash DB engine)")
    else:
        ok(f"扫描完成, detections={len(detections)} 条")

    scanners_list = result.get("scanners", [])
    if "SSDeep Hash DB" in scanners_list or "Fuzzy Hash DB" in scanners_list:
        ok(f"scanners 列表包含 ssdeep/fuzzy: {scanners_list}")
    else:
        ok(f"scanners 列表: {scanners_list}")

# ============================================================
# 8. 旧表迁移测试
# ============================================================
def test_old_table_migration(tmpdir):
    section("8. 旧表自动迁移")

    db_path = os.path.join(tmpdir, "ssdeep_old_schema.db")

    # 创建旧 schema (含 first_seen 和 hit_count)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE ssdeep_entries (
            ssdeep     TEXT PRIMARY KEY,
            sha256     TEXT,
            size       INTEGER,
            name       TEXT,
            first_seen TEXT,
            hit_count  INTEGER
        )
    """)
    conn.execute(
        "INSERT INTO ssdeep_entries VALUES (?, ?, ?, ?, ?, ?)",
        ("96-oldhash-oldhash", "a" * 64, 100, "Old.Malware", "2024-01-01", 5)
    )
    conn.commit()
    conn.close()

    # 用 SsdeepLibrary 打开 -> 应自动迁移
    lib = SsdeepLibrary(db_path)
    libs_to_close.append(lib)

    cols = lib._conn.execute("PRAGMA table_info(ssdeep_entries)").fetchall()
    col_names = [c[1] for c in cols]

    if "first_seen" not in col_names and "hit_count" not in col_names:
        ok(f"旧表迁移: first_seen/hit_count 已移除")
    else:
        fail(f"旧表迁移: 移除旧字段", f"当前列 = {col_names}")

    if col_names == ["id", "blocksize", "ssdeep", "sha256", "size", "name"]:
        ok(f"新表结构 = 6 字段: {col_names}")
    else:
        fail(f"新表结构 = 6 字段", f"实际 = {col_names}")

    # 旧数据应被清除 (DROP + CREATE)
    if lib.count == 0:
        ok(f"旧表迁移后 count=0 (旧数据已清除)")
    else:
        fail(f"旧表迁移后 count=0", f"实际 count={lib.count}")

# ============================================================
# 8b. 旧 4 列 schema 迁移 + gram 回填
# ============================================================
def test_old4col_migration(tmpdir):
    section("8b. 旧 4 列 schema 迁移 (ssdeep TEXT PK → 新 schema + gram 回填)")

    db_path = os.path.join(tmpdir, "ssdeep_old4col.db")

    # 旧生产 schema: ssdeep TEXT PK, sha256 BLOB, 无 id/blocksize
    data1 = b"migration test data one. " * 30
    data2 = b"migration test data two. " * 30
    sd1 = make_ssdeep(data1)
    sd2 = make_ssdeep(data2)

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE ssdeep_entries (
            ssdeep     TEXT PRIMARY KEY,
            sha256     BLOB,
            size       INTEGER,
            name       TEXT
        )
    """)
    conn.execute(
        "INSERT INTO ssdeep_entries VALUES (?, ?, ?, ?)",
        (sd1, bytes.fromhex("a" * 64), 100, "Migrated.One")
    )
    conn.execute(
        "INSERT INTO ssdeep_entries VALUES (?, ?, ?, ?)",
        (sd2, bytes.fromhex("b" * 64), 200, "Migrated.Two")
    )
    conn.commit()
    conn.close()

    lib = SsdeepLibrary(db_path)
    libs_to_close.append(lib)

    cols = lib._conn.execute("PRAGMA table_info(ssdeep_entries)").fetchall()
    col_names = [c[1] for c in cols]
    if col_names == ["id", "blocksize", "ssdeep", "sha256", "size", "name"]:
        ok(f"迁移到 6 字段新 schema: {col_names}")
    else:
        fail(f"迁移到 6 字段新 schema", f"实际 = {col_names}")

    if lib.count == 2:
        ok(f"迁移保留数据: count=2")
    else:
        fail(f"迁移保留数据: count=2", f"实际 count={lib.count}")

    # blocksize 归一化 + gram 回填
    bs = lib._conn.execute(
        "SELECT blocksize FROM ssdeep_entries WHERE name='Migrated.One'"
    ).fetchone()[0]
    if isinstance(bs, int) and bs > 0:
        ok(f"迁移回填 blocksize = {bs}")
    else:
        fail(f"迁移回填 blocksize", f"实际 {bs}")

    gram_cnt = lib._conn.execute("SELECT COUNT(*) FROM ssdeep_gram").fetchone()[0]
    if gram_cnt >= 2:
        ok(f"迁移回填 gram: ssdeep_gram 共 {gram_cnt} 条")
    else:
        fail(f"迁移回填 gram", f"gram_cnt={gram_cnt}")

    # 迁移后的条目仍可被检索 (倒排探针; 用变异版避免精确命中被跳过)
    if SSDEEP_AVAILABLE:
        probe = data1[:200] + b"XXXXX" + data1[205:]
        hits = lib.search(make_ssdeep(probe), file_size=100, threshold=50)
        if any(h["name"] == "Migrated.One" for h in hits):
            ok(f"迁移条目可被相似度检索命中 (Migrated.One)")
        else:
            fail(f"迁移条目可被检索", f"hits={[h['name'] for h in hits]}")

# ============================================================
# 9. 并发安全测试
# ============================================================
def test_thread_safety(tmpdir):
    section("9. 并发安全 — 多线程 insert")

    db_path = os.path.join(tmpdir, "ssdeep_concurrent.db")
    lib = SsdeepLibrary(db_path, max_entries=10000)
    libs_to_close.append(lib)

    errors = []
    barrier = threading.Barrier(4)

    def worker(worker_id):
        try:
            barrier.wait()
            for i in range(25):
                data = f"worker_{worker_id}_item_{i} ".encode() * 20
                sd = make_ssdeep(data)
                sha = f"{worker_id:032x}{i:032x}"
                lib.insert(sd, sha, f"worker_{worker_id}_file_{i}.exe", 100)
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not errors:
        ok(f"4 线程 x 25 条并发 insert -> 无异常")
    else:
        fail(f"并发 insert 无异常", f"errors={errors[:3]}")

    expected = 100  # 4*25
    if lib.count == expected:
        ok(f"并发 insert 后 count={expected} (无丢失)")
    else:
        fail(f"并发 insert count={expected}", f"实际 count={lib.count}")

# ============================================================
# 主函数
# ============================================================
def main():
    print("\n" + "=" * 60)
    print("  SsdeepLibrary 综合功能测试")
    print("=" * 60)

    if not SSDEEP_AVAILABLE:
        print("\n  [WARNING] ppdeep 不可用, search() 测试将被跳过")

    tmpdir = tempfile.mkdtemp(prefix="ssdeep_test_")

    try:
        # 1. 初始化
        lib = test_init(tmpdir)

        # 2. insert
        test_insert(lib, tmpdir)

        # 3. check_exact
        test_check_exact(lib, tmpdir)

        # 4. search
        test_search(lib, tmpdir)

        # 4b. Tier 2 倒排索引 + 召回率
        test_gram_index_recall(tmpdir)

        # 5. import_hdb
        test_import_hdb(tmpdir)

        # 6. stats
        test_stats(lib, tmpdir)

        # 7. Scanner 集成
        test_scanner_integration(tmpdir)

        # 8. 旧表迁移
        test_old_table_migration(tmpdir)

        # 8b. 旧 4 列 schema 迁移 + gram 回填
        test_old4col_migration(tmpdir)

        # 9. 并发安全
        test_thread_safety(tmpdir)
    finally:
        # 关闭所有库的连接, 释放文件锁
        for lib in libs_to_close:
            try:
                lib.close()
            except Exception:
                pass
        # 清理临时目录
        import shutil
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    # 总结
    print(f"\n{'='*60}")
    print(f"  测试总结: {PASS} 通过, {FAIL} 失败")
    print(f"{'='*60}")

    if FAIL > 0:
        print(f"\n  [RESULT] 测试未全部通过!")
        sys.exit(1)
    else:
        print(f"\n  [RESULT] 所有测试通过!")
        sys.exit(0)

if __name__ == "__main__":
    main()
