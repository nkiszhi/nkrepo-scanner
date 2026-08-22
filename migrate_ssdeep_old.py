#!/usr/bin/env python
"""两阶段迁移: 仅条目 (快) + 重建 gram 表 (批量)。

Phase 1: _ssdeep_old → ssdeep_entries (不生成 gram, ~20 分钟)
  - 按 rowid 顺序读 _ssdeep_old
  - INSERT OR IGNORE into ssdeep_entries (仅 UNIQUE 索引, 快)

Phase 2: 从头重建 ssdeep_gram 表 (~3-4 小时, 替代逐行 INSERT OR IGNORE 的 57 小时)
  - DROP 现有 ssdeep_gram (101M 行, 仅为 1.7M 条目)
  - CREATE gram_temp (普通表, 无索引, 用于快速批量插入)
  - 按 id 顺序读 ssdeep_entries, 生成 gram, 批量 INSERT 到 gram_temp
  - CREATE ssdeep_gram (WITHOUT ROWID, PK(gram, entry_id))
  - INSERT INTO ssdeep_gram SELECT FROM gram_temp ORDER BY gram, entry_id
    (SQLite 自动外部归并排序 + 有序 b-tree 插入, O(n) 而非 O(n log n))
  - DROP gram_temp
  - CREATE INDEX idx_ssdeep_gram_entry ON ssdeep_gram(entry_id)

Phase 3: 清理
  - DROP TABLE _ssdeep_old
  - WAL checkpoint
"""
import os
import sys
import sqlite3
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from scanner import SsdeepLibrary

DB = os.path.join(HERE, "signatures", "ssdeep_library.db")

BATCH = 50_000
CHECKPOINT_EVERY = 4  # 每 4 批做一次 WAL 截断


class MigrationSsdeepLibrary(SsdeepLibrary):
    """迁移专用子类: _init_db 跳过 idx_ssdeep_gram_entry 创建 (100M+ 行极慢)"""

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-512000")  # 512MB cache (default 2MB too small)
        cols = self._conn.execute("PRAGMA table_info(ssdeep_entries)").fetchall()
        if cols:
            col_names = {c[1] for c in cols}
            if "first_seen" in col_names or "hit_count" in col_names:
                self._conn.execute("DROP TABLE ssdeep_entries")
                cols = []
        self._conn.execute(self._GRAM_DDL)
        # *** 跳过 idx_ssdeep_gram_entry 创建 (迁移期不需要, 结束后重建) ***
        if cols:
            col_names = {c[1] for c in cols}
            if "id" not in col_names or "blocksize" not in col_names:
                self._migrate_v1()
        self._conn.execute(self._ENTRIES_DDL)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ssdeep_bs_size "
            "ON ssdeep_entries(blocksize, size)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS imported_files(name TEXT PRIMARY KEY)")
        self._conn.commit()
        self._count = self._conn.execute(
            "SELECT COUNT(*) FROM ssdeep_entries").fetchone()[0]
        self._imported_files = {
            r[0] for r in self._conn.execute(
                "SELECT name FROM imported_files").fetchall()
        }


def ro_query(query, params=()):
    """独立 RO 连接查询, 读后关闭释放 WAL 快照"""
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    conn.execute("PRAGMA cache_size=-128000")  # 128MB cache for RO
    try:
        return conn.execute(query, params).fetchall()
    finally:
        conn.close()


def main():
    lib = MigrationSsdeepLibrary(DB)
    total_start = time.time()

    # ========== Phase 1: Migrate entries (no gram) ==========
    print("=" * 60, flush=True)
    print("[P1] Migrating entries (no gram)...", flush=True)
    print("=" * 60, flush=True)

    max_rowid = ro_query("SELECT max(rowid) FROM _ssdeep_old")[0][0] or 0
    print(f"[P1] _ssdeep_old max_rowid={max_rowid:,}", flush=True)

    with lib._lock:
        lib._conn.execute("PRAGMA synchronous=OFF")

    last_rowid = 0
    migrated = 0
    batch_num = 0
    p1_start = time.time()

    while True:
        rows = ro_query(
            "SELECT ssdeep, sha256, size, name, rowid FROM _ssdeep_old "
            "WHERE rowid > ? ORDER BY rowid LIMIT ?",
            (last_rowid, BATCH))
        if not rows:
            break
        last_rowid = rows[-1][4]

        pending = []
        for ssdeep_val, sha256_blob, size, name, _ in rows:
            std = lib._ssdeep_to_standard(ssdeep_val)
            if std is None:
                continue
            pending.append((
                lib._parse_block_size(std), std,
                sha256_blob, size, name))

        with lib._lock:
            before = lib._conn.total_changes
            lib._conn.executemany(
                "INSERT OR IGNORE INTO ssdeep_entries"
                "(blocksize, ssdeep, sha256, size, name) VALUES(?,?,?,?,?)",
                pending)
            added = lib._conn.total_changes - before
            lib._conn.commit()
            migrated += added
            batch_num += 1
            if batch_num % CHECKPOINT_EVERY == 0:
                lib._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        if batch_num % 20 == 0:
            elapsed = time.time() - p1_start
            pct = last_rowid / max_rowid * 100 if max_rowid > 0 else 0
            print(f"[P1] batch {batch_num}, +{added:,}, migrated {migrated:,}, "
                  f"rowid {last_rowid:,}/{max_rowid:,} {pct:.1f}%, "
                  f"{elapsed:.1f}s", flush=True)

    p1_elapsed = time.time() - p1_start
    print(f"[P1] DONE: +{migrated:,} entries in {p1_elapsed:.1f}s "
          f"({p1_elapsed/60:.1f}min)", flush=True)

    # ========== Phase 2: Rebuild gram table ==========
    print("=" * 60, flush=True)
    print("[P2] Rebuilding gram table from scratch...", flush=True)
    print("=" * 60, flush=True)
    p2_start = time.time()

    with lib._lock:
        # Drop existing gram table + any leftover temp
        lib._conn.execute("DROP TABLE IF EXISTS ssdeep_gram")
        lib._conn.execute("DROP TABLE IF EXISTS gram_temp")
        # Create temp table (regular rowid table, NO index = fast append-only inserts)
        lib._conn.execute("CREATE TABLE gram_temp(gram INTEGER, entry_id INTEGER)")
        lib._conn.commit()
        entry_count = lib._conn.execute(
            "SELECT COUNT(*) FROM ssdeep_entries").fetchone()[0]
        max_id = lib._conn.execute(
            "SELECT max(id) FROM ssdeep_entries").fetchone()[0] or 0
    print(f"[P2] entries={entry_count:,}, max_id={max_id:,}", flush=True)

    # --- Phase 2a: Bulk insert grams into gram_temp ---
    print("[P2a] Generating + bulk inserting grams into gram_temp...", flush=True)
    last_id = 0
    total_grams = 0
    gram_batch = 0
    p2a_start = time.time()

    while True:
        rows = ro_query(
            "SELECT id, ssdeep FROM ssdeep_entries "
            "WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, BATCH))
        if not rows:
            break
        last_id = rows[-1][0]

        # Generate grams for this batch
        gram_rows = []
        for entry_id, ssdeep_val in rows:
            for g in lib._entry_gram_codes(ssdeep_val):
                gram_rows.append((g, entry_id))

        with lib._lock:
            lib._conn.executemany(
                "INSERT INTO gram_temp(gram, entry_id) VALUES(?,?)",
                gram_rows)
            lib._conn.commit()
            total_grams += len(gram_rows)
            gram_batch += 1
            if gram_batch % CHECKPOINT_EVERY == 0:
                lib._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        if gram_batch % 20 == 0:
            elapsed = time.time() - p2a_start
            pct = last_id / max_id * 100 if max_id > 0 else 0
            rate = total_grams / elapsed if elapsed > 0 else 0
            print(f"[P2a] batch {gram_batch}, grams={total_grams:,}, "
                  f"id {last_id:,}/{max_id:,} {pct:.1f}%, "
                  f"{elapsed:.1f}s, {rate:,.0f} grams/s", flush=True)

    p2a_elapsed = time.time() - p2a_start
    print(f"[P2a] DONE: {total_grams:,} grams in {p2a_elapsed:.1f}s "
          f"({p2a_elapsed/60:.1f}min)", flush=True)

    # --- Phase 2b: Build final WITHOUT ROWID table via sorted INSERT ---
    print("[P2b] Building final ssdeep_gram (WITHOUT ROWID, PK)...", flush=True)

    with lib._lock:
        lib._conn.execute(
            "CREATE TABLE ssdeep_gram(gram INTEGER, entry_id INTEGER, "
            "PRIMARY KEY(gram, entry_id)) WITHOUT ROWID")
        lib._conn.commit()

        print("[P2b] INSERT INTO ssdeep_gram SELECT FROM gram_temp "
              "ORDER BY gram, entry_id...", flush=True)
        sort_start = time.time()
        lib._conn.execute(
            "INSERT INTO ssdeep_gram(gram, entry_id) "
            "SELECT gram, entry_id FROM gram_temp ORDER BY gram, entry_id")
        lib._conn.commit()
        sort_elapsed = time.time() - sort_start
        print(f"[P2b] sort+insert done in {sort_elapsed:.1f}s "
              f"({sort_elapsed/60:.1f}min)", flush=True)

        print("[P2b] DROP TABLE gram_temp...", flush=True)
        lib._conn.execute("DROP TABLE gram_temp")
        lib._conn.commit()
        lib._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        print("[P2b] CREATE INDEX idx_ssdeep_gram_entry...", flush=True)
        idx_start = time.time()
        lib._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ssdeep_gram_entry "
            "ON ssdeep_gram(entry_id)")
        lib._conn.commit()
        idx_elapsed = time.time() - idx_start
        print(f"[P2b] index creation done in {idx_elapsed:.1f}s "
              f"({idx_elapsed/60:.1f}min)", flush=True)

        # Restore safe PRAGMA settings
        lib._conn.execute("PRAGMA synchronous=NORMAL")
        lib._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        final_entries = lib._conn.execute(
            "SELECT COUNT(*) FROM ssdeep_entries").fetchone()[0]
        final_grams = lib._conn.execute(
            "SELECT COUNT(*) FROM ssdeep_gram").fetchone()[0]

    p2_elapsed = time.time() - p2_start
    print(f"[P2] DONE: entries={final_entries:,}, grams={final_grams:,} "
          f"in {p2_elapsed:.1f}s ({p2_elapsed/60:.1f}min)", flush=True)

    # ========== Phase 3: Cleanup ==========
    print("=" * 60, flush=True)
    print("[P3] Cleanup...", flush=True)
    print("=" * 60, flush=True)

    with lib._lock:
        lib._conn.execute("DROP TABLE IF EXISTS _ssdeep_old")
        lib._conn.commit()
        lib._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    print("[P3] _ssdeep_old dropped", flush=True)

    lib.close()
    total_elapsed = time.time() - total_start
    print("=" * 60, flush=True)
    print(f"[DONE] Total: {total_elapsed:.1f}s "
          f"({total_elapsed/3600:.1f}h)", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
