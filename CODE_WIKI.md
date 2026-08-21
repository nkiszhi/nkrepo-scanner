# NKAMG Scanner — Code Wiki

> 轻量级静态恶意软件扫描平台（类 VirusTotal 极简版）：上传文件 → 干净 / 报毒。
> 本文档基于源码分析生成，覆盖架构、模块职责、关键类与函数、依赖关系与运行方式。

---

## 目录

1. [项目概述](#1-项目概述)
2. [整体架构](#2-整体架构)
3. [目录结构](#3-目录结构)
4. [主要模块职责](#4-主要模块职责)
5. [关键类与函数说明](#5-关键类与函数说明)
6. [数据库（签名库）结构](#6-数据库签名库结构)
7. [依赖关系](#7-依赖关系)
8. [配置说明](#8-配置说明)
9. [项目运行方式](#9-项目运行方式)
10. [Web API 接口](#10-web-api-接口)
11. [安全机制](#11-安全机制)

---

## 1. 项目概述

**NKAMG Scanner** 是一个纯 Python 实现的静态恶意软件扫描平台，核心特点：

| 检测引擎 | 说明 |
|---------|------|
| Hash DB | 整文件哈希比对，两个**并列**库：SHA256 库（62,587,049 条主库）+ MD5 库（540,169 条） |
| Fuzzy Hash DB | 模糊哈希增强库（62,331,195 条）：ssdeep / vhash / authentihash / imphash / rich_header_hash 五表结构 |
| YARA | 字节模式 + 规则逻辑（内置规则 + 第三方规则库约 18,346 条） |
| 查壳 Packer | 多特征融合识别：DIE 特征体系 + PEiD 经典库 + 外部 YARA 扩展规则 |

辅助能力：

- **文件类型识别**（`filetype.py`，移植自 ClamAV FTM 魔数签名表，70+ 种类型）
- **静态信息提取**（`staticinfo.py`）：ssdeep / TLSH / imphash / authentihash + PE 元数据
- **Web 界面**（Flask）：VirusTotal 风格两段式扫描、报告详情页、哈希管理后台

技术选型：**Flask + SQLite（动态分片）+ Bloom 过滤器 + yara-python + pefile + ppdeep**，无独立数据库服务。

---

## 2. 整体架构

### 2.1 架构分层

```
┌─────────────────────────────────────────────────────────────┐
│  Web 层 (app.py, 846 行)                                     │
│  Flask 多线程服务 · 两段式扫描 · 任务轮询 · 结果缓存 · 管理后台 │
├─────────────────────────────────────────────────────────────┤
│  扫描门面 (scanner.Scanner)                                  │
│  阶段1: 哈希+类型+签名库点查 (毫秒级)                          │
│  阶段2: YARA+静态信息+模糊哈希 (后台线程)                      │
├──────────────┬──────────────┬───────────────┬───────────────┤
│ HashSignatureDB │ HashSignatureDB │ FuzzySignatureDB │ YaraScanner │
│ (SHA256 库)     │ (MD5 库, 可选)  │ (模糊哈希库, 可选) │ (规则合并编译)│
├──────────────┴──────────────┴───────────────┴───────────────┤
│  静态分析支撑                                                 │
│  filetype.py (FTM 类型识别) · staticinfo.py (模糊哈希/PE 元数据) │
│  packer.py (壳识别) · tlsh.py (TLSH 纯 Python 实现)           │
├─────────────────────────────────────────────────────────────┤
│  存储: Bloom 位图 + 动态分片 SQLite (signatures/*.shards/)     │
│  缓存: uploads/<sha256>.json (与样本同目录) · 配置: config.json  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 核心数据流：两段式扫描

```
POST /scan (文件上传, 内存直读不落盘)
   │
   ├─ compute_hashes_bytes(data)  一次计算 MD5 + SHA1 + SHA256
   │
   ├─ 缓存命中? ── 是 ──→ 直接返回 cached=true (毫秒级, history 异步追加)
   │
   ├─【阶段1 · 同步 · 毫秒级】 scanner.scan_phase1()
   │     ├─ HashSignatureDB.check()      SHA256 库: Bloom 排除 → 分片点查
   │     ├─ md5_db.check_hash()          MD5 库:   Bloom 排除 → 分片点查
   │     └─ filetype.detect_file_type()  FTM 魔数识别
   │   → 立即返回 {task_id, status:"phase2", result(阶段1结果)}
   │
   └─【阶段2 · 后台线程】 _run_phase2() (信号量限并发)
         ├─ YaraScanner.scan_data()          单次合并编译规则匹配 (10s 超时)
         ├─ staticinfo.compute_static_info() ssdeep/TLSH/imphash/authentihash
         │                                   /PE 元数据/壳识别 (≤2MB 限制)
         └─ fuzzy_db.check_by_computed_hashes()  模糊哈希库比对
       → 前端轮询 GET /api/task/<id> 至 done
       → 先合并写缓存 uploads/<sha256>.json, 再标记 done
```

### 2.3 存储架构：Bloom 驱动的动态分片

```
查询 hash
   │
   ▼
① Bloom 预过滤 ─── 1% 误判率位图, 按分片独立 (懒加载+LRU)
   │                肯定不在库 → 直接返回未命中 (无锁读)
   ▼ 可能命中
② 分片路由 ─────── hex 布局: digest[0] (256 片, 00~ff)
   │                modulo 布局: digest[:4] % N (分片名 0000~N-1)
   ▼
③ 分片点查 ─────── 只读打开该分片 SQLite, BLOB 主键点查
                    (连接级串行锁, 不同分片并行, LRU 缓存上限 max_open_shards)
```

---

## 3. 目录结构

```
nkrepo-scanner/
├── app.py                 # Flask Web 服务（路由/两段式扫描/缓存/管理后台）
├── scanner.py             # 扫描核心引擎（签名库/YARA/门面，1984 行）
├── staticinfo.py          # 静态信息与模糊哈希（ssdeep/tlsh/imphash/PE 元数据）
├── packer.py              # 壳/保护器识别（DIE+PEiD+外部 YARA 融合判定）
├── tlsh.py                # TLSH 纯 Python 实现（官方 C 算法 JS 移植）
├── filetype.py            # 文件类型识别（ClamAV FTM 机制移植）
├── build_md5_db.py        # 构建并列 MD5 库（extracted/ → md5.db.shards/）
├── build_fuzzy_db.py      # 构建模糊哈希库（hdb/ 8 字段行 → fuzzy.db.shards/）
├── extract_cvd.py         # ClamAV .cvd 病毒库解包（→ extracted/）
├── fetch_yara.py          # 第三方 YARA 规则库下载（GitHub → yara_sources/）
├── gen_sigs.py            # 合成签名生成器（千万级压测用）
├── bench.py               # 性能基准（延迟/内存/磁盘）
├── test_shards.py         # 分片库自动化测试（命中/重分片/懒加载）
├── test_filetype.py       # 文件类型识别验证脚本（26+ 类样本）
├── config.json            # 全部配置（bloom/server/packer/admin 八节）
├── requirements.txt       # Python 依赖（4 项）
├── templates/             # Jinja2 模板（index/scan/file/login/hash_admin）
├── static/                # 前端资源（app.js 渲染库 / admin.js / CSS）
├── packer_rules/          # 外部 YARA 扩展壳库（.yar 规则）
├── signatures/            # 签名根目录（rules.yar/hashes.hdb + 分片库）
│   ├── sha256.db.shards/  #   SHA256 库分片 SQLite（运行时生成）
│   ├── sha256.db.bloom/   #   SHA256 库分片 Bloom 位图
│   ├── md5.db.shards/     #   MD5 库分片（build_md5_db.py 生成）
│   └── fuzzy.db.shards/   #   模糊哈希库分片（build_fuzzy_db.py 生成）
├── hdb/                   # ClamAV 官方哈希分桶数据源（00.hdb~ff.hdb, 256 个, ~12.4GB）
├── extracted/             # CVD 解包产物（hdb/hsb/mdb/ndb/ldb...）
├── cvd/                   # 下载的 main.cvd / daily.cvd
├── uploads/               # 上传样本 + 扫描报告（样本 <sha256> 原始字节, 报告 <sha256>.json, 同目录; LRU 淘汰）
└── yara_sources/          # 第三方 YARA 规则库（.gitignore 忽略, fetch_yara.py 拉取）
```

---

## 4. 主要模块职责

| 模块 | 行数 | 职责 |
|------|-----|------|
| [scanner.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/scanner.py) | 1984 | 核心引擎：`BloomFilter`（位图预过滤）、`HashSignatureDB`（SHA256/MD5 并列分片库）、`FuzzySignatureDB`（5 表模糊哈希库）、`YaraScanner`（规则合并编译）、`Scanner`（两阶段扫描门面） |
| [app.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/app.py) | 846 | Flask Web 服务：15 个路由、两段式扫描调度、任务内存管理、扫描缓存（LRU 淘汰）、API token 认证、管理员登录、限流、阶段2 并发控制 |
| [staticinfo.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/staticinfo.py) | 255 | 静态信息统一入口：ssdeep/tlsh/imphash/authentihash 计算、PE 元数据提取、缺失原因 notes 机制 |
| [packer.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/packer.py) | 516 | 壳识别：精确特征（节名/EP 字节/magic/外部 YARA）+ 启发特征（熵/导入数/RWX/EP 位置）融合判定，含 CPU 放大防护 |
| [tlsh.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/tlsh.py) | 298 | TLSH 局部敏感哈希纯 Python 实现（滑动窗口 + 128 桶 + 分位数编码），零外部依赖 |
| [filetype.py](file:///c:/Users/nkisz/Desktop/恶意代码分析与防治技术/nkrepo-scanner/filetype.py) | ~257 | ClamAV FTM 四层判定链：固定偏移魔数 → 模式搜索 → 尾部魔数 → 文本编码兜底，含 OOXML 细分 |
| build_md5_db.py | 48 | MD5 库构建脚本：从 `extracted/` 提取 32hex 行导入 `md5.db.shards/` |
| build_fuzzy_db.py | 65 | 模糊哈希库构建脚本：从 `hdb/` 8 字段行提取 5 种模糊哈希入库 |
| extract_cvd.py | ~70 | CVD 解包：512B 头校验 + gzip/tar 展开到 `extracted/` |
| fetch_yara.py | ~60 | 从 GitHub 拉取 3 个第三方 YARA 规则仓库 tarball |
| gen_sigs.py | ~70 | 确定性合成签名生成（`sha256("seed:i")`），压测填充 |
| bench.py | ~140 | 基准测试：加载耗时/未命中延迟/命中延迟/端到端扫描/峰值内存 |
| test_shards.py | ~90 | 分片库不变量测试：任意分片数命中不丢/命名合规/冷启动零加载 |
| test_filetype.py | ~60 | 文件类型识别人工核对脚本（26+ 类构造样本） |

---

## 5. 关键类与函数说明

### 5.1 scanner.py — 核心引擎

#### BloomFilter（L109-179）

纯 Python 双哈希 Bloom 过滤器，利用安全检测"宁误报不漏报"特性前置排除绝大部分干净查询。

| 方法 | 行号 | 说明 |
|------|-----|------|
| `__init__(expected_items, fp_rate)` | L114-120 | 参数推导：`m = ceil(-n·ln(p)/ln²2)`，`k = clamp(round(m/n·ln2), 1, 16)` |
| `_positions(digest)` | L125-143 | blake2b(digest, digest_size=8) 解包为 h1/h2（h2|=1 防零步长），位置 = `(h1 + i·h2) % m`；带 4096 条 LRU 缓存 |
| `add(digest)` / `__contains__` | L145-155 | 置位与查询 |
| `save(path)` / `load(path)` | L161-179 | 持久化格式：`MAGIC b"NKB1"`(4B) + `<QQd`(m,k,fp) + `<Q`(n) + 原始位图 |

#### HashSignatureDB（L185-1057）

千万级精确哈希签名库，通过 `hash_algo` 参数化为 SHA256 库与 MD5 库两个并列实例。

| 方法 | 行号 | 说明 |
|------|-----|------|
| `__init__(db_path, shard_count=4, bloom_fp_rate=0.01, max_open_shards=4, hash_algo="sha256", ddl, insert_sql, row_cols, layout)` | L201-287 | 初始化 meta/目录结构；触发旧单库迁移（`_migrate_legacy`）与布局同步（`_sync_layout`）；初始化连接 LRU / 连接级锁 / Bloom LRU |
| `_route(digest)` | L300-305 | 分片路由：hex 布局取 `digest[0]`；modulo 布局 `int.from_bytes(digest[:4],'big') % N` |
| `_detect_layout()` | L338-350 | 按分片文件名推断布局（4 位十进制=modulo；2 位 hex=256 片） |
| `_sync_layout()` / `_reshard()` | L352-453 | meta 记录的布局与配置不一致时自动重分片：旧分片按新路由重写，旧文件备份至 `.shards.legacy/`，Bloom 全部重建 |
| `_ro_conn(shard_id)` | L474-504 | 只读连接懒加载 + LRU 淘汰（上限 `max_open_shards`）；淘汰的连接移入 `_retired` 延迟关闭 |
| `_query_shard(shard_id, sql, params)` | L506-525 | 连接级串行锁点查；连接刚被 LRU 淘汰时开临时只读连接补查（C1 修复，确保不漏报） |
| `_migrate_legacy(legacy_path)` | L560-646 | 旧版单一 SQLite 库自动按路由拆入分片，原库改名 `.migrated`；失败按空库启动不中断 |
| `import_hdb(filepath, batch=50000)` | L714-784 | 导入 ClamAV `.hdb/.hsb`（`hash:size:name` 行）；`imported_files` 表幂等去重；仅接受本库主键长度的行 |
| `add_hash(h, size, name)` / `delete_hash(h)` | L839-917 | 单条增删（管理端 API 用），Bloom 增量更新即时生效 |
| `check_hash(hash_hex, file_size)` | L924-956 | Bloom 排除短路 → 单分片 SQLite 点查 → 大小校验 |
| `check(file_path, file_size, md5, sha1, sha256)` | L958-997 | 兼容旧接口：按哈希长度路由到对应库点查 |
| `finalize()` | L790-804 | 重建 dirty 分片的 Bloom 位图 |
| `stats()` / `close()` | L1000-1056 | 存储层状态（tier/分片数/Bloom 状态）/ 关闭全部连接 |

#### FuzzySignatureDB（L1126-1604）

5 表模糊哈希库，每种 fuzzy hash 独立成表、以自身值为主键，256 hex 分片（每分片文件含 5 张表）。

| 方法 | 行号 | 说明 |
|------|-----|------|
| `_route(fuzzy_type, value)` | L1204-1208 | BLOB 类型取首字节；ssdeep 取 `sha256(str)` 首字节 → 00~ff 分片 |
| `import_hdb(filepath)` | L1365-1449 | 解析 8 字段行 `sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash`，每个非空 fuzzy 字段按自身值路由写入对应表 |
| `check_fuzzy(fuzzy_type, value)` | L1495-1525 | 按类型 × 值点查 |
| `check_by_computed_hashes(static_info_fuzzy)` | L1527-1543 | 用阶段2 计算出的模糊哈希批量比对（扫描主路径） |
| `finalize()` / `stats()` / `close()` | L1452-1604 | Bloom 按类型×分片重建（`{shard}_{type}.bloom`）/ 状态 / 关闭 |

#### YaraScanner（L1610-1768）

| 方法 | 行号 | 说明 |
|------|-----|------|
| `load_rules(filepath)` | L1642-1658 | 仅收集 `.yar` 路径到 `_pending`，延迟编译 |
| `_ensure_compiled()` | L1664-1695 | `yara.compile(filepaths={namespace: path})` **一次性合并编译为单一 Rules 对象**（每文件独立 namespace）；整体失败时逐文件编译定位坏规则后重编好文件 |
| `warmup()` | L1660-1662 | 启动时预编译，消除首扫延迟（双检查锁） |
| `scan_data(data)` / `scan(file_path)` | L1708-1732 | 单次 `match()` 调用（timeout=30/10s），捕获 `yara.TimeoutError` 返回超时标记 |

#### Scanner（L1774-1977）— 统一扫描门面

组合 `hash_db` + `md5_db`（可选）+ `yara_scanner` + `fuzzy_db`（可选）。

| 方法 | 行号 | 说明 |
|------|-----|------|
| `scan_file(file_path)` | L1786-1799 | ≤64MB（`INLINE_LIMIT`）内存扫描；超过走 `_scan_large` |
| `scan_bytes(data, filename)` | L1801-1803 | Web 路径：内存缓冲扫描 |
| `scan_phase1(data, filename, hashes)` | L1805-1810 | 阶段1：哈希（可传入预计算值免重算）→ 类型识别 → SHA256/MD5 双库点查 |
| `scan_phase2(data, filename, phase1)` | L1812-1814 | 阶段2：YARA → staticinfo → fuzzy 比对 |
| `merge_phases(p1, p2)` | L1816-1818 | 合并两阶段结果（`phase="done"`） |
| `_scan_large(file_path)` | L1935-1977 | 大文件路径：分块哈希 + 头尾类型识别 + YARA 路径扫描，**跳过模糊哈希与静态信息** |

### 5.2 app.py — Web 层

#### 初始化流程（L22-237）

1. `load_config()`（L68-83）读 `config.json` 覆盖 `DEFAULT_CONFIG`（`_` 开头键为注释）
2. 实例化 `hash_db`（L131）→ 条件实例化 `md5_db`（L141，`md5.db.shards/` 存在才加载）与 `fuzzy_db`（L158）
3. 遍历 `signatures/` 自动导入新 `.hdb/.hsb`（幂等）与 `.yar`；递归加载 `yara_sources/` 第三方规则（L172-195）
4. `yara_scanner.warmup()` 预编译（L206）→ `hash_db.finalize()`（L208）→ `packer.configure()` 加载壳库（L215）→ 组装 `Scanner`（L224）

#### 关键函数

| 函数 | 行号 | 说明 |
|------|-----|------|
| `_require_auth()` | L365-374 | API token 校验（`Authorization: Bearer` 或 `?token=`），未配置则匿名放行 |
| `_check_admin_credentials()` | L385-392 | `SHA-256(salt:password)` + `hmac.compare_digest` 常量时间比较 |
| `admin_required` 装饰器 | L395-405 | GET 未登录跳登录页，其余方法 401 |
| `_rate_limited(ip)` | L419-432 | 每 IP 60 秒滑动窗口计数（deque+锁），默认 30 次/分钟 |
| `_task_cleanup()` | L444-452 | 惰性清理过期任务（`TASKS_MAX=100` / `TASK_TTL=600s`） |
| `_load_cached_result` / `_save_cached_result` | L251-314 | 缓存读写；写入用临时文件 + `os.replace` 原子替换（Windows 共享冲突重试 5 次） |
| `_cache_cleanup()` | L317-362 | LRU 淘汰：超 `CACHE_MAX_FILES=10000` 按 mtime 删旧、超 30 天过期删；1 小时节流 |
| `_run_phase2(task, data, filename)` | L619-651 | 阶段2 后台线程（daemon）：信号量限并发；超 32MB 仅跑 YARA；**先合并写缓存再标 done**（消除 404 窗口） |
| `_route_hash_db(h)` | L408-416 | 按哈希长度路由：64hex→SHA256 库，32hex→MD5 库 |

### 5.3 staticinfo.py — 静态信息

统一入口 `compute_static_info(data)`（L202-255）返回 `{fuzzy, pe, packer, notes}`。

| 函数 | 行号 | 说明 |
|------|-----|------|
| `compute_ssdeep(data)` | L63-73 | 基于 ppdeep；<32B / >2MB / 未安装返回 None |
| `compute_tlsh(data)` | L76-82 | 基于本地 `tlsh.py`；<50B / 复杂度不足 / >2MB 返回 None |
| `compute_imphash(data, pe_obj=None)` | L85-100 | PE 导入表 MD5（pefile）；非 PE 返回 None |
| `compute_authentihash(data)` | L103-131 | 清零 CheckSum 与 Security Directory 后全文件 SHA256（手工按 PE32/PE32+ 偏移清零） |
| `compute_pe_meta(data, pe_obj=None)` | L142-189 | machine/时间戳/入口点/节表/导入表（每 DLL 最多 32 函数） |
| `compute_static_info(data)` | L202-255 | **C5 优化**：PE 只 `pefile.PE(data)` 解析一次，pe_obj 传给 imphash/pe_meta/packer 复用；缺失原因记入 `notes` |

关键常量：`FUZZY_MAX_BYTES = 2MB`（L39，纯 Python 实现实测 1MB≈24s，故设上限并在后台线程计算）。

### 5.4 packer.py — 壳识别

核心函数 `detect_packer(data, pe_obj=None)`（L330-505），融合判定：

**精确特征（exact）**

| 信号 | 数据表 | 权重 |
|------|-------|------|
| 特征节名 | `SECTION_NAMES`（L125-149，upx0/.aspack/.vmp0/.themida 等 22 族） | 2 |
| EP 字节模式 | `EP_PATTERNS`（L68-81，12 条 PEiD hex 模式，支持 `??` 通配） | 2 |
| magic 字符串 | `MAGIC_STRINGS`（L84-115，30 条）；overlay 命中权重 3 / 文件内 1；短 magic(<5B) 仅限 overlay 防误报 | 1-3 |
| 外部 YARA 规则 | `PackerYaraRules`（L208-307）加载 `packer_rules/`，meta 约定 `packer`/`weight`/`desc` | meta 声明（默认 2） |

**启发特征（heuristics）**：最高节熵 ≥7.0（w=10）、≥2 节熵 ≥6.5（w=10）、导入表 0<条目≤15（w=15）、RWX 节存在（w=15）、EP 位于最后一节（w=15）。

**融合判定**（L443-505）：`heu_score = min(40, 启发权重和)`；每壳族 `score = min(60, 20+(w-1)*12)`；`packed_score = min(100, exact_score + heu_score)`。精确命中任一 high 或 packed_score≥65 → 整体 high；无精确但 heu_score≥35 → "Unknown (启发式)" medium。

**CPU 放大防护**（恶意 PE 构造对抗）：单节熵采样上限 4MB（`ENTROPY_SAMPLE_BYTES` L57）、全文件 magic 搜索上限 32MB（L59）、节熵总字节预算 16MB（`ENTROPY_TOTAL_BUDGET` L63）。

### 5.5 filetype.py — 文件类型识别

移植 ClamAV `libclamav/filetypes.c` FTM 机制，四层判定链（`detect_file_type`，L218-250）：

```
① 固定偏移魔数 (MAGIC_SIGS, L25-107, ~80 条 type-0 签名)
     │ 命中 ZIP → _detect_ooxml 细分 (Word/Excel/PPT/JAR/ODF)
② 模式搜索 (PATTERN_SIGS, L124-131, type-1: MZ+PE\0\0 / SFX / HTML)
③ 尾部魔数 (DMG 'koly' @ EOF-512)
④ 文本编码检测兜底 (_detect_text: BOM/UTF-8/UTF-16/ASCII)
```

| 函数 | 行号 | 说明 |
|------|-----|------|
| `_zip_entry_names(data)` | L155-170 | struct 解析前 1024B 内最多 16 个 ZIP local file header 条目名 |
| `_detect_ooxml(names)` | L173-190 | 两遍匹配：强前缀（xl/、word/、ppt/）优先，弱表兜底 |
| `detect_file_type(head, tail)` | L218-250 | 主入口，返回 `{name, cl_type, category, method}` |
| `read_head_tail(path)` | L253-257 | 读头 1024B + 尾 512B（大文件类型识别用） |

### 5.6 tlsh.py — TLSH 实现

移植官方 trendmicro/tlsh 的 `js_ext/tlsh.js`，输出 70 位大写 hex（无 T1 前缀，兼容 VirusTotal/MalwareBazaar 格式）。

- 滑动窗口 5 字节（`SLIDING_WND_SIZE` L38），每字节经 `_b_mapping`（L55-61，4 次 `V_TABLE` 查表链）更新校验和 + 6 组桶计数
- `_find_quartile`（L109-180）对 128 有效桶 quickselect 求 q1/q2/q3
- `final()`（L241-274）：长度 ≥50 且非零桶过半（防复杂度不足），每 4 桶编码为 2bit 分位数码
- 对外接口：`hash_bytes(data)`（L292-298），失败返回 None
- 已与官方 JS 实现交叉验证（9 类用例输出完全一致）

---

## 6. 数据库（签名库）结构

全部基于 SQLite，无独立数据库服务。物理形态为**分片目录**而非单一文件。

### 6.1 三库并列总览

| 库 | 目录 | 表结构 |
|----|------|-------|
| SHA256 库 | `signatures/sha256.db.shards/` | `sigs(sha256 BLOB PK, size, name, md5 BLOB) WITHOUT ROWID`（v3 四列） |
| MD5 库 | `signatures/md5.db.shards/` | `sigs(md5 BLOB PK, size, name) WITHOUT ROWID`（三列） |
| 模糊哈希库 | `signatures/fuzzy.db.shards/` | 每分片 5 张表：`sigs_ssdeep(ssdeep TEXT PK, size, name, sha256 BLOB)` 等，均 WITHOUT ROWID |

### 6.2 meta 元数据库（`_meta.db`，三库共用同一 schema）

```sql
CREATE TABLE imported_files(name TEXT PRIMARY KEY);        -- 已导入源文件登记（幂等去重）
CREATE TABLE shard_counts(prefix TEXT PRIMARY KEY,
                          cnt INTEGER NOT NULL);            -- 分片计数缓存
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);              -- 通用 KV
```

`meta` 表实际键：`layout`（hex/modulo）、`shard_count`、`counts_valid`、`schema_version`、`primary_key`、`migrated_from`。

### 6.3 设计要点

- **BLOB 主键 + WITHOUT ROWID**：32B 二进制主键较 64 位 hex 字符串省一半存储；主键即聚簇索引，纯点查无需二级索引（全项目无显式 `CREATE INDEX`）
- **Bloom 与分片一一对应**：`{shard}.db` ↔ `{shard}.bloom`；fuzzy 库为 `{shard}_{type}.bloom`
- **幂等导入**：`INSERT OR IGNORE` + `imported_files` 去重，重跑仅新增
- **自动迁移**：旧单库 → 分片（`.migrated`）；布局/分片数变更 → 自动重分片（`.shards.legacy` 备份）
- **性能实测**（千万级）：常驻内存 11.43MB（仅 Bloom）、未命中 0.009ms/次、命中 0.014ms/次

### 6.4 扫描结果缓存（非 SQLite）

`uploads/<sha256>.json`：扫描报告缓存（与样本 `uploads/<sha256>` 同目录），原子写入、LRU 淘汰（10000 个 / 30 天）、内含 `history` 提交历史（上限 100 条）。

---

## 7. 依赖关系

### 7.1 Python 包依赖（requirements.txt）

| 包 | 版本 | 用途 | 缺失时降级行为 |
|----|------|------|---------------|
| flask | ≥3.0 | Web 框架 | 必需 |
| yara-python | ≥4.3 | YARA 规则引擎 | `YARA_AVAILABLE=False`，扫描跳过 YARA |
| pefile | ≥2023.2.7 | PE 静态分析 | imphash/authentihash/PE 元数据/壳识别返回 None + note |
| ppdeep | ≥20200505 | ssdeep 模糊哈希 | ssdeep 返回 None + note |

> TLSH 为项目内置纯 Python 移植（`tlsh.py`，仅依赖标准库 math），无需额外安装。

### 7.2 模块间依赖

```
app.py ──→ scanner.py (HashSignatureDB / FuzzySignatureDB / YaraScanner / Scanner)
       ──→ packer.py  (configure)
       └─→ config.json

scanner.py ──→ filetype.py  (guess_file_type / read_head_tail)
          ──→ staticinfo.py (compute_static_info, 阶段2)

staticinfo.py ──→ tlsh.py   (compute_tlsh)
             ──→ packer.py  (detect_packer)
             ──→ pefile / ppdeep (可选)

build_md5_db.py  ──→ scanner.HashSignatureDB (hash_algo="md5")
build_fuzzy_db.py ──→ scanner.FuzzySignatureDB
gen_sigs.py / bench.py / test_shards.py ──→ scanner（直接操作库）
extract_cvd.py / fetch_yara.py ──→ 无项目内依赖（数据获取）
```

依赖注入方向单一：`app.py` 为组合根；`scanner.Scanner` 组合各引擎；`staticinfo` 组合 `tlsh`/`packer`。所有第三方依赖均有 ImportError 探测与降级路径。

---

## 8. 配置说明

全部配置集中在 `config.json`（缺省项回落代码默认值，`_` 开头键为注释）：

| 配置节 | 键 | 默认值 | 说明 |
|-------|-----|-------|------|
| `bloom` | `shards` | 4 | Bloom/SQLite 分片数（modulo 布局生效；修改后下次启动自动重分片） |
| | `fp_rate` | 0.01 | Bloom 误判率 |
| `sha256` | `layout` | hex | `hex`=256 片按首字节；`modulo`=按 `shards` 取模 |
| | `max_open_shards` | 16 | 分片连接 LRU 缓存上限 |
| `md5` | `layout` / `max_open_shards` | hex / 16 | 同上（MD5 库） |
| `fuzzy` | `layout` / `max_open_shards` | hex / 16 | 同上（模糊哈希库） |
| `server` | `host` / `port` | 127.0.0.1 / 5000 | 监听地址 |
| | `max_upload_mb` | 10 | `/scan` 上传上限（超限 413） |
| | `uploads_dir` | uploads | 测试样本目录（相对项目根或绝对路径） |
| | `api_token` | ""（匿名） | 非空时 `/scan`、`/api/*` 需 Bearer 认证 |
| | `scan_rate_limit` | 30 | 每 IP 每分钟 `/scan` 次数（0 不限） |
| | `phase2_max_mb` | 32 | 阶段2 深度分析样本上限（超过仅跑 YARA） |
| | `phase2_concurrency` | 4 | 阶段2 后台线程并发上限（信号量） |
| | `secret_key` | 随机生成 | Flask 会话签名密钥 |
| `admin` | `username` / `salt` / `password_hash` | admin / ... | 管理员凭据；`password_hash = SHA-256(salt:password)` |
| `packer` | `rules_dir` | packer_rules | 外部 YARA 壳库目录 |
| | `max_yara_bytes` | 16777216 | 外部规则匹配样本大小上限 |

---

## 9. 项目运行方式

### 9.1 安装与启动

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt   # Windows
# source venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
venv\Scripts\python app.py
```

打开 <http://127.0.0.1:5000>。启动流程：加载配置 → 实例化三库（md5/fuzzy 缺失自动降级）→ 自动导入 `signatures/` 新签名 → YARA 合并编译预热 → 壳库加载 → `app.run(threaded=True)`。

### 9.2 签名库构建（完整流程）

```bash
# 1. 下载 ClamAV 官方病毒库
curl -A "ClamAV/freshclam/1.4.2" -O https://database.clamav.net/main.cvd
curl -A "ClamAV/freshclam/1.4.2" -O https://database.clamav.net/daily.cvd

# 2. 解包到 extracted/
python extract_cvd.py cvd/main.cvd cvd/daily.cvd

# 3. 导入 SHA256 库（仅 64hex 行；幂等增量）
python -c "from scanner import HashSignatureDB; db = HashSignatureDB('signatures/sha256.db'); \
[db.import_hdb(f) for f in ['extracted/main.main.hdb','extracted/main.main.hsb', \
'extracted/daily.daily.hdb','extracted/daily.daily.hsb']]; db.finalize(); db.close()"

# 4. 构建 MD5 库（仅 32hex 行）
python build_md5_db.py

# 5. 批量导入官方 sha256 分桶（hdb/00.hdb~ff.hdb, 可选, 实测 62,586,907 行）
python -c "
import glob
from scanner import HashSignatureDB
db = HashSignatureDB('signatures/sha256.db')
for f in sorted(glob.glob('hdb/*.hdb')):
    n = db.import_hdb(f); print(f, '+', n)
db.finalize(); db.close()"

# 5b. 构建模糊哈希增强库（hdb/ 8 字段行提取 5 种模糊哈希）
python build_fuzzy_db.py

# 6. 拉取第三方 YARA 规则（可选）
python fetch_yara.py

# 7. 重启服务生效
```

### 9.3 日常扩充

- **SHA256 哈希**：往 `signatures/*.hdb` 追加 `hash:size:name` 行（仅 64hex 生效），重启自动导入
- **YARA**：往 `signatures/*.yar` 追加规则，重启生效
- **壳库**：往 `packer_rules/` 添加 `.yar`（meta 声明 `packer` 壳族），重启生效
- **Web 管理端**：`/admin/hash` 页面单条增删查 + 批量导入（即时生效，无需重启）

### 9.4 测试与压测

```bash
python test_shards.py        # 分片库不变量测试（命中/重分片/懒加载）应 ALL PASS
python test_filetype.py      # 文件类型识别验证（26+ 类样本）

python gen_sigs.py --n 10000000   # 生成 1000 万条合成签名
python bench.py                    # 延迟/内存/磁盘基准
```

### 9.5 生产部署建议

- 用 `waitress` / `gunicorn` 多 worker 替代内置服务器
- `host` 保持 `127.0.0.1` 或置于内网 + Nginx 反代后暴露
- 公网访问务必配置 `api_token` 并启用 HTTPS

---

## 10. Web API 接口

> 认证：配置 `api_token` 后全部检测接口需 `Authorization: Bearer <token>` 或 `?token=`；限流：`/scan` 超 30 次/分/IP 返回 429。

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 搜索首页（哈希查询 + 拖拽上传 + 统计） |
| `/scan` | GET | VirusTotal 风格扫描页 |
| `/scan` | POST | 上传扫描（multipart 字段 `file`，全程内存不落盘）。两段式：立即返回阶段1 哈希结果 + `task_id`；缓存命中直接返回 `cached:true` |
| `/api/task/<task_id>` | GET | 轮询阶段2 进度（phase2 / done / error；任务 TTL 600s） |
| `/api/stats` | GET | 引擎统计（哈希/MD5/模糊/YARA/壳库条数与存储状态） |
| `/api/hash/<hash>` | GET | 哈希查询：32hex→MD5 库，64hex→SHA256 库；SHA256 命中附加 fuzzy 信息 |
| `/file/<sha256>` | GET | 文件报告详情页（VT 风格） |
| `/api/file/<sha256>` | GET | 读缓存扫描报告（未扫描过返回 404） |
| `/admin/login` | GET/POST | 管理员登录（session） |
| `/admin/logout` | GET | 登出 |
| `/admin/hash` | GET | 哈希签名管理页（需登录） |
| `/api/admin/hash/<hash>` | GET | 查询单条签名（需登录） |
| `/api/admin/hash` | POST | 新增单条签名 `{hash, size, name}`（需登录，Bloom 增量即时生效） |
| `/api/admin/hash/<hash>` | DELETE | 删除单条签名（需登录） |
| `/api/admin/import` | POST | 批量导入 `.hdb/.hsb/.yar`（需登录，存入 `signatures/` 持久化） |

---

## 11. 安全机制

| 类别 | 机制 | 实现位置 |
|------|------|---------|
| API 认证 | Bearer token（可选，默认匿名本地模式） | app.py L365-374 |
| 管理端认证 | session + `SHA-256(salt:password)` + 常量时间比较；`next` 仅站内路径防开放重定向；响应 `Cache-Control: no-store` | app.py L385-405, L713-746 |
| 限流 | 每 IP 每分钟滑动窗口（默认 30 次），超限 429 | app.py L419-432 |
| 上传限制 | `max_upload_mb`（默认 10MB，413 拒绝）+ 前端本地预检 | app.py L109, L531 |
| 阶段2 资源上限 | 超 32MB 仅跑 YARA；后台线程信号量限并发（4） | app.py L619-651 |
| CPU 放大封堵 | 熵采样 4MB/节 + 总预算 16MB + magic 搜索 32MB（对抗恶意 PE 构造，实测 34 倍提速） | packer.py L57-63 |
| YARA 超时 | match timeout 10-30s，超时返回标记而非阻塞 | scanner.py L1708-1741 |
| 任务内存上限 | `TASKS_MAX=100` / `TASK_TTL=600s` 惰性清理 | app.py L437-452 |
| XSS 防护 | 前端所有动态内容经 `esc()`（textContent 级转义）插入 | static/app.js |
| 缓存写入 | 临时文件 + `os.replace` 原子替换（Windows 重试 5 次） | app.py L287-314 |

已知低风险项（未修复）：无安全响应头（可前置 Nginx）、无 CSRF 令牌（无状态 API + Bearer 认证风险低）、依赖未锁精确版本、任务结果驻留内存（TTL 已限制）。

---

## 附：性能参考数据

| 指标 | 数值（千万级签名实测） |
|------|---------------------|
| 常驻内存 | 11.43 MB（仅 Bloom 位图） |
| 磁盘占用 | 590 MB（SQLite） |
| 启动耗时 | ~1.0 s |
| 未命中查询 | 0.009 ms/次 |
| 命中查询 | 0.014 ms/次（200/200 验证） |
| 端到端扫描 | ~1 ms（含哈希计算） |

对比纯内存 dict 方案（千万条约 3GB+ 内存），内存降低两个数量级，且获得持久化与增量更新能力。
