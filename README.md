# NKAMG Scanner

轻量级静态恶意软件扫描平台（类 VirusTotal 极简版）：**上传文件 → 干净 / 报毒**。

仅实现四类静态检测，无其它特征类型：

| 引擎      | 说明                         | 签名格式                                          |
| ------- | -------------------------- | --------------------------------------------- |
| Hash DB | 整文件 **SHA256** 比对（当前 62,587,049 条，v3 起库内仅存 SHA256 签名，MD5/SHA1 参数仅接口兼容） | 兼容 ClamAV `.hdb` / `.hsb`：`hash:size:virname`；导入**仅接受 64hex（SHA256）行**，32hex（md5）/ 40hex（sha1）行计数跳过 |
| YARA    | 字节模式 + 规则逻辑                | 标准 `.yar` 规则语法                                |
| 模糊哈希  | ssdeep / TLSH / imphash / authentihash | 见「静态信息与模糊哈希」章节            |
| 查壳     | 多特征融合识别（DIE 特征体系 + PEiD 经典库 + 外部 YARA 扩展规则） | 精确特征（magic/EP 字节/节名/外部规则）+ 启发特征（节熵/导入/RWX/EP 位置） |

另附 **文件类型识别**（`filetype.py`，移植自 ClamAV FTM 机制），扫描结果中展示类型名称、`CL_TYPE_*` 码、分类与判定方法。

当前签名库：**62,587,049 条 SHA256 整文件哈希签名**，源自 ClamAV 官方病毒库整文件哈希（`signatures/hdb/` 下 256 个分桶 `.hdb` 文件，共 62,586,907 行且全部为 64hex sha256 签名，2026-08-17 全量导入），按 `bloom.shards = 4` 拆为 4 个分片存储（单分片约 1,560 万条，分片库合计约 4.4GB）。

> 历史背景：v3 迁移曾将旧库 540,357 条 md5/sha1 签名按用户决策移除、仅保留 186 条 sha256（备份见 `000X.db.pre_multi_hash.bak` / `000X.db.pre_sha256_pk.bak`）；随后全量导入官方 sha256 分桶库，检测能力恢复并超越至 6200 万+ 条。

## 静态信息与模糊哈希

Web 扫描采用**两段式**：`/scan` 先返回**哈希查询结果**（MD5/SHA1/SHA256 计算值 + 哈希签名库命中 + 文件类型，毫秒级；其中**库比对仅 sha256 生效**，见「存储架构」），随后在后台计算一组**模糊哈希 / 静态特征**（≤256KB 的文件），前端轮询 `/api/task/<id>` **动态更新**展示（类似 VirusTotal 的渐进式结果，深度分析完成前卡片保持 `SCANNING` 状态）：

| 字段          | 算法                                                             | 适用样本    | 缺失原因（Web 上悬停 `-` 可见）                |
| ----------- | -------------------------------------------------------------- | ------- | ---------------------------------- |
| `ssdeep`    | 上下文触发分段哈希（CTPH），SpamSum 兼容，基于 **ppdeep**（纯 Python）        | 任意类型   | 输入 <32B / 超过 256KB 上限 / 未安装 ppdeep |
| `tlsh`      | Trend Micro 局部敏感哈希，基于本地 **`tlsh.py`**（官方 C 算法 JS 移植，纯 Python） | 任意类型   | 输入 <50B / 内容复杂度不足 / 超过 256KB 上限    |
| `imphash`   | PE 导入表哈希（pefile）                                            | 仅 PE    | 非 PE 样本                            |
| `authentihash` | PE Authenticode 哈希：清零 OptionalHeader.CheckSum 与 Security Directory 条目后 SHA256 全文件 | 仅 PE | 非 PE 样本 |

- **256KB 上限（`FUZZY_MAX_BYTES`）**：ssdeep/TLSH 为纯 Python 逐字节实现，耗时随输入近线性增长，超大文件会阻塞 Web 阶段2 后台线程。实测 256KB 约 1.4s、512KB 约 7.4s、1MB 约 24s、3MB 约 73s，故上限收紧至 256KB；超过仅跳过模糊哈希，PE 的 imphash/authentihash 与元数据不受影响
- **PE 静态元数据**（`static_info.pe`）：machine 架构、64 位标记、编译时间戳、subsystem、入口点、ImageBase、节表（名称/VirtualSize/RawSize/Flags）、导入表（每 DLL 最多列出 32 个函数）

## 壳 / Packer 识别（`static_info.packer`）

参考 **VirusTotal 静态查壳架构**，多特征融合识别（`packer.py`）：

| 信号类型 | 特征 | 说明 |
| ------ | ---- | ---- |
| **精确特征** | overlay / 文件内 magic 字符串 | DIE 特征体系风格，如 `UPX!`、`MPRESS`、`ASPack`；短 magic（<5B）仅限 overlay，避免全文件误报 |
| | EP 字节模式 | PEiD 经典特征库风格，入口点 hex 序列前缀匹配（支持 `??` 通配），如 `60 E8 03 00 00 00 61 E9` |
| | 特征节名 | `UPX0/UPX1`、`.aspack`、`.petite`、`.vmp0`、`.themida` 等 23 类 |
| | 外部 YARA 规则 | `packer_rules/` 下 `.yar` 规则命中，即精确特征（meta 声明壳族，见下文） |
| **启发特征** | 节熵 | 最高节熵 ≥ 7.0 或 ≥2 节 ≥ 6.5（疑似压缩/加密） |
| | 导入表条目数 | ≤ 15 个函数（加壳程序导入极少） |
| | RWX 节存在性 | 节特性含 READ\|WRITE\|EXECUTE（0xE0000000） |
| | 入口点位于最后一节 | 壳代码通常垫在文件末尾 |

融合判定输出：`detected`、`confidence`（high/medium/low）、`packers`（壳名 + 证据信号列表）、`packed_score`（0-100 加壳评分）、`heuristics`（启发信号明细）、`summary`、`yara_rules_loaded`（外部规则数）、`yara_error`（规则编译错误汇总）。

- 精确特征命中 → 直接报具体壳名（如 UPX），证据 ≥3 分判 high
- 无精确特征但 ≥3 条启发信号（≥35 分）→ 报 `Unknown (启发式)`，medium
- 未达判定线 → `detected=false`，启发信号仍随结果返回供研判
- 所有哈希不可用时返回 `null`，原因汇总在 `static_info.notes`
- TLSH 纯 Python 移植已用官方 JS 实现（trendmicro/tlsh `js_ext/tlsh.js`）交叉验证：9 类用例（文本/随机/低熵/256B 边界/真实 PE）输出**完全一致**；低熵输入同样返回不可用

### 外部 YARA 扩展壳库（`packer_rules/`）

内置 DIE + PEiD 特征之外，支持用 **YARA 规则扩展壳库**：`packer_rules/` 目录下所有 `.yar`/`.yara` 规则启动时自动编译加载，命中后作为「精确特征」进入同一融合判定（权重累加 → 置信度 → packed_score）。规则 meta 约定：

| meta 字段 | 必选 | 说明 |
| --------- | ---- | ---- |
| `packer`  | 是   | 壳族名称（Web 显示名）；缺省取规则名 |
| `weight`  | 否   | 证据权重 1-5，默认 2（与内置同量纲：overlay magic=3 / 节名·EP=2 / 文件内 magic=1） |
| `desc`    | 否   | 证据描述，默认 `YARA 规则 <name> 命中` |
| `confidence` | 否 | 可选；缺省由融合推导（权重 ≥3 high / ≥2 medium / 其余 low） |

```yara
rule Packer_MPRESS_Magic {
    meta:
        packer = "MPRESS"
        weight = 3
        desc = "MPRESS 压缩标记"
    strings:
        $m = "MPRESS" nocase
    condition:
        uint16(0) == 0x5A4D and $m
}
```

- 建议 condition 加 `uint16(0) == 0x5A4D`（PE 魔数）前置，避免非 PE 误命中
- 多条规则命中同一壳族时权重累加；单个文件编译失败不影响其它规则（启动日志与 Web 端警告）
- 命中证据在 Web 端标注 `(YARA:<规则名>[...])` 来源；顶部徽章显示「外部规则 N 条」，加载有警告时置橙色
- 规则目录与匹配大小上限可在 `config.json` 的 `packer.rules_dir` / `packer.max_yara_bytes` 调整（默认 `packer_rules` / 16MB）；修改规则后重启服务生效

## 文件类型识别（ClamAV FTM 机制移植）

ClamAV 通过 `libclamav/filetypes.c` 的 **FTM（File Type Magic）签名表**（`filetypes_int.h`，镜像官方 `daily.ftm`）判断文件类型，签名格式 `type:offset:magic:名称:父类型:CL_TYPE_xxx`。`filetype.py` 按同样的四层判定链实现：

```
文件头 1024B (CL_FILE_MBUFF_SIZE)
   │
   ▼
① 固定偏移魔数 (type-0) ── ELF/Mach-O/ZIP/RAR/PDF/OLE2/PNG/LNK/pyc... 70+ 种
   │ 命中 ZIP 时 → 解析 local file header 条目名细分 OOXML (word/ xl/ ppt/)
   ▼
② 模式搜索 (type-1) ── MZ+PE\0\0 → PE；MZ+偏移魔数 → ZIP/RAR/7z/CAB SFX；HTML 标签
   │
   ▼
③ 尾部魔数 ── DMG 'koly' @ EOF-512
   │
   ▼
④ 文本编码检测兜底 ── BOM/UTF-8/UTF-16/ASCII（对应 ClamAV cli_texttype）
```

- 类型码沿用 ClamAV 的 `CL_TYPE_*` 命名，共 12 个 UI 分类（executable / document / archive / graphics / media / script / mail / text / disk / ai-model / data / binary）
- OOXML 细分与 ClamAV `ooxml_detect` 表一致：遍历前 1024 字节内全部 ZIP 条目名，强前缀（`word/`、`xl/`、`ppt/`、`META-INF/MANIFEST.MF`）优先于通用条目（`[Content_Types].xml`）
- `/scan` 响应新增 `file_type_info` 字段：`{"name": 类型名, "cl_type": "CL_TYPE_xxx", "category": 分类, "method": "magic|magic+ooxml|pattern|tail-magic|text-detect"}`
- 验证：`python test_filetype.py`（27 类样本全覆盖）

## 存储架构（千万级容量）

哈希签名不是明文 `.hdb` 直读，而是 **Bloom 预过滤 + 动态分片 SQLite**。分片数 N 完全由 `config.json` 的 `bloom.shards` 决定（任意正整数，默认 4），修改后下次启动自动重分片，`check()` 接口对上层透明：

```
查询 hash (sha256)
   │
   ▼
① Bloom 预过滤 ──── 1% 误判率位图（k=7），按 N 拆成独立位图文件（懒加载 + LRU），
                    肯定不在库 → 直接返回未命中
   │ 可能命中
   ▼
② 动态分片定位 ──── 取摘要前 4 字节 int.from_bytes(..., 'big') % N，映射 N 个分片之一
   │
   ▼
③ 分片点查 ─────── 只打开该分片对应的 signatures.db.shards/XXXX.db（只读连接，
                    懒加载 + LRU 缓存，上限 max_open_shards），BLOB 主键点查
```

- 分片目录 `signatures/signatures.db.shards/`：`0000.db` ~ `{N-1:04d}.db` 共 N 个小库 + `_meta.db`（导入记录、分片计数与布局标记）；单分片体量仅为全库 1/N，点查与增量导入互不干扰。当前（2026-08-17 全量导入后）4 分片实际计数：`15,637,579 / 15,650,214 / 15,650,005 / 15,649,251`，与 `_meta.db` 的 `shard_counts` 一致
- `sigs` 表为 **SHA256 主键结构**（v3，`_meta.db` 中 `schema_version=3` / `primary_key=sha256` 标记）：
  `sha256 BLOB PRIMARY KEY`（库内仅存 SHA256 签名，32B）、`size`、`name`，
  另有预留列 `md5` / `sha1`（同文件其它标准哈希，暂无数据源为 NULL）
  及 fuzzy 列 `ssdeep` / `tlsh` / `sdhash` / `mvhash`（预留：需原始样本源接入后回填）。
  查询走 `sha256` 主键点查；迁移前旧库备份为 `000X.db.pre_multi_hash.bak`，切主键前备份为 `000X.db.pre_sha256_pk.bak`
- **v3 起仅接受 SHA256 签名**：导入 `.hdb/.hsb` 时 64hex 行入库，32hex（md5）/ 40hex（sha1）行计数跳过并提示；查询只对 sha256 摘要做一次 Bloom 排除 + 主键点查（见「并发与 IO 说明」）；冷启动 0 分片加载，随查询按需打开
- Bloom 位图与 SQLite 分片一一对应，持久化到 `signatures/signatures.db.bloom/{shard_id:04d}.bloom`，签名总数不变不重建
- `.hdb/.hsb` 只是**导入格式**：启动时自动导入 `signatures/` **顶层**的新文件（`imported_files` 表去重，幂等）；`signatures/hdb/` 分桶子目录**不自动导入**，需按「签名库更新」章节的批量命令手动导入
- 自动重分片：检测到旧 hex 前缀布局（16/256/4096 片）或 `bloom.shards` 变更时，启动自动按新路由重分布（实测 54 万条 hex 256 → modulo 4 迁移约 20s），旧布局备份为 `signatures.db.shards.legacy`
- 兼容迁移：旧版单一 `signatures.db` 自动按前缀拆入分片（原文件保留为 `signatures.db.migrated`）；旧版单文件 Bloom（`signatures.db.bloom`）自动备份为 `signatures.db.bloom.legacy`

### 千万级实测数据（1000 万条合成签名）

> 下表在 256 分片配置下测得；当前默认 4 分片下 Bloom 位图按需懒加载，冷启动常驻内存更低，延迟量级不变。

| 指标    | 数值                     |
| ----- | ---------------------- |
| 常驻内存  | 11.43 MB（仅 Bloom 位图）   |
| 磁盘占用  | 590 MB（SQLite）         |
| 启动耗时  | ~1.0 s                 |
| 未命中查询 | 0.009 ms/次             |
| 命中查询  | 0.014 ms/次（200/200 验证） |
| 端到端扫描 | ~1 ms（含哈希计算）           |

对比纯内存 dict 方案（千万条约 3GB+ 内存、每次重启重新解析明文），内存降低两个数量级，且获得持久化与增量更新能力。

## 配置（config.json）

所有配置可在 `config.json` 中调整（缺省项回落到代码内默认值，`_` 开头的键为注释，不影响加载）：

```json
{
  "bloom": {
    "shards": 4,            // Bloom Filter 分片数, 同时驱动 SQLite 动态分片数 (任意正整数, 默认 4)
    "fp_rate": 0.01         // Bloom 误判率 (0.01 = 1%), 越小内存越大
  },
  "hash_db": {
    "max_open_shards": 4    // 分片 SQLite 连接 / Bloom 位图懒加载 LRU 缓存上限
  },
  "server": {
    "host": "127.0.0.1",
    "port": 5000,
    "max_upload_mb": 10,    // /scan 上传大小上限 (MB)
    "uploads_dir": "uploads", // 上传测试样本目录: 相对路径基于项目根目录解析, 也支持绝对路径; 启动时目录不存在会自动创建
    "api_token": "",        // API 认证: 留空 = 匿名本地模式; 配置后 /scan /api/task /api/stats 需带 Authorization: Bearer <token> 或 ?token=<token>
    "scan_rate_limit": 30,  // 每 IP 每分钟最多 /scan 次数 (0 = 不限), 防恶意刷扫描耗尽 CPU
    "phase2_max_mb": 32,    // 阶段2 深度分析(模糊哈希/PE元数据/查壳)的样本大小上限; 超过仅执行 YARA 并返回 phase2_note
    "phase2_concurrency": 4 // 阶段2 后台线程并发上限 (信号量, 超限排队), 控制 CPU 峰值
  },
  "packer": {
    "rules_dir": "packer_rules",   // 外部 YARA 扩展壳库目录 (相对项目根目录或绝对路径); 目录下所有 .yar/.yara 自动加载
    "max_yara_bytes": 16777216     // 外部规则匹配的样本大小上限 (16MB); 内置 DIE/PEiD 特征不受限
  }
}
```

> 修改 `bloom.shards` 后**下次启动自动重分片**（旧布局备份为 `.shards.legacy`），数据不丢失。

## 运行

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt   # Windows
# source venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
venv\Scripts\python app.py
```

打开 <http://127.0.0.1:5000>

依赖：`flask` + `yara-python` + `pefile` + `ppdeep`（Windows 下 pip 均有预编译 wheel 或纯 Python 实现；TLSH 为项目内置纯 Python 移植 `tlsh.py`，无需额外依赖）。

### 并发与 IO 说明（P0 优化）

- **多线程 Web 服务**：`app.py` 以 `threaded=True` 启动，每个请求独立线程；`/scan` 上传走
  内存流（`scan_bytes`），哈希 / 文件类型识别 / YARA 复用同一份缓冲，**全程不落盘**（每文件只读一遍）
- **查询并发模型**：`HashSignatureDB.check()` 不再持全局锁 —— Bloom 位图查询期只读（无锁读），
  SQLite 分片连接用**连接级串行锁**（同一连接内串行、不同分片连接并行，并发度 = min(分片数, LRU 上限)），
  LRU 字典操作用细粒度缓存锁；被淘汰的连接延迟到 `close()` 统一关闭
- **sha256 单次点查**：v3 起库内仅存 sha256 签名，查询只对 sha256 摘要做 1 次
  Bloom + SQL 主键点查（md5/sha1 参数仅为接口兼容，必然未命中）
- **Bloom 热路径**：`_positions`（blake2b 双哈希 → k 个位）带实例级 LRU 缓存（上限 4096），
  重复样本直接复用位置数组，省去重复哈希与求模
- **内存扫描阈值**：`Scanner.INLINE_LIMIT = 64MB` —— ≤64MB 的文件一次性读入内存，
  哈希 / 类型识别 / YARA 复用同一份缓冲；更大文件自动退回分块 + 路径扫描（`_scan_large`），
  防止大文件占满内存；Web 端 `/scan` 另有 `server.max_upload_mb`（默认 10MB）上限
- 生产环境建议用 `waitress` / `gunicorn` 多 worker 替代内置服务器

## 目录结构

```
nkrepo-scanner/
├── app.py                        # Flask Web 服务（/ 搜索首页、GET /scan 扫描页、POST /scan 两段式上传、/api/task/<id> 轮询、/api/stats、/api/hash/<sha256> 哈希查询）
├── scanner.py                    # 扫描核心（HashSignatureDB 动态分片存储 + YaraScanner + 静态信息集成）
├── staticinfo.py                 # 静态信息与模糊哈希（ssdeep/tlsh/imphash/authentihash + PE 元数据 + 壳检测）
├── packer.py                     # 壳/保护器识别（精确特征 DIE+PEiD+外部YARA规则 + 启发特征融合判定）
├── packer_rules/                 # 外部 YARA 扩展壳库（.yar 规则 + README.md 编写约定）
├── tlsh.py                       # TLSH 纯 Python 实现（官方 C 算法 JS 移植，无第三方依赖）
├── filetype.py                   # 文件类型识别（ClamAV FTM 魔数机制移植）
├── test_filetype.py              # 文件类型识别验证脚本（27 类样本）
├── static/
│   ├── app.css                   # 共享暗色主题样式（index / scan 两页共用，VirusTotal 风格）
│   └── app.js                    # 共享渲染库（扫描结果卡 / 检测环 / 哈希查询 / 统计加载；upload 带 onDone 回调）
├── templates/
│   ├── index.html                # 搜索首页（VT 风格大搜索框哈希查询 + 拖拽上传 + 统计卡 + 结果展示）
│   └── scan.html                 # 扫描页（GET /scan，VT 风格：FILE/URL/搜索选项条 + 大上传区 + 最近扫描历史 localStorage + 结果展示）
├── config.json                   # 配置（bloom 分片数/误判率、连接缓存上限、服务端口/上传目录）
├── extract_cvd.py                # 从 ClamAV .cvd 病毒库解包提取签名
├── gen_sigs.py                   # 合成签名生成器（压测用）
├── bench.py                      # 性能基准（延迟 / 内存 / 磁盘）
├── signatures/
│   ├── hashes.hdb                # 本地哈希签名（含 EICAR 三种哈希行；仅 SHA256 行生效）
│   ├── hdb/                      # ClamAV 官方整文件哈希分桶（00.hdb~ff.hdb 共 256 文件，全部 64hex sha256，约 5.5GB，62,586,907 行）
│   ├── rules.yar                 # YARA 规则集
│   ├── signatures.db.shards/     # 动态分片 SQLite（0000.db~{N-1}.db + _meta.db，运行时生成）
│   ├── signatures.db.bloom/      # 分片 Bloom 位图（0000.bloom~{N-1}.bloom，运行时生成）
│   └── *.legacy / *.migrated     # 旧布局/旧版单库备份（自动迁移时生成）
├── extracted/                    # CVD 解包产物（hdb/hsb/mdb/ndb/ldb/fp...）
├── cvd/                          # 下载的 main.cvd / daily.cvd
├── uploads/                      # 测试样本目录（路径由 server.uploads_dir 配置，相对项目根目录或绝对路径；启动时不存在会自动创建；/scan 上传不落盘）
└── requirements.txt
```

## 签名库更新

### 导入 ClamAV 官方库（真实签名）

```bash
# 1. 下载官方病毒库（database.clamav.net 或可信镜像）
curl -A "ClamAV/freshclam/1.4.2" -O https://database.clamav.net/main.cvd
curl -A "ClamAV/freshclam/1.4.2" -O https://database.clamav.net/daily.cvd

# 2. 解包提取整文件哈希签名到 extracted/
python extract_cvd.py cvd/main.cvd cvd/daily.cvd

# 3. 导入 SQLite（增量、幂等; 分片数默认取 config 的 bloom.shards=4,
#    如需覆盖可传 shard_count=N; 注意: v3 起仅接受 64hex(SHA256) 行,
#    官方 main/daily 库中 32hex(md5)/40hex(sha1) 行会被跳过, 仅 SHA256 实际入库)
python -c "from scanner import HashSignatureDB; db = HashSignatureDB('signatures/signatures.db'); \
[db.import_hdb(f) for f in ['extracted/main.main.hdb','extracted/main.main.hsb', \
'extracted/daily.daily.hdb','extracted/daily.daily.hsb']]; db.finalize(); db.close()"

# 4. 批量导入官方 sha256 分桶库（signatures/hdb/ 下 00.hdb~ff.hdb, 全为 64hex;
#    实测 62,586,907 行: 导入约 41min + Bloom 重建约 7min, 幂等可重复续导)
python -c "
import glob
from scanner import HashSignatureDB
db = HashSignatureDB('signatures/signatures.db')
for f in sorted(glob.glob('signatures/hdb/*.hdb')):
    n = db.import_hdb(f)
    print(f, '+', n)
db.finalize(); db.close()"

# 5. 重启服务生效
```

CVD 文件为 512 字节头 + gzip 压缩 tar，`extract_cvd.py` 解包后会顺带提取 `.mdb/.ndb/.ldb` 等其它类型签名（留在 `extracted/`，约 280MB），本平台暂不使用，可作为日后扩展字节级检测的数据源。

### 日常扩充

- **哈希**：往 `signatures/*.hdb` 追加 `hash:size:name` 行（size 为 `*` 时通配大小），或放入任何 ClamAV 格式 `.hdb/.hsb` 文件，重启自动导入。**仅接受 64hex（SHA256）行**——32hex（md5）/ 40hex（sha1）行会被跳过并计数提示（如示例库 `hashes.hdb` 中非 64hex 行即为此类，仅 SHA256 行生效）；大规模分桶文件（如 `signatures/hdb/`）用上文批量命令导入
- **YARA**：往 `signatures/*.yar` 追加规则或新增 `.yar` 文件，重启生效
- **壳库（查壳扩展）**：往 `packer_rules/` 添加 `.yar` 规则（meta 声明 `packer` 壳族，约定见上文），重启生效——命中即作为查壳精确特征，**不进入报毒判定**

### 压测

```bash
python gen_sigs.py --n 10000000   # 生成 1000 万条合成签名入库
python bench.py                   # 延迟 / 内存 / 磁盘基准
```

## API

> **认证（可选）**：`config.json` 配置 `server.api_token` 后，以下全部接口需携带
> `Authorization: Bearer <token>` 或 `?token=<token>`，否则返回 `401`；留空则匿名放行（默认本地模式）。
> **限流**：`/scan` 每 IP 每分钟超过 `server.scan_rate_limit`（默认 30）次返回 `429`。
> 前端页面首次以 `http://host:port/?token=<token>` 访问会自动记住 token（localStorage），后续请求自动带认证头。

| 接口           | 方法   | 说明                                                                                                 |
| ------------ | ---- | -------------------------------------------------------------------------------------------------- |
| `/`          | GET  | Web 界面（搜索首页：SHA256 哈希查询 + 拖拽上传 + 统计；页面本身无需认证，数据接口受保护）                             |
| `/scan`      | GET  | Web 界面（VirusTotal 风格扫描页：FILE/URL/搜索选项条 + 大上传区 + 最近扫描历史，结果渲染与首页共用 `static/app.js`） |
| `/scan`      | POST | 上传文件（multipart 字段 `file`，**全程内存不落盘**，受 `server.max_upload_mb` 限制）。**两段式**：立即返回 `{task_id, status: "phase2", result}`，`result` 为阶段 1 哈希查询结果（`phase:"hash"`、`md5/sha1/sha256`、`file_type_info`、`detections` 仅含 Hash DB 命中、`elapsed_ms` 为阶段 1 耗时；**v3 起 Hash DB 仅按 sha256 点查**，md5/sha1 字段为计算展示值、不参与库比对）；阶段 2（YARA 规则 + `static_info` 模糊哈希/PE 元数据/查壳）由后台线程执行。超过 `server.phase2_max_mb` 的样本阶段 2 仅执行 YARA 并返回 `phase2_note` 说明，`static_info` 为空 |
| `/api/task/<task_id>` | GET | 轮询深度分析进度：`phase2`（进行中）/ `done`（返回 `{task_id, status:"done", result}`，`result.phase:"done"`，为阶段 1 + 阶段 2 合并的完整扫描结果，结构同旧版 `/scan`：`verdict`/`detections`（Hash DB + YARA）/`static_info`/`static_ms`/`elapsed_ms`，超限样本含 `phase2_note`）/ `error`（后台异常）；任务过期或不存在返回 404（内存保留 `TASKS_MAX=100` 个、`TASK_TTL=600s`） |
| `/api/stats` | GET  | 签名统计：`hash_signatures`（哈希条数）、`yara_rules`、`yara_available`、`packer_yara_rules`/`packer_yara_available`/`packer_yara_error`（壳库外部规则）、`hash_sources`/`yara_sources`（签名来源文件）、`storage`（存储层 tier / 分片 / Bloom 位图状态，见下）、`max_upload_mb`（上传大小上限，前端据此本地预检超限文件） |
| `/api/hash/<sha256>` | GET | SHA256 哈希查询（VirusTotal 风格首页搜索框）：校验 64 位 hex，命中与否均 200；返回 `{sha256, hit, detections, scanner}`，`hit=true` 时 `detections` 为签名库命中详情；非 64 位 hex 返回 400 |

## 安全

静态安全审查（OWASP 类别逐项）+ 动态恶意输入验证后落地的加固项：

- **认证（M1）**：`server.api_token` 非空时，`/scan`、`/api/task/<id>`、`/api/stats` 全部要求
  `Authorization: Bearer <token>` 或 `?token=<token>`（`401`）；默认留空 = 匿名本地模式，方便本机使用
- **限流（M1）**：`/scan` 每 IP 每分钟滑动窗口计数（`scan_rate_limit`，默认 30），超限 `429`，
  防未认证部署下被恶意刷扫描耗尽 CPU
- **阶段 2 资源上限（M3）**：超过 `phase2_max_mb`（默认 32MB）的样本跳过模糊哈希 / PE 元数据 / 查壳，
  仅执行 YARA（10s 超时）并返回 `phase2_note` —— 避免超大文件纯 Python 逐字节分析打满 CPU / 内存
- **CPU 放大封堵（M2）**：单节熵计算采样上限 4MB（`packer.ENTROPY_SAMPLE_BYTES`），全文件 magic
  搜索上限 32MB（`packer.MAGIC_FILE_SEARCH_BYTES`）—— 恶意 PE 把节 `PointerToRawData=0` /
  `SizeOfRawData=0xFFFFFFFF` 使熵切片覆盖全文件的放大向量实测 45MB 样本阶段 2 耗时
  **10.0s → 0.29s**（约 34 倍），且不再产生整文件 `lower()` 副本
- **CPU 放大封堵·节数维度（M2b，2026-08 复检发现）**：恶意 PE 可声明**大量节**（`NumberOfSections`
  最多 65535）且每节 `PointerToRawData=0` / `SizeOfRawData≥4MB`，使「切片 + 逐字节计数」按节数线性放大
  —— 实测 8MB 样本 100 节阶段 2 查壳耗时 **24.2s**。已增加节熵**总采样字节预算**
  `ENTROPY_TOTAL_BUDGET`（16MB，累计耗尽后跳过剩余节）：同一样本 100 / 1000 / 65535 节分别降至
  **0.93s / 0.93s / 1.05s**（pefile 自带 `MAX_SECTIONS=2048` 兜底），正常 PE 熵启发无回归
- **阶段 2 并发控制（M3）**：后台线程信号量 `phase2_concurrency`（默认 4），超限排队，防止 CPU 峰值打满
- **任务内存上限**：内存中任务保留 `TASKS_MAX=100` / `TASK_TTL=600s`，惰性清理防无限增长
- **前端 XSS 防护**：所有动态内容经 `esc()`（DOM textContent 级转义）后插入；上传大小受
  `server.max_upload_mb` 限制（413 超限拒绝）

> 已知低风险项（未修复，按需处理）：无安全响应头（`X-Frame-Options` 等，可前置 Nginx）、
> 无 CSRF 令牌（服务为无状态 API + Bearer 认证，CSRF 风险低）、`requirements.txt` 未锁定精确版本、
> 任务结果驻留内存（TTL 已限制）。
>
> 生产部署建议：`host` 保持 `127.0.0.1` 或置于内网 + 反代（Nginx）后暴露；如需公网访问务必配置
> `api_token` 并启用 HTTPS。

## 验证

### 系统功能测试（2026-08-17，全量导入 6200 万条后实测 12/12 PASS）

| 检查项 | 结果 |
| ------ | ---- |
| `GET /` 首页 / `GET /api/stats`（hash_signatures=62,587,049） | PASS |
| 库级 Hash DB 命中：从分片库读真实签名 → `db.check(sha256)` 命中（测试约定：**不使用 EICAR 文件**） | PASS |
| `/scan` 上传普通文本 → 无检测 | PASS |
| `/scan` 上传 MZ+UPX 伪样本 → 200 + 文件类型识别 | PASS |
| 两段式：`/api/task/<id>` 轮询至 `status=done`，`result` 合并 `static_info`（ssdeep/tlsh/packer/pe）与 `verdict` | PASS |
| 错误路径：缺 `file` 字段返回 400；超过 `max_upload_mb=10` 返回 413，且响应为明确 JSON `{"error":"文件过大: 超过上传上限 10MB, 请压缩后重试"}`（前端本地预检同文案，不发起请求） | PASS |

按项目约定**测试不使用 EICAR 文件**（本机杀软会锁定 EICAR 导致文件读写失败，且哈希不可反推文件内容）。哈希命中采用**库级直查**（直接传 sha256 字符串，不依赖构造文件内容），Web 层用普通/特征样本验证路径：

```bash
# 1) 库级 Hash DB 命中：从分片库读取一条真实签名并断言命中
python -c "
import sqlite3
from scanner import HashSignatureDB
db = HashSignatureDB('signatures/signatures.db')
conn = sqlite3.connect('file:signatures/signatures.db.shards/0000.db?mode=ro', uri=True)
h, size, name = conn.execute('SELECT hex(sha256), size, name FROM sigs LIMIT 1').fetchone()
hits = db.check('', size, '0'*32, '0'*40, h)
assert any(x['name'] == name for x in hits), f'应命中 {name}'
print(f'Hash DB 命中: {name} ({h[:16]}...)')
"

# 2) Web 层放行路径：上传普通文本 → 无检测
python -c "import requests; r = requests.post('http://127.0.0.1:5000/scan', files={'file': ('clean.txt', b'hello')}, timeout=30); print(r.status_code, r.json()['result']['detections'])"

# 3) Web 层 YARA 命中：构造含 NKAMG_Test_Marker 特征串的样本上传, 轮询至 done 应见 YARA 命中
python -c "
import requests, time
r = requests.post('http://127.0.0.1:5000/scan', files={'file': ('marker.txt', b'NKAMG-MALWARE-TEST-MARKER')}, timeout=30)
tid = r.json()['task_id']
for _ in range(20):
    rr = requests.get(f'http://127.0.0.1:5000/api/task/{tid}', timeout=10).json()
    if rr.get('status') == 'done':
        break
    time.sleep(0.5)
print(rr['result']['detections'])
"
```

`uploads/` 为运行时上传目录（重启清理，不入库）。库级自动化测试见 `test_shards.py`（自造 SHA256 签名导入临时库，验证命中 / 重分片保持命中 / Bloom 懒加载，运行 `python test_shards.py` 应 ALL PASS）；文件类型识别测试见 `test_filetype.py`；系统功能测试见上文表格（12/12 PASS）。

## 设计参考

- 哈希存储「Bloom 预过滤 + 按摘要取模动态分片 + BLOB 主键点查」，以分片粒度持久化 SQLite 与位图，冷启动零加载、按查询懒加载，思路对齐 ClamAV `libclamav/matcher-hash.c` 的哈希匹配层级
- Bloom 预过滤利用安全检测「宁误报不漏报」的特性，先以 1.2MB/百万条 的内存成本拒绝绝大部分干净查询
- YARA 部分由 yara-python 编译执行，规则本身即可高效处理上万条
- 文件类型识别移植自 ClamAV `libclamav/filetypes.c` + `filetypes_int.h`（FTM 签名表、MAGIC_BUFFER_SIZE=1024、ooxml_detect 条目名细分、cli_texttype 文本检测兜底）
