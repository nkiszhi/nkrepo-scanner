# NKREPO Scanner

轻量级静态恶意软件扫描平台（类 VirusTotal 极简版）：**上传文件 → 干净 / 报毒**。

仅实现三类静态检测，无其它特征类型：

| 引擎      | 说明                         | 签名格式                                          |
| ------- | -------------------------- | --------------------------------------------- |
| Hash DB | 整文件 MD5 / SHA1 / SHA256 比对 | 兼容 ClamAV `.hdb` / `.hsb`：`hash:size:virname` |
| YARA    | 字节模式 + 规则逻辑                | 标准 `.yar` 规则语法                                |
| 模糊哈希  | ssdeep / TLSH / imphash / authentihash（vhash 仅标注） | 见「静态信息与模糊哈希」章节            |

另附 **文件类型识别**（`filetype.py`，移植自 ClamAV FTM 机制），扫描结果中展示类型名称、`CL_TYPE_*` 码、分类与判定方法。

当前签名库为 **ClamAV 官方真实病毒库**（main v63 + daily v28092，2026-08-14 快照）中的全部整文件哈希签名，共 **540,357 条**，当前按 `bloom.shards = 4` 拆为 4 个分片存储。

## 静态信息与模糊哈希

每次扫描（≤8MB 的文件）都会计算一组**模糊哈希 / 静态特征**，随 `/scan` 响应返回并展示在 Web 界面：

| 字段          | 算法                                                             | 适用样本    | 缺失原因（Web 上悬停 `-` 可见）                |
| ----------- | -------------------------------------------------------------- | ------- | ---------------------------------- |
| `ssdeep`    | 上下文触发分段哈希（CTPH），SpamSum 兼容，基于 **ppdeep**（纯 Python）        | 任意类型   | 输入 <32B / 超过 8MB 上限 / 未安装 ppdeep |
| `tlsh`      | Trend Micro 局部敏感哈希，基于本地 **`tlsh.py`**（官方 C 算法 JS 移植，纯 Python） | 任意类型   | 输入 <50B / 内容复杂度不足 / 超过 8MB 上限    |
| `imphash`   | PE 导入表哈希（pefile）                                            | 仅 PE    | 非 PE 样本                            |
| `authentihash` | PE Authenticode 哈希：清零 OptionalHeader.CheckSum 与 Security Directory 条目后 SHA256 全文件 | 仅 PE | 非 PE 样本 |
| `vhash`     | VirusTotal 私有算法                                                 | -       | **本地无法复现**，仅标注字段，恒为 `null`       |

- **8MB 上限（`FUZZY_MAX_BYTES`）**：ssdeep/TLSH 为纯 Python 逐字节实现，超大文件耗时失控，超过上限跳过（8MB 随机数据约 1s）；PE 的 imphash/authentihash 与元数据不受上限影响
- **PE 静态元数据**（`static_info.pe`）：machine 架构、64 位标记、编译时间戳、subsystem、入口点、ImageBase、节表（名称/VirtualSize/RawSize/Flags）、导入表（每 DLL 最多列出 32 个函数）
- 所有哈希不可用时返回 `null`，原因汇总在 `static_info.notes`
- TLSH 纯 Python 移植已用官方 JS 实现（trendmicro/tlsh `js_ext/tlsh.js`）交叉验证：9 类用例（文本/随机/低熵/256B 边界/真实 PE）输出**完全一致**；低熵输入同样返回不可用

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
查询 hash (md5 / sha1 / sha256)
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

- 分片目录 `signatures/signatures.db.shards/`：`0000.db` ~ `{N-1:04d}.db` 共 N 个小库 + `_meta.db`（导入记录、分片计数与布局标记）；单分片体量仅为全库 1/N，点查与增量导入互不干扰
- MD5 / SHA1 / SHA256 签名按**各自哈希**的摘要路由，查询顺序 sha256 → sha1 → md5、命中即短路（见「并发与 IO 说明」），最坏情况打开 3 个分片、通常只需 1 个；冷启动 0 分片加载，随查询按需打开
- Bloom 位图与 SQLite 分片一一对应，持久化到 `signatures/signatures.db.bloom/{shard_id:04d}.bloom`，签名总数不变不重建
- `.hdb/.hsb` 只是**导入格式**：启动时自动导入 `signatures/` 下的新文件（`imported_files` 表去重，幂等）
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
    "max_upload_mb": 50,    // /scan 上传大小上限 (MB)
    "uploads_dir": "uploads" // 上传测试样本目录: 相对路径基于项目根目录解析, 也支持绝对路径; 启动时目录不存在会自动创建
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
- **sha256 优先短路**：查询顺序 sha256 → sha1 → md5，任一命中即返回，恶意文件平均只做 1 次
  Bloom + SQL 点查
- **Bloom 热路径**：`_positions`（blake2b 双哈希 → k 个位）带实例级 LRU 缓存（上限 4096），
  重复样本直接复用位置数组，省去重复哈希与求模
- **内存扫描阈值**：`Scanner.INLINE_LIMIT = 64MB` —— ≤64MB 的文件一次性读入内存，
  哈希 / 类型识别 / YARA 复用同一份缓冲；更大文件自动退回分块 + 路径扫描（`_scan_large`），
  防止大文件占满内存；Web 端 `/scan` 另有 `server.max_upload_mb`（默认 50MB）上限
- 生产环境建议用 `waitress` / `gunicorn` 多 worker 替代内置服务器

## 目录结构

```
nkrepo-scanner/
├── app.py                        # Flask Web 服务（/、/scan、/api/stats）
├── scanner.py                    # 扫描核心（HashSignatureDB 动态分片存储 + YaraScanner + 静态信息集成）
├── staticinfo.py                 # 静态信息与模糊哈希（ssdeep/tlsh/imphash/authentihash + PE 元数据）
├── tlsh.py                       # TLSH 纯 Python 实现（官方 C 算法 JS 移植，无第三方依赖）
├── filetype.py                   # 文件类型识别（ClamAV FTM 魔数机制移植）
├── test_filetype.py              # 文件类型识别验证脚本（27 类样本）
├── templates/index.html          # Web 界面（拖拽上传 + 结果展示 + 类型徽章 + 模糊哈希/PE 元数据）
├── config.json                   # 配置（bloom 分片数/误判率、连接缓存上限、服务端口/上传目录）
├── extract_cvd.py                # 从 ClamAV .cvd 病毒库解包提取签名
├── gen_sigs.py                   # 合成签名生成器（压测用）
├── bench.py                      # 性能基准（延迟 / 内存 / 磁盘）
├── signatures/
│   ├── hashes.hdb                # 本地哈希签名（含 EICAR）
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
#    如需覆盖可传 shard_count=N）
python -c "from scanner import HashSignatureDB; db = HashSignatureDB('signatures/signatures.db'); \
[db.import_hdb(f) for f in ['extracted/main.main.hdb','extracted/main.main.hsb', \
'extracted/daily.daily.hdb','extracted/daily.daily.hsb']]; db.finalize(); db.close()"

# 4. 重启服务生效
```

CVD 文件为 512 字节头 + gzip 压缩 tar，`extract_cvd.py` 解包后会顺带提取 `.mdb/.ndb/.ldb` 等其它类型签名（留在 `extracted/`，约 280MB），本平台暂不使用，可作为日后扩展字节级检测的数据源。

### 日常扩充

- **哈希**：往 `signatures/*.hdb` 追加 `hash:size:name` 行（size 为 `*` 时通配大小），或放入任何 ClamAV 格式 `.hdb/.hsb` 文件，重启自动导入
- **YARA**：往 `signatures/*.yar` 追加规则或新增 `.yar` 文件，重启生效

### 压测

```bash
python gen_sigs.py --n 10000000   # 生成 1000 万条合成签名入库
python bench.py                   # 延迟 / 内存 / 磁盘基准
```

## API

| 接口           | 方法   | 说明                                                                                                 |
| ------------ | ---- | -------------------------------------------------------------------------------------------------- |
| `/`          | GET  | Web 界面                                                                                             |
| `/scan`      | POST | 上传文件（multipart 字段 `file`，**全程内存不落盘**，受 `server.max_upload_mb` 限制），返回 JSON：`verdict`（CLEAN/DETECTED）、`detections`（引擎+病毒名+哈希明细）、`file_type_info`（类型名/CL_TYPE 码/分类/判定方法）、`md5/sha1/sha256`、`static_info`（`fuzzy`：ssdeep/tlsh/imphash/authentihash/vhash；`pe`：PE 元数据；`notes`：缺失原因，≤8MB 文件计算）、`static_ms`（静态分析耗时）、`elapsed_ms` |
| `/api/stats` | GET  | 签名统计：`hash_signatures`（哈希条数）、`yara_rules`、`yara_available`、`hash_sources`/`yara_sources`（签名来源文件）、`storage`（存储层 tier / 分片 / Bloom 位图状态，见下） |

## 验证

生成 EICAR 测试文件上传（应报 `EICAR-Test-File`，同时命中 YARA `EICAR_Test_String`）：

```bash
python -c "open('eicar.com','wb').write(b'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')"
```

`uploads/` 下现有测试样本：`marker.txt`（YARA 报毒）、`clean.txt`（放行）；`eicar.com` 因安全工具会拦截其文件读写、不入库，用上面命令在 `uploads/` 下生成即可（其余 `tmp*` 为上传残留，自动忽略）。

## 设计参考

- 哈希存储「Bloom 预过滤 + 按摘要取模动态分片 + BLOB 主键点查」，以分片粒度持久化 SQLite 与位图，冷启动零加载、按查询懒加载，思路对齐 ClamAV `libclamav/matcher-hash.c` 的哈希匹配层级
- Bloom 预过滤利用安全检测「宁误报不漏报」的特性，先以 1.2MB/百万条 的内存成本拒绝绝大部分干净查询
- YARA 部分由 yara-python 编译执行，规则本身即可高效处理上万条
- 文件类型识别移植自 ClamAV `libclamav/filetypes.c` + `filetypes_int.h`（FTM 签名表、MAGIC_BUFFER_SIZE=1024、ooxml_detect 条目名细分、cli_texttype 文本检测兜底）
