# NKREPO Scanner

轻量级静态恶意软件扫描平台（类 VirusTotal 极简版）：**上传文件 → 干净 / 报毒**。

仅实现两类静态检测，无其它特征类型：

| 引擎      | 说明                         | 签名格式                                          |
| ------- | -------------------------- | --------------------------------------------- |
| Hash DB | 整文件 MD5 / SHA1 / SHA256 比对 | 兼容 ClamAV `.hdb` / `.hsb`：`hash:size:virname` |
| YARA    | 字节模式 + 规则逻辑                | 标准 `.yar` 规则语法                                |

另附 **文件类型识别**（`filetype.py`，移植自 ClamAV FTM 机制），扫描结果中展示类型名称、`CL_TYPE_*` 码、分类与判定方法。

当前签名库为 **ClamAV 官方真实病毒库**（main v63 + daily v28092，2026-08-14 快照）中的全部整文件哈希签名，共 **540,357 条**。

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

哈希签名不是明文 `.hdb` 直读，而是三层架构，`check()` 接口对上层透明：

```
查询 hash
   │
   ▼
① Bloom 预过滤 ──── 1% 误判率位图（k=7），肯定不在库 → 直接返回未命中
   │ 可能命中
   ▼
② 内存排序数组 ──── 32B/条二进制摘要，bisect 二分查找（>200 万条时启用）
   │
   ▼
③ SQLite 持久层 ─── BLOB 主键 + WITHOUT ROWID，磁盘存储，增量导入
```

- `.hdb/.hsb` 只是**导入格式**：启动时自动导入 `signatures/` 下的新文件（`imported_files` 表去重，幂等）
- Bloom 位图持久化到 `signatures/signatures.db.bloom`，签名总数不变不重建（首次构建千万条约 43s，之后启动即加载）

### 千万级实测数据（1000 万条合成签名）

| 指标    | 数值                     |
| ----- | ---------------------- |
| 常驻内存  | 11.43 MB（仅 Bloom 位图）   |
| 磁盘占用  | 590 MB（SQLite）         |
| 启动耗时  | ~1.0 s                 |
| 未命中查询 | 0.009 ms/次             |
| 命中查询  | 0.014 ms/次（200/200 验证） |
| 端到端扫描 | ~1 ms（含哈希计算）           |

对比纯内存 dict 方案（千万条约 3GB+ 内存、每次重启重新解析明文），内存降低两个数量级，且获得持久化与增量更新能力。

## 运行

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt   # Windows
# source venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
venv\Scripts\python app.py
```

打开 <http://127.0.0.1:5000>

依赖：`flask` + `yara-python`（Windows 下 pip 有预编译 wheel）。

## 目录结构

```
nkrepo-scanner/
├── app.py                        # Flask Web 服务（/、/scan、/api/stats）
├── scanner.py                    # 扫描核心（HashSignatureDB 三层存储 + YaraScanner）
├── filetype.py                   # 文件类型识别（ClamAV FTM 魔数机制移植）
├── test_filetype.py              # 文件类型识别验证脚本（27 类样本）
├── templates/index.html          # Web 界面（拖拽上传 + 结果展示 + 类型徽章）
├── extract_cvd.py                # 从 ClamAV .cvd 病毒库解包提取签名
├── gen_sigs.py                   # 合成签名生成器（压测用）
├── bench.py                      # 性能基准（延迟 / 内存 / 磁盘）
├── signatures/
│   ├── hashes.hdb                # 本地哈希签名（含 EICAR）
│   ├── rules.yar                 # YARA 规则集
│   ├── signatures.db             # SQLite 签名库（运行时生成）
│   └── signatures.db.bloom       # Bloom 位图（运行时生成）
├── extracted/                    # CVD 解包产物（hdb/hsb/mdb/ndb/ldb/fp...）
├── cvd/                          # 下载的 main.cvd / daily.cvd
├── uploads/                      # 测试样本（eicar.com / marker.txt / clean.txt）
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

# 3. 导入 SQLite（增量、幂等）
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
| `/scan`      | POST | 上传文件（multipart 字段 `file`），返回 JSON：`verdict`（CLEAN/DETECTED）、`detections`（引擎+病毒名+哈希明细）、`file_type_info`（类型名/CL_TYPE 码/分类/判定方法）、`elapsed_ms` |
| `/api/stats` | GET  | 签名统计：哈希签名数、YARA 规则数、存储层（tier）、Bloom/内存数组状态                                                         |

## 验证

生成 EICAR 测试文件上传（应报 `EICAR-Test-File`，同时命中 YARA `EICAR_Test_String`）：

```bash
python -c "open('eicar.com','wb').write(b'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')"
```

`uploads/` 下已有现成测试样本：`eicar.com`（报毒）、`marker.txt`（YARA 报毒）、`clean.txt`（放行）。

## 设计参考

- 哈希存储的「排序数组 + 二分查找 + 按需分层」思路对齐 ClamAV `libclamav/matcher-hash.c` 的实现
- Bloom 预过滤利用安全检测「宁误报不漏报」的特性，先以 1.2MB/百万条 的内存成本拒绝绝大部分干净查询
- YARA 部分由 yara-python 编译执行，规则本身即可高效处理上万条
- 文件类型识别移植自 ClamAV `libclamav/filetypes.c` + `filetypes_int.h`（FTM 签名表、MAGIC_BUFFER_SIZE=1024、ooxml_detect 条目名细分、cli_texttype 文本检测兜底）
