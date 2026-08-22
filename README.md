# NKAMG Scanner

轻量级静态恶意软件扫描平台（类 VirusTotal 极简版）：**上传文件 → 干净 / 报毒**。

仅实现四类静态检测，无其它特征类型：

| 引擎      | 说明                         | 签名格式                                          |
| ------- | -------------------------- | --------------------------------------------- |
| SHA256 Hash DB | 整文件 **SHA256** 哈希比对（**62,587,049 条**，主键）；Web 搜索框 64hex SHA256 可查询 | 兼容 ClamAV `.hdb` / `.hsb`：`hash:size:virname`；SHA256 库导入**仅接受 64hex 行**，其余长度计数跳过 |
| MD5 Hash DB | 整文件 **MD5** 哈希比对（**540,276 条**，独立并列库；2026-08-18 新增）；Web 搜索框 32hex MD5 可查询 | 由 `build_md5_db.py` 构建，**仅接受 32hex 行**，其余长度计数跳过 |
| YARA    | 字节模式 + 规则逻辑                | 标准 `.yar` 规则语法                                |
| 模糊哈希  | ssdeep / TLSH / imphash / authentihash | 见「静态信息与模糊哈希」章节            |
| SSDeep Hash DB | 与独立 SSDeep 库中签名做 **0-100 模糊匹配**（2026-08-21 新增, 2026-08-22 独立为单文件库, 非精确哈希比对） | 详见「ssdeep 相似度检测」章节          |
| TLSH Hash DB | 基于 TLSH 局部敏感哈希的相似度检测，**自增长库**（每次精确哈希命中的样本自动入库累积，2026-08-22 新增；同日 **v2 千万级优化**：BLOB 主键 + lv 索引剪枝 + numpy 向量化，检索 ~18-27×、哈希生成 ~7× 加速） | 详见「TLSH 哈希相似度检测」章节        |
| 查壳     | 多特征融合识别（DIE 特征体系 + PEiD 经典库 + 外部 YARA 扩展规则） | 精确特征（magic/EP 字节/节名/外部规则）+ 启发特征（节熵/导入/RWX/EP 位置） |

另附 **文件类型识别**（`filetype.py`，ClamAV FTM 机制移植 + 4 项结构化校验增强，2026-08-20）：扫描结果中展示类型名称、`CL_TYPE_*` 码、分类与判定方法；新增 ZIP 中央目录解析、PE 头结构校验、扩展名/魔数不一致可疑信号、libmagic 兜底层。详见「文件类型识别」章节。

当前签名库：**62,587,049 条 SHA256 整文件哈希签名**，源自 ClamAV 官方病毒库整文件哈希（项目根 `hdb/` 下 256 个分桶 `.hdb` 文件，每行 sha256 主键（64hex）+ filesize + name + 5 个模糊哈希字段共 8 段，合计 62,586,907 行，2026-08-17 全量导入），按 **256 hex 分片**（`layout=hex`，SHA256 前两字符路由到 `00.db`~`ff.db`）存储（单分片约 24 万条，分片库合计约 3.9GB）。另有**并列的 MD5 整文件哈希库 540,276 条**（独立 256 hex 分片库 `signatures/md5.db.shards/`，由 `build_md5_db.py` 从 `extracted/` 的 ClamAV `.hdb/.hsb` 提取 32hex MD5 签名构建，2026-08-18 新增，约 32MB），文件扫描与 Web 哈希查询均按哈希长度自动路由到对应库；以及**并列的模糊哈希增强库**（独立 256 hex 分片库 `signatures/fuzzy.db.shards/`，由 `build_fuzzy_db.py` 从 `hdb/` 8 字段行提取 ssdeep/vhash/authentihash/imphash/rich_header_hash 构建，2026-08-19 重构为 **5 表独立结构**，每种 fuzzy hash 以自身值为 PRIMARY KEY 独立成表，导入进行中 61,374,502 条，详见「模糊哈希增强库」）。

> 历史背景：v3 迁移曾将旧库 540,357 条 md5/sha1 签名按用户决策移除、仅保留 186 条 sha256（备份见 `000X.db.pre_multi_hash.bak` / `000X.db.pre_sha256_pk.bak`）；随后全量导入官方 sha256 分桶库，检测能力恢复并超越至 6200 万+ 条。2026-08-19 三库（SHA256/MD5/Fuzzy）统一迁移至 256 hex 分片布局，旧 4 分片 modulo 库备份为 `*.shards.bak_4shard`；Fuzzy 库同时从单表（sha256 PK + 5 fuzzy 列）重构为 5 表独立结构（每种 fuzzy hash 为主键），schema_version 升至 v4。

## 静态信息与模糊哈希

Web 扫描采用**两段式**：`/scan` 先返回**哈希查询结果**（MD5/SHA1/SHA256 计算值 + 哈希签名库命中 + 文件类型，毫秒级；**SHA256 比对 SHA256 库、MD5 比对并列的 MD5 库**均生效，见「存储架构」；**SHA1 不参与任何库查询但已计算**，供 Web 文件哈希展示），随后在后台计算一组**模糊哈希 / 静态特征**（≤2MB 的文件），前端轮询 `/api/task/<id>` **动态更新**展示（类似 VirusTotal 的渐进式结果，深度分析完成前卡片保持 `SCANNING` 状态）。阶段 2 中，**模糊哈希增强库查询**在 staticinfo 计算 ssdeep/imphash/authentihash 后执行——按计算出的 fuzzy hash 值查对应的 `sigs_*` 表（而非旧版按 SHA256 反查），命中返回 `engine="Fuzzy Hash DB"`。已完成扫描的结果按 SHA256 落盘缓存，重复上传同一文件直接命中缓存毫秒级返回（见「扫描缓存与报告详情页」）：

| 字段          | 算法                                                             | 适用样本    | 缺失原因（Web 上悬停 `-` 可见）                |
| ----------- | -------------------------------------------------------------- | ------- | ---------------------------------- |
| `ssdeep`    | 上下文触发分段哈希（CTPH），SpamSum 兼容，基于 **ppdeep**（纯 Python）        | 任意类型   | 输入 <32B / 超过 2MB 上限 / 未安装 ppdeep |
| `tlsh`      | Trend Micro 局部敏感哈希，基于本地 **`tlsh.py`**（官方 C 算法 JS 移植，纯 Python） | 任意类型   | 输入 <50B / 内容复杂度不足 / 超过 2MB 上限    |
| `imphash`   | PE 导入表哈希（pefile）                                            | 仅 PE    | 非 PE 样本                            |
| `authentihash` | PE Authenticode 哈希：清零 OptionalHeader.CheckSum 与 Security Directory 条目后 SHA256 全文件 | 仅 PE | 非 PE 样本 |

- **2MB 上限（`FUZZY_MAX_BYTES`）**：ssdeep/TLSH 为纯 Python 逐字节实现，耗时随输入近线性增长（实测 256KB 约 1.4s、512KB 约 7.4s、1MB 约 24s、3MB 约 73s）。绝大多数真实 PE 样本超过原来的 256KB 上限，故提升至 2MB 以覆盖常见样本体积；计算在 Web 阶段2 后台线程执行，不阻塞 HTTP 响应。超过 2MB 仅跳过模糊哈希，PE 的 imphash/authentihash 与元数据不受影响
- **PE 静态元数据**（`static_info.pe`）：machine 架构、64 位标记、编译时间戳、subsystem、入口点、ImageBase、节表（名称/VirtualSize/RawSize/Flags）、导入表（每 DLL 最多列出 32 个函数）

## 扫描缓存与报告详情页（2026-08-19 新增）

- **结果缓存**：阶段 1+2 全部完成后，合并结果以 `uploads/<sha256>.json` 落盘（与上传样本 `uploads/<sha256>` 同目录，原子写入：先写临时文件再 rename）。相同 SHA256 再次上传 `/scan` 时**直接命中缓存**返回完整结果（响应含 `cached: true`，`filename` / `submitted_at` 以本次上传为准），毫秒级跳过全部扫描
- **提交历史**：缓存内含 `history` 数组，每次上传（含缓存命中）追加 `{filename, submitted_at}`，保留最近 `HISTORY_MAX=100` 条；缓存命中路径的历史追加与写盘在**后台线程异步执行**（P2-2），不阻塞 HTTP 响应
- **缓存写入顺序**：先合并结果并写缓存，再标记任务 `done` —— 消除轮询到 `done` 但 `/api/file` 尚未就绪的 404 窗口
- **LRU 淘汰（C3）**：总量超过 `CACHE_MAX_FILES=10000` 时按 mtime 从旧到新删除，超过 `CACHE_MAX_AGE_DAYS=30` 天的过期删除；启动时后台强制清理一次 + 每次 `/scan` 提交后惰性触发（1 小时节流，高频上传不反复遍历目录）
- **报告详情页** `/file/<sha256>`（参考 VirusTotal `/gui/file/<hash>`）：渲染该文件的完整扫描报告（基本信息 / 哈希 / 检测命中 / 静态信息 / 提交历史）；非法哈希渲染友好提示而非裸 404。数据接口为 `GET /api/file/<sha256>`（读缓存；该文件未在本系统扫描过返回 404 `{"found": false}`）
- **报告页 Tab**：报告卡片含「检测结果」与「详细信息」两个 Tab，「详细信息」展示哈希值列表（SHA256/SHA1/MD5）与文件静态分析详细结果（文件类型、模糊哈希、PE 元数据/查壳等）
- **重新扫描**（2026-08-22 新增）：`/scan` 上传时按 SHA256 去重把原始字节保存到 `uploads/`（`server.uploads_dir` 配置，文件名即 `<sha256>`，扫描报告 `uploads/<sha256>.json` 同目录存储）；报告页横幅「重新扫描」按钮调用 `POST /api/rescan/<sha256>` 读取保存的样本重跑**完整**扫描，完成后覆盖更新 `uploads/<sha256>.json` 报告并在前端重渲染（提交历史追加一条）。样本随缓存 LRU 一起淘汰删除，防止磁盘无限增长

## 管理端（哈希签名管理，2026-08-19 新增）

检测功能（`/`、`/scan`、`/api/*`）**无需登录**；仅哈希管理页面 `/admin/hash` 与 `/api/admin/*` 接口要求管理员登录（Flask session）。

- **登录**：`/admin/login`（用户名 + 密码表单）。凭据存 `config.json` 的 `admin` 节——`username` / `salt` / `password_hash`，其中 `password_hash = SHA256(salt:password)`（明文不落配置）；校验用 `hmac.compare_digest` 常量时间比较防计时侧信道。登录跳转 `next` 参数仅接受站内相对路径（防开放重定向）；登出 `/admin/logout` 清空整个会话；管理响应统一带 `Cache-Control: no-store`（防登出后从浏览器缓存还原管理页）
- **管理页** `/admin/hash`：单条签名查 / 增 / 删 + 签名文件批量导入 + **SSDeep / TLSH 模糊哈希管理**（2026-08-22 新增）
- **API**（均需登录，未登录 GET 跳登录页 / 其余返回 401 JSON）：
  - `GET /api/admin/hash/<hash>`——按哈希查单条签名（32hex→MD5 库 / 64hex→SHA256 库，命中与否均 200）
  - `POST /api/admin/hash`——JSON `{hash, size, name}` 新增单条（自动按长度路由 SHA256/MD5 库；写分片 SQLite + **增量更新 Bloom** 即时生效；已存在返回 `added: 0`）
  - `DELETE /api/admin/hash/<hash>`——删除单条签名
  - `GET /api/admin/fuzzy/<kind>/<value>`——按值精确查询 SSDeep/TLSH 模糊哈希（`kind` = `ssdeep` / `tlsh`；命中返回关联的 sha256/size/name，命中与否均 200）
  - `POST /api/admin/fuzzy/<kind>`——JSON `{value, sha256, name?, size?}` 新增一条模糊哈希（写入 SSDeep/TLSH 自增长库，即时生效；SSDeep 需 `块大小:hash1:hash2` 或 ClamAV 短横线格式，TLSH 需 70 位十六进制，SHA256 必填 64hex）
  - `DELETE /api/admin/fuzzy/<kind>/<value>`——删除单条模糊哈希记录
  - `POST /api/admin/import`——上传 `.hdb/.hsb`（同时导入 SHA256 与 MD5 并列库，按行长度自动分流）或 `.yar/.yara`（追加 YARA 规则并即时编译生效）；文件存入 `signatures/` 持久化，重启不丢失
- 生成密码哈希示例：

  ```bash
  python -c "import hashlib,os; salt=os.urandom(16).hex(); pw='你的密码'; print('salt:', salt); print('password_hash:', hashlib.sha256(f'{salt}:{pw}'.encode()).hexdigest())"
  ```

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

## 文件类型识别（ClamAV FTM 机制移植 + 增强）

ClamAV 通过 `libclamav/filetypes.c` 的 **FTM（File Type Magic）签名表**（`filetypes_int.h`，镜像官方 `daily.ftm`）判断文件类型，签名格式 `type:offset:magic:名称:父类型:CL_TYPE_xxx`。`filetype.py` 按同样的四层判定链实现，并在此基础上叠加 **4 项结构化校验增强（2026-08-20）**，提升准确率与抗伪造能力：

```
文件头 1024B (CL_FILE_MBUFF_SIZE)             完整 data (大文件可用)
   │                                                │
   ▼                                                ▼
① 固定偏移魔数 (type-0) ── ELF/Mach-O/ZIP/RAR/PDF/OLE2/PNG/LNK/pyc... 70+ 种
   │ 命中 ZIP 时 → 优先解析「中央目录」(EOCD 反向定位)  [增强 A]
   │              失败/截断 → 退回 local file header 条目名细分 OOXML (word/ xl/ ppt/)
   ▼
② 模式搜索 (type-1) ── MZ+PE\0\0 → PE；随后做 PE 头结构校验 [增强 B]
   │                       MZ+偏移魔数 → ZIP/RAR/7z/CAB SFX；HTML 标签
   ▼
③ 尾部魔数 ── DMG 'koly' @ EOF-512
   │
   ▼
④ 文本编码检测兜底 ── BOM/UTF-8/UTF-16/ASCII（对应 ClamAV cli_texttype）
   │
   ▼  (未命中)
⑤ libmagic 兜底 [增强 D] ── 可选依赖 python-magic-bin；未安装/异常静默降级
                              通用 binary → "二进制数据"
   │
   ▼
⑥ 扩展名一致性检查 [增强 C] ── 30+ 扩展名映射；高危不一致（.jpg/.pdf + PE/ELF）
                                 生成 detections 可疑信号，verdict=DETECTED
```

### 四项增强详情（2026-08-20）

**A. ZIP 中央目录解析**（`_detect_zip_central_dir`）
- 从文件尾反向搜索 **EOCD（`PK\x05\x06`）**（校验 comment 长度对齐防伪造），遍历**全量**中央目录条目名细分 OOXML/JAR
- 解决旧方案只看前 1024 字节内 local file header、条目名被截断导致的大型 docx/xlsx/JAR 误判为普通 ZIP 的问题
- 无 EOCD / ZIP64 / 截断文件自动退回 local header 方案，`method` 标记 `magic+ooxml-cd` 与旧路径区分

**B. PE 头结构校验**（`_verify_pe_structure`）
- 零依赖轻量校验：`e_lfanew` 指向 → `PE\0\0` 签名 → 已知 Machine（8 种架构 x86/x86-64/ARM/ARM64/...）→ Optional Header Magic（PE32/PE32+/ROM）
- 三态结果：`ok`（`method` 带 `pe-verify` + `pe_arch` 架构名）/ `anomaly`（结果带 `suspect` 字段进入可疑信号）/ `unknown`（缓冲不足，不误报）
- 大 DOS stub（`e_lfanew > 1024B`）用完整 `data` 继续校验，兼容仅头尾缓冲的旧接口；与阶段2 pefile 解析独立，不产生额外依赖调用

**C. 扩展名 / 魔数不一致检测**（`_type_suspicion_signals`）
- 30+ 扩展名映射表；高危场景（`.jpg`/`.pdf` 扩展名 + PE/ELF/SFX 等可执行内容）标注「**疑似伪装扩展名**」，普通不一致给中性描述
- 信号以 `engine: "FileType"` 条目进入 `detections`，文件最终 `verdict` 变为 DETECTED，检测表中独立成行（红色 T 图标，前端 `app.js` 已支持渲染）
- 阶段 1 与 `_scan_large` 路径均接入，大文件扫描同样受益

**D. libmagic 兜底层**（`_libmagic`）
- 魔数链落入 generic binary 时咨询 libmagic（`pip install python-magic-bin` 启用）
- 未安装 / `from_buffer` 抛异常 / API 不兼容（误装 `file-magic`）/ 返回 `"data"`/空串 → 全部静默降级到原「二进制数据」结果，与 `pefile` / `ppdeep` 的降级模式一致
- 已识别类型（魔数命中）不经过 libmagic 分支，零开销
- `method` 标记 `libmagic` 区分兜底来源

### 字段与判定规则

- 类型码沿用 ClamAV 的 `CL_TYPE_*` 命名，共 12 个 UI 分类（executable / document / archive / graphics / media / script / mail / text / disk / ai-model / data / binary）
- OOXML 细分与 ClamAV `ooxml_detect` 表一致：强前缀（`word/`、`xl/`、`ppt/`、`META-INF/MANIFEST.MF`）优先于通用条目（`[Content_Types].xml`）
- `/scan` 响应的 `file_type_info` 字段：
  `{"name": 类型名, "cl_type": "CL_TYPE_xxx", "category": 分类, "method": "magic|magic+ooxml|magic+ooxml-cd|pattern|pattern+pe-verify|tail-magic|text-detect|libmagic|fallback", "pe_arch"?: "x86-64"|..., "suspect"?: bool}`
- 验证：`python test_filetype.py`（27 类基础样本 + 16 类增强用例：ZIP 中央目录 / PE 结构校验 / 伪装扩展名 / libmagic 降级 6 分支全覆盖）

## 存储架构（千万级容量）

哈希签名不是明文 `.hdb` 直读，而是 **Bloom 预过滤 + 动态分片 SQLite**。三个库（SHA256 / MD5 / Fuzzy）均支持两种布局：`modulo`（按摘要取模 `bloom.shards` 片）和 `hex`（按哈希前缀分 256 片），由 `config.json` 的 `sha256.layout` / `md5.layout` / `fuzzy.layout` 决定。当前三个库均使用 **`layout=hex`（256 分片）**，路由规则为哈希前两字符 → `00.db`~`ff.db`，`check()` 接口对上层透明：

```
查询 hash (sha256 / md5 / fuzzy hash)
   │
   ▼
① Bloom 预过滤 ──── 1% 误判率位图（k=7），按分片拆成独立位图文件（懒加载 + LRU），
                    肯定不在库 → 直接返回未命中
   │ 可能命中
   ▼
② 动态分片定位 ──── hex 布局: 取哈希前两字符 → 00~ff 分片;
                    modulo 布局: 取摘要前4字节 int.from_bytes(...,'big') % N
   │
   ▼
③ 分片点查 ─────── 只打开该分片对应的 .db（只读连接，
                    懒加载 + LRU 缓存，上限 max_open_shards），BLOB/TEXT 主键点查
```

- 分片目录 `signatures/sha256.db.shards/`：`00.db` ~ `ff.db` 共 256 个小库 + `_meta.db`（导入记录、分片计数与布局标记）；单分片体量仅为全库 1/256，点查与增量导入互不干扰。当前（2026-08-17 全量导入后）256 hex 分片实际计数约 24.4 万条/分片，分片库合计约 3.9GB
- `sigs` 表为 **SHA256 主键结构**（v3，`_meta.db` 中 `schema_version=3` / `primary_key=sha256` 标记），**精简四列**（2026-08-18）：
  `sha256 BLOB PRIMARY KEY`（库内仅存 SHA256 签名，32B）、`size`、`name`、
  及 `md5` 列（同文件 MD5 哈希，无数据源时为 NULL；原 `sha1` 与 fuzzy 预留列已删除）。
  查询走 `sha256` 主键点查；迁移前旧库备份为 `000X.db.pre_multi_hash.bak`，切主键前备份为 `000X.db.pre_sha256_pk.bak`
- **v3 起 SHA256 库仅接受 SHA256 签名**：导入 `.hdb/.hsb` 时 64hex 行入库，32hex（md5）/ 40hex（sha1）行计数跳过并提示；查询只对 sha256 摘要做一次 Bloom 排除 + 主键点查（见「并发与 IO 说明」）；冷启动 0 分片加载，随查询按需打开

### MD5 并列哈希库（2026-08-18 新增，2026-08-19 迁移至 256 hex 分片）

`HashSignatureDB` 通过 `hash_algo="md5"` 参数化（规格表 `HASH_SPECS` 定义主键列/`hex_len`/`label`/`bytes`），与 SHA256 库**完全并列、独立分片 + 独立 Bloom**：

- 分片目录 `signatures/md5.db.shards/`（256 hex 分片，`layout=hex`）+ Bloom `signatures/md5.db.bloom/`，当前 **540,276 条 32hex MD5 签名**（约 32MB）
- 由 `build_md5_db.py` 从 `extracted/` 的 ClamAV `.hdb/.hsb` 提取 `md5:size:name` 行构建（仅接受 32hex 行；与 SHA256 库不同，MD5 库导入时 64hex 行跳过）
- 文件扫描：`Scanner` 同时持有 `hash_db`（SHA256）与 `md5_db`（MD5），阶段 1 对样本 MD5 调 `md5_db.check_hash(md5_hex)`、对 SHA256 调 `hash_db.check(...)`，两者命中合并进 `detections`（`engine` 分别为 `SHA256 Hash DB` / `MD5 Hash DB`，`detail` 标注 `SHA256 命中:` / `MD5 命中:`，前端检测表独立成两行）
- Web 哈希查询：`/api/hash/<h>` 按长度路由——32hex→MD5 库，64hex→SHA256 库，非法长度返回 400；前端搜索框与结果卡均按哈希类型动态显示 `MD5`/`SHA256` 标签
- `app.py` 启动时检测 `signatures/md5.db.shards/` 是否存在：存在则只读实例化 `md5_db`，否则降级为 `None`（SHA256 功能不受影响）；`/api/stats` 额外返回 `md5_signatures` / `md5_available` / `md5_sources` / `md5_storage`
- Bloom 位图与 SQLite 分片一一对应，持久化到 `signatures/sha256.db.bloom/{shard_id:02x}.bloom`（hex 布局）或 `{shard_id:04d}.bloom`（modulo 布局），签名总数不变不重建
- `.hdb/.hsb` 只是**导入格式**：启动时自动导入 `signatures/` **顶层**的新文件（`imported_files` 表去重，幂等）；项目根 `hdb/` 分桶目录**不自动导入**，需按「签名库更新」章节的批量命令手动导入
- 自动重分片：检测到布局不一致（如 `modulo` → `hex`）或 `shard_count` 变更时，启动自动按新路由重分布，旧布局备份为 `*.shards.legacy`
- 兼容迁移：旧版单一 `sha256.db` 自动按前缀拆入分片（原文件保留为 `sha256.db.migrated`）；旧版单文件 Bloom（`sha256.db.bloom`）自动备份为 `sha256.db.bloom.legacy`

### 模糊哈希增强库（FuzzySignatureDB，4 表独立结构，2026-08-22 重构）

与 SHA256/MD5 库并列的第三库，数据源为 ClamAV 官方 hdb 分桶的 **8 字段行**：

```
sha256:filesize:result:ssdeep:vhash:authentihash:imphash:rich_header_hash
```

- 由 `build_fuzzy_db.py` 读取 hdb 分桶目录（`--hdb-dir` 参数，默认项目根 `hdb/`）逐行解析，提取 **vhash / authentihash / imphash / rich_header_hash** 四个模糊哈希字段；**每种 fuzzy hash 独立成表，以 fuzzy hash 本身为主键**
- **注意**：ssdeep 已从 FuzzySignatureDB 独立出来，迁移到单文件 `SsdeepLibrary`（详见「ssdeep 相似度检测」章节），不再使用分片 bloom
- **4 表结构**（每个 hex 分片文件含 4 张表）：

  ```
  sigs_vhash        (vhash BLOB PRIMARY KEY,        size INTEGER, name TEXT, sha256 BLOB) WITHOUT ROWID
  sigs_authentihash (authentihash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB) WITHOUT ROWID
  sigs_imphash      (imphash BLOB PRIMARY KEY,      size INTEGER, name TEXT, sha256 BLOB) WITHOUT ROWID
  sigs_rich_header_hash (rich_header_hash BLOB PRIMARY KEY, size INTEGER, name TEXT, sha256 BLOB) WITHOUT ROWID
  ```

  每个非空 fuzzy 字段独立写入对应表（值为 NULL 的字段不入库）；`sha256` 列仅作溯源关联，无索引不参与查询

- **路由**（hex 布局，256 分片）：BLOB 类型取 `value[0]`（首字节）→ `00`~`ff` 分片
- 分片目录 `signatures/fuzzy.db.shards/`（256 hex 分片，`layout=hex`）+ Bloom `signatures/fuzzy.db.bloom/`；Bloom 按 **类型 × 分片** 独立管理，命名格式 `{shard_id:02x}_{type}.bloom`，共 4×256=1024 个 bloom 文件，懒加载 + LRU 缓存
- 4 表共享同一分片 SQLite 连接（同一 `.db` 文件），连接按 `shard_id` 管理；`FuzzySignatureDB` 为**独立类**（不继承 `HashSignatureDB`），自行管理 meta、连接 LRU、bloom LRU、导入和查询

- **查询方式**：
  - `check_fuzzy(fuzzy_type, hash_value, file_size)` —— 精确查询：路由 → bloom 排除 → SQL 主键点查，命中返回 `{size, name, sha256, type}` 完整信息
  - `check_by_computed_hashes(imphash_hex, authentihash_hex, file_size)` —— 批量查询：用 `staticinfo.compute_static_info()` 计算出的 fuzzy hash 值，分别查 `sigs_imphash` / `sigs_authentihash` 表，合并返回命中列表（ssdeep 精确匹配由 SsdeepLibrary.check_exact 处理）

- **接入扫描流程**：模糊哈希查询在**阶段 2**——`staticinfo` 计算 imphash/authentihash 后调 `check_by_computed_hashes()` 精确比对
- `app.py` 启动检测 `signatures/fuzzy.db.shards/`，存在则只读实例化 `fuzzy_db`，否则降级 `None`；`/api/stats` 返回 `fuzzy_signatures` / `fuzzy_available` / `fuzzy_sources` / `fuzzy_storage`

### ssdeep 相似度检测（2026-08-21 新增, 2026-08-22 独立为 SsdeepLibrary）

在**精确 ssdeep 比对**（`SsdeepLibrary.check_exact()` 主键等值查询）之外，基于 ssdeep（CTPH）的**模糊相似度检索**：Web 提交的文件在阶段 2 计算出 ssdeep 后，与独立 SSDeep 库 `ssdeep_entries` 表中的所有 ssdeep 签名做 **0-100 相似度比对**（`ppdeep.compare`），能发现「哈希不同但内容相似」的变体（加壳 / 改字符串 / 改资源等导致的整文件哈希变化），弥补精确哈希对未知变体失效的短板。

**独立库架构（SsdeepLibrary）**：
- 单文件 SQLite（`signatures/ssdeep_library.db`），**不使用分片 Bloom filter**——ssdeep 为变长 TEXT 主键，精确查询走主键索引，相似度检索走 GLOB 前缀 + 7-gram 预过滤
- 表结构（4 字段）：`ssdeep_entries(ssdeep TEXT PRIMARY KEY, sha256 BLOB, size INTEGER, name TEXT)`
- **sha256 存为 BLOB 二进制**（32 字节 vs 64 字符 hex，节省 50% 存储空间）
- 数据来源：① 从 hdb 文件批量导入（`build_fuzzy_db.py` 同时构建 SsdeepLibrary）② 每次精确哈希命中的样本自动入库累积（自增长）
- 库容量上限 50000 条，超限淘汰最先插入的条目（ROWID 最小）

**执行策略**：SSDeep 检测（精确匹配 + 相似度检索）**始终执行**，与阶段 1 的 SHA256/MD5 精确哈希**并行**，不再由哈希命中结果决定是否启动。`hash_hit = any(d["engine"] in ("SHA256 Hash DB", "MD5 Hash DB") for d in phase1["detections"])` 仅用于控制**自增长入库**——只有精确哈希命中时当前样本才加入库，保持库内仅累积已知恶意样本。检测到相似时 `detections` 出现 `engine="SSDeep Hash DB"` 条目且 `scanners` 追加 `SSDeep Hash DB`，前端检测表以 **S 徽标引擎行**展示相似度分数与库中 ssdeep 原文。

**候选筛选（避免对 6200 万条签名逐条比对）**：

1. **块大小候选集**：解析查询 ssdeep 的块大小 B，候选块大小 ∈ {B//2, B, B×2} —— ssdeep 算法对块大小相差 ≤2 倍的签名才有比较意义
2. **文件大小过滤**：样本大小 ±2 倍（库 `size` 为 NULL 的行保留）
3. **索引前缀扫描**：每分片每候选块大小用 `GLOB 'B-*'`（而非 LIKE —— GLOB 大小写敏感可走主键前缀索引，LIKE 退化为全表扫描）+ size 过滤 + `LIMIT` 控制候选量
4. **7-gram 预过滤（性能关键）**：`ppdeep.compare` 内部先做 `_common_substring`（需共享 ≥7 字符的连续子串，否则直接得 0），其 O(m×n) 嵌套循环是主要耗时（实测 7.7 万次 compare 约 40s）。`check_ssdeep_similarity` 先用集合运算（`_ssdeep_strip` + `_ssdeep_grams7`）预判「是否共享 7-gram」，判定与 ppdeep 完全一致、**零召回损失**；随机内容几乎不共享 7-gram，可砍掉绝大多数昂贵 compare（实测检索从 ~72s 降到 ~2s，20 倍以上加速）
5. **全库遍历**：单文件 SQLite，用 GLOB 前缀索引扫描候选块大小的行 + 7-gram 预过滤 + `ppdeep.compare`；汇总得分 ≥ 阈值的命中按得分降序取 top_k

**参数与返回**（`SsdeepLibrary.search`）：

| 参数 | 默认值 | 说明 |
| ---- | ---- | ---- |
| `threshold` | 50 | 相似度阈值（ssdeep 官方：≥50 高度可能相关） |
| `top_k` | 5 | 返回得分最高的前 N 条 |
| `SSDEEP_SIM_LIMIT` | 500 | 每候选块大小最多取多少行 |

命中以 `engine="SSDeep Hash DB"`、`type="fuzzy-similar"` 条目进入 `detections`，携带 `score`（0-100）、`ssdeep`（库中原始 ClamAV 格式）、`sha256`、`name`、`size`；完全相同的 ssdeep 由精确比对命中，相似度检索自动跳过避免重复。前端检测表以 **S 徽标引擎行**渲染（`app.js` `detectionsTable` + `app.css` `.e-icon.s`），展示相似度分数与库中 ssdeep 原文。未安装 `ppdeep` 或库为空时自动返回空结果（降级路径与现有模糊哈希一致）。

格式兼容：`_ssdeep_to_standard` 把库中的 ClamAV 格式（`12-hash1-hash2`，短横线分隔）归一化为标准 ssdeep 格式（`12:hash1:hash2`，冒号分隔）后再比对，两种格式均兼容。

### TLSH 哈希相似度检测（2026-08-22 新增）

基于 **TLSH（Trend Micro Locality Sensitive Hash）** 的相似度检测，与 ssdeep 相似度互补：ssdeep 基于上下文触发分段哈希，TLSH 基于局部敏感哈希，两者对同一家族变体的检测能力各有侧重。

**数据来源——自增长库**：hdb 签名库不含 TLSH 字段，因此 TLSH 库 **无预置数据**，采用自增长策略——每次精确哈希命中（SHA256/MD5）的样本，其 TLSH 自动入库累积（`signatures/tlsh_library.db`），后续扫描将文件 TLSH 与库内已有条目做距离比对。库容量上限 50000 条，超限自动淘汰最先插入的条目。

**表结构 v2**（`tlsh_entries` 表，2026-08-22 千万级优化重构，**旧 TEXT 表启动时自动迁移**）：

| 字段 | 类型 | 说明 |
| ---- | ---- | ---- |
| `tlsh` | BLOB PRIMARY KEY | TLSH 原始 35 字节二进制（1 校验和 + 1 Lvalue + 1 Q + 32 body code），统一大写规范化，`WITHOUT ROWID` |
| `lv` | INTEGER | 反 swap 后的 Lvalue 派生列（0-255），建 `idx_tlsh_lv` 索引供检索剪枝 |
| `q1` / `q2` | INTEGER | Q 比率派生列（0-15），阈值裁剪用 |
| `sha256` | BLOB | 样本 SHA256（关联精确哈希命中记录；BLOB 二进制 32 字节，与 ssdeep 库一致） |
| `size` | INTEGER | 样本文件大小（字节） |
| `name` | TEXT | 恶意名称（来自哈希签名库的命中名称） |

**检索流水线 v2**（原「全表 fetchall + 逐行纯 Python diff」暴力扫描已重构为四层加速）：

1. **SQL 剪枝下推**（零召回损失）：距离 ≤ threshold 时 Lvalue/Q 贡献非负，可反推必要条件——threshold=40 时 `ldiff≥4`（≥48 分）或 `qdiff≥5`（≥48 分）必淘汰；构造 `lv BETWEEN ...` 范围条件（模 256 环绕拆区间）走 `idx_tlsh_lv` 索引，砍掉 60-90% 候选
2. **分块流式打分**：`fetchmany` 分块迭代（杜绝全表 fetchall 物化），查询哈希只解析一次（`tlsh.to_binary`），候选逐块用 `diff_bin()` 比对，超过阈值**早退**
3. **numpy 向量化**（**可选依赖**，候选块 ≥2048 条时启用）：35 字节镜像矩阵 + 65536 字节对距离表 2D gather 一次算整块；未安装 numpy 自动回退纯 Python
4. **连接复用**：线程局部持久只读连接（WAL 模式，读写不阻塞），不再每次查询新建连接

**性能实测**（2 万条库，2026-08-22）：

| 指标 | 优化前 | 优化后 |
| ---- | ---- | ---- |
| 单次距离计算 | ~19µs（逐四分位循环） | ~3.7µs（65536 字节对距离表查表；早退 1.3µs） |
| 检索（纯 Python 路径） | 858ms | 48ms（**18×**） |
| 检索（numpy 路径） | — | 32ms（**27×**） |
| 批量写入 2 万条 | ~26s | ~4.8s（WAL + `INSERT OR IGNORE` + upsert，**~5×**） |
| 哈希生成 1MB（numpy 路径） | ~1500ms | ~220ms（**~7×**） |
| 哈希生成小文件（纯 Python 路径，5KB） | ~5.8ms | ~1.6ms（**~4×**） |

千万级外推单次全扫约 1-3s（numpy），满足阶段 2 后台模糊匹配场景；EXPLAIN QUERY PLAN 已确认剪枝查询走 `idx_tlsh_lv` 索引范围扫描。

**哈希生成算法优化**（`tlsh.py`，2026-08-22，输出与官方算法逐字节一致，含 Lvalue 分段边界 656/3199 用例验证）：

- **滑窗查表内联**：`update()` 热循环内 7 次 `_b_mapping` 链式查表（每次 4 连查）预合成为 7 张 256×256 二级 Q 表（`Q[s][i][j] = V_TABLE[V_TABLE[V_TABLE[s]^i]^j]`），每字节降至 1 次查表
- **numpy 向量化路径**（**可选依赖**，输入 ≥2KB 时启用，缺失或异常自动回退纯 Python）：6 组桶计数对整个输入一次性 2D gather + `bincount` 统计（桶索引只依赖滑窗字节，无顺序依赖）；校验和为顺序链式依赖，保持逐字节循环但已预取 Q0 查表结果
- **分位数求取**：`_find_quartile` 由 quickselect 移植改为 `sorted()` 直接取索引 31/63/95（确定性顺序统计量，输出完全等价，128 元素排序远快于多轮分区）
- **hex 编码**：`hexdigest()` 改用 `bytes.hex().upper()`（替代逐字节 f-string 拼接）

**检测流程**：

1. 文件上传 → 阶段 1 计算 SHA256/MD5 → 精确哈希签名库查询
2. 阶段 2 计算 TLSH → **始终**与自增长库做相似度检索（v2 流水线：lv 索引剪枝 → 分块流式 `diff_bin` 早退 → 大块 numpy 向量化；与 SHA256/MD5 精确哈希并行，不再由哈希命中结果决定是否启动）→ 距离 ≤ 阈值（默认 40）的条目按距离升序取 top_k（默认 10）→ 命中条目以 `engine="TLSH Hash DB"` 进入 `detections`
3. 自增长入库：**仅在精确哈希命中**时当前样本 TLSH 才加入库（保持库内仅累积已知恶意样本）

**TLSH 距离算法**（移植自官方 trendmicro/tlsh `lsh_bin_totalDiff`，纯 Python 实现）：

- TLSH hex = 70 hex 字符 = 35 字节（1 校验和 + 1 Lvalue + 1 Q + 32 body code）
- 校验和差异：不同则 +1
- 长度差异（`mod_diff` 循环距离）：`ldiff==0→+0, ldiff==1→+1, else +ldiff×12`
- Q 比率差异（Q1/Q2 各一）：`qdiff≤1→+qdiff, else +(qdiff-1)×12`
- body code 逐字节：4 个 2-bit 四分位对差异之和，权重矩阵 `d(0,3)=d(3,0)=6`（极端差异加重惩罚），对角线为 0；v2 起预合成 **65536 字节对距离表**（`tlsh.byte_dist_table()`，懒构建），`diff_bin()` 直接查表并支持超阈值早退
- 距离语义：**0=完全相同，越小越相似**（与 ssdeep score 语义相反）

**参数与返回**（`TlshLibrary.search`）：

| 参数 | 默认值 | 说明 |
| ---- | ---- | ---- |
| `threshold` | 40 | 距离阈值（≤ threshold 视为相似；0=完全相同） |
| `top_k` | 10 | 返回距离最小的前 N 条 |
| `max_entries` | 50000 | 自增长库容量上限（超限淘汰最旧） |

命中以 `engine="TLSH Hash DB"`、`type="fuzzy-similar"` 条目进入 `detections`，携带 `score`（TLSH 距离，越小越相似）、`tlsh`（库中匹配条目的 TLSH）、`sha256`、`name`、`size`、`detail`（`"TLSH 距离 N (越小越相似)"`）。前端检测表以 **L 徽标引擎行**渲染（`app.js` `detectionsTable` + `app.css` `.e-icon.l`，teal 色），展示距离徽标与库中 TLSH 原文。

**配置**（`config.json` → `tlsh` 段）：

| 参数 | 默认值 | 说明 |
| ---- | ---- | ---- |
| `threshold` | 40 | 距离阈值 |
| `top_k` | 10 | 返回前 N 条 |
| `max_entries` | 50000 | 库容量上限 |

`/api/stats` 返回 `tlsh_entries`（当前库条目数）、`tlsh_available`、`tlsh_storage`（含 threshold/top_k/max_entries）；首页统计栏显示「TLSH 自增长库」条目数。

### 千万级实测数据（1000 万条合成签名）

> 下表在 256 hex 分片配置下测得；冷启动仅按查询惰性加载 Bloom 位图与 SQLite 连接，常驻内存随实际查询分布增长，延迟量级不变。

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
    "shards": 4,            // modulo 布局时的分片数; hex 布局固定 256 片, 此值不生效
    "fp_rate": 0.01         // Bloom 误判率 (0.01 = 1%), 越小内存越大
  },
  "sha256": {
    "layout": "hex",        // SHA256 库分片布局: 'hex'(256 片, 哈希前两字符) | 'modulo'(按 bloom.shards 取模)
    "max_open_shards": 16   // 256 片时建议 16-32, 减少频繁换页; modulo 4 片时 4 足够
  },
  "md5": {
    "layout": "hex",        // MD5 库分片布局, 同上
    "max_open_shards": 16
  },
  "fuzzy": {
    "layout": "hex",        // 模糊哈希库分片布局, 同上; 4 表共享同一组分片文件 (ssdeep 已独立)
    "max_open_shards": 16   // 4 表共享连接, bloom 按 类型×分片 独立
  },
  "hash_db": {
    "max_open_shards": 4    // 旧版兼容: 当 sha256/md5/fuzzy 未配置时回退到此值
  },
  "server": {
    "host": "127.0.0.1",
    "port": 5000,
    "max_upload_mb": 10,    // /scan 上传大小上限 (MB)
    "uploads_dir": "uploads", // 上传样本目录: /scan 上传时按 SHA256 去重保存原始字节 (uploads/<sha256>), 供报告页"重新扫描"按钮读取重扫; 相对路径基于项目根目录解析, 也支持绝对路径; 随缓存 LRU 一起清理 (2026-08-22)
    "api_token": "",        // API 认证: 留空 = 匿名本地模式; 配置后 /scan /api/task /api/stats 需带 Authorization: Bearer <token> 或 ?token=<token>
    "scan_rate_limit": 30,  // 每 IP 每分钟最多 /scan 次数 (0 = 不限), 防恶意刷扫描耗尽 CPU
    "phase2_max_mb": 32,    // 阶段2 深度分析(模糊哈希/PE元数据/查壳)的样本大小上限; 超过仅执行 YARA 并返回 phase2_note
    "phase2_concurrency": 4 // 阶段2 后台线程并发上限 (信号量, 超限排队), 控制 CPU 峰值
  },
  "packer": {
    "rules_dir": "packer_rules",      // 外部 YARA 扩展壳库目录 (相对项目根目录或绝对路径); 目录下所有 .yar/.yara 自动加载
    "max_yara_bytes": 16777216        // 外部规则匹配的样本大小上限 (16MB); 内置 DIE/PEiD 特征不受限
  },
  "tlsh": {
    "threshold": 40,              // TLSH 距离阈值 (≤ threshold 视为相似; 0=完全相同; 典型 30-50)
    "top_k": 10,                   // 返回距离最小的前 N 条相似结果
    "max_entries": 50000           // 自增长库容量上限; 超限淘汰最先插入的条目 (ROWID 最小)
  },
  "ssdeep": {
    "threshold": 50,              // SSDeep 相似度阈值 (≥ threshold 视为相似; 0-100; 官方推荐 ≥50)
    "top_k": 5,                   // 返回得分最高的前 N 条相似结果
    "max_entries": 50000          // 自增长库容量上限; 超限淘汰最先插入的条目 (ROWID 最小)
  },
  "admin": {
    "username": "admin",              // 管理员用户名 (/admin/login 登录)
    "salt": "<32hex 随机串>",          // 密码盐: os.urandom(16).hex() 生成
    "password_hash": "<64hex>"        // SHA256(salt:password); 留空则管理端不可登录
  }
}
```

> 修改 `layout` 后**下次启动自动重分片**（旧布局备份为 `.shards.legacy`），数据不丢失。三库布局独立配置，可分别使用 `hex` / `modulo`。

## 运行

```bash
python -m venv venv
venv\Scripts\pip install -r requirements.txt   # Windows
# source venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
venv\Scripts\python app.py
```

打开 <http://127.0.0.1:5000>

依赖：`flask` + `yara-python` + `pefile` + `ppdeep`（Windows 下 pip 均有预编译 wheel 或纯 Python 实现；TLSH 为项目内置纯 Python 移植 `tlsh.py`，无需额外依赖）。**可选依赖**：`numpy`（TLSH 大库检索向量化加速，2 万条以上库实测 ~1.5× 额外提速，缺失时自动回退纯 Python 路径，功能不受影响）、`python-magic-bin`（启用文件类型识别 libmagic 兜底层，缺失时静默降级；安装命令 `pip install python-magic-bin`）。

### 并发与 IO 说明（P0 优化）

- **多线程 Web 服务**：`app.py` 以 `threaded=True` 启动，每个请求独立线程；`/scan` 上传走
  内存流（`scan_bytes`），哈希 / 文件类型识别 / YARA 复用同一份缓冲，**全程不落盘**（每文件只读一遍）
- **YARA 合并编译（P0-1）**：全部规则文件（`signatures/` + `yara_sources/` + 壳库）收集后用
  `yara.compile(filepaths={namespace: path})` **一次性合并编译为单一 Rules 对象**（双检查锁保护，
  启动时 `warmup()` 预热），单个样本匹配从「逐规则集 N 次 `.match()`」降为**单次调用**；
  批量编译失败自动逐文件排查剔除坏文件后重编
- **哈希一次计算全程传递（P0-2）**：`/scan` 请求线程内 `compute_hashes_bytes(data)` 一次算出
  MD5+SHA1+SHA256，以元组传入 `scan_phase1(hashes=...)`，阶段 1 与缓存 key 复用同一结果，
  不再各自重算 SHA256；**SHA1 不参与任何库查询但已计算**，供 Web 文件哈希展示（P1-1 曾为省 1/3 哈希 CPU 跳过，2026-08-22 恢复）
- **pefile 统一解析（C5）**：阶段 2 中 PE 文件只做一次 `pefile.PE(data)`，解析实例传给
  imphash / PE 元数据 / 查壳（`detect_packer(data, pe_obj=...)`）复用，不再重复解析 2~3 次
- **熵计算与 magic 搜索加速（P1-2 / P1-3）**：节熵统计用 `collections.Counter` 替代逐字节循环
  （约 5 倍加速）；壳 magic 特征用预编译 `re.IGNORECASE` 正则直接匹配，不再产生整文件
  `lower()` 的 32MB 内存副本
- **查询并发模型**：`HashSignatureDB.check()` 不再持全局锁 —— Bloom 位图查询期只读（无锁读），
  SQLite 分片连接用**连接级串行锁**（同一连接内串行、不同分片连接并行，并发度 = min(分片数, LRU 上限)），
  LRU 字典操作用细粒度缓存锁；被淘汰的连接延迟到 `close()` 统一关闭；
  查询路径上连接锁被 LRU 并发淘汰的竞态以临时只读连接补查兜底（C1，确保不漏报）
- **sha256 / md5 单次点查**：SHA256 库只对 sha256 摘要做 1 次 Bloom + SQL 主键点查；MD5 库（参数化 `hash_algo="md5"`）对 md5 摘要做同样流程（两者并列，见上「MD5 并列哈希库」）；模糊哈希库在阶段 2 按 staticinfo 计算的 fuzzy hash 值查对应 4 表（`check_by_computed_hashes`），ssdeep 精确匹配由 SsdeepLibrary.check_exact 处理，不参与阶段 1 快速哈希查询；`scanner.check` 接口对上层透明，文件扫描自动合并三库命中
- **Bloom 热路径**：`_positions`（blake2b 双哈希 → k 个位）带实例级 LRU 缓存（上限 4096），
  重复样本直接复用位置数组，省去重复哈希与求模
- **内存扫描阈值**：`Scanner.INLINE_LIMIT = 64MB` —— ≤64MB 的文件一次性读入内存，
  哈希 / 类型识别 / YARA 复用同一份缓冲；更大文件自动退回分块 + 路径扫描（`_scan_large`），
  防止大文件占满内存；Web 端 `/scan` 另有 `server.max_upload_mb`（默认 10MB）上限
- 生产环境建议用 `waitress` / `gunicorn` 多 worker 替代内置服务器

## 目录结构

```
nkrepo-scanner/
├── app.py                        # Flask Web 服务（/ 搜索首页、GET/POST /scan 两段式上传、/api/task/<id> 轮询、/api/stats、/api/hash/<hash> 双库哈希查询、/file/<sha256> 报告详情页、/api/file/<sha256>、/api/rescan/<sha256> 重新扫描、/admin/login 登录、/admin/hash 哈希管理页、/api/admin/* 签名增删查/批量导入、扫描缓存 + LRU 淘汰、样本保存）
├── scanner.py                    # 扫描核心（HashSignatureDB 动态分片存储 + FuzzySignatureDB 4 表独立模糊哈希库[256 hex 分片, vhash/authentihash/imphash/rich_header_hash] + SsdeepLibrary 自增长相似度库[单文件, 无 bloom] + TlshLibrary 自增长相似度库 + YaraScanner + 静态信息集成 + ssdeep/TLSH 相似度检索）
├── build_md5_db.py               # 构建并列 MD5 哈希库（从 extracted/ 的 ClamAV .hdb/.hsb 提取 32hex MD5 签名 → signatures/md5.db.shards/）
├── build_fuzzy_db.py             # 构建模糊哈希增强库 + SSDeep 独立库（从 hdb/ 8 字段行提取 fuzzy hash → FuzzySignatureDB 4 表 + SsdeepLibrary 单文件；支持 --hdb-dir 指定数据源目录）
├── staticinfo.py                 # 静态信息与模糊哈希（ssdeep/tlsh/imphash/authentihash + PE 元数据 + 壳检测）
├── packer.py                     # 壳/保护器识别（精确特征 DIE+PEiD+外部YARA规则 + 启发特征融合判定）
├── packer_rules/                 # 外部 YARA 扩展壳库（.yar 规则 + README.md 编写约定）
├── yara_sources/                 # 第三方 YARA 规则库（Neo23x0/signature-base, Yara-Rules/rules, ATR, InQuest；.gitignore 忽略，fetch_yara.py 拉取）
├── fetch_yara.py                 # 第三方 YARA 规则库下载脚本（GitHub tarball → yara_sources/）
├── tlsh.py                       # TLSH 纯 Python 实现（官方 C 算法 JS 移植 + v2 优化: 生成端 Q 表内联/numpy 桶计数向量化 + 比对端 65536 字节对距离表/diff_bin 早退, numpy 可选）
├── filetype.py                   # 文件类型识别（ClamAV FTM 移植 + 4 项增强：ZIP 中央目录/PE 结构校验/扩展名不一致可疑信号/libmagic 兜底）
├── test_filetype.py              # 文件类型识别验证脚本（27 类基础 + 16 类增强用例）
├── static/
│   ├── app.css                   # 共享暗色主题样式（index / scan 两页共用，VirusTotal 风格；含 FileType 红色可疑信号图标）
│   └── app.js                    # 共享渲染库（扫描结果卡 / 检测环 / 哈希查询 / 统计加载 / FileType 可疑信号渲染；upload 带 onDone 回调）
├── templates/
│   ├── index.html                # 搜索首页（VT 风格大搜索框哈希查询 + 拖拽上传 + 统计卡；**提交文件后直接原地显示扫描报告，复用 app.js 两段式渲染**）
│   ├── scan.html                 # 扫描页（GET /scan，VT 风格：FILE/搜索选项条 + 大上传区 + 最近扫描历史 localStorage + 结果展示；当前顶部菜单已无此入口）
│   ├── file.html                 # 文件报告详情页（/file/<sha256>：基本信息/哈希/检测命中/静态信息/提交历史）
│   ├── login.html                # 管理员登录页（/admin/login，用户名 + 密码）
│   └── hash_admin.html           # 哈希签名管理页（/admin/hash：查/增/删单条 + 批量导入）
├── config.json                   # 配置（bloom 分片数/误判率、连接缓存上限、服务端口/上传目录）
├── extract_cvd.py                # 从 ClamAV .cvd 病毒库解包提取签名
├── hdb/                          # ClamAV 官方整文件哈希分桶（00.hdb~ff.hdb 共 256 文件，8 字段完整行、sha256 主键 64hex，约 12.4GB、62,586,907 行；SHA256 库与模糊哈希库的共同数据源，不自动导入）
├── gen_sigs.py                   # 合成签名生成器（压测用）
├── bench.py                      # 性能基准（延迟 / 内存 / 磁盘）
├── signatures/
│   ├── hashes.hdb                # 本地哈希签名（含 EICAR 三种哈希行；仅 SHA256 行生效）
│   ├── rules.yar                 # YARA 规则集
│   ├── sha256.db.shards/        # 动态分片 SQLite（00.db~ff.db + _meta.db，hex 布局 256 片，运行时生成）
│   ├── sha256.db.bloom/         # 分片 Bloom 位图（00.bloom~ff.bloom，hex 布局 256 片）
│   ├── md5.db.shards/            # 并列 MD5 哈希库分片（hex 布局 256 片，build_md5_db.py 生成）
│   ├── md5.db.bloom/             # 并列 MD5 库分片 Bloom 位图
│   ├── fuzzy.db.shards/          # 模糊哈希库分片（hex 布局 256 片，每分片含 4 张表：sigs_vhash/sigs_authentihash/sigs_imphash/sigs_rich_header_hash）
│   ├── fuzzy.db.bloom/           # 模糊哈希库分片 Bloom 位图（{shard}_{type}.bloom，4×256=1024 文件）
│   ├── ssdeep_library.db         # SSDeep 自增长相似度库（单文件 SQLite，无 bloom，sha256 存 BLOB 二进制；从 hdb 导入 + 精确命中自增长入库）
│   ├── tlsh_library.db           # TLSH 自增长相似度库（单文件 SQLite, v2 BLOB schema + lv 索引剪枝; 精确哈希命中时自动入库累积; 旧 TEXT 表启动自动迁移）
│   └── *.legacy / *.migrated     # 旧布局/旧版单库备份（自动迁移时生成）
├── extracted/                    # CVD 解包产物（hdb/hsb/mdb/ndb/ldb/fp...）
├── cvd/                          # 下载的 main.cvd / daily.cvd
├── uploads/                      # 上传样本 + 扫描报告目录（路径由 server.uploads_dir 配置；样本 = <sha256> 原始字节，报告 = <sha256>.json，均与上传文件同目录；/scan 上传时保存，供"重新扫描"读取，随缓存 LRU 一起淘汰）
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
#    如需覆盖可传 shard_count=N; 注意: v3 起 SHA256 库仅接受 64hex(SHA256) 行,
#    官方 main/daily 库中 32hex(md5)/40hex(sha1) 行会被跳过, 仅 SHA256 实际入库)
python -c "from scanner import HashSignatureDB; db = HashSignatureDB('signatures/sha256.db'); \
[db.import_hdb(f) for f in ['extracted/main.main.hdb','extracted/main.main.hsb', \
'extracted/daily.daily.hdb','extracted/daily.daily.hsb']]; db.finalize(); db.close()"

# 4. 构建并列 MD5 哈希库（从 extracted/ 提取 32hex MD5 签名, 仅 MD5 行,
#    其余长度跳过; 生成 signatures/md5.db.shards/ + signatures/md5.db.bloom/）
python build_md5_db.py

# 5. 批量导入官方 sha256 分桶库（项目根 hdb/ 下 00.hdb~ff.hdb, 全为 64hex;
#    实测 62,586,907 行: 导入约 41min + Bloom 重建约 7min, 幂等可重复续导)
python -c "
import glob
from scanner import HashSignatureDB
db = HashSignatureDB('signatures/sha256.db')
for f in sorted(glob.glob('hdb/*.hdb')):
    n = db.import_hdb(f)
    print(f, '+', n)
db.finalize(); db.close()"

# 5b. 构建模糊哈希增强库 + SSDeep 独立库（读取 hdb/ 下 256 个分桶的 8 字段行,
#     提取 vhash/authentihash/imphash/rich_header_hash → FuzzySignatureDB 4 表;
#     提取 ssdeep → SsdeepLibrary 单文件库 (无 bloom, sha256 存 BLOB);
#     --hdb-dir 可指定 hdb 数据源目录 (默认项目根 hdb/);
#     幂等可续导: 已导入的文件跳过, 断点续传)
python build_fuzzy_db.py
# 或指定 hdb 目录: python build_fuzzy_db.py --hdb-dir /path/to/hdb

# 6. 重启服务生效
```

CVD 文件为 512 字节头 + gzip 压缩 tar，`extract_cvd.py` 解包后会顺带提取 `.mdb/.ndb/.ldb` 等其它类型签名（留在 `extracted/`，约 280MB），本平台暂不使用，可作为日后扩展字节级检测的数据源。

### 日常扩充

- **SHA256 哈希**：往 `signatures/*.hdb` 追加 `hash:size:name` 行（size 为 `*` 时通配大小），或放入任何 ClamAV 格式 `.hdb/.hsb` 文件，重启自动导入。**仅接受 64hex（SHA256）行**——32hex（md5）/ 40hex（sha1）行会被跳过并计数提示（如示例库 `hashes.hdb` 中非 64hex 行即为此类，仅 SHA256 行生效）；大规模分桶文件（如项目根 `hdb/`）用上文批量命令导入
- **MD5 哈希（并列库）**：MD5 库不通过启动自动导入构建，而是运行 `python build_md5_db.py`（从 `extracted/` 的 ClamAV `.hdb/.hsb` 提取 32hex MD5 签名，仅 MD5 行入库）；构建后重启即自动加载 `signatures/md5.db.shards/`
- **模糊哈希（增强库，4 表结构 + SSDeep 独立库）**：运行 `python build_fuzzy_db.py`（从 `hdb/` 8 字段行提取 vhash/authentihash/imphash/rich_header_hash → 4 表独立结构，同时提取 ssdeep → SsdeepLibrary 单文件库）；构建后重启即自动加载；导入幂等可续导，断点继续不丢数据
- **YARA**：往 `signatures/*.yar` 追加规则或新增 `.yar` 文件，重启生效
- **第三方 YARA 规则库**（`yara_sources/`，2026-08-18 新增）：从 GitHub 开源社区收集的 YARA 规则，启动时递归收集 `yara_sources/` 下全部 `.yar/.yara` 文件，首次匹配前用 `yara.compile(filepaths=...)` **合并编译为单一 Rules 对象**（P0-1，启动时 `warmup()` 预热），匹配只需单次 `.match()` 调用（10s 超时）而非逐规则集扫描；批量合并编译失败时自动退化为逐文件编译排查坏文件，坏文件跳过不影响其它。当前来源：

  | 目录 | 仓库 | 规则文件数 | 说明 |
  | ---- | ---- | --------- | ---- |
  | `yara_sources/Neo23x0_signature-base/` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | 751 | THOR / ATiM 扫描器配套规则，含 APT / 漏洞利用 / webshell / hacktools 等 |
  | `yara_sources/Yara-Rules_rules/` | [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | 566 | 社区维护的 YARA 规则库，含 APT / malware / packers / webshells |
  | `yara_sources/ATR_Yara-Rules/` | [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) | 125 | Trellix (McAfee) ATR 团队规则，含 APT / ransomware / stealer / miners |
  | `yara_sources/InQuest_yara-rules-vt/` | [InQuest/yara-rules-vt](https://github.com/InQuest/yara-rules-vt) | 38 | VirusTotal 专用规则集 |

  加载后 YARA 规则总量：**18,346 条**（1,409 文件成功编译，72 文件因依赖不可用模块如 `filepath`/`filename`/`file_type` 而跳过）。`yara_sources/` 已加入 `.gitignore`，需用 `fetch_yara.py` 重新拉取。
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
| `/`          | GET  | Web 界面（**搜索首页**：MD5/SHA256 哈希查询 + 拖拽上传；提交文件后**直接原地显示扫描报告**，复用 `static/app.js` 的两段式渲染，不再跳转 `/scan`。顶部导航仅「搜索 / 管理」两项）                             |
| `/scan`      | GET  | Web 界面（VirusTotal 风格扫描页：FILE/搜索选项条 + 大上传区 + 最近扫描历史，结果渲染与首页共用 `static/app.js`。当前顶部菜单已无此入口，仅保留页面路由兼容历史链接） |
| `/scan`      | POST | 上传文件（multipart 字段 `file`，**全程内存不落盘**，受 `server.max_upload_mb` 限制）。**两段式**：立即返回 `{task_id, status: "phase2", result}`，`result` 为阶段 1 哈希查询结果（`phase:"hash"`、`md5/sha256`（`sha1` 恒为 `null`，见 P1-1）、`file_type_info`、`detections` 含 SHA256 Hash DB / MD5 Hash DB 命中、`elapsed_ms` 为阶段 1 耗时）；阶段 2（YARA 规则 + `static_info` 模糊哈希/PE 元数据/查壳 + **模糊哈希库精确比对**（`check_by_computed_hashes`：ssdeep/imphash/authentihash 各查对应 5 表）+ **ssdeep 相似度检索**）由后台线程执行。超过 `server.phase2_max_mb` 的样本阶段 2 仅执行 YARA 并返回 `phase2_note` 说明，`static_info` 为空。**缓存命中**：该 SHA256 已扫描过时直接返回 `{status: "done", cached: true, result}`（完整合并结果，含每次提交的 `history`；历史追加与写盘异步执行） |
| `/api/task/<task_id>` | GET | 轮询深度分析进度：`phase2`（进行中）/ `done`（返回 `{task_id, status:"done", result}`，`result.phase:"done"`，为阶段 1 + 阶段 2 合并的完整扫描结果，结构同旧版 `/scan`：`verdict`/`detections`（SHA256/MD5/SSDeep/TLSH Hash DB + YARA + FileType）/`static_info`/`static_ms`/`elapsed_ms`，超限样本含 `phase2_note`）/ `error`（后台异常）；任务过期或不存在返回 404（内存保留 `TASKS_MAX=100` 个、`TASK_TTL=600s`） |
| `/api/stats` | GET  | 签名统计：`hash_signatures`（SHA256 哈希条数）、`md5_signatures`/`md5_available`/`md5_sources`/`md5_storage`（并列 MD5 库）、`fuzzy_signatures`/`fuzzy_available`/`fuzzy_sources`/`fuzzy_storage`（模糊哈希增强库）、`yara_rules`、`yara_available`、`packer_yara_rules`/`packer_yara_available`/`packer_yara_error`（壳库外部规则）、`hash_sources`/`yara_sources`（签名来源文件）、`storage`（存储层 tier / 分片 / Bloom 位图状态，见下）、`max_upload_mb`（上传大小上限，前端据此本地预检超限文件） |
| `/api/hash/<hash>` | GET | 哈希查询（VirusTotal 风格首页搜索框）：**32 位 hex → MD5 库，64 位 hex → SHA256 库**，命中与否均 200；返回 `{md5\|sha256, hash_algo, hit, detections, scanner}`，`hit=true` 时 `detections` 为签名库命中详情；非 32/64 位 hex 返回 400（模糊哈希增强库不参与哈希查询，仅在文件扫描阶段 2 中按计算的 fuzzy hash 值查询） |
| `/file/<sha256>` | GET | 文件报告详情页（参考 VT `/gui/file/<hash>`）：渲染完整扫描报告（基本信息/哈希/检测命中/静态信息/提交历史）；非法哈希渲染友好提示而非 404；页面本身无需认证，数据接口受保护 |
| `/api/file/<sha256>` | GET | 按 SHA256 读取缓存中的扫描报告（`uploads/<sha256>.json`）：返回 `{found: true, sha256, result}`（result 含 `history` 提交历史）；该文件未在本系统扫描过返回 404 `{found: false}`；非 64 位 hex 返回 400 |
| `/api/rescan/<sha256>` | POST | 重新扫描（报告页「重新扫描」按钮）：读取 `uploads/<sha256>` 保存的原始字节重跑完整扫描并覆盖缓存报告；返回两段式 `{task_id, status:"phase2", result: 阶段1, rescanned:true}`，前端轮询 `/api/task/<id>` 后重渲染。样本未保留返回 404；非法 SHA256 返回 400 |
| `/admin/login` | GET/POST | 管理员登录页（用户名 + 密码表单）；POST 校验通过写 session 并跳转 `next`（仅站内相对路径）。凭据见 `config.json` 的 `admin` 节 |
| `/admin/logout` | GET | 退出登录，清空整个会话 |
| `/admin/hash` | GET | 哈希签名管理页（**需管理员登录**）：单条签名查/增/删 + 批量导入签名文件 |
| `/api/admin/hash/<hash>` | GET | 查询单条签名（32hex→MD5 / 64hex→SHA256，**需登录**），命中与否均 200 |
| `/api/admin/hash` | POST | 新增单条签名（JSON `{hash, size, name}`，**需登录**；自动路由 SHA256/MD5 库，Bloom 增量更新即时生效；已存在返回 `added: 0`） |
| `/api/admin/hash/<hash>` | DELETE | 删除单条签名（**需登录**），返回删除条数 |
| `/api/admin/import` | POST | 批量导入签名文件（**需登录**）：`.hdb/.hsb` 同时导入 SHA256 + MD5 库（按行长分流）、`.yar/.yara` 追加 YARA 规则即时编译；文件存入 `signatures/` 持久化 |

## 安全

静态安全审查（OWASP 类别逐项）+ 动态恶意输入验证后落地的加固项：

- **认证（M1）**：`server.api_token` 非空时，`/scan`、`/api/task/<id>`、`/api/stats` 全部要求
  `Authorization: Bearer <token>` 或 `?token=<token>`（`401`）；默认留空 = 匿名本地模式，方便本机使用
- **管理端认证（M1）**：哈希管理页与 `/api/admin/*` 独立于 api_token，走管理员 session 认证——
  凭据为 `config.json` 的 `admin` 节（`password_hash = SHA256(salt:password)` 明文不落配置），
  校验用 `hmac.compare_digest` 常量时间比较；登录跳转仅接受站内相对路径（防开放重定向）；
  管理响应带 `Cache-Control: no-store`（防登出后从缓存还原页面）；`admin` 节留空则管理端不可登录
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
| `GET /` 首页 / `GET /api/stats`（hash_signatures=62,587,049，md5_signatures=540,276） | PASS |
| 库级 Hash DB 命中：从分片库读真实签名 → `db.check(sha256)` / `md5_db.check_hash(md5)` 命中（测试约定：**不使用 EICAR 文件**） | PASS |
| `/api/hash/<h>` 双库路由：32hex→MD5 库命中（库内真实 MD5 签名）/ 未命中均 200；64hex→SHA256 库命中 200；非 32/64hex 返回 400 | PASS（2026-08-18 实测） |
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
db = HashSignatureDB('signatures/sha256.db')
conn = sqlite3.connect('file:signatures/sha256.db.shards/0000.db?mode=ro', uri=True)
h, size, name = conn.execute('SELECT hex(sha256), size, name FROM sigs LIMIT 1').fetchone()
hits = db.check('', size, '0'*32, '0'*40, h)
assert any(x['name'] == name for x in hits), f'应命中 {name}'
print(f'Hash DB 命中: {name} ({h[:16]}...)')
"

# 1b) 并列 MD5 库命中：从 md5.db 分片读取一条真实 32hex MD5 签名并断言命中
python -c "
import sqlite3
from scanner import HashSignatureDB
md5_db = HashSignatureDB('signatures/md5.db', hash_algo='md5')
conn = sqlite3.connect('file:signatures/md5.db.shards/0000.db?mode=ro', uri=True)
m, size, name = conn.execute('SELECT hex(md5), size, name FROM sigs LIMIT 1').fetchone()
hits = md5_db.check_hash(m)
assert any(x['name'] == name for x in hits), f'应命中 {name}'
print(f'MD5 库命中: {name} ({m[:16]}...)')
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

- 哈希存储「Bloom 预过滤 + 按哈希前缀动态分片 + BLOB/TEXT 主键点查」，三个库统一 256 hex 分片（`00.db`~`ff.db`），冷启动零加载、按查询懒加载，思路对齐 ClamAV `libclamav/matcher-hash.c` 的哈希匹配层级
- 模糊哈希库 4 表独立结构 + SSDeep 独立单文件库：FuzzySignatureDB 中每种 fuzzy hash 以自身值为 PRIMARY KEY 独立成表（vhash/authentihash/imphash/rich_header_hash），BLOB 类型按首字节路由，Bloom 按 类型×分片 独立管理（1024 个位图文件）；SSDeep 独立为 SsdeepLibrary 单文件 SQLite（无 bloom, 无分片, sha256 存 BLOB 二进制）
- Bloom 预过滤利用安全检测「宁误报不漏报」的特性，先以 1.2MB/百万条 的内存成本拒绝绝大部分干净查询
- YARA 部分由 yara-python 编译执行，规则本身即可高效处理上万条
- 文件类型识别移植自 ClamAV `libclamav/filetypes.c` + `filetypes_int.h`（FTM 签名表、MAGIC_BUFFER_SIZE=1024、ooxml_detect 条目名细分、cli_texttype 文本检测兜底）
