"""
NKAMG Scanner - 文件类型识别模块 (移植自 ClamAV libclamav/filetypes.c)

ClamAV 的判断机制:
  1. FTM (File Type Magic) 签名表 (filetypes_int.h, 镜像 daily.ftm):
     格式 "type:offset:magic:TypeName:parentType:CL_TYPE_xxx"
       - type 0: 固定偏移的静态魔数 (memcmp)
       - type 1: 带通配符的模式搜索 (?? / * / {n-m} / (aa|bb)), offset 为 * 或 start,max
  2. 匹配缓冲区: 文件头 1024 字节 (CL_FILE_MBUFF_SIZE)
  3. 魔数未命中 → cli_texttype() 文本编码检测 (ASCII/UTF-8/UTF-16)
  4. 命中 ZIP → 解析条目名细分 OOXML (Word/Excel/PPT/HWP)
  5. 命中 BINARY_DATA → is_tar() 兜底; MBR 用偏移 510 的 55AA

本模块在 ClamAV 思路上的增强:
  A. ZIP 细分改用 End of Central Directory 定位的中央目录解析 (传入完整 data 时):
     条目名集中存放于文件尾, 不受前 1024 字节截断限制, 覆盖全部条目,
     大型 OOXML/JAR 归档识别准确率显著提升; 解析失败自动退回 local header 方案。
  B. PE 命中后追加轻量结构校验 (e_lfanew 指向 / PE 签名 / Machine / 可选头 magic):
     校验失败 → 结果带 suspect 字段, 由扫描层转为可疑信号。
  C. check_extension_mismatch(): 扩展名与魔数识别结果交叉校验,
     "图片扩展名 + PE 内容" 等伪装场景 → 可疑信号。
  D. libmagic 兜底层 (python-magic 可选依赖, 缺失时静默降级):
     魔数链落入 generic binary 时借用 libmagic 描述丰富类型名。

返回结构化类型信息 (名称 / CL_TYPE_* 码 / 分类 / 判定方法 / 可疑说明)。
"""
import os
import re
import struct

# ------------------------------------------------------------
# libmagic 兜底层 (可选依赖: pip install python-magic 或 python-magic-bin)
# 缺失 / DLL 不可用时静默降级, 与 pefile/ppdeep 的降级模式一致
# ------------------------------------------------------------
try:
    import magic as _libmagic
except Exception:  # ImportError 或 DLL 加载失败
    _libmagic = None

MAGIC_BUFFER_SIZE = 1024  # ClamAV CL_FILE_MBUFF_SIZE

# ------------------------------------------------------------
# 1. 固定偏移魔数表 (ClamAV type-0 FTM 签名, 精选高频类型)
#    (offset, magic_bytes, 类型名, cl_type, 分类)
# ------------------------------------------------------------
MAGIC_SIGS = [
    # --- 可执行文件 ---
    (0, b"\x7fELF", "ELF 可执行文件", "CL_TYPE_ELF", "executable"),
    (0, b"\xce\xfa\xed\xfe", "Mach-O (32位 LE)", "CL_TYPE_MACHO", "executable"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O (64位 LE)", "CL_TYPE_MACHO", "executable"),
    (0, b"\xfe\xed\xfa\xce", "Mach-O (32位 BE)", "CL_TYPE_MACHO", "executable"),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O (64位 BE)", "CL_TYPE_MACHO", "executable"),
    (0, b"\xca\xfe\xba\xbe\x00\x00\x00", "Mach-O 通用二进制 / Java 字节码", "CL_TYPE_MACHO_UNIBIN", "executable"),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows 快捷方式 (LNK)", "CL_TYPE_LNK", "executable"),
    (0, b"\xa3\x48\x4b\xbe", "AutoIt 编译脚本", "CL_TYPE_AUTOIT", "executable"),
    (0, b"\xef\xbe\xad\xde", "NSIS 安装程序", "CL_TYPE_NULSFT", "executable"),
    (0, b"\x02\x09\x99\x00", "Python 字节码 (.pyc)", "CL_TYPE_PYTHON_COMPILED", "executable"),
    (0, b"\x0b\x0d\x0a", "Python 3.7+ 字节码 (.pyc)", "CL_TYPE_PYTHON_COMPILED", "executable"),
    # --- 压缩包 / 容器 ---
    (0, b"PK\x03\x04", "ZIP 容器", "CL_TYPE_ZIP", "archive"),
    (0, b"PK\x05\x06", "ZIP (空档案)", "CL_TYPE_ZIP", "archive"),
    (0, b"PK\x07\x08", "ZIP (分卷)", "CL_TYPE_ZIP", "archive"),
    (0, b"Rar!\x1a\x07\x00", "RAR 压缩包 (v4)", "CL_TYPE_RAR", "archive"),
    (0, b"Rar!\x1a\x07\x01\x00", "RAR 压缩包 (v5)", "CL_TYPE_RAR", "archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip 压缩包", "CL_TYPE_7Z", "archive"),
    (0, b"\x1f\x8b", "GZip 压缩", "CL_TYPE_GZ", "archive"),
    (0, b"BZh", "BZip2 压缩", "CL_TYPE_BZ", "archive"),
    (0, b"\xfd7zXZ\x00", "XZ 压缩", "CL_TYPE_XZ", "archive"),
    (0, b"\x28\xb5\x2f\xfd", "Zstandard 压缩", "CL_TYPE_ZSTD", "archive"),
    (0, b"\x60\xea", "ARJ 压缩包", "CL_TYPE_ARJ", "archive"),
    (0, b"MSCF\x00\x00\x00\x00", "MS CAB 压缩包", "CL_TYPE_MSCAB", "archive"),
    (0, b"ITSF", "MS CHM 帮助文档", "CL_TYPE_MSCHM", "archive"),
    (0, b"xar!", "XAR 容器", "CL_TYPE_XAR", "archive"),
    (0, b"EGGA", "Egg 压缩包", "CL_TYPE_EGG", "archive"),
    (0, b"ALZ\x01", "ALZ 压缩包", "CL_TYPE_ALZ", "archive"),
    (257, b"ustar", "TAR 归档 (POSIX)", "CL_TYPE_POSIX_TAR", "archive"),
    # --- 文档 ---
    (0, b"%PDF-", "PDF 文档", "CL_TYPE_PDF", "document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 容器 (doc/xls/ppt/msi)", "CL_TYPE_MSOLE2", "document"),
    (0, b"{\\rtf", "RTF 文档", "CL_TYPE_RTF", "document"),
    (0, b"\xe4\x52\x5c\x7b", "Microsoft OneNote 文档", "CL_TYPE_ONENOTE", "document"),
    (0, b"HWP Document File V3.00 ", "HWP3 文档 (韩文)", "CL_TYPE_HWP3", "document"),
    (0, b"%!PS-Adobe-", "PostScript 文档", "CL_TYPE_PS", "document"),
    (0, b"\x78\x9f\x3e\x22", "TNEF (winmail.dat)", "CL_TYPE_TNEF", "document"),
    (4, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "HWP 内嵌 OLE2", "CL_TYPE_HWPOLE2", "document"),
    # --- 图形 ---
    (0, b"\x89PNG", "PNG 图片", "CL_TYPE_PNG", "graphics"),
    (0, b"GIF8", "GIF 图片", "CL_TYPE_GIF", "graphics"),
    (0, b"\xff\xd8\xff", "JPEG 图片", "CL_TYPE_JPEG", "graphics"),
    (0, b"\x00\x00\x00\x0cjP  ", "JPEG2000 图片", "CL_TYPE_GRAPHICS", "graphics"),
    (0, b"BM", "BMP 图片", "CL_TYPE_GRAPHICS", "graphics"),
    (0, b"II*\x00", "TIFF 图片 (LE)", "CL_TYPE_TIFF", "graphics"),
    (0, b"MM\x00*", "TIFF 图片 (BE)", "CL_TYPE_TIFF", "graphics"),
    # --- 媒体 ---
    (0, b"RIFF", "RIFF 媒体 (AVI/WAV)", "CL_TYPE_RIFF", "media"),
    (0, b"RIFX", "RIFX 媒体", "CL_TYPE_RIFF", "media"),
    (0, b"ID3", "MP3 音频", "CL_TYPE_IGNORED", "media"),
    (0, b"OggS", "Ogg 流媒体", "CL_TYPE_IGNORED", "media"),
    (0, b"\xff\xfb", "MP3 音频", "CL_TYPE_IGNORED", "media"),
    (0, b"\x00\x00\x01\xb3", "MPEG 视频流", "CL_TYPE_BINARY_DATA", "media"),
    (0, b"\x00\x00\x01\xba", "MPEG 系统流", "CL_TYPE_BINARY_DATA", "media"),
    # --- Flash / Java ---
    (0, b"FWS", "SWF (未压缩)", "CL_TYPE_SWF", "executable"),
    (0, b"CWS", "SWF (zlib 压缩)", "CL_TYPE_SWF", "executable"),
    (0, b"ZWS", "SWF (LZMA 压缩)", "CL_TYPE_SWF", "executable"),
    (0, b"\xca\xfe\xba\xbe\x00\x00\x00\x02", "Java 类文件", "CL_TYPE_JAVA", "executable"),
    (0, b"\xca\xfe\xba\xbe\x00\x00\x00\x03", "Java 类文件", "CL_TYPE_JAVA", "executable"),
    # --- 邮件 / 脚本 ---
    (0, b"From ", "MBox 邮箱", "CL_TYPE_MAIL", "mail"),
    (0, b"From: ", "Exim 邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"Received: ", "原始邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"Return-Path: ", "Maildir 邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"Delivered-To: ", "邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"Message-ID: ", "邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"Subject: ", "邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"X-Originating-IP: ", "邮件", "CL_TYPE_MAIL", "mail"),
    (0, b"[aliases]", "mIRC 脚本", "CL_TYPE_SCRIPT", "script"),
    (0, b"begin ", "UUencode 编码", "CL_TYPE_UUENCODED", "text"),
    # --- 磁盘 / 分区镜像 ---
    (510, b"\x55\xaa", "磁盘镜像 (MBR)", "CL_TYPE_MBR", "disk"),
    (512, b"EFI PART", "磁盘镜像 (GPT)", "CL_TYPE_GPT", "disk"),
    # --- 数据库 / 其它 ---
    (0, b"SQLite format 3\x00", "SQLite 数据库", "CL_TYPE_IGNORED", "data"),
    (0, b"\x23\x40\x7e\x5e", "SCRENC 加密", "CL_TYPE_SCRENC", "data"),
    (0, b"SZDD", "MS compress.exe 压缩", "CL_TYPE_MSSZDD", "archive"),
    (0, b"GGUF", "GGUF AI 模型", "CL_TYPE_AI_MODEL", "ai-model"),
    (4, b"TFL3", "TensorFlow Lite 模型", "CL_TYPE_AI_MODEL", "ai-model"),
]

# ------------------------------------------------------------
# 2. 模式搜索表 (ClamAV type-1 FTM 签名 → Python 正则)
#    (正则(bytes), 类型名, cl_type, 分类)
# ------------------------------------------------------------
# ClamAV: "1:*:4d5a{60-300}50450000:PE:CL_TYPE_ANY:CL_TYPE_MSEXE"
RE_PE = re.compile(b"MZ.{96,772}?PE\x00\x00", re.DOTALL)
# ClamAV SFX 系列: 魔数出现在非零偏移 (前面有 stub)
RE_ZIPSFX = re.compile(b"^MZ.{0,996}?PK\x03\x04", re.DOTALL)
RE_RARSFX = re.compile(b"^MZ.{0,996}?Rar!\x1a\x07\x00", re.DOTALL)
RE_7ZSFX = re.compile(b"^MZ.{0,996}?7z\xbc\xaf\x27\x1c", re.DOTALL)
RE_CABSFX = re.compile(b"^MZ.{0,996}?MSCF", re.DOTALL)
# ClamAV HTML: "<html>"/"<head>"/"<script ..." 等标签出现在前 1024 字节
RE_HTML = re.compile(
    b"<(html|head|script|iframe|img|object|table|a\\s[^>]*href|!DOCTYPE|body)\\b", re.IGNORECASE
)
PATTERN_SIGS = [
    (RE_PE, "PE 可执行文件", "CL_TYPE_MSEXE", "executable"),
    (RE_ZIPSFX, "ZIP 自解压 (SFX)", "CL_TYPE_ZIPSFX", "executable"),
    (RE_RARSFX, "RAR 自解压 (SFX)", "CL_TYPE_RARSFX", "executable"),
    (RE_7ZSFX, "7-Zip 自解压 (SFX)", "CL_TYPE_7ZSFX", "executable"),
    (RE_CABSFX, "CAB 自解压 (SFX)", "CL_TYPE_CABSFX", "executable"),
    (RE_HTML, "HTML 文档", "CL_TYPE_HTML", "document"),
]

# ------------------------------------------------------------
# 3. OOXML 细分表 (ClamAV filetypes.c ooxml_detect)
#    ZIP local file header 条目名 → 具体文档类型
#    强类型前缀优先 (遍历全部条目), 通用条目仅作兜底
# ------------------------------------------------------------
OOXML_STRONG = [
    (b"xl/", "OOXML Excel 文档 (.xlsx)", "CL_TYPE_OOXML_XL", "document"),
    (b"ppt/", "OOXML PowerPoint 文档 (.pptx)", "CL_TYPE_OOXML_PPT", "document"),
    (b"word/", "OOXML Word 文档 (.docx)", "CL_TYPE_OOXML_WORD", "document"),
    (b"Contents/content.hpf", "OOXML HWP 文档", "CL_TYPE_OOXML_HWP", "document"),
    (b"meta-inf/manifest.mf", "Java 归档 (JAR)", "CL_TYPE_JAVA", "executable"),
    (b"mimetypeapplication/vnd.oasis", "ODF 文档", "CL_TYPE_ZIP", "document"),
]
OOXML_WEAK = [
    (b"mimetype", "文档容器 (ODF/EPUB)", "CL_TYPE_ZIP", "archive"),
    (b"[content_types].xml", "OOXML 文档", "CL_TYPE_ZIP", "document"),
    (b"[contenttypes].xml", "OOXML 文档", "CL_TYPE_ZIP", "document"),
    (b"docProps/", "OOXML 文档", "CL_TYPE_ZIP", "document"),
    (b"BinData", "HWP 文档 (OLE 包装)", "CL_TYPE_ZIP", "document"),
]


def _zip_entry_names(head):
    """提取 head 中所有 ZIP local file header 的条目名 (ClamAV: 遍历前 1024 字节内的 lhdr)

    仅作为中央目录不可用时的退回方案: 局限在文件头 1024 字节内,
    大型归档后半部分条目 (如深层 word/ 目录) 会漏识别。
    """
    names = []
    pos = head.find(b"PK\x03\x04")
    while pos != -1 and len(names) < 16:
        if pos + 30 > len(head):
            break
        nlen, elen = struct.unpack_from("<HH", head, pos + 26)
        start = pos + 30
        if start + nlen <= len(head):
            names.append(head[start:start + nlen])
        nxt = head.find(b"PK\x03\x04", start + max(nlen, 1))
        if nxt == -1:
            break
        pos = nxt
    return names


def _zip_central_dir_names(data, max_entries=64):
    """从 End of Central Directory 定位中央目录, 提取全部条目名 (增强 A)

    相比 local header 方案的优势:
      · 条目名集中存放在文件尾的中央目录中, 不受前 1024 字节截断限制
      · 覆盖全部条目 (local 方案最多 16 个且要求头 1024 字节内出现)
    返回条目名列表; 解析失败 (无 EOCD / ZIP64 / 布局异常) 返回 None,
    调用方退回 _zip_entry_names。
    """
    if not data or len(data) < 22:
        return None
    # EOCD 位于文件尾 (含最多 65535 字节 comment): 反向搜索 PK\x05\x06,
    # 并校验 comment_len 与文件尾对齐, 排除 comment 数据中伪造的签名
    scan_start = max(0, len(data) - 22 - 65535)
    pos = data.rfind(b"PK\x05\x06", scan_start)
    while pos != -1:
        try:
            comment_len = struct.unpack_from("<H", data, pos + 20)[0]
            if pos + 22 + comment_len == len(data):
                break  # 尾部对齐 → 可信 EOCD
        except struct.error:
            pass  # 记录不完整 (签名贴近文件尾) → 继续向前找
        pos = data.rfind(b"PK\x05\x06", scan_start, pos)
    if pos == -1:
        return None
    try:
        (_sig, _disk, _cd_disk, _n_disk, n_total,
         cd_size, cd_offset, _clen) = struct.unpack_from("<IHHHHIIH", data, pos)
    except struct.error:
        return None
    # ZIP64 占位值 (0xFFFF/0xFFFFFFFF): 普通布局无法定位, 退回 local header 方案
    if cd_offset == 0xFFFFFFFF or n_total == 0xFFFF:
        return None
    names = []
    p = cd_offset
    for _ in range(min(n_total, max_entries)):
        # 中央目录头: 46 字节定长 + 文件名(nlen) + 扩展(elen) + 注释(clen)
        if p < 0 or p + 46 > len(data) or data[p:p + 4] != b"PK\x01\x02":
            break
        nlen, elen, clen = struct.unpack_from("<HHH", data, p + 28)
        start = p + 46
        if start + nlen > len(data):
            break
        names.append(data[start:start + nlen])
        p = start + nlen + elen + clen
    return names


def _detect_ooxml(names):
    """ZIP 条目名 → OOXML 细分类型 (对应 ClamAV ooxml_detect)

    names 来源: 中央目录解析 (优先, 全量条目) 或 local file header (退回方案)。
    与 ClamAV 一致: 强类型前缀 (word/ xl/ ppt/ ...) 优先于通用条目
    ([Content_Types].xml 等)。
    """
    # 第一遍: 强类型前缀
    for prefix, tname, cl_type, category in OOXML_STRONG:
        for name in names:
            if name.lower().startswith(prefix):
                return tname, cl_type, category
    # 第二遍: 通用条目兜底
    for prefix, tname, cl_type, category in OOXML_WEAK:
        for name in names:
            if name.lower().startswith(prefix):
                return tname, cl_type, category
    return None


def _detect_text(head):
    """文本编码检测 (对应 ClamAV cli_texttype): BOM / UTF-8 / UTF-16 / ASCII"""
    if not head:
        return "空文件", "CL_TYPE_ANY", "other"
    if head.startswith(b"\xef\xbb\xbf"):
        return "UTF-8 文本 (带 BOM)", "CL_TYPE_TEXT_UTF8", "text"
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "UTF-16 文本", "CL_TYPE_TEXT_UTF16LE" if head[:2] == b"\xff\xfe" else "CL_TYPE_TEXT_UTF16BE", "text"
    # UTF-16 特征: 高比例的 \x00 交错 (CJK/ASCII 范围)
    if len(head) >= 8:
        zeros = head.count(0)
        if zeros > len(head) * 0.35 and b"\r\n\x00" not in head:
            return "UTF-16 文本", "CL_TYPE_TEXT_UTF16LE", "text"
    try:
        head.decode("utf-8")
        if head[:1].isascii() or all(b < 128 or b >= 0xC2 for b in head[:4]):
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
            if printable > len(head) * 0.90:
                return "ASCII 文本", "CL_TYPE_TEXT_ASCII", "text"
        return "UTF-8 文本", "CL_TYPE_TEXT_UTF8", "text"
    except UnicodeDecodeError:
        pass
    return "二进制数据", "CL_TYPE_BINARY_DATA", "binary"


# ------------------------------------------------------------
# PE 结构校验 (增强 B): 零依赖轻量校验, 不引入 pefile
#   e_lfanew 指向合法 → PE\0\0 签名 → 已知 Machine → 可选头 magic
# ------------------------------------------------------------
PE_KNOWN_MACHINES = {
    0x014c: "i386", 0x8664: "x86-64", 0x01c0: "ARM", 0x01c4: "ARMNT",
    0xaa64: "ARM64", 0x0200: "IA64", 0x5064: "RISCV64", 0x0ebc: "EFI BC",
}
PE_OPT_MAGICS = (0x10B, 0x20B, 0x107)  # PE32 / PE32+ / ROM


def _validate_pe_structure(head, data=None):
    """轻量 PE 头结构校验 (增强 B)

    head: 文件头缓冲 (≥1024B 或整文件); data: 完整数据 (可选, e_lfanew 超出
    head 范围时用它继续校验)。返回 (state, reason):
      state="ok"      结构合法, reason=架构名 (如 "x86-64")
      state="anomaly" 结构异常 (伪装/损坏), reason=异常描述
      state="unknown" 缓冲不足无法判定 (不产生信号, 保持原结果)
    """
    src = data if data is not None else head
    if len(src) < 0x40 or src[:2] != b"MZ":
        return "unknown", None
    e_lfanew = struct.unpack_from("<I", src, 0x3C)[0]
    # e_lfanew 合理范围: ≥0x40 (DOS 头之后), 且 PE 签名+COFF 头须在缓冲内
    if e_lfanew + 24 > len(src):
        if data is None and e_lfanew >= len(head):
            return "unknown", None  # 大 DOS stub 超出头缓冲: 无法判定
        return "anomaly", f"e_lfanew=0x{e_lfanew:X} 越界 (文件大小 0x{len(src):X})"
    if e_lfanew < 0x40:
        return "anomaly", f"e_lfanew=0x{e_lfanew:X} 小于 DOS 头长度"
    if src[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return "anomaly", f"e_lfanew=0x{e_lfanew:X} 处无 PE 签名"
    machine = struct.unpack_from("<H", src, e_lfanew + 4)[0]
    if machine not in PE_KNOWN_MACHINES:
        return "anomaly", f"未知 Machine=0x{machine:04X}"
    opt_magic = struct.unpack_from("<H", src, e_lfanew + 24)[0]
    if opt_magic not in PE_OPT_MAGICS:
        return "anomaly", f"可选头 magic=0x{opt_magic:04X} 异常"
    return "ok", PE_KNOWN_MACHINES[machine]


# ------------------------------------------------------------
# 扩展名/魔数交叉校验 (增强 C)
# ------------------------------------------------------------
# 可执行内容的 CL_TYPE 集合 (扩展名伪装检测的高危判定)
EXECUTABLE_CL_TYPES = {
    "CL_TYPE_MSEXE", "CL_TYPE_ELF", "CL_TYPE_MACHO", "CL_TYPE_MACHO_UNIBIN",
    "CL_TYPE_JAVA", "CL_TYPE_SWF", "CL_TYPE_PYTHON_COMPILED", "CL_TYPE_AUTOIT",
    "CL_TYPE_NULSFT", "CL_TYPE_ZIPSFX", "CL_TYPE_RARSFX", "CL_TYPE_7ZSFX",
    "CL_TYPE_CABSFX",
}
# 本身即声明可执行的扩展名 (内容可执行属正常)
EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".ax",
                   ".efi", ".jar", ".pyc", ".swf"}
# 扩展名 → 期望的 CL_TYPE 集合 (未列出的扩展名不做校验, 避免误报)
EXT_EXPECTED_TYPES = {
    # 可执行族 (exe 也可能是 SFX 自解压安装包)
    ".exe": {"CL_TYPE_MSEXE", "CL_TYPE_ZIPSFX", "CL_TYPE_RARSFX",
             "CL_TYPE_7ZSFX", "CL_TYPE_CABSFX", "CL_TYPE_AUTOIT", "CL_TYPE_NULSFT"},
    ".dll": {"CL_TYPE_MSEXE"}, ".sys": {"CL_TYPE_MSEXE"},
    ".scr": {"CL_TYPE_MSEXE"}, ".cpl": {"CL_TYPE_MSEXE"},
    # 文档
    ".pdf": {"CL_TYPE_PDF"},
    ".doc": {"CL_TYPE_MSOLE2"}, ".xls": {"CL_TYPE_MSOLE2"}, ".ppt": {"CL_TYPE_MSOLE2"},
    ".docx": {"CL_TYPE_OOXML_WORD", "CL_TYPE_ZIP", "CL_TYPE_ZIPSFX"},
    ".xlsx": {"CL_TYPE_OOXML_XL", "CL_TYPE_ZIP", "CL_TYPE_ZIPSFX"},
    ".pptx": {"CL_TYPE_OOXML_PPT", "CL_TYPE_ZIP", "CL_TYPE_ZIPSFX"},
    ".hwp": {"CL_TYPE_HWP3", "CL_TYPE_HWPOLE2", "CL_TYPE_OOXML_HWP",
             "CL_TYPE_ZIP", "CL_TYPE_ZIPSFX", "CL_TYPE_MSOLE2"},
    ".rtf": {"CL_TYPE_RTF"},
    ".jar": {"CL_TYPE_JAVA", "CL_TYPE_ZIP", "CL_TYPE_ZIPSFX"},
    ".msi": {"CL_TYPE_MSOLE2", "CL_TYPE_MSCAB"},
    # 图形
    ".png": {"CL_TYPE_PNG"}, ".gif": {"CL_TYPE_GIF"},
    ".jpg": {"CL_TYPE_JPEG"}, ".jpeg": {"CL_TYPE_JPEG"},
    ".bmp": {"CL_TYPE_GRAPHICS"}, ".ico": {"CL_TYPE_GRAPHICS"},
    ".tif": {"CL_TYPE_TIFF"}, ".tiff": {"CL_TYPE_TIFF"},
    ".webp": {"CL_TYPE_RIFF"},
    # 压缩包
    ".zip": {"CL_TYPE_ZIP", "CL_TYPE_ZIPSFX", "CL_TYPE_OOXML_WORD",
             "CL_TYPE_OOXML_XL", "CL_TYPE_OOXML_PPT", "CL_TYPE_OOXML_HWP",
             "CL_TYPE_JAVA"},
    ".rar": {"CL_TYPE_RAR", "CL_TYPE_RARSFX"},
    ".7z": {"CL_TYPE_7Z", "CL_TYPE_7ZSFX"},
    ".gz": {"CL_TYPE_GZ"}, ".bz2": {"CL_TYPE_BZ"}, ".xz": {"CL_TYPE_XZ"},
    ".cab": {"CL_TYPE_MSCAB", "CL_TYPE_CABSFX"},
    # 网页
    ".html": {"CL_TYPE_HTML"}, ".htm": {"CL_TYPE_HTML"},
}


def check_extension_mismatch(filename, ftype):
    """扩展名与魔数识别结果交叉校验 (增强 C)

    返回可疑信号描述字符串; 一致 / 扩展名未登记 / 无法判定时返回 None。
    高危场景 (图片/文档扩展名 + 可执行内容) 给出"疑似伪装"措辞。
    """
    if not filename or not isinstance(ftype, dict):
        return None
    cl = ftype.get("cl_type")
    if not cl or cl == "CL_TYPE_ANY":
        return None
    ext = os.path.splitext(filename)[1].lower()
    expected = EXT_EXPECTED_TYPES.get(ext)
    if not expected or cl in expected:
        return None
    content = ftype.get("name") or cl
    if cl in EXECUTABLE_CL_TYPES and ext not in EXECUTABLE_EXTS:
        return (f"扩展名 {ext} 与内容不符: 实际为可执行文件 ({content}), "
                f"疑似伪装扩展名")
    return f"扩展名 {ext} 与内容不符: 实际为 {content}"


def _libmagic_describe(head):
    """libmagic 兜底描述 (增强 D): python-magic 可选依赖, 失败静默降级"""
    if _libmagic is None:
        return None
    try:
        desc = _libmagic.from_buffer(head)
    except Exception:
        return None
    if not desc:
        return None
    desc = desc.strip()
    if not desc or desc.lower() in ("data", "empty"):
        return None
    return desc


def detect_file_type(head, tail=b"", filename=None, data=None):
    """主入口: 模拟 ClamAV cli_compare_ftm_file + cli_determine_fmap_type

    head: 文件头 (至少 MAGIC_BUFFER_SIZE=1024 字节, 不足则整文件)
    tail: 文件末尾 (用于 DMG 'koly' 尾部魔数, 可选)
    filename: 文件名 (供扩展名交叉校验等调用方使用, 此处仅透传)
    data: 完整文件数据 (可选增强): ZIP 中央目录解析 + PE 结构校验
          在完整数据上执行; 未提供时自动退回头尾缓冲方案
    返回 dict: name / cl_type / category / method / suspect(可选, 可疑说明)
    """
    if not head:
        return {"name": "空文件", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "empty"}

    # --- 第 1 层: 固定偏移魔数 (type-0 FTM, 首个命中即返回, 与 ClamAV 遍历顺序一致) ---
    for offset, magic, tname, cl_type, category in MAGIC_SIGS:
        if head[offset:offset + len(magic)] == magic:
            # ZIP → 尝试 OOXML 细分 (ClamAV cli_determine_fmap_type 的 ooxml 分支)
            if cl_type == "CL_TYPE_ZIP" and head[:4] == b"PK\x03\x04":
                # 增强 A: 优先中央目录 (全量条目, 不受 1024B 截断), 失败退回 local header
                cd_used = False
                names = _zip_central_dir_names(data) if data is not None else None
                if names:
                    cd_used = True
                else:
                    names = _zip_entry_names(head)
                ooxml = _detect_ooxml(names)
                if ooxml:
                    return {"name": ooxml[0], "cl_type": ooxml[1],
                            "category": ooxml[2],
                            "method": "magic+ooxml-cd" if cd_used else "magic+ooxml"}
            return {"name": tname, "cl_type": cl_type, "category": category, "method": "magic"}

    # --- 第 2 层: 模式搜索 (type-1 FTM: PE / SFX / HTML) ---
    for regex, tname, cl_type, category in PATTERN_SIGS:
        if regex.search(head):
            result = {"name": tname, "cl_type": cl_type, "category": category, "method": "pattern"}
            # 增强 B: PE 命中 → 轻量结构校验 (e_lfanew / PE 签名 / Machine / 可选头)
            if cl_type == "CL_TYPE_MSEXE":
                state, reason = _validate_pe_structure(head, data)
                if state == "ok":
                    result["method"] = "pattern+pe-verify"
                    result["pe_arch"] = reason
                elif state == "anomaly":
                    result["name"] = "PE 可执行文件 (头部结构异常)"
                    result["method"] = "pattern+pe-verify"
                    result["suspect"] = f"PE 头部结构校验失败: {reason}"
            return result

    # --- 第 3 层: 尾部魔数 (DMG 'koly' @ EOF-512, ClamAV: "1:EOF-512:6b6f6c79") ---
    if tail and b"koly" in tail:
        return {"name": "DMG 磁盘镜像", "cl_type": "CL_TYPE_DMG", "category": "disk", "method": "tail-magic"}

    # --- 第 4 层: 文本编码检测兜底 (cli_texttype) ---
    tname, cl_type, category = _detect_text(head)
    if category == "text":
        return {"name": tname, "cl_type": cl_type, "category": category, "method": "text-detect"}
    # 增强 D: generic binary → libmagic 兜底 (可选依赖, 失败静默降级为原结果)
    lm_desc = _libmagic_describe(head)
    if lm_desc:
        return {"name": lm_desc, "cl_type": cl_type, "category": category, "method": "libmagic"}
    return {"name": tname, "cl_type": cl_type, "category": category, "method": "fallback"}


def read_head_tail(file_path, head_size=MAGIC_BUFFER_SIZE, tail_size=512):
    """读取文件头 + 尾部 (尾部用于 DMG 检测, 小于 head+tail 的文件只读一次)"""
    size = 0
    try:
        size = os.path.getsize(file_path)
    except OSError:
        pass
    with open(file_path, "rb") as f:
        head = f.read(head_size)
        tail = b""
        if size > head_size + tail_size:
            f.seek(-tail_size, 2)
            tail = f.read(tail_size)
    return head, tail
