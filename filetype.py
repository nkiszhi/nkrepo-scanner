"""
NKAMG Scanner - 文件类型识别模块 (移植自 ClamAV libclamav/filetypes.c)

ClamAV 的判断机制:
  1. FTM (File Type Magic) 签名表 (filetypes_int.h, 镜像 daily.ftm):
     格式 "type:offset:magic:TypeName:parentType:CL_TYPE_xxx"
       - type 0: 固定偏移的静态魔数 (memcmp)
       - type 1: 带通配符的模式搜索 (?? / * / {n-m} / (aa|bb)), offset 为 * 或 start,max
  2. 匹配缓冲区: 文件头 1024 字节 (CL_FILE_MBUFF_SIZE)
  3. 魔数未命中 → cli_texttype() 文本编码检测 (ASCII/UTF-8/UTF-16)
  4. 命中 ZIP → 解析 local file header 条目名细分 OOXML (Word/Excel/PPT/HWP)
  5. 命中 BINARY_DATA → is_tar() 兜底; MBR 用偏移 510 的 55AA

本模块按同样思路实现, 返回结构化类型信息 (名称 / CL_TYPE_* 码 / 分类 / 判定方法)。
"""
import re
import struct

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
    """提取 head 中所有 ZIP local file header 的条目名 (ClamAV: 遍历前 1024 字节内的 lhdr)"""
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


def _detect_ooxml(head):
    """ZIP 命中后解析条目名细分 OOXML 类型 (对应 ClamAV ooxml_detect)

    与 ClamAV 一致: 遍历前 1024 字节内所有 local file header 的条目名,
    强类型前缀 (word/ xl/ ppt/ ...) 优先于通用条目 ([Content_Types].xml 等)。
    """
    names = _zip_entry_names(head)
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


def detect_file_type(head, tail=b"", filename=None):
    """主入口: 模拟 ClamAV cli_compare_ftm_file + cli_determine_fmap_type

    head: 文件头 (至少 MAGIC_BUFFER_SIZE=1024 字节, 不足则整文件)
    tail: 文件末尾 (用于 DMG 'koly' 尾部魔数, 可选)
    返回 dict: name / cl_type / category / method
    """
    if not head:
        return {"name": "空文件", "cl_type": "CL_TYPE_ANY", "category": "other", "method": "empty"}

    # --- 第 1 层: 固定偏移魔数 (type-0 FTM, 首个命中即返回, 与 ClamAV 遍历顺序一致) ---
    for offset, magic, tname, cl_type, category in MAGIC_SIGS:
        if head[offset:offset + len(magic)] == magic:
            # ZIP → 尝试 OOXML 细分 (ClamAV cli_determine_fmap_type 的 ooxml 分支)
            if cl_type == "CL_TYPE_ZIP" and head[:4] == b"PK\x03\x04":
                ooxml = _detect_ooxml(head)
                if ooxml:
                    return {"name": ooxml[0], "cl_type": ooxml[1], "category": ooxml[2], "method": "magic+ooxml"}
            return {"name": tname, "cl_type": cl_type, "category": category, "method": "magic"}

    # --- 第 2 层: 模式搜索 (type-1 FTM: PE / SFX / HTML) ---
    for regex, tname, cl_type, category in PATTERN_SIGS:
        if regex.search(head):
            return {"name": tname, "cl_type": cl_type, "category": category, "method": "pattern"}

    # --- 第 3 层: 尾部魔数 (DMG 'koly' @ EOF-512, ClamAV: "1:EOF-512:6b6f6c79") ---
    if tail and b"koly" in tail:
        return {"name": "DMG 磁盘镜像", "cl_type": "CL_TYPE_DMG", "category": "disk", "method": "tail-magic"}

    # --- 第 4 层: 文本编码检测兜底 (cli_texttype) ---
    tname, cl_type, category = _detect_text(head)
    method = "text-detect" if category == "text" else "fallback"
    return {"name": tname, "cl_type": cl_type, "category": category, "method": method}


def read_head_tail(file_path, head_size=MAGIC_BUFFER_SIZE, tail_size=512):
    """读取文件头 + 尾部 (尾部用于 DMG 检测, 小于 head+tail 的文件只读一次)"""
    size = 0
    try:
        import os
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
