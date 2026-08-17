"""
packer.py - PE 壳 / 保护器识别 (参考 VirusTotal 静态查壳架构)

多特征融合识别 (DIE 特征体系 + PEiD 经典特征库双重校验):

  1. 精确特征 (高置信, 直接指向具体壳):
     - magic 字符串 : overlay / 全文件搜索 (如 UPX!, MPRESS, ASPack...)
     - EP 字节模式  : 入口点 hex 序列前缀匹配 (PEiD 经典特征, 支持 ?? 通配)
     - 特征节名      : UPX0 / .aspack / .petite / .vmp0 等

  2. 启发特征 (加壳行为共性, 组合判定):
     - 节熵       : 压缩/加密壳节高熵 (>= 7.0)
     - 导入表条目数: 加壳程序导入极少 (<= 15)
     - RWX 节存在性: READ|WRITE|EXECUTE (0xE0000000)
     - 入口点位于最后一节: 壳代码通常垫在文件末尾

  融合判定: 精确命中 -> 报具体壳名; 启发组合 (>=45 分) -> 疑似加壳;
            两者叠加提高置信度。

输出结构 (compute_static_info().packer):
  {
    "detected": bool,
    "confidence": "high" | "medium" | "low" | null,
    "packers": [{"name", "confidence", "signals": [描述...]}],
    "packed_score": int (0-100),
    "heuristics": [{"key", "label", "weight"}],
    "summary": str
  }
"""
import math

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover
    PEFILE_AVAILABLE = False

# ================================================================ 精确特征库

# PEiD 经典 EP 字节模式 (hex, ?? = 任意字节), 从入口点起始前缀匹配
EP_PATTERNS = [
    ("ASPack",    "60 E8 03 00 00 00 61 E9"),
    ("ASProtect", "60 E8 03 00 00 00 61"),
    ("FSG",       "BE ?? ?? ?? ?? 8D BE"),
    ("FSG",       "BE 00 00 00 00 8B BE"),
    ("MPRESS",    "B8 ?? ?? ?? ?? 8B 08"),
    ("PECompact", "50 60 E8"),
    ("Themida",   "55 8B EC 6A FF 68"),
    ("VMProtect", "55 8B EC 83 C4 F8"),
    ("Petite",    "60 E8 03 00 00 00 61 E8"),
    ("UPX",       "60 BE"),
    ("UPX",       "60 E8"),
    ("UPX",       "B8 00 10 40 00"),
]

# DIE 风格 magic 字符串 (小写化匹配, overlay 命中权重更高)
MAGIC_STRINGS = [
    ("UPX",               b"UPX!"),
    ("MPRESS",            b"MPRESS"),
    ("ASPack",            b"ASPack"),
    ("Themida",           b"Themida"),
    ("WinLicense",        b"WinLicense"),
    ("VMProtect",         b"VMProtect"),
    ("Enigma Protector",  b"Enigma"),
    ("Obsidium",          b"Obsidium"),
    ("PELock",            b"PELOCK"),
    ("ExeStealth",        b"ExeStealth"),
    ("Armadillo",         b"Armadillo"),
    ("PESpin",            b"PESpin"),
    ("Shrinker",          b"Shrinker"),
    ("Petite",            b"Petite"),
    ("MoleBox",           b"MoleBox"),
    ("Morphine",          b"Morphine"),
    ("CodeVirtualizer",   b"CodeVirtualizer"),
    ("NsPack",            b"NsPack"),
    ("KKrunchy",          b"kkrunchy"),
    ("Crinkler",          b"Crinkler"),
    ("MEW",               b"MEW"),
    ("tElock",            b"tElock"),
    ("Y0da Cryptor",      b"y0da"),
    ("BeRoEXEPacker",     b"BeRoEXEPacker"),
    ("PackMan",           b"PackMan"),
    ("WWPack32",          b"WWP32"),
    ("NeoLite",           b"NeoLite"),
    ("SVKP",              b"SVKP"),
    ("The Pack",          b"TPack"),
    ("FSG",               b"FSG!"),
]

# 特征节名 (小写存储; 命中即精确特征)
SECTION_NAMES = {
    "UPX":               ["upx0", "upx1", "upx2", "upx3"],
    "ASPack":            [".aspack"],
    "MPRESS":            [".mpress1", ".mpress2"],
    "FSG":               [".fsg"],
    "PECompact":         [".pec1", ".pec2"],
    "Petite":            [".petite"],
    "tElock":            [".telock", ".tlock"],
    "Y0da Cryptor":      ["y0da"],
    "Enigma Protector":  [".enigma1", ".enigma2"],
    "Obsidium":          [".obsidium"],
    "PELock":            ["pelock"],
    "Armadillo":         [".adata"],
    "PESpin":            [".pespin"],
    "Shrinker":          [".shrink"],
    "NsPack":            [".nsp0", ".nsp1", ".nsp2"],
    "KKrunchy":          ["kkrunchy"],
    "MEW":               ["mew"],
    "MoleBox":           [".molebox"],
    "SVKP":              [".svkp"],
    "The Pack":          [".thepack", "tpack"],
    "WinLicense":        [".winlice", ".winlicense"],
    "Themida":           [".themida"],
    "VMProtect":         [".vmp0", ".vmp1", ".vmp2"],
}

# ================================================================ 基础工具

def _is_pe(data):
    if len(data) < 0x40 + 4 or data[:2] != b"MZ":
        return False
    import struct
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    return data[pe_off:pe_off + 4] == b"PE\x00\x00"


def _compile_hex(pat):
    """'60 E8 ?? 61' -> [0x60, 0xE8, None, 0x61]"""
    out = []
    for tok in pat.split():
        out.append(None if tok == "??" else int(tok, 16))
    return out


def _match_hex_prefix(buf, pat):
    """从 buf 起始处前缀匹配 hex 模式 (?? 通配)"""
    p = _compile_hex(pat)
    if len(buf) < len(p):
        return False
    for j, v in enumerate(p):
        if v is not None and buf[j] != v:
            return False
    return True


def _section_entropy(data, sec):
    """计算单节 Shannon 熵 (基于 raw data)"""
    off, size = sec.PointerToRawData, sec.SizeOfRawData
    chunk = data[off:off + size]
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    n = len(chunk)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _sec_name(sec):
    return sec.Name.rstrip(b"\x00").decode("latin-1", "replace")


# ================================================================ 主入口

def detect_packer(data):
    """检测 PE 样本的壳 / 保护器; 非 PE 或解析失败返回 None"""
    if not PEFILE_AVAILABLE or not data or not _is_pe(data):
        return None
    try:
        pe = pefile.PE(data=data)
    except Exception:
        return None

    exact = []       # {"family", "kind", "desc", "weight"}
    heuristics = []  # {"key", "label", "weight"}

    # ---- 1) 特征节名 (精确) ----
    sec_names = [_sec_name(s) for s in pe.sections]
    for family, names in SECTION_NAMES.items():
        for n in sec_names:
            if n.lower() in names:
                exact.append({"family": family, "kind": "section",
                              "desc": f"特征节名 {n}", "weight": 2})
                break

    # ---- 2) EP 字节模式 (精确, PEiD 风格) ----
    ep_buf = None
    try:
        ep_off = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        if ep_off is not None:
            ep_buf = data[ep_off:ep_off + 64]
    except Exception:
        ep_buf = None
    if ep_buf:
        for family, pat in EP_PATTERNS:
            if _match_hex_prefix(ep_buf, pat):
                exact.append({"family": family, "kind": "ep",
                              "desc": f"EP 字节模式 {pat}", "weight": 2})

    # ---- 3) magic 字符串 (精确, DIE 风格; overlay 优先) ----
    # 注意: 短 magic (<5 字节, 如 MEW/FSG!) 仅接受 overlay 命中, 避免全文件随机误报
    overlay = _get_overlay(data, pe)
    overlay_low = overlay.lower() if overlay else b""
    file_low = data.lower()
    for family, magic in MAGIC_STRINGS:
        lm = magic.lower()
        if overlay_low and lm in overlay_low:
            exact.append({"family": family, "kind": "magic",
                          "desc": f"overlay magic '{magic.decode('latin-1')}'", "weight": 3})
        elif len(magic) >= 5 and lm in file_low:
            exact.append({"family": family, "kind": "magic",
                          "desc": f"文件内 magic '{magic.decode('latin-1')}'", "weight": 1})

    # ---- 4) 启发特征 ----
    # 4.1 节熵
    if pe.sections:
        ent = [(sec_names[i], _section_entropy(data, s)) for i, s in enumerate(pe.sections)]
        top_name, top_e = max(ent, key=lambda x: x[1])
        if top_e >= 7.0:
            heuristics.append({"key": "high_entropy",
                               "label": f"最高节熵 {top_name or '(无名)'} {top_e:.2f} (>=7.0 疑似压缩/加密)",
                               "weight": 10})
        if sum(1 for _, e in ent if e >= 6.5) >= 2:
            heuristics.append({"key": "multi_high_entropy",
                               "label": "多个高熵节 (疑似整体加密/压缩)", "weight": 10})
    # 4.2 导入表条目数
    imp_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        imp_count = sum(len(e.imports or []) for e in pe.DIRECTORY_ENTRY_IMPORT)
    if 0 < imp_count <= 15:
        heuristics.append({"key": "few_imports",
                           "label": f"导入表极少 ({imp_count} 个函数, 加壳特征)", "weight": 15})
    # 4.3 RWX 节
    for i, s in enumerate(pe.sections):
        if s.Characteristics & 0xE0000000 == 0xE0000000:
            heuristics.append({"key": "rwx_section",
                               "label": f"RWX 节 {sec_names[i] or '(无名)'} (可读可写可执行)",
                               "weight": 15})
            break
    # 4.4 入口点位于最后一节
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if pe.sections:
        last_i, last_end = 0, -1
        for i, s in enumerate(pe.sections):
            span = s.Misc_VirtualSize or s.SizeOfRawData
            end = s.VirtualAddress + span
            if end > last_end:
                last_i, last_end = i, end
        s_last = pe.sections[last_i]
        span = s_last.Misc_VirtualSize or s_last.SizeOfRawData
        if s_last.VirtualAddress <= ep_rva < s_last.VirtualAddress + span:
            heuristics.append({"key": "ep_in_last_section",
                               "label": f"入口点位于最后一节 {sec_names[last_i] or '(无名)'} (壳代码特征)",
                               "weight": 15})

    # ---- 5) 融合判定 ----
    heu_score = min(40, sum(h["weight"] for h in heuristics))

    families = {}
    for sig in exact:
        families.setdefault(sig["family"], []).append(sig)

    packers = []
    for fam, sigs in families.items():
        w = sum(s["weight"] for s in sigs)
        score = min(60, 20 + (w - 1) * 12)
        if w >= 3:
            conf = "high"
        elif w >= 2:
            conf = "medium"
        else:
            conf = "low"
        packers.append({"name": fam, "confidence": conf,
                        "signals": [s["desc"] for s in sigs], "weight": w, "score": score})
    packers.sort(key=lambda p: (-p["weight"], p["name"]))

    exact_score = min(60, sum(p["score"] for p in packers))
    packed_score = min(100, exact_score + heu_score)

    if packers:
        detected = True
        if any(p["confidence"] == "high" for p in packers) or packed_score >= 65:
            confidence = "high"
        elif any(p["confidence"] == "medium" for p in packers):
            confidence = "medium"
        else:
            confidence = "low"
        pk_list = [{"name": p["name"], "confidence": p["confidence"],
                    "signals": p["signals"]} for p in packers]
        summary = "命中精确特征: " + "、".join(
            f"{p['name']} (证据 {p['weight']} 分)" for p in packers)
        if heuristics:
            summary += f"; 启发信号 {len(heuristics)} 条"
    elif heu_score >= 35:  # 3 条启发信号 (至少含 2 条强信号 15 分)
        detected = True
        confidence = "medium"
        pk_list = [{"name": "Unknown (启发式)",
                    "confidence": "medium",
                    "signals": ["无精确特征命中, 由启发式信号组合判定"]}]
        summary = f"未命中已知壳特征, 启发信号 {len(heuristics)} 条, 疑似加壳"
    else:
        detected = False
        confidence = None
        pk_list = []
        summary = "未检测到已知壳"
        if heuristics:
            summary += f"; 存在 {len(heuristics)} 条启发信号 (不足以判定)"

    return {
        "detected": detected,
        "confidence": confidence,
        "packers": pk_list,
        "packed_score": packed_score,
        "heuristics": heuristics,
        "summary": summary,
    }


def _get_overlay(data, pe):
    """返回最后一个节 raw 末尾之后的数据 (overlay)"""
    try:
        last_end = 0
        for s in pe.sections:
            last_end = max(last_end, s.PointerToRawData + s.SizeOfRawData)
        return data[last_end:] if last_end < len(data) else b""
    except Exception:
        return b""
