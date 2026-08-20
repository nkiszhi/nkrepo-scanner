"""
staticinfo.py - 样本静态信息与模糊哈希提取

提供以下模糊哈希 / 静态特征计算:
  - ssdeep       : 上下文触发分段哈希 (CTPH), 基于 ppdeep (纯 Python, SpamSum 兼容)
  - tlsh         : Trend Micro 局部敏感哈希, 基于本地 tlsh.py (纯 Python, 官方算法移植)
  - imphash      : PE 导入表哈希 (pefile), 仅 PE 样本
  - authentihash : PE Authenticode 哈希 (清零 CheckSum + Security Directory 后 SHA256), 仅 PE

适用类型: 所有样本计算 ssdeep/tlsh (超 FUZZY_MAX_BYTES 跳过); PE 样本额外计算
imphash/authentihash 与 PE 静态元数据 (节表 / 导入 DLL / 编译时间等)。

依赖 (见 requirements.txt): pefile, ppdeep
"""
import hashlib
import struct
import time

import tlsh as tlsh_mod
import packer

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:  # pragma: no cover
    PEFILE_AVAILABLE = False

try:
    import ppdeep
    SSDEEP_AVAILABLE = True
except ImportError:  # pragma: no cover
    SSDEEP_AVAILABLE = False

# 模糊哈希输入上限: 纯 Python 实现, 耗时随输入近线性增长
# (实测: 256KB≈1.4s / 512KB≈7.4s / 1MB≈24s / 3MB≈73s)。绝大多数真实 PE 样本
# 远超 256KB, 原上限使模糊哈希对实际样本形同虚设 (P2-1); 故提升至 2MB——
# 计算发生在 Web 阶段2 后台线程, 不阻塞 HTTP 响应, 接受较长耗时。
# (长期优化: 替换为 C 扩展 ssdeep/pyssdeep, 1MB 可降至 <100ms)
FUZZY_MAX_BYTES = 2 * 1024 * 1024


def _fmt_size_kb(n):
    """把字节数格式化为 KB/MB 文案 (用于 notes 提示)"""
    return f"{n // 1024}KB" if n < 1024 * 1024 else f"{n // (1024 * 1024)}MB"

# 低于该长度 ssdeep 无意义 (官方 fuzzy_hash_buf 对极短输入返回空)
SSDEEP_MIN_BYTES = 32

MACHINE_NAMES = {
    0x014C: "x86 (I386)", 0x8664: "x64 (AMD64)", 0xAA64: "ARM64",
    0x01C0: "ARM", 0x01C4: "ARMv7", 0x0200: "IA64", 0x5032: "RISC-V32",
    0x5064: "RISC-V64", 0x01F0: "PowerPC", 0x01F1: "PowerPC-LE",
}
SUBSYSTEM_NAMES = {
    1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI",
    7: "POSIX_CUI", 9: "WINDOWS_CE_GUI", 10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER",
    14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
}


# ================================================================ 单个哈希
def compute_ssdeep(data):
    """ssdeep (CTPH); 返回字符串或 None (不可用/输入过小/超限)"""
    if not SSDEEP_AVAILABLE or not data or len(data) < SSDEEP_MIN_BYTES:
        return None
    if len(data) > FUZZY_MAX_BYTES:
        return None
    try:
        h = ppdeep.hash(data)
        return h if h and h != "3::" else None
    except Exception:
        return None


def compute_tlsh(data):
    """TLSH; 返回 70 hex 字符串或 None (输入过短/复杂度不足/超限)"""
    if not data or len(data) < tlsh_mod.MIN_DATA_LEN:
        return None
    if len(data) > FUZZY_MAX_BYTES:
        return None
    return tlsh_mod.hash_bytes(data)


def compute_imphash(data, pe_obj=None):
    """PE 导入表哈希 (pefile); 非 PE 或解析失败返回 None

    pe_obj: 可选已解析的 pefile.PE 实例 (C5: 复用解析结果, 避免重复解析)
    """
    if not PEFILE_AVAILABLE or not data:
        return None
    try:
        if pe_obj is not None:
            return pe_obj.get_imphash()
        if not _is_pe(data):
            return None
        pe = pefile.PE(data=data)
        return pe.get_imphash()
    except Exception:
        return None


def compute_authentihash(data):
    """PE Authenticode 哈希: 清零 CheckSum 与 Security Directory 条目后 SHA256 全文件"""
    if not data:
        return None
    try:
        if not _is_pe(data):
            return None
        buf = bytearray(data)
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        opt_off = pe_off + 4 + 20  # 'PE\0\0' + COFF header(20B)

        # CheckSum: OptionalHeader + 64 (PE32 与 PE32+ 相同)
        buf[opt_off + 64:opt_off + 68] = b"\x00" * 4

        magic = struct.unpack_from("<H", buf, opt_off)[0]
        if magic == 0x10B:        # PE32
            dd_off = opt_off + 96
        elif magic == 0x20B:      # PE32+
            dd_off = opt_off + 112
        else:
            return None

        sec_off = dd_off + 4 * 8  # DataDirectory[4] = Security (证书表)
        if sec_off + 8 <= len(buf):
            buf[sec_off:sec_off + 8] = b"\x00" * 8

        return hashlib.sha256(bytes(buf)).hexdigest()
    except Exception:
        return None


# ================================================================ PE 元数据
def _is_pe(data):
    if len(data) < 0x40 + 4 or data[:2] != b"MZ":
        return False
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    return data[pe_off:pe_off + 4] == b"PE\x00\x00"


def compute_pe_meta(data, pe_obj=None):
    """提取 PE 静态元数据; 非 PE 返回 None

    pe_obj: 可选已解析的 pefile.PE 实例 (C5: 复用解析结果, 避免重复解析)
    """
    if not PEFILE_AVAILABLE:
        return None
    if pe_obj is None:
        if not data or not _is_pe(data):
            return None
        try:
            pe_obj = pefile.PE(data=data)
        except Exception:
            return None
    try:
        pe = pe_obj
        meta = {
            "machine": MACHINE_NAMES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            "is_64bit": pe.FILE_HEADER.Machine in (0x8664, 0xAA64),
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "timestamp": _fmt_timestamp(pe.FILE_HEADER.TimeDateStamp),
            "subsystem": SUBSYSTEM_NAMES.get(pe.OPTIONAL_HEADER.Subsystem,
                                             str(pe.OPTIONAL_HEADER.Subsystem)),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [],
            "imports": [],
        }
        for s in pe.sections:
            meta["sections"].append({
                "name": s.Name.rstrip(b"\x00").decode("latin-1", "replace"),
                "vsize": s.Misc_VirtualSize,
                "rsize": s.SizeOfRawData,
                "flags": hex(s.Characteristics),
            })
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
                funcs = []
                for imp in (entry.imports or [])[:32]:  # 每 DLL 最多列 32 个
                    if imp.name:
                        funcs.append(imp.name.decode("latin-1", "replace"))
                    else:
                        funcs.append(f"ord_{imp.ordinal}")
                meta["imports"].append({"dll": dll, "funcs": funcs})
        return meta
    except Exception:
        return None


def _fmt_timestamp(ts):
    if not ts:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
    except (OverflowError, OSError, ValueError):
        return str(ts)


# ================================================================ 统一入口
def compute_static_info(data):
    """计算样本静态信息; 返回结构化 dict

    结构:
      fuzzy:  {ssdeep, tlsh, imphash, authentihash}
      pe:     PE 元数据 (仅 PE 样本, 否则 None)
      packer: 壳/保护器识别结果 (仅 PE 样本, 否则 None)
      notes:  说明列表 (不可用的原因)

    C5 优化: PE 样本只解析一次 pefile.PE 实例, 传入 imphash/pe_meta/packer 复用,
    避免 pefile.PE(data=data) 对同一数据重复解析 3 次。
    """
    notes = []
    fuzzy = {
        "ssdeep": None,
        "tlsh": None,
        "imphash": None,
        "authentihash": None,
    }

    if len(data) > FUZZY_MAX_BYTES:
        notes.append(f"样本超过 {_fmt_size_kb(FUZZY_MAX_BYTES)}, 跳过 ssdeep/tlsh 计算")
    else:
        fuzzy["ssdeep"] = compute_ssdeep(data)
        fuzzy["tlsh"] = compute_tlsh(data)
        if not SSDEEP_AVAILABLE:
            notes.append("ssdeep 不可用: 未安装 ppdeep")
        if fuzzy["tlsh"] is None and len(data) >= tlsh_mod.MIN_DATA_LEN:
            notes.append("tlsh 不可用: 内容复杂度不足或输入过短")

    # C5 优化: 统一解析一次 PE 实例, 传入各子函数复用
    is_pe = _is_pe(data)
    pe_obj = None
    if is_pe and PEFILE_AVAILABLE:
        try:
            pe_obj = pefile.PE(data=data)
        except Exception:
            pe_obj = None

    if is_pe:
        if pe_obj is not None:
            fuzzy["imphash"] = compute_imphash(data, pe_obj=pe_obj)
        else:
            fuzzy["imphash"] = None  # PE 解析失败或 pefile 不可用
        fuzzy["authentihash"] = compute_authentihash(data)
        if not PEFILE_AVAILABLE:
            notes.append("imphash/authentihash 不可用: 未安装 pefile")

    return {
        "fuzzy": fuzzy,
        "pe": compute_pe_meta(data, pe_obj=pe_obj) if is_pe and pe_obj is not None else None,
        "packer": packer.detect_packer(data, pe_obj=pe_obj) if is_pe else None,
        "notes": notes,
    }
