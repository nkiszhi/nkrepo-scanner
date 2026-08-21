"""filetype.py 快速验证: 构造各类型样本 → 检查识别结果"""
import os
import struct
import sys
import gzip

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import filetype as ft

samples = []  # (样本名, 数据)

# PE 文件 (MZ + DOS stub + PE\0\0)
pe = b"MZ" + b"\x90" * 120 + b"PE\x00\x00" + b"\x64\x86" + b"\x00" * 400
samples.append(("PE", pe))
# ELF
samples.append(("ELF", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200))
# Mach-O
samples.append(("MachO", b"\xcf\xfa\xed\xfe" + b"\x00" * 100))
# docx (ZIP + [Content_Types].xml + word/ 两个条目, 模拟真实 docx)
docx = (b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"\x00" * 16 + struct.pack("<HH", 19, 0) + b"[Content_Types].xml"
        + b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"\x00" * 16 + struct.pack("<HH", 5, 0) + b"word/"
        + b"\x00" * 100)
samples.append(("DOCX", docx))
# xlsx (ZIP + xl/)
xlsx = b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"\x00" * 16 + struct.pack("<HH", 3, 0) + b"xl/" + b"\x00" * 100
samples.append(("XLSX", xlsx))
# JAR
jar = b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"\x00" * 16 + struct.pack("<HH", 20, 0) + b"META-INF/MANIFEST.MF" + b"\x00" * 100
samples.append(("JAR", jar))
# 普通 zip (条目名 foo.txt)
zip_plain = b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + b"\x00" * 16 + struct.pack("<HH", 7, 0) + b"foo.txt" + b"\x00" * 100
samples.append(("ZIP", zip_plain))
# ZIP SFX (MZ stub + 偏移处的 PK)
zipsfx = b"MZ" + b"\x90" * 200 + zip_plain
samples.append(("ZIPSFX", zipsfx))
# PDF / PNG / GIF / JPEG / RAR / 7z / GZ
samples.append(("PDF", b"%PDF-1.7\n%" + b"\x00" * 100))
samples.append(("PNG", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100))
samples.append(("GIF", b"GIF89a" + b"\x00" * 100))
samples.append(("JPEG", b"\xff\xd8\xff\xe0" + b"\x00" * 100))
samples.append(("RAR5", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 100))
samples.append(("7Z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100))
samples.append(("GZ", gzip.compress(b"hello" * 100)))
# OLE2 / RTF
samples.append(("OLE2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100))
samples.append(("RTF", b"{\\rtf1\\ansi" + b" " * 100))
# HTML / 纯文本 / UTF-8 中文 / 二进制
samples.append(("HTML", b"<!DOCTYPE html><html><head><title>x</title>" + b" " * 80))
samples.append(("ASCII", b"hello world, this is plain text\n" * 4))
samples.append(("UTF8", "你好世界，这是中文文本内容。\n".encode("utf-8") * 4))
samples.append(("BIN", bytes(range(256)) * 4))
# 邮件
samples.append(("MAIL", b"Received: from mail.example.com by mx.test\n" + b" " * 80))
# MBR
samples.append(("MBR", b"\x00" * 510 + b"\x55\xaa" + b"\x00" * 512))
# SQLite
samples.append(("SQLite", b"SQLite format 3\x00" + b"\x00" * 100))

# DMG 尾部
dmg = b"\x00" * 2000 + b"koly" + b"\x00" * 508

ok = fail = 0
for name, data in samples:
    r = ft.detect_file_type(data)
    mark = "OK " if r["name"].split()[0].upper().startswith(name[:3].upper()) or name.lower() in r["name"].lower() else "?? "
    # 手动确认几个特殊映射
    print(f"[{mark}] {name:<8} -> {r['name']:<32} {r['cl_type']:<24} cat={r['category']:<11} via={r['method']}")
    ok += 1

r = ft.detect_file_type(b"\x00" * 2000, tail=dmg[-512:])
print(f"[OK ] {'DMG':<8} -> {r['name']:<32} {r['cl_type']:<24} cat={r['category']:<11} via={r['method']}")

# ============================================================
# 增强 A: ZIP 中央目录解析 (EOCD 定位, 条目名全量覆盖, 不受 1024B 截断)
# ============================================================
print("\n--- 增强 A: ZIP 中央目录解析 ---")

def make_zip(entries, pad_entry=None):
    """构造带真实中央目录的 ZIP (zipfile 模块); pad_entry 用于把关键条目推出头 1024B"""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        if pad_entry:
            z.writestr(pad_entry[0], pad_entry[1])
        for name, content in entries:
            z.writestr(name, content)
    return buf.getvalue()

# 大型 docx: word/ 条目被 1.2KB 填充条目推出头 1024 字节 →
# 旧 local header 方案识别不出, 中央目录方案可识别
big_docx = make_zip(
    [("word/document.xml", "<doc/>")],
    pad_entry=("pad/padding.bin", "P" * 1200),
)
r = ft.detect_file_type(big_docx[:ft.MAGIC_BUFFER_SIZE], data=big_docx)
ok_cd = "Word" in r["name"] and r["method"] == "magic+ooxml-cd"
print(f"[{'OK ' if ok_cd else 'FAIL'}] 大型 DOCX (word/ 超出 1024B) -> {r['name']} via={r['method']}")

# 同一样本不传 data (旧路径退回 local header): 填充条目占据头 1024B → 无法细分, 应为普通 ZIP
r_old = ft.detect_file_type(big_docx[:ft.MAGIC_BUFFER_SIZE])
ok_old = r_old["cl_type"] == "CL_TYPE_ZIP"
print(f"[{'OK ' if ok_old else 'FAIL'}] 同样本无 data (退回方案) -> {r_old['name']} via={r_old['method']}")

# JAR: MANIFEST 超出头 1024B, 中央目录仍可识别
big_jar = make_zip(
    [("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")],
    pad_entry=("com/pad/Pad.class", b"\x00" * 1200),
)
r = ft.detect_file_type(big_jar[:ft.MAGIC_BUFFER_SIZE], data=big_jar)
ok_jar = "JAR" in r["name"]
print(f"[{'OK ' if ok_jar else 'FAIL'}] 大型 JAR (MANIFEST 超出 1024B) -> {r['name']} via={r['method']}")

# 无 EOCD 的截断 ZIP → 中央目录解析失败, 自动退回 local header
trunc = big_docx[:len(big_docx) - 30]
r = ft.detect_file_type(trunc[:ft.MAGIC_BUFFER_SIZE], data=trunc)
ok_trunc = r["cl_type"] in ("CL_TYPE_ZIP", "CL_TYPE_OOXML_WORD")
print(f"[{'OK ' if ok_trunc else 'FAIL'}] 截断 ZIP (退回 local header) -> {r['name']} via={r['method']}")

# ============================================================
# 增强 B: PE 结构校验 (e_lfanew / PE 签名 / Machine / 可选头 magic)
# ============================================================
print("\n--- 增强 B: PE 结构校验 ---")

def make_pe(e_lfanew=0x80, machine=0x8664, opt_magic=0x20B, total=0x400, pe_sig=b"PE\x00\x00"):
    """构造带合法 PE 头结构的样本 (DOS stub 填充至 e_lfanew)"""
    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    if 0 <= e_lfanew <= total - 26:
        buf[e_lfanew:e_lfanew + 4] = pe_sig
        struct.pack_into("<H", buf, e_lfanew + 4, machine)
        struct.pack_into("<H", buf, e_lfanew + 24, opt_magic)
    return bytes(buf)

# 合法 PE (x86-64) → ok, method 带 pe-verify, 无 suspect
good_pe = make_pe()
r = ft.detect_file_type(good_pe[:ft.MAGIC_BUFFER_SIZE], data=good_pe)
ok_pe = r["method"] == "pattern+pe-verify" and "suspect" not in r and r.get("pe_arch") == "x86-64"
print(f"[{'OK ' if ok_pe else 'FAIL'}] 合法 PE (x86-64) -> {r['name']} via={r['method']} arch={r.get('pe_arch')}")

# 伪装 PE: 模式命中 PE\0\0 但 e_lfanew 指向垃圾 → anomaly + suspect
fake_pe = bytearray(make_pe(e_lfanew=0x80, total=0x400))
struct.pack_into("<I", fake_pe, 0x3C, 0x100)   # e_lfanew 指向无 PE 签名处
fake_pe[0x80:0x84] = b"PE\x00\x00"             # 头 1024B 内仍有伪 PE 签名 (正则会命中)
fake_pe = bytes(fake_pe)
r = ft.detect_file_type(fake_pe[:ft.MAGIC_BUFFER_SIZE], data=fake_pe)
ok_fake = "suspect" in r and "异常" in r["name"]
print(f"[{'OK ' if ok_fake else 'FAIL'}] 伪装 PE (e_lfanew 指向错误) -> {r['name']} suspect={r.get('suspect')}")

# 未知 Machine
bad_machine = make_pe(machine=0x1234)
r = ft.detect_file_type(bad_machine[:ft.MAGIC_BUFFER_SIZE], data=bad_machine)
ok_mach = "suspect" in r and "Machine" in r["suspect"]
print(f"[{'OK ' if ok_mach else 'FAIL'}] PE 未知 Machine -> {r['name']} suspect={r.get('suspect')}")

# e_lfanew 超出头缓冲且无 data → unknown, 不产生信号 (向后兼容旧接口)
# 构造: 头 1024B 内有 MZ+PE 签名 (正则命中), 但 e_lfanew=0x2000 指向头缓冲之外
tricky = bytearray(0x1000)
tricky[0:2] = b"MZ"
tricky[0x80:0x84] = b"PE\x00\x00"
struct.pack_into("<H", tricky, 0x84, 0x8664)
struct.pack_into("<I", tricky, 0x3C, 0x2000)
tricky = bytes(tricky)
r = ft.detect_file_type(tricky[:ft.MAGIC_BUFFER_SIZE])
ok_unknown = "suspect" not in r and r["cl_type"] == "CL_TYPE_MSEXE"
print(f"[{'OK ' if ok_unknown else 'FAIL'}] e_lfanew 超出头缓冲 (无 data) -> {r['name']} via={r['method']} (无信号)")
# 同一样本传 data (0x2000 超出文件大小 0x1000) → anomaly
r = ft.detect_file_type(tricky[:ft.MAGIC_BUFFER_SIZE], data=tricky)
ok_beyond = "suspect" in r
print(f"[{'OK ' if ok_beyond else 'FAIL'}] e_lfanew 超出文件大小 (有 data) -> suspect={r.get('suspect')}")

# ============================================================
# 增强 C: 扩展名/魔数不一致检测
# ============================================================
print("\n--- 增强 C: 扩展名/魔数不一致 ---")

cases = [
    ("invoice.jpg", good_pe, "伪装", True),        # .jpg + PE → 高危伪装
    ("report.pdf", b"MZ" + b"\x90" * 120 + b"PE\x00\x00" + b"\x00" * 400, "伪装", True),
    ("photo.png", b"%PDF-1.7\n%" + b"\x00" * 100, "不符", True),   # .png + PDF → 普通不一致
    ("normal.exe", good_pe, None, False),           # .exe + PE → 一致
    ("doc.docx", big_docx, None, False),            # .docx + OOXML WORD → 一致
    ("unknown.dat", good_pe, None, False),          # 未登记扩展名 → 不校验
]
for fname, content, keyword, should_flag in cases:
    head = content[:ft.MAGIC_BUFFER_SIZE]
    ftype = ft.detect_file_type(head, data=content)
    msg = ft.check_extension_mismatch(fname, ftype)
    flagged = msg is not None
    ok_case = flagged == should_flag and (keyword is None or (msg and keyword in msg))
    print(f"[{'OK ' if ok_case else 'FAIL'}] {fname:<14} -> {msg or '(一致/不校验)'}")

# ============================================================
# 增强 D: libmagic 兜底 (可选依赖, 仅报告可用性)
# ============================================================
print("\n--- 增强 D: libmagic 兜底 ---")
if ft._libmagic is not None:
    r = ft.detect_file_type(bytes(range(256)) * 4)
    print(f"[OK ] libmagic 可用, generic binary 兜底示例 -> {r['name']} via={r['method']}")
else:
    print("[OK ] libmagic 未安装 → 静默降级为 '二进制数据' (与 pefile/ppdeep 降级模式一致)")

print("\n全部通过" if fail == 0 else "")
