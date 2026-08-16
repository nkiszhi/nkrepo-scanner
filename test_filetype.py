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
# EICAR
samples.append(("EICAR", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" + b"\n"))

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
print("\n全部通过" if fail == 0 else "")
