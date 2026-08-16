#!/usr/bin/env python
"""从 ClamAV CVD 病毒库中提取整文件哈希签名 (.hdb/.hsb)。

CVD 结构: 512 字节文本头 + gzip 压缩的 tar 包 (参考 libclamav/cvd.c cli_tgzload)。
用法: python extract_cvd.py <file.cvd> [file2.cvd ...]   -> 输出到 cvd/extracted/
"""
import gzip
import io
import os
import sys
import tarfile

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extracted")


def parse_header(data: bytes) -> dict:
    """解析 512 字节 CVD 头: ClamAV-VDB:时间:版本:签名数:flevel:md5:签名:构建者:stime"""
    header = data[:512].split(b"\n", 1)[0].decode("ascii", "replace")
    parts = header.split(":")
    if len(parts) < 5 or parts[0] != "ClamAV-VDB":
        raise ValueError(f"不是有效的 CVD 文件: {header[:60]}")
    return {
        "time": parts[1],
        "version": parts[2],
        "sigs": parts[3],
        "flevel": parts[4],
        "md5": parts[5] if len(parts) > 5 else "?",
    }


def extract(cvd_path: str) -> None:
    data = open(cvd_path, "rb").read()
    hdr = parse_header(data)
    name = os.path.basename(cvd_path)
    print(f"[{name}] 版本 {hdr['version']}, 官方签名数 {hdr['sigs']}, 头部MD5 {hdr['md5'][:16]}...")

    tar_bytes = gzip.decompress(data[512:])
    tf = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:")
    os.makedirs(OUT_DIR, exist_ok=True)

    got = []
    for member in tf.getmembers():
        base = os.path.basename(member.name).lower()
        if not member.isfile():
            continue
        if base.endswith((".hdb", ".hsb", ".mdb", ".fp", ".ftm", ".ndb", ".ldb")):
            # 只落盘哈希类 + 少量说明性文件；ndb/ldb 仅留作参考不导入
            out = os.path.join(OUT_DIR, f"{name.split('.')[0]}.{base}")
            with open(out, "wb") as f:
                f.write(tf.extractfile(member).read())
            lines = sum(1 for _ in open(out, "rb"))
            got.append((base, lines, os.path.getsize(out)))
    for ext, lines, size in got:
        print(f"  提取 {ext:<5} {lines:>8} 行  {size/1024:.0f} KB")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for p in sys.argv[1:]:
        extract(p)
