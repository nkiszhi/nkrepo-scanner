#!/usr/bin/env python3
"""Download YARA rule repos from GitHub via tarball."""
import urllib.request, tarfile, io, os, sys

REPOS = [
    ("Yara-Rules", "rules", "master", "Yara-Rules_rules"),
    ("InQuest", "yara-rules-vt", "main", "InQuest_yara-rules-vt"),
    ("advanced-threat-research", "Yara-Rules", "master", "ATR_Yara-Rules"),
]

def main():
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_sources")
    os.makedirs(base, exist_ok=True)

    for owner, name, branch, dirname in REPOS:
        dest = os.path.join(base, dirname)
        if os.path.isdir(dest) and os.listdir(dest):
            print(f"[SKIP] {owner}/{name} -> {dirname} (already exists)")
            continue

        url = f"https://github.com/{owner}/{name}/archive/refs/heads/{branch}.tar.gz"
        print(f"[FETCH] {owner}/{name} (branch={branch})...")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NKAMG-Scanner"})
            resp = urllib.request.urlopen(req, timeout=60)
            data = resp.read()
            print(f"  Downloaded {len(data):,} bytes")

            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
            members = tf.getmembers()
            extracted = 0
            for m in members:
                if m.isfile() and (m.name.endswith(".yar") or m.name.endswith(".yara")):
                    rel = "/".join(m.name.split("/")[1:])
                    if not rel:
                        continue
                    target = os.path.join(dest, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    fobj = tf.extractfile(m)
                    if fobj:
                        with open(target, "wb") as f:
                            f.write(fobj.read())
                        extracted += 1
            print(f"  Extracted {extracted} .yar/.yara files to {dirname}/")
        except Exception as e:
            print(f"  ERROR: {e}")

    # Summary
    total = 0
    for d in sorted(os.listdir(base)):
        dp = os.path.join(base, d)
        if os.path.isdir(dp):
            count = sum(
                1 for root, _, files in os.walk(dp)
                for f in files if f.endswith((".yar", ".yara"))
            )
            total += count
            print(f"  {d}/: {count} YARA files")
    print(f"Total YARA files in yara_sources/: {total}")

if __name__ == "__main__":
    main()
