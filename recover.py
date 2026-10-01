#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recover.py — 校验逻辑还原脚手架（CHECK_FN -> scheme 参数）

作用：把「目标二进制里的常量」和「反汇编伪代码里的运算序列」映射成
      schemes.py 中某个模板的参数，然后交给 keygen.py 签发。

用法:
  python recover.py scan  <binary> [--min 6] [--max 40]     # 候选常量提取
  python recover.py scan  <binary> --kind salt              # 只列高熵候选（盐/密钥）
  python recover.py hash  <binary>                          # 指纹（比对版本用）
  python recover.py map   --ops "md5,strcat,base32"         # 运算序列 -> 推荐方案
"""
from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import struct
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 反汇编里出现的特征调用 -> 方案推荐
OPS_TO_SCHEME = {
    "md5": "md5salt", "md5_init": "md5salt", "md5update": "md5salt",
    "sha1": "hmac", "hmac": "hmac", "sha256": "hmac",
    "crc32": "crc16", "crc16": "crc16",
    "rsa": "rsa", "modpow": "rsa", "bignum": "rsa", "cryptverify": "rsa",
    "atoi": "modsum", "modulo": "modsum", "idiv": "modsum",
}


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = [0] * 256
    for c in b:
        freq[c] += 1
    return -sum((f / len(b)) * math.log2(f / len(b)) for f in freq if f)


def strings_ascii(data: bytes, minlen: int = 6, maxlen: int = 40):
    for m in re.finditer(rb"[\x20-\x7e]{%d,%d}" % (minlen, maxlen), data):
        yield m.start(), m.group().decode("ascii")


def strings_utf16(data: bytes, minlen: int = 6, maxlen: int = 40):
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (minlen, maxlen), data):
        yield m.start(), m.group().decode("utf-16-le")


# 目标程序里"像盐/密钥/注册表键"的过滤规则
INTERESTING = re.compile(
    r"(salt|key|secret|licen|serial|regist|activ|card|auth|token|sign|hmac|"
    r"Software\\|SOFTWARE\\|\.lic|\.key|\.dat|expire|trial|verif)",
    re.I,
)
NOISE = re.compile(r"^(?:[A-Za-z]:\\|https?://|\.dll$|\.exe$|<\?xml)", re.I)


def cmd_scan(a) -> int:
    with open(a.binary, "rb") as f:
        data = f.read()
    print(f"# file={a.binary}  size={len(data)}  sha256={hashlib.sha256(data).hexdigest()}")
    print(f"# {'OFFSET':<10} {'ENC':<6} {'LEN':<4} {'ENT':<5} CLASS  VALUE")
    print("-" * 100)
    hits = 0
    for off, s in list(strings_ascii(data, a.min, a.max)) + list(strings_utf16(data, a.min, a.max)):
        if NOISE.search(s):
            continue
        ent = entropy(s.encode("utf-8", "ignore"))
        cls = []
        if INTERESTING.search(s):
            cls.append("KEYWORD")
        if a.kind == "salt" and 8 <= len(s) <= 32 and " " not in s and ent >= 3.2:
            cls.append("SALT?")
        elif not a.kind and ent >= 3.4 and 8 <= len(s) <= 32 and " " not in s:
            cls.append("HIGH-ENT")
        if not cls:
            continue
        hits += 1
        enc = "UTF16" if "\x00" in repr(s) or any(ord(c) > 127 for c in s) else "ASCII"
        print(f"0x{off:<8X} {enc:<6} {len(s):<4} {ent:<5.2f} {','.join(cls):<14} {s[:70]}")
        if hits >= a.limit:
            print(f"... (达到上限 {a.limit}，用 --limit 放宽)")
            break
    if hits == 0:
        print("(无候选；放宽 --min / 降低熵阈值，或先脱壳)")
    return 0


def cmd_hash(a) -> int:
    with open(a.binary, "rb") as f:
        d = f.read()
    print(f"path   {os.path.abspath(a.binary)}")
    print(f"size   {len(d)}")
    print(f"md5    {hashlib.md5(d).hexdigest()}")
    print(f"sha1   {hashlib.sha1(d).hexdigest()}")
    print(f"sha256 {hashlib.sha256(d).hexdigest()}")
    if d[:2] == b"MZ":
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        machine, nsec = struct.unpack_from("<HH", d, pe + 4)
        magic = struct.unpack_from("<H", d, pe + 24)[0]
        print(f"pe     machine=0x{machine:04X} sections={nsec} magic=0x{magic:04X} "
              f"({'PE32+' if magic == 0x20B else 'PE32'})")
        ts = struct.unpack_from("<I", d, pe + 8)[0]
        import datetime
        print("stamp  " + datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
              .strftime("%Y-%m-%d %H:%M:%S UTC"))
    return 0


def cmd_map(a) -> int:
    ops = [o.strip().lower() for o in a.ops.split(",") if o.strip()]
    score: dict[str, int] = {}
    for o in ops:
        for k, v in OPS_TO_SCHEME.items():
            if k in o:
                score[v] = score.get(v, 0) + 1
    if not score:
        print("无法判定，默认按 md5salt 起步")
        return 0
    rank = sorted(score.items(), key=lambda kv: -kv[1])
    print(f"ops = {ops}")
    print(f"{'SCHEME':<10} SCORE")
    for k, v in rank:
        print(f"{k:<10} {v}")
    print(f"\n=> 建议起点: {rank[0][0]}  (python keygen.py gen --scheme {rank[0][0]} --name TARGET_NAME)")
    print("   随后按 CHECK_FN 反汇编替换 schemes.py 中该方案的常量，用 selftest 回归。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="recover")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan")
    s.add_argument("binary")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--max", type=int, default=40)
    s.add_argument("--limit", type=int, default=80)
    s.add_argument("--kind", choices=["salt"], default=None)
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("hash")
    h.add_argument("binary")
    h.set_defaults(func=cmd_hash)

    m = sub.add_parser("map")
    m.add_argument("--ops", required=True, help="逗号分隔的调用/助记符序列")
    m.set_defaults(func=cmd_map)

    a = ap.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
