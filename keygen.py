#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keygen.py — 注册机主程序（许可证算法演示实现）

用法:
  python keygen.py list
  python keygen.py gen   --scheme md5salt --name "ACME Corp" --count 5
  python keygen.py gen   --scheme modsum  --name "ACME Corp" --count 3 --out serials.txt
  python keygen.py gen   --scheme rsa     --name "ACME Corp" --exp 2030-12-31 --features PRO --keygen-keypair
  python keygen.py gen   --scheme hmac    --name "ACME Corp" --exp 20301231 --secret-file secret.bin
  python keygen.py verify --scheme modsum --name "ACME Corp" --serial 123456789012
  python keygen.py selftest
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import schemes  # noqa: E402

for _s in (sys.stdout, sys.stderr):          # Windows 控制台 UTF-8 直出
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
KEYFILE = os.path.join(HERE, "keys", "license_private.json")


# ---------------------------------------------------------------------
# 密钥管理（方案 C 用）
# ---------------------------------------------------------------------
def load_or_make_keypair(bits: int = 1024, regen: bool = False) -> dict:
    os.makedirs(os.path.dirname(KEYFILE), exist_ok=True)
    if os.path.exists(KEYFILE) and not regen:
        with open(KEYFILE, "r", encoding="utf-8") as f:
            return json.load(f)
    print(f"[*] 生成 {bits} 位 RSA 密钥对（首次较慢）...", file=sys.stderr)
    priv = schemes.RsaLicense.gen_keypair(bits)
    pub = {"n": priv["n"], "e": priv["e"], "bits": priv["bits"]}
    with open(KEYFILE, "w", encoding="utf-8") as f:
        json.dump({"private": priv, "public": pub}, f, indent=2)
    pubpath = os.path.join(HERE, "keys", "license_public.json")
    with open(pubpath, "w", encoding="utf-8") as f:
        json.dump(pub, f, indent=2)
    print(f"[*] 私钥 -> {KEYFILE}\n[*] 公钥 -> {pubpath}（这个交给目标端内嵌）", file=sys.stderr)
    return {"private": priv, "public": pub}


# ---------------------------------------------------------------------
# 生成
# ---------------------------------------------------------------------
def cmd_gen(a) -> int:
    mod = schemes.get(a.scheme)["mod"]
    names = [a.name] if a.name else [f"USER{i:04d}" for i in range(1, a.count + 1)]
    if a.name and a.count > 1:
        names = [a.name] * a.count          # 同一授权名的多组序列号（随机型方案出不同值）
    if a.namefile:
        with open(a.namefile, "r", encoding="utf-8") as f:
            names = [ln.strip() for ln in f if ln.strip()]

    rows = []
    kw = {}

    if a.scheme == "rsa":
        kp = load_or_make_keypair(a.bits, a.keygen_keypair)
        priv, pub = kp["private"], kp["public"]
        for n in names:
            blob = mod.sign(n, priv, expiry=a.exp, features=a.features)
            ok = mod.verify(n, blob, pub) is not None
            rows.append((n, blob, "OK" if ok else "FAIL"))
    elif a.scheme == "hmac":
        secret = schemes.HmacTime.SECRET
        if a.secret_file and os.path.exists(a.secret_file):
            with open(a.secret_file, "rb") as f:
                secret = f.read()
        elif a.secret_hex:
            secret = bytes.fromhex(a.secret_hex)
        kw["secret"] = secret
        for n in names:
            s = mod.sign(n, expiry=a.exp.replace("-", ""), **kw)
            rows.append((n, s, "OK" if mod.verify(n, s, **kw) else "FAIL"))
    else:
        for n in names:
            s = mod.sign(n, **kw)
            rows.append((n, s, "OK" if mod.verify(n, s, **kw) else "FAIL"))

    print(f"# scheme={a.scheme}  count={len(rows)}  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'NAME':<24} {'SERIAL':<72} SELFCHECK")
    print("-" * 104)
    for n, s, ok in rows:
        print(f"{n:<24} {s:<72} {ok}")

    if a.out:
        ext = os.path.splitext(a.out)[1].lower()
        with open(a.out, "w", encoding="utf-8", newline="") as f:
            if ext == ".csv":
                w = csv.writer(f)
                w.writerow(["name", "serial", "selfcheck"])
                w.writerows(rows)
            elif ext == ".json":
                json.dump([{"name": n, "serial": s, "ok": ok} for n, s, ok in rows],
                          f, indent=2, ensure_ascii=False)
            else:
                for n, s, _ in rows:
                    f.write(f"{n}\t{s}\n")
        print(f"\n[+] 已写出 -> {a.out}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------
def cmd_verify(a) -> int:
    mod = schemes.get(a.scheme)["mod"]
    if a.scheme == "rsa":
        pub = load_or_make_keypair()["public"]
        data = mod.inspect(a.serial, pub)
        print("VALID" if data else "INVALID")
        if data:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0 if data else 1
    ok = mod.verify(a.name, a.serial)
    print("VALID" if ok else "INVALID")
    return 0 if ok else 1


# ---------------------------------------------------------------------
# 自校验：每个方案 200 组随机 name，sign->verify 必须全通
# ---------------------------------------------------------------------
def cmd_selftest(_a) -> int:
    import string
    rnd = __import__("random")
    fails = 0
    print(f"{'SCHEME':<10} {'CASES':<8} {'PASS':<8} {'NEG-CTRL':<10} RESULT")
    print("-" * 52)
    for name in schemes.SCHEMES:
        mod = schemes.get(name)["mod"]
        kw = {}
        if name == "rsa":
            kp = load_or_make_keypair()
            kw = {"priv": kp["private"]}
        p = neg = 0
        for _ in range(200):
            nm = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(rnd.randint(4, 16)))
            if name == "rsa":
                s = mod.sign(nm, kw["priv"])
                ok = mod.verify(nm, s, kp["public"]) is not None
            else:
                s = mod.sign(nm)
                ok = mod.verify(nm, s)
            p += bool(ok)
            # 负控：改一位必须被拒
            if name == "rsa":
                bad = s[:-2] + ("AA" if s[-2:] != "AA" else "BB")
                neg += (mod.inspect(bad, kp["public"]) is None)
            else:
                bad = s[:-1] + ("0" if s[-1] != "0" else "1")
                neg += (not mod.verify(nm, bad))
        good = (p == 200 and neg == 200)
        fails += (not good)
        print(f"{name:<10} {200:<8} {p:<8} {neg:<10} {'PASS' if good else 'FAIL'}")
    print("-" * 52)
    print("SELFTEST", "PASS" if fails == 0 else f"FAIL ({fails})")
    return 0 if fails == 0 else 1


# ---------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(prog="keygen", description="许可证算法演示实现")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="列出可用方案")

    g = sub.add_parser("gen", help="生成序列号")
    g.add_argument("--scheme", required=True)
    g.add_argument("--name", default=None, help="授权名；缺省则批量 USER0001..")
    g.add_argument("--namefile", default=None, help="每行一个授权名的文件")
    g.add_argument("--count", type=int, default=1)
    g.add_argument("--exp", default="9999-12-31", help="到期日 YYYY-MM-DD 或 YYYYMMDD")
    g.add_argument("--features", default="PRO")
    g.add_argument("--bits", type=int, default=1024)
    g.add_argument("--keygen-keypair", action="store_true", help="强制重生成 RSA 密钥对")
    g.add_argument("--secret-file", default=None)
    g.add_argument("--secret-hex", default=None)
    g.add_argument("--out", default=None, help="输出 .txt/.csv/.json")
    g.set_defaults(func=cmd_gen)

    v = sub.add_parser("verify", help="校验序列号")
    v.add_argument("--scheme", required=True)
    v.add_argument("--name", required=True)
    v.add_argument("--serial", required=True)
    v.set_defaults(func=cmd_verify)

    s = sub.add_parser("selftest", help="全方案 sign/verify 往返 + 负控回归")
    s.set_defaults(func=cmd_selftest)

    a = ap.parse_args()
    if a.cmd == "list":
        print("可用方案：")
        print(schemes.listing())
        return 0
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
