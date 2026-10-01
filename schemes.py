# -*- coding: utf-8 -*-
"""
schemes.py — 许可证校验方案模板集（keygen 引擎）

每个方案提供一对函数：
    sign(name, **opts)    -> str    生成序列号 / 许可 blob
    verify(name, serial)  -> bool   复刻目标端校验逻辑（用于自校验 + 回归）

工程用法（逆向 -> keygen 的落地路径）：
    1. 从目标 CHECK_FN 还原出：参与运算的字段、常量、运算序列
    2. 在本文件中匹配最接近的模板，替换 SALT / TARGET / 模数 / 权重
    3. 若目标方案不在模板里，照抄一个 scheme 结构新增即可（见文末 add_scheme 说明）
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import random
import time

SCHEMES: dict[str, dict] = {}


def scheme(name: str, desc: str):
    def deco(cls):
        SCHEMES[name] = {"desc": desc, "mod": cls}
        return cls
    return deco


# =====================================================================
# 方案 A：MD5 + 静态盐 -> Base32 序列号
# 还原来源：目标把 name 小写化 -> 拼 .rdata 常量盐 -> MD5 -> 取前 N 字节转 Base32
# 需替换常量：SALT（从目标常量池/strings 提取）
# =====================================================================
@scheme("md5salt", "MD5(name.lower() + SALT) -> Base32 分组序列号")
class Md5Salt:
    SALT = b"PLACEHOLDER_SALT"   # <<< 换成目标里的盐
    LEN = 16                     # 序列号字符数（不含分隔符）
    GROUP = 4                    # 分组宽度

    @classmethod
    def sign(cls, name: str, salt: bytes | None = None, **_) -> str:
        salt = cls.SALT if salt is None else salt
        h = hashlib.md5(name.strip().lower().encode("utf-8") + salt).digest()
        s = base64.b32encode(h).decode().rstrip("=")[: cls.LEN].upper()
        return "-".join(s[i:i + cls.GROUP] for i in range(0, len(s), cls.GROUP))

    @classmethod
    def verify(cls, name: str, serial: str, salt: bytes | None = None, **_) -> bool:
        norm = serial.replace("-", "").replace(" ", "").upper()
        want = cls.sign(name, salt).replace("-", "")
        return hmac.compare_digest(norm, want)


# =====================================================================
# 方案 B：双约束数字校验（name 权重和 + 逐位和）
# 还原来源：经典 mod-10 校验，序列号末两位由 name 决定，其余位任意
# 需替换常量：MOD、权重步进、末两位位置
# =====================================================================
@scheme("modsum", "name 字符和 / 加权和 决定序列号末两位（mod 10 双约束）")
class ModSum:
    LEN = 12

    @staticmethod
    def _plain(name: str) -> int:
        return sum(ord(c) for c in name)

    @staticmethod
    def _weighted(name: str) -> int:
        return sum(ord(c) * (i + 1) for i, c in enumerate(name))

    @classmethod
    def sign(cls, name: str, length: int | None = None, **_) -> str:
        n = length or cls.LEN
        digits = [random.randrange(10) for _ in range(n)]
        digits[-1] = cls._plain(name) % 10
        # 末二位由 name 加权和 + 前 n-2 位和 决定（自身不参与求和，保证可解）
        digits[-2] = (cls._weighted(name) + sum(digits[:-2])) % 10
        return "".join(map(str, digits))

    @classmethod
    def verify(cls, name: str, serial: str, **_) -> bool:
        serial = serial.strip()
        if not serial.isdigit() or len(serial) < 4:
            return False
        d = [int(c) for c in serial]
        if d[-1] != cls._plain(name) % 10:
            return False
        if d[-2] != (cls._weighted(name) + sum(d[:-2])) % 10:
            return False
        return True


# =====================================================================
# 方案 C：非对称离线许可（RSA 签名 license blob）
# 还原来源：目标内置公钥 (n, e)，校验 license 文件签名
# keygen 侧持有私钥 -> 签发任意 name / 有效期 / 功能位
# 这是商业离线授权最常见的形态：目标端只有公钥，无法伪造 -> 必须持私钥签发
# =====================================================================
@scheme("rsa", "RSA 私钥签发 license blob（目标端公钥验签）")
class RsaLicense:

    # ---------- 素数 / 密钥 ----------
    @staticmethod
    def _is_prime(n: int, rounds: int = 32) -> bool:
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        rnd = random.SystemRandom()
        for _ in range(rounds):
            x = pow(rnd.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    @classmethod
    def _gen_prime(cls, bits: int) -> int:
        rnd = random.SystemRandom()
        while True:
            p = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
            if cls._is_prime(p):
                return p

    @classmethod
    def gen_keypair(cls, bits: int = 1024, e: int = 65537) -> dict:
        while True:
            p, q = cls._gen_prime(bits // 2), cls._gen_prime(bits // 2)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) != 1:
                continue
            return {"n": n, "e": e, "d": pow(e, -1, phi), "bits": bits}

    # ---------- 签发 ----------
    @classmethod
    def sign(cls, name: str, priv: dict, expiry: str = "9999-12-31",
             features: str = "PRO", **_) -> str:
        payload = json.dumps(
            {"n": name, "exp": expiry, "feat": features},
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
        dg = int.from_bytes(hashlib.sha256(payload).digest(), "big")
        size = (priv["n"].bit_length() + 7) // 8
        sig = pow(dg, priv["d"], priv["n"]).to_bytes(size, "big")
        return base64.b64encode(payload + b"\x00" + sig).decode("ascii")

    # ---------- 目标端校验（只需公钥） ----------
    @classmethod
    def verify(cls, name: str, serial: str, pub: dict | None = None, **_) -> bool:
        return cls.inspect(serial, pub) is not None

    @classmethod
    def inspect(cls, blob: str, pub: dict | None = None) -> dict | None:
        try:
            raw = base64.b64decode(blob, validate=True)
            payload, _, sigb = raw.partition(b"\x00")
            data = json.loads(payload.decode("utf-8"))
        except Exception:
            return None
        if pub is None:
            return data                      # 无公钥 -> 只解出明文
        size = (pub["n"].bit_length() + 7) // 8
        if len(sigb) != size:
            return None
        dg = int.from_bytes(hashlib.sha256(payload).digest(), "big")
        if pow(int.from_bytes(sigb, "big"), pub["e"], pub["n"]) != dg:
            return None
        if data.get("exp", "9999-12-31") < time.strftime("%Y-%m-%d"):
            return None
        return data


# =====================================================================
# 方案 D：HMAC + 到期日（共享密钥，目标端内嵌 secret）
# 还原来源：目标把 name + 到期日 拼 secret 做 HMAC-SHA256，取前 8 字节
# 需替换常量：SECRET（从目标常量池提取）
# =====================================================================
@scheme("hmac", "HMAC-SHA256(SECRET, name|expiry) 截断 -> 带到期序列号")
class HmacTime:
    SECRET = b"PLACEHOLDER_SECRET"    # <<< 换成目标里的密钥
    SIGLEN = 8

    @classmethod
    def sign(cls, name: str, expiry: str = "20301231", secret: bytes | None = None,
             **_) -> str:
        secret = cls.SECRET if secret is None else secret
        msg = f"{name}|{expiry}".encode("utf-8")
        mac = hmac.new(secret, msg, hashlib.sha256).digest()[: cls.SIGLEN]
        body = base64.b32encode(mac).decode().rstrip("=")
        return f"{expiry}-{body}"

    @classmethod
    def verify(cls, name: str, serial: str, secret: bytes | None = None, **_) -> bool:
        serial = serial.strip()
        if "-" not in serial:
            return False
        expiry, _, _body = serial.partition("-")
        want = cls.sign(name, expiry, secret)
        return hmac.compare_digest(serial.upper(), want.upper())


# =====================================================================
# 方案 E：纯校验位（CRC16 尾缀）——最轻量，常见于小工具
# =====================================================================
@scheme("crc16", "CRC16(name) 十六进制尾缀")
class Crc16:
    @staticmethod
    def _crc16(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        return crc

    @classmethod
    def sign(cls, name: str, **_) -> str:
        body = base64.b32encode(name.strip().lower().encode("utf-8")).decode().rstrip("=")[:10]
        return f"{body}-{cls._crc16(name.strip().lower().encode('utf-8')):04X}"

    @classmethod
    def verify(cls, name: str, serial: str, **_) -> bool:
        return hmac.compare_digest(serial.strip().upper(), cls.sign(name).upper())


def get(name: str) -> dict:
    if name not in SCHEMES:
        raise KeyError(f"unknown scheme: {name} (available: {', '.join(SCHEMES)})")
    return SCHEMES[name]


def listing() -> str:
    return "\n".join(f"  {k:<8} {v['desc']}" for k, v in SCHEMES.items())
