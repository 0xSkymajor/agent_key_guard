# -*- coding: utf-8 -*-
"""密码学原语：密钥派生、vault blob 加解密、面板密码 KDF 与 TOTP。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

⚠️ MAGIC 与 AAD 是加密格式的组成部分，**绝对不许改**：
  - MAGIC 是密文魔数前缀，用于校验文件格式；
  - AAD 是 AES-GCM 的附加认证数据（AAD），改了现有 vault.enc 永远解不开。
它不是产品名，重命名时绝不改动 —— 历次 VaultBroker→AgentKeyGuard
改名都特意跳过它。要改只有一条路：先解密全库、再换 AAD 重新加密。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time

MAGIC = b"VBRKv1\x00\x00"
AAD = b"vaultbroker-vault-v1"
SCRYPT = dict(n=1 << 15, r=8, p=1)          # 32 MiB, 约 100ms


def _aesgcm(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key)


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, dklen=32,
        maxmem=128 * 1024 * 1024, **SCRYPT,
    )


def hkdf_mix(kek: bytes, secret: bytes) -> bytes:
    """把服务端密钥混进 KEK。

    有了这一层，攻击者光拿到主密码还不够——还得拿到 /etc 下那把 root-only
    的 vault-secret 才能算出正确的 KEK。它挡的是「拿到服务用户权限但不是 root」
    这一类，挡不住 root。
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b"akg-vault-kek-v1", info=b"agentkeyguard").derive(kek + secret)


def unlock_blob(blob: bytes, password: str, secret: bytes = b"") -> tuple[dict, bytearray]:
    """用主密码解库，返回 (数据, KEK)。

    盐就存在 blob 头部，所以不需要任何附加文件——这也是能彻底去掉 master.key
    的原因：派生所需的一切都在密文里，或者在你脑子里。

    密码错时 AES-GCM 认证失败直接抛 ValueError，不需要另存密码校验值：
    「解得开」本身就是「密码对」。
    """
    if len(blob) < 38 or blob[:8] != MAGIC:
        raise ValueError("vault 文件格式不正确")
    salt = blob[8:24]
    kek = derive_key(password, salt)
    if secret:
        kek = hkdf_mix(kek, secret)
    data = _decrypt_blob(blob, kek)
    # 用 bytearray 返回：bytes 不可变，无法在锁定/退出时原地覆写
    return data, bytearray(kek)


def _decrypt_blob(blob: bytes, key: bytes) -> dict:
    if len(blob) < 38 or blob[:8] != MAGIC:
        raise ValueError("vault 文件格式不正确")
    nonce, ct = blob[24:36], blob[36:]
    return json.loads(_aesgcm(key).decrypt(nonce, ct, AAD).decode("utf-8"))


def _encrypt_to_blob(data: dict, key: bytes, salt: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm(key).encrypt(
        nonce, json.dumps(data, ensure_ascii=False).encode("utf-8"), AAD)
    return MAGIC + salt + nonce + ct


# ────────────────────────────── 面板密码 KDF / TOTP ──────────────────────────────

def portal_hash(pw: str, salt: bytes) -> bytes:
    """面板密码的 KDF。n=2^14 足够——它只是在线校验，且还有 TOTP 兜底。"""
    return hashlib.scrypt(pw.encode("utf-8"), salt=salt, dklen=32,
                          maxmem=64 * 1024 * 1024, n=1 << 14, r=8, p=1)


def totp(secret_b32: str, digits: int = 6, period: int = 30, at: float | None = None) -> str:
    key = base64.b32decode(re.sub(r"[\s-]", "", secret_b32).upper())
    counter = int((time.time() if at is None else at) // period)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = h[-1] & 0x0F
    val = struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF
    return str(val % (10 ** digits)).zfill(digits)
