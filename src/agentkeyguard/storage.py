# -*- coding: utf-8 -*-
"""保险箱读写、访问令牌与审计日志。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

⚠️ 状态变量一律"调用期读取"：所有路径都写成 config.VAULT_PATH 等，
绝不 `from .config import VAULT_PATH` 把值固化到本模块。原因：selftest 会在
运行期把 config.VAULT_PATH/TOKEN_PATH/AUDIT_PATH/DATA_DIR 指向临时目录，
固化后自检就改不动了。
"""
from __future__ import annotations

import datetime
import json
import os
import secrets
import sys
import threading
from pathlib import Path

from . import config
from .crypto import MAGIC, _decrypt_blob, _encrypt_to_blob, derive_key


def _ensure_home() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config.DATA_DIR, 0o700)
    except OSError:
        pass


def read_vault_with_key(key: bytes) -> dict:
    """用已派生的 KEK 直接重读 vault.enc —— 供 /admin/reload 热加载用。"""
    return _decrypt_blob(config.VAULT_PATH.read_bytes(), key)


def read_vault_salt() -> bytes:
    """只读 blob 头部的盐（第 8~24 字节），不解密、不碰密文主体。

    盐不是秘密，暴露它没有风险；但它决定了「同一个密码能否算出同一个 KEK」。
    """
    blob = config.VAULT_PATH.read_bytes()
    if len(blob) < 38 or blob[:8] != MAGIC:
        raise ValueError("vault 文件格式不正确")
    return blob[8:24]


def unlock_vault(password: str, secret: bytes = b"") -> tuple[dict, bytearray]:
    """从磁盘解库，全程不落盘任何密钥。密码错抛 ValueError。"""
    from .crypto import unlock_blob
    return unlock_blob(config.VAULT_PATH.read_bytes(), password, secret)


# ── KDF 模式侧车与服务端密钥（REQ-308） ──

def read_meta() -> dict:
    """读 vault.meta。不存在或损坏时按纯 scrypt 处理（旧库兼容）。"""
    try:
        return json.loads(config.VAULT_META_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def write_meta(meta: dict) -> None:
    _ensure_home()
    tmp = config.VAULT_META_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, config.VAULT_META_PATH)


def load_vault_secret() -> bytes:
    """读服务端密钥。优先 systemd 传入的 credential，其次 /etc 下的文件。

    两处都没有就返回 b""——表示不启用这一层，库仍可用纯 scrypt 解开。
    """
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY") or ""
    candidates = []
    if cred_dir:
        candidates.append(Path(cred_dir) / "vault_secret")
    candidates.append(config.VAULT_SECRET_PATH)
    for p in candidates:
        try:
            if p.exists():
                raw = p.read_text(encoding="utf-8").strip()
                if raw:
                    return raw.encode("utf-8")
        except OSError:
            continue
    return b""


def vault_kdf_mode() -> str:
    """当前库用的派生方式：'scrypt' 或 'scrypt+secret'。"""
    return str(read_meta().get("kdf") or "scrypt")


def load_vault(password: str):
    """返回 (data, salt)。主密码错误会抛 SystemExit。"""
    if not config.VAULT_PATH.exists():
        raise SystemExit(f"没有找到 {config.VAULT_PATH}，先运行: {Path(sys.argv[0]).name} init")
    blob = config.VAULT_PATH.read_bytes()
    if len(blob) < 38 or blob[:8] != MAGIC:
        raise SystemExit("vault 文件格式不正确")
    salt = blob[8:24]
    key = derive_key(password, salt)
    try:
        return _decrypt_blob(blob, key), salt
    except Exception:
        raise SystemExit("主密码错误，或 vault 文件已损坏")


def save_vault(data: dict, password: str, salt: bytes) -> None:
    key = derive_key(password, salt)
    _write_vault_blob(_encrypt_to_blob(data, key, salt))


def _write_vault_blob(blob: bytes) -> None:
    _ensure_home()
    tmp = config.VAULT_PATH.with_suffix(".tmp")
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, config.VAULT_PATH)


def ensure_token() -> str:
    _ensure_home()
    if config.TOKEN_PATH.exists():
        t = config.TOKEN_PATH.read_text(encoding="utf-8").strip()
        if t:
            return t
    tok = secrets.token_urlsafe(32)
    config.TOKEN_PATH.write_text(tok + "\n", encoding="utf-8")
    os.chmod(config.TOKEN_PATH, 0o600)
    return tok


# ────────────────────────────── 审计 ──────────────────────────────

_audit_lock = threading.Lock()


def audit(rec: dict, quiet: bool = False) -> None:
    """落一行 JSON 审计。quiet=True 时**不打印**（仍写文件）。

    为什么要 quiet：向导是绿色主题的交互界面，中间插一行
    `[审计] {"event": "..."}` 会把版面切碎。默认 False 保持不变，
    旧命令的输出一字不动 —— 只在 setup 里传 quiet。
    注意：审计**必须照写**，quiet 只压屏显，不做取舍。
    """
    rec = {"ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), **rec}
    line = json.dumps(rec, ensure_ascii=False, default=str)
    with _audit_lock:
        try:
            _ensure_home()
            with open(config.AUDIT_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            os.chmod(config.AUDIT_PATH, 0o600)
        except OSError:
            pass
    if not quiet:
        print(f"  [审计] {line}", flush=True)


def read_audit_tail(limit: int = 20, events=None) -> list[dict]:
    """从审计文件尾部倒读最近 `limit` 条记录（可只取指定事件），返回正序。

    只读尾部 64KB 块并逐块前移，绝不整文件读入：审计会随运行时间无限增长，
    一次性 read_text 会让面板越用越慢，也白占内存。
    文件不存在、权限不足、某行 JSON 损坏都只是跳过，不向上抛异常。
    """
    want = set(events or ())
    out: list[dict] = []
    chunk = 64 * 1024
    try:
        fh = open(config.AUDIT_PATH, "rb")
    except OSError:
        return out
    with fh:
        try:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
        except OSError:
            return out
        buf = b""
        while pos > 0 and len(out) < limit:
            step = min(chunk, pos)
            pos -= step
            fh.seek(pos)
            block = fh.read(step) + buf
            lines = block.split(b"\n")
            if pos > 0:
                # 首段可能被块边界切断，留到下一轮和更前面的字节拼起来
                buf = lines[0]
                candidates = lines[1:]
            else:
                buf = b""
                candidates = lines
            for raw in reversed(candidates):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw.decode("utf-8"))
                except Exception:  # noqa: BLE001
                    continue
                if not isinstance(rec, dict):
                    continue
                if want and rec.get("event") not in want:
                    continue
                out.append(rec)
                if len(out) >= limit:
                    break
    return list(reversed(out))


def save_vault_with_key(key: bytes, data: dict) -> None:
    """用已缓存的 KEK 落盘。salt 沿用文件头里的，所以不需要主密码。"""
    if not key:
        raise RuntimeError("服务未缓存解锁密钥，无法写盘")
    salt = config.VAULT_PATH.read_bytes()[8:24]
    _write_vault_blob(_encrypt_to_blob(data, key, salt))
