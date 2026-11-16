# -*- coding: utf-8 -*-
"""登录口令校验：主密码 + TOTP 必须同时正确。

生物识别（WebAuthn / Face ID / Windows Hello）已整体移除，本模块只剩口令
校验这一件事。会话计时由 `auth` 的滑动空闲负责（`SESSION_IDLE` / `SESSION_IDLE_KEEP`），
不再有「生物识别失败 N 次转密码」的状态机 —— 那套状态机的前提（免密登录）
已经不存在了。
"""
from __future__ import annotations

import base64
import hmac
import time

from .crypto import portal_hash, totp


def verify_password(vault: dict, master: str, code: str) -> tuple[bool, str]:
    """TOTP + 主密码必须同时正确。"""
    p = vault.get("portal") or {}
    secret = p.get("totp_secret")
    if not secret or not p.get("pw_hash") or not p.get("pw_salt"):
        return False, "not_configured"
    try:
        salt = base64.b64decode(p["pw_salt"])
        want = base64.b64decode(p["pw_hash"])
    except Exception:  # noqa: BLE001
        return False, "corrupt"
    if not hmac.compare_digest(portal_hash(master or "", salt), want):
        return False, "bad_password"
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        return False, "bad_totp"
    now = time.time()
    for delta in (-30, 0, 30):
        if hmac.compare_digest(totp(secret, 6, 30, now + delta), code):
            return True, "ok"
    return False, "bad_totp"
