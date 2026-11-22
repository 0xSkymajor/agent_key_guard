# -*- coding: utf-8 -*-
"""管道一：服务侧动态 env 注入 + 挂起人工授权（单次授权）。"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import re
import secrets
import threading
import time

from .approval import push_bark

_LOCK = threading.Lock()
PENDING: dict[str, dict] = {}
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_MAX_VALUE_LEN = 4096


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _hash(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()


def _clean_env(env: dict) -> dict:
    """清洗环境变量：键名合法、值去首尾空白、不空、不超长。

    与前端 `parseEnvText` 的校验规则保持一致（REQ-118）：前端已经拦过一遍，
    这里再拦是防止有人直接打接口塞进空值或超长值。
    """
    out = {}
    for k, v in (env or {}).items():
        key = str(k).strip()
        if not _KEY_RE.match(key):
            raise ValueError(f"bad_env_key:{key}")
        val = str(v).strip()
        if not val:
            raise ValueError(f"empty_env_value:{key}")
        if len(val) > _MAX_VALUE_LEN:
            raise ValueError(f"env_value_too_long:{key}")
        out[key] = val
    if not out:
        raise ValueError("empty_env")
    return out


def list_services(vault: dict) -> list:
    return [{
        "id": s.get("id", sid),
        "name": s.get("name", ""),
        "env_keys": list(s.get("env_keys") or []),
        "builtin": s.get("builtin", ""),
        "created": s.get("created", ""),
        "last_request": s.get("last_request", ""),
        "revoked": bool(s.get("revoked")),
    } for sid, s in sorted((vault.get("services") or {}).items())]


def delete_env_key(vault: dict, sid: str, key: str) -> bool:
    """删单个键值对（Bark 的历史一条条删，不用把整个服务清掉）。"""
    s = (vault.get("services") or {}).get(sid)
    if not s:
        return False
    env = s.get("env") or {}
    if key not in env:
        return False
    env.pop(key, None)
    s["env"] = env
    s["env_keys"] = sorted(env)
    if not env:
        vault["services"].pop(sid, None)     # 键删空了，记录本身也没意义了
    return True


def service_by_token(vault: dict, token: str) -> tuple[str, dict] | None:
    h = _hash(token or "")
    for sid, s in (vault.get("services") or {}).items():
        if s.get("builtin") or s.get("revoked"):
            continue                          # 内置留档记录不参与鉴权
        if hmac.compare_digest(str(s.get("token_hash") or ""), h):
            return sid, s
    return None


def create_service(vault: dict, name: str, env: dict) -> tuple[dict, str]:
    name = (name or "").strip()
    if not name or len(name) > 64:
        raise ValueError("bad_service_name")
    env = _clean_env(env)
    sid = secrets.token_hex(6)
    token = secrets.token_urlsafe(32)
    svc = {
        "id": sid, "name": name, "token_hash": _hash(token),
        "env": env, "env_keys": sorted(env),
        "created": _now(), "last_request": "", "revoked": False,
    }
    vault.setdefault("services", {})[sid] = svc
    return svc, token


def update_service(vault: dict, sid: str, env: dict) -> bool:
    s = (vault.get("services") or {}).get(sid)
    if not s or s.get("revoked"):
        return False
    if env:
        s["env"] = _clean_env(env)
        s["env_keys"] = sorted(s["env"])
    return True


def revoke_service(vault: dict, sid: str) -> bool:
    s = (vault.get("services") or {}).get(sid)
    if not s:
        return False
    s["revoked"] = True
    return True


def delete_service(vault: dict, sid: str) -> bool:
    """从列表里彻底移除。

    撤销（revoke）只是停用、保留记录便于追溯；删除用于清理建错的/不再需要的服务。
    记录一旦删除，它对应的注入 URL 立即失效（token_hash 随之消失）。
    """
    svcs = vault.get("services") or {}
    if sid not in svcs:
        return False
    svcs.pop(sid, None)
    return True


def _notify(rid: str, name: str, keys: list) -> None:
    try:
        push_bark(rid, "service.env", name, name, ", ".join(keys),
                  title=f"服务 {name} 请求环境变量", quiet=True)
    except Exception:  # noqa: BLE001
        pass


def request_env(vault: dict, token: str, keys, ip: str, ua: str,
                timeout: int = 300) -> tuple[dict | None, str, int]:
    found = service_by_token(vault, token)
    if not found:
        return None, "bad_service_token", 403
    _sid, s = found
    allowed = set(s.get("env_keys") or [])
    want = [k for k in (keys or []) if k in allowed] if keys else list(s.get("env_keys") or [])
    if keys and not want:
        return None, "no_allowed_keys", 403
    if not want:
        return None, "empty_env", 403

    # 指纹去重：客户端超时重试会把同一条 env 请求发两遍（1.4.3 在普通审批路径
    # 已经用 approval_identity 修过，env 服务路径当时漏了）。同一服务、同一组
    # key、且上一条还在等审批时，复用它的结论，不再新建卡片、不再推一条 Bark。
    # 只有「仍在等待」的才算孪生；已决策/已 pop 的都是正常的新请求，不合并。
    identity = (_sid, tuple(sorted(want)))
    with _LOCK:
        twin = next((e for e in PENDING.values()
                     if not e.get("decision") and e.get("identity") == identity), None)
        if twin is None:
            rid = secrets.token_hex(8)
            ev = threading.Event()
            entry = {"request_id": rid, "event": ev, "decision": None,
                     "service": s["name"], "sid": _sid, "keys": want,
                     "ip": ip, "ua": (ua or "")[:200], "created": time.time(),
                     "identity": identity}
            PENDING[rid] = entry
            owner = True
        else:
            entry = twin
            owner = False

    if owner:
        threading.Thread(target=_notify, args=(rid, s["name"], want), daemon=True).start()

    # 主请求和孪生请求都等同一个 Event；只有 owner 负责推送和清理。
    # 这样一次审批只推一条 Bark、只显示一张卡，两条请求都拿到相同结论。
    ok = entry["event"].wait(timeout)
    if owner:
        with _LOCK:
            PENDING.pop(rid, None)
    if not ok:
        return None, "timeout", 408
    if entry.get("decision") != "yes":
        return None, str(entry.get("reason") or "denied"), 403
    s["last_request"] = _now()
    return {k: (s.get("env") or {}).get(k, "") for k in want}, "", 200


def pending_head() -> dict | None:
    """只返回「还在等」的那一条（和 approval.pending_head 同语义）。

    曾经不过滤已决策条目：点了「批准」后、request_env 线程还没 pop 的那一瞬间，
    旧卡片会被下一次 3 秒轮询再次显示出来；再点一次就是对一个已消失的 rid 决策，
    services.decide 返回 False → /api/service/decision 报 404。这是「点到最后一个
    弹 Not Found」的根因。已决策的不再展示，队列数也只算真正等待中的。
    """
    with _LOCK:
        items = [e for e in PENDING.values() if not e.get("decision")]
        items.sort(key=lambda e: e["created"])
        if not items:
            return None
        e = items[0]
        return {"request_id": e["request_id"], "service": e["service"],
                "keys": list(e["keys"]), "ip": e["ip"], "created": e["created"],
                "title": f"服务 {e['service']} 请求环境变量", "queue": len(items)}


def decide(rid: str, decision: str, reason: str = "") -> bool:
    """幂等：条目存在即视为成功（已决策过的重复点击直接忽略，不覆盖结论）。

    和 /api/approve 的语义对齐——同一条决策重复提交不该报 not_found。
    只有 rid 根本不存在（超时已 pop / 伪造）才返回 False。
    """
    with _LOCK:
        e = PENDING.get(rid)
        if not e:
            return False
        if e.get("decision"):
            return True                      # 重复点击：保留先到的结论，直接 OK
        e["decision"] = "yes" if decision == "yes" else "no"
        e["reason"] = str(reason or "")[:500]
        e["event"].set()
        return True
