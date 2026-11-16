# -*- coding: utf-8 -*-
"""人类会话：主密码 + TOTP 登录、会话级 HttpOnly cookie、滑动空闲、登出、CSRF。

会话只有两态：已登录 / 未登录。「锁定」已并入「退出登录」——`destroy()` 只删
会话与 cookie，**从不触碰** `Broker.key`；服务重启后的 423 `vault_locked` 是
「保险库尚未解密」，与登录态无关。

计时模型（无绝对过期）：

  · 每条会话只有一个 `idle` 到期时刻，任何一次成功续期都推后到 `now + span`；
  · span 由 remember 决定：勾选「本窗口保持登录」= `SESSION_IDLE_KEEP`（4 小时），
    不勾 = `SESSION_IDLE`（15 分钟）；
  · 续期来源只有两种：勾选档的任意请求（含面板 3 秒轮询），或不勾档时用户真实
    操作触发的 `touch()`。Agent 的请求不带 cookie，且「新审批入队」刻意不续期，
    所以谁也拖不成永久会话；
  · cookie 恒为会话级（不写 `Max-Age`），关浏览器即被丢弃 —— 这才是「关窗即退」
    的真正保障，与 span 取 900 还是 14400 无关。

关闭标签页后服务端为什么能知道：前端在 `pagehide` 时 `sendBeacon('/api/session/bye')`
打一个标记，服务端**不立刻删**——刷新、站内跳转会马上发新请求，任何请求都撤销标记。
超过 `SESSION_BYE_GRACE`（60 秒）仍没有任何请求，才判定「窗口真的关了」并清掉记录。
两个时间戳分工：

  · `last` —— 最近一次**真实活动**（remember 续期或 touch），列表里显示为「最近活动」；
  · `seen` —— 最近一次**任何**请求（含 3 秒轮询），在线判定与超限淘汰都用它。

只看 `last` 会把「挂着不动但一直在轮询」的标签页误报成离线，只看 `seen` 又会把
「刚被关掉的标签页」显示成在线 90 秒，所以两个都要。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
import urllib.parse

from . import config, unlock
from .storage import audit

_LOCK = threading.Lock()
_SESSIONS: dict[str, dict] = {}
_LOGIN_FAILS: dict[str, list] = {}
_COOKIE = "akg_session"
_HINT = "akg_https"
_LOGIN_WINDOW = 60
_LOGIN_MAX = 8

# 会话生命周期相关审计事件：近期记录的过滤名单。
# session_bye 与 session_expired 必须分开：前者是「窗口关了」，后者是「放着不动超时」，
# 混在一起就分不清「我关的」和「自己掉的」。
SESSION_EVENTS = ("login_ok", "logout", "session_revoke", "session_expired",
                  "session_evict", "session_bye", "session_prune")

# 设备摘要用的 UA 特征。顺序有意义：Edge/Opera 的 UA 里也含 Chrome/，
# Chrome 的 UA 里也含 Safari/，所以必须从最具体匹配到最宽泛。
_UA_BROWSERS = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                ("Chrome/", "Chrome"), ("Safari/", "Safari"))
_UA_SYSTEMS = (("Windows", "Windows"), ("iPhone", "iOS"), ("iPad", "iPadOS"),
               ("Android", "Android"), ("Mac OS X", "macOS"),
               ("Macintosh", "macOS"), ("Linux", "Linux"))


def _cookie_value(handler, name: str) -> str:
    raw = handler.headers.get("Cookie", "")
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


def _cookie(name: str, value: str, max_age: int | None = None,
            secure: bool = False) -> str:
    """拼 Set-Cookie。max_age=None 时**不写 Max-Age**，即浏览器会话 cookie。"""
    bits = [f"{name}={value}", "Path=/"]
    if max_age is not None:
        bits.append(f"Max-Age={max_age}")
    bits.append("SameSite=Strict")
    if secure:
        bits.append("Secure")
    if name == _COOKIE:
        bits.append("HttpOnly")
    return "; ".join(bits)


def set_session_cookie(handler, token: str) -> None:
    # 关键：不传 max_age。会话级 cookie 关浏览器即消失，这是「关窗即退」的根。
    handler._auth_cookie = _cookie(_COOKIE, token, None, True)


def clear_session_cookie(handler) -> None:
    handler._auth_cookie = _cookie(_COOKIE, "", 0, True)


def set_https_hint(handler) -> None:
    # 仅“已安装根证书”的提示，不是身份凭证；不设 Secure 才能在 HTTP 侧读到。
    handler._auth_cookie = _cookie(_HINT, "1", 86400 * 365, False)


def clear_https_hint(handler) -> None:
    handler._auth_cookie = _cookie(_HINT, "", 0, False)


def has_https_hint(handler) -> bool:
    return _cookie_value(handler, _HINT) == "1"


# ────────────────────────────── 会话索引 ──────────────────────────────

def _sid(token: str) -> str:
    """对外标识：sha256(token) 前 12 位。不可反推、不可当凭证用。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _span(rec: dict) -> int:
    return config.SESSION_IDLE_KEEP if rec.get("remember") else config.SESSION_IDLE


def _evict_oldest() -> dict | None:
    """超上限时淘汰最久没发过请求的一条（调用方必须持锁）。返回被淘汰记录。

    用 `seen` 而不是 `last`：不勾保持登录的标签页一直挂着不动，`last` 永远是登录
    那一刻，按 `last` 排序会把「一直开着的最新窗口」当成最旧的淘汰掉。
    """
    if len(_SESSIONS) < max(1, config.SESSION_MAX):
        return None
    victim = min(_SESSIONS.items(),
                 key=lambda kv: kv[1].get("seen") or kv[1].get("last", 0))[0]
    return _SESSIONS.pop(victim, None)


def _reap_locked(now: float, keep: str = "") -> list[tuple[str, dict]]:
    """持锁调用：清掉已关页 / 已超时的会话，返回待落审计的 (事件, 记录) 列表。

    `keep` 是本次请求自己的 token：先续期再清别人，避免把自己误杀。
    """
    dead: list[tuple[str, dict]] = []
    for t, s in list(_SESSIONS.items()):
        if t == keep:
            continue
        bye_at = s.get("bye") or 0
        if bye_at and now - bye_at > config.SESSION_BYE_GRACE:
            dead.append(("session_bye", _SESSIONS.pop(t)))
        elif s.get("idle", 0) <= now:
            dead.append(("session_expired", _SESSIONS.pop(t)))
    return dead


def _audit_dead(dead: list[tuple[str, dict]]) -> None:
    for event, s in dead:
        audit({"event": event, "sid": s.get("sid"), "device": s.get("device"),
               "ip": s.get("ip"), "remember": bool(s.get("remember"))})


def device_of(ua: str) -> str:
    """把 User-Agent 压成「Chrome · Windows」这样的短摘要，供会话列表展示。"""
    raw = str(ua or "")
    if not raw.strip():
        return "未知客户端"
    browser = next((n for k, n in _UA_BROWSERS if k in raw), "其他浏览器")
    system = next((n for k, n in _UA_SYSTEMS if k in raw), "未知系统")
    return f"{browser} · {system}"


# ────────────────────────────── 生命周期 ──────────────────────────────

def current(handler, touch: bool = False):
    """读当前会话；过期即删并落审计。

    `touch=True` 只在 `POST /api/session/touch` 里传：那是用户真实操作触发的
    续期，不勾选档也认。其余请求一律走 `touch=False`，此时只有 remember 会话
    才续期 —— 否则面板自己的轮询就能让 15 分钟超时彻底失效。

    无论哪个档，每次请求都会刷新 `seen` 并撤销 `bye` 标记（后者见模块注释）。
    """
    tok = _cookie_value(handler, _COOKIE)
    if not tok:
        return None
    now = time.time()
    rec = None
    dead: list[tuple[str, dict]] = []
    with _LOCK:
        s = _SESSIONS.get(tok)
        if s:
            s.pop("bye", None)
            s["seen"] = now
            if s["idle"] <= now:
                dead.append(("session_expired", _SESSIONS.pop(tok)))
            else:
                if touch or s.get("remember"):
                    s["last"] = now
                    # 只延长、不缩短：remember 与 touch 交叉调用时不会把计时拉回。
                    s["idle"] = max(s["idle"], now + _span(s))
                rec = dict(s)
        # 顺手清理别人的：列表页与 3 秒轮询都会走到这里，等于一个免费的后台清扫。
        dead.extend(_reap_locked(now, tok))
    if dead:
        _audit_dead(dead)
    return rec


def create(handler, ip: str, ua: str, remember: bool = False):
    now = time.time()
    tok = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    rec = {"sid": _sid(tok), "created": now, "last": now, "seen": now,
           "idle": now + (config.SESSION_IDLE_KEEP if remember
                          else config.SESSION_IDLE),
           "remember": bool(remember), "csrf": csrf,
           "ip": ip, "ua": (ua or "")[:200], "device": device_of(ua)}
    with _LOCK:
        evicted = _evict_oldest()
        _SESSIONS[tok] = rec
    if evicted:
        audit({"event": "session_evict", "sid": evicted["sid"],
               "device": evicted["device"], "ip": evicted["ip"]})
    set_session_cookie(handler, tok)
    return tok, rec


def bye(handler) -> bool:
    """标记「本窗口正在关闭」。不删会话——刷新/站内跳转会立刻撤销它。

    由 `navigator.sendBeacon()` 调用，没有自定义头（所以不做 CSRF 校验），
    但必须带 cookie；`SameSite=Strict` 保证跨站请求根本带不上 cookie。
    """
    tok = _cookie_value(handler, _COOKIE)
    if not tok:
        return False
    with _LOCK:
        s = _SESSIONS.get(tok)
        if not s:
            return False
        s["bye"] = time.time()
        return True


def destroy(handler, token: str = "") -> None:
    """登出：删会话 + 清 cookie。不碰 Broker.key（那是保险库解密态）。"""
    tok = token or _cookie_value(handler, _COOKIE)
    if tok:
        with _LOCK:
            _SESSIONS.pop(tok, None)
    clear_session_cookie(handler)


def revoke(handler, sid: str) -> tuple[bool, bool]:
    """按 sid 踢下线。返回 (是否命中, 是否踢的是自己)。"""
    tok = _cookie_value(handler, _COOKIE)
    hit = None
    is_self = False
    with _LOCK:
        for t, s in list(_SESSIONS.items()):
            if s.get("sid") == sid:
                hit = _SESSIONS.pop(t, None)
                is_self = (t == tok)
                break
    if not hit:
        return False, False
    audit({"event": "session_revoke", "sid": hit["sid"], "device": hit["device"],
           "ip": hit["ip"], "self": is_self})
    if is_self:
        # 必须同时清 cookie，否则跳 /login 后仍会因 cookie 存在被 302 回来。
        clear_session_cookie(handler)
    return True, is_self


def list_sessions(handler) -> list[dict]:
    """会话列表（当前会话在前，其余按最近活动倒序）。不含 token / csrf。

    `online` 看 `seen`（最近任何请求）而不是 `last`（最近真实操作），否则「开着
    但没在动」的标签页会被误判为离线；关掉的标签页超过 `SESSION_ONLINE` 秒没有
    请求，就会自然变成「已离线」，不需要等到 idle 到期。
    """
    tok = _cookie_value(handler, _COOKIE)
    now = time.time()
    online_span = max(1, config.SESSION_ONLINE)
    with _LOCK:
        dead = _reap_locked(now, tok)
        rows = [{
            "sid": s["sid"],
            "device": s.get("device") or device_of(s.get("ua", "")),
            "ip": s.get("ip", ""),
            "created": int(s["created"]),
            "last": int(s["last"]),
            "seen": int(s.get("seen") or s["last"]),
            "online": (now - (s.get("seen") or s["last"])) <= online_span,
            "remember": bool(s.get("remember")),
            "self": t == tok,
            "idle_in": max(0, int(s["idle"] - now)),
        } for t, s in _SESSIONS.items()]
    if dead:
        _audit_dead(dead)
    rows.sort(key=lambda r: (not r["self"], not r["online"], -r["seen"]))
    return rows


def prune_offline(handler) -> int:
    """清掉所有已离线的会话记录（不含自己），返回清理条数。

    只删记录不删「正在用的浏览器」：真正在线的那条 `seen` 是刚刚，扫不到。
    """
    tok = _cookie_value(handler, _COOKIE)
    now = time.time()
    online_span = max(1, config.SESSION_ONLINE)
    gone: list[dict] = []
    with _LOCK:
        for t, s in list(_SESSIONS.items()):
            if t == tok:
                continue
            if now - (s.get("seen") or s["last"]) > online_span:
                gone.append(_SESSIONS.pop(t))
    for s in gone:
        audit({"event": "session_prune", "sid": s.get("sid"),
               "device": s.get("device"), "ip": s.get("ip"),
               "remember": bool(s.get("remember"))})
    return len(gone)


def idle_in(rec: dict) -> int:
    """剩余秒数，供 /api/me 与 touch 回包校准前端倒计时。"""
    return max(0, int(rec["idle"] - time.time()))


# ────────────────────────────── 登录限流 ──────────────────────────────

def login_allowed(ip: str) -> bool:
    now = time.time()
    with _LOCK:
        arr = [t for t in _LOGIN_FAILS.get(ip, []) if t > now - _LOGIN_WINDOW]
        _LOGIN_FAILS[ip] = arr
        return len(arr) < _LOGIN_MAX


def note_login_fail(ip: str) -> None:
    with _LOCK:
        _LOGIN_FAILS.setdefault(ip, []).append(time.time())


def clear_login_fail(ip: str) -> None:
    with _LOCK:
        _LOGIN_FAILS.pop(ip, None)


def origin_ok(handler) -> bool:
    origin = handler.headers.get("Origin", "")
    if not origin:
        return True
    try:
        return urllib.parse.urlsplit(origin).netloc == handler.headers.get("Host", "")
    except Exception:  # noqa: BLE001
        return False


def csrf_ok(handler, session: dict) -> bool:
    if handler.command in ("GET", "HEAD", "OPTIONS"):
        return True
    return hmac.compare_digest(
        str(handler.headers.get("X-CSRF-Token", "")),
        str(session.get("csrf", "")),
    )


def require(handler):
    s = current(handler)
    if not s:
        handler._send(401, {"error": "login_required"})
        return None
    if not csrf_ok(handler, s):
        handler._send(403, {"error": "csrf"})
        return None
    return s


def login(vault: dict, username: str, master: str, code: str) -> tuple[bool, str]:
    p = vault.get("portal") or {}
    expected = str(p.get("username") or "admin")
    if not hmac.compare_digest(str(username or "admin"), expected):
        return False, "bad_username"
    return unlock.verify_password(vault, master, code)
