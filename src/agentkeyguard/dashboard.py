# -*- coding: utf-8 -*-
"""工作台页面、面板会话（desk/reveal token）与二次验证。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

⚠️ _DASH_HTML 是**逐字节原样**搬过来的内联 HTML/JS —— 严禁格式化或改写，
否则页面里的 JavaScript 会被破坏。要改只能整段替换。
"""
from __future__ import annotations

import base64
import hmac
import html
import re
import secrets
import threading
import time
from pathlib import Path

from . import VERSION, config
from .crypto import portal_hash, totp


_PAGE_CSS = """
/* AgentKeyGuard 1.4 · 手机审批页 */
:root{--text:#EBF2FF;--t2:#A8B8D8;--t3:#6C7C9F;--t4:#6C7C9F;
  --line:rgba(143,208,255,.14);--line2:rgba(143,208,255,.30);
  --ok:#3BE0A8;--warn:#FFC24B;--danger:#FF7A93;
  --mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body.has-bar{padding-bottom:168px}
body{margin:0;min-height:100vh;padding:22px 16px 60px;color:var(--text);font-size:14px;line-height:1.6;
  font-family:"PingFang SC","HarmonyOS Sans SC","Microsoft YaHei",system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
  background:
    radial-gradient(760px 420px at 8% -8%,rgba(77,107,254,.20),transparent 62%),
    radial-gradient(620px 420px at 104% 22%,rgba(108,77,254,.12),transparent 60%),
    linear-gradient(158deg,#060A24,#03050F 72%) fixed}
/* 短状态页（成功 / 失败 / 链接失效）：竖向居中，别让下半页空着 */
body:not(.has-bar){display:flex;flex-direction:column;justify-content:center;min-height:100dvh}
body:not(.has-bar) .wrap{width:100%;margin:0 auto}
.wrap{max-width:520px;margin:0 auto}
.hd{display:flex;align-items:center;gap:8px;margin:0 0 16px;font-size:11.5px;color:var(--t3);
  letter-spacing:.04em}
.hd .dot{width:6px;height:6px;border-radius:50%;background:var(--warn);box-shadow:0 0 0 3px rgba(255,194,75,.16)}
.hd .brand{color:var(--t2);font-weight:600}
h3{margin:0 0 6px;font-size:18px;font-weight:700;letter-spacing:-.01em}
p{margin:0 0 16px;color:var(--t3);font-size:12.5px}
p.sub{color:var(--t2)}
.badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;
  padding:2px 8px;border-radius:999px;color:var(--warn);
  background:rgba(255,194,75,.10);border:1px solid rgba(255,194,75,.30)}
.dban{background:rgba(255,122,147,.08);border:1px solid rgba(255,122,147,.28);color:#FFD3DB;
  border-radius:10px;padding:10px 12px;margin:0 0 12px;font-size:12.5px;font-weight:600}
.rf{background:rgba(255,194,75,.06);border:1px solid rgba(255,194,75,.24);
  border-left:2px solid rgba(255,194,75,.55);border-radius:10px;padding:10px 12px;margin:0 0 14px}
.rf-h{color:#FFD79A;font-size:11.5px;font-weight:600;margin:0 0 4px}
.rf-b{color:#FFE9C7;font-size:12px;line-height:1.65;white-space:pre-wrap;overflow-wrap:anywhere}
.kv{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:0 0 14px;
  background:rgba(255,255,255,.02)}
.kv .r{display:flex;gap:10px;padding:9px 12px;border-bottom:1px solid rgba(143,208,255,.07);font-size:12px}
.kv .r:last-child{border-bottom:0}
.kv .k{flex:0 0 52px;color:var(--t3);font-size:11px}
.kv .v{flex:1;min-width:0;color:#DCEAFF;overflow-wrap:anywhere}
.kv code{font-family:var(--mono);font-size:11px;color:#C4E7FF}
.wrap pre{margin:0 0 14px;border:1px solid rgba(143,208,255,.10);border-radius:10px;background:rgba(255,255,255,.03);
  padding:10px 12px;white-space:pre-wrap;word-break:break-all}
.wrap pre code{background:none;padding:0;font-size:12px;color:#DCEAFF;font-family:var(--mono);line-height:1.65}
.cmd code{background:none;padding:0;font-size:inherit;color:inherit}
.cmd{border:1px solid rgba(143,208,255,.10);border-radius:10px;background:rgba(255,255,255,.03);
  padding:10px 12px;font-family:var(--mono);font-size:12px;color:#DCEAFF;
  white-space:pre-wrap;word-break:break-all;line-height:1.65;margin:0 0 14px}
.tip{margin:4px 0 0;font-size:12px;color:var(--t2)}
/* 终态页的返回入口：短页面不再只能靠关标签页 */
.back{display:inline-flex;align-items:center;justify-content:center;height:44px;padding:0 22px;
  border:1px solid var(--line2);border-radius:10px;color:var(--t2);text-decoration:none;
  font-size:14px;font-weight:600;margin-top:8px}
.back:hover{color:var(--text);border-color:#8FD0FF}
.bar{position:fixed;left:0;right:0;bottom:0;z-index:20;padding:12px 16px calc(12px + env(safe-area-inset-bottom));
  background:#040614;border-top:1px solid var(--line);backdrop-filter:blur(10px)}
.bar .in{max-width:520px;margin:0 auto}
.bar input[type=text],.bar input:not([type]){width:100%;padding:10px 12px;border-radius:10px;font-size:16px;
  color:var(--text);background:rgba(255,255,255,.04);border:1px solid var(--line);
  font-family:inherit;outline:none;margin:0 0 10px}
.bar input:focus{border-color:#8FD0FF;box-shadow:0 0 0 3px rgba(77,107,254,.18)}
.bar .acts{display:flex;gap:10px}
button{flex:1;height:50px;border:0;border-radius:10px;font-size:15px;font-weight:600;font-family:inherit;
  cursor:pointer;color:#04150F;background:linear-gradient(96deg,#7CF0C8,#3BE0A8);
  box-shadow:0 8px 22px rgba(59,224,168,.22)}
button.no{background:rgba(255,122,147,.18);border:1px solid rgba(255,122,147,.55);color:#FFD9E1;
  box-shadow:none}
.done{display:flex;align-items:center;gap:10px;font-size:19px;font-weight:700;margin:18px 0 6px}
.done .ic{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;font-size:16px}
.done.ok{color:var(--ok)} .done.ok .ic{background:rgba(59,224,168,.12);border:1px solid rgba(59,224,168,.30)}
.done.ng{color:var(--danger)} .done.ng .ic{background:rgba(255,122,147,.12);border:1px solid rgba(255,122,147,.30)}
.dl{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:0 0 14px;background:rgba(255,255,255,.02)}
.dl .r{display:flex;gap:10px;padding:9px 12px;border-bottom:1px solid rgba(143,208,255,.07);font-size:12px}
.dl .r:last-child{border-bottom:0}
.dl .k{flex:0 0 52px;color:var(--t3);font-size:11px}
.dl .v{flex:1;min-width:0;color:#DCEAFF;word-break:break-all}
.dl code{font-family:var(--mono);font-size:11px;color:#C4E7FF}
"""



def _page(inner: str, bar: bool = False) -> str:
    cls = ' class="has-bar"' if bar else ""
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<meta name="theme-color" content="#05081C">'
        '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
        '<title>凭证代理审批</title><style>' + _PAGE_CSS + '</style></head>'
        f'<body{cls}>{inner}</body></html>'
    )


def _page_pending(rid: str, e: dict) -> str:
    esc = html.escape
    title = esc(e.get("title") or f"{e.get('kind', '')} → {e.get('profile', '')}")
    detail = esc(str(e.get("detail", ""))[:1500])
    banner = ('<div class="dban">🚨 高危操作 · 已要求 Agent 自我反思</div>'
              if e.get("dangerous") else "")
    reflect = ""
    if e.get("self_reflection"):
        reflect = ('<div class="rf"><div class="rf-h">Agent 的自我反思</div>'
                   f'<div class="rf-b">{esc(e["self_reflection"])}</div></div>')
    return _page(
        '<div class="wrap">'
        '<div class="hd"><span class="dot"></span><span class="brand">AgentKeyGuard</span>'
        '<span class="badge">待审批</span></div>'
        f'<h3>{title}</h3>'
        '<p class="sub">已请求批准该操作</p>'
        + banner + reflect
        + '<div class="kv">'
        + f'<div class="r"><span class="k">类型</span><span class="v">{esc(e.get("kind", ""))} → {esc(e.get("profile", ""))}</span></div>'
        + f'<div class="r"><span class="k">目标</span><span class="v">{esc(e.get("target", ""))}</span></div>'
        + f'<div class="r"><span class="k">请求码</span><span class="v"><code>{esc(e.get("code", ""))}</code> · 来源 {esc(e.get("source", ""))}</span></div>'
        + '</div>'
        + f'<pre><code>{detail}</code></pre>'
        + f'<p class="tip"><span id="cd">{int(config.APPROVAL_TIMEOUT)}</span> 秒内有效，超时自动拒绝。</p>'
        + '<script>(function(){var n=' + str(int(config.APPROVAL_TIMEOUT)) +
        ';var el=document.getElementById("cd");var t=setInterval(function(){n--;'
        + 'if(el)el.textContent=n;if(n<=0){clearInterval(t);var b=document.querySelectorAll(".bar button");'
        + 'for(var i=0;i<b.length;i++){b[i].disabled=true;}if(el)el.textContent="0";}},1000);})();</script>'
        + '</div>'
        + '<form class="bar" action="/approve" method="POST"><div class="in">'
        + f'<input type="hidden" name="id" value="{esc(rid)}">'
        + '<input name="reason" maxlength="500" placeholder="拒绝原因（可选，Agent 会看到）">'
        + '<div class="acts">'
        + '<button class="no" name="decision" value="no">拒绝</button>'
        + '<button name="decision" value="yes">同意</button>'
        + '</div></div></form>',
        bar=True,
    )


def _page_decided(e: dict) -> str:
    yes = e.get("decision") == "yes"
    cls, word, icon = ("ok", "已同意", "✓") if yes else ("ng", "已拒绝", "✕")
    esc = html.escape
    return _page(
        '<div class="wrap">'
        '<div class="hd"><span class="brand">AgentKeyGuard</span></div>'
        f'<div class="done {cls}"><span class="ic">{icon}</span>{word}</div>'
        '<p class="sub">审批结果已回传给 Agent。</p>'
        '<div class="dl">'
        f'<div class="r"><span class="k">目标</span><span class="v">{esc(e.get("profile", ""))} · {esc(e.get("target", ""))}</span></div>'
        f'<div class="r"><span class="k">请求码</span><span class="v"><code>{esc(e.get("code", ""))}</code></span></div>'
        '</div>'
        '<p class="tip">可以关闭此页面。</p>'
        '<a class="back" href="/dashboard">返回控制台</a>'
        '</div>'
    )


def _page_gone() -> str:
    return _page(
        '<div class="wrap">'
        '<div class="hd"><span class="brand">AgentKeyGuard</span></div>'
        '<div class="done ng"><span class="ic">✕</span>链接已失效</div>'
        '<p class="sub">该请求不存在、已处理，或已超时。请回到终端查看最新状态。</p>'
        '<a class="back" href="/dashboard">返回控制台</a>'
        '</div>'
    )


REVEAL_TOKENS: dict[str, dict] = {}


_PORTAL_FAILS: dict[str, dict] = {}


_PORTAL_LOCK = threading.Lock()


def portal_configured(vault: dict) -> bool:
    p = vault.get("portal") or {}
    return bool(p.get("totp_secret") and p.get("pw_hash") and p.get("pw_salt"))


def issue_reveal_token(ip: str) -> tuple[str, int]:
    """二次 TOTP 通过后发放，只管"能不能看明文"，不能用来审批。"""
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with _PORTAL_LOCK:
        for k in [k for k, v in REVEAL_TOKENS.items() if v["expires"] < now]:
            REVEAL_TOKENS.pop(k, None)
        REVEAL_TOKENS[tok] = {"expires": now + config.REVEAL_TTL, "ip": ip}
    return tok, config.REVEAL_TTL


def check_reveal_token(tok: str, ip: str) -> bool:
    if not tok:
        return False
    with _PORTAL_LOCK:
        s = REVEAL_TOKENS.get(tok)
        if not s:
            return False
        if s["expires"] < time.time():
            REVEAL_TOKENS.pop(tok, None)
            return False
        return s["ip"] == ip          # 绑来源 IP，token 被偷走也不能换机器用


def drop_reveal_token(tok: str) -> None:
    with _PORTAL_LOCK:
        REVEAL_TOKENS.pop(tok, None)


# ── 工作台会话状态（原 994-999 行）──
DESK_TOKENS: dict[str, dict] = {}
_DESK_LOCK = threading.Lock()
_DESK_LAST_STEP = -1                 # 登录用的 TOTP 重放计数
_REVEAL_LAST_STEP = -1               # 二次验证用的 TOTP 重放计数（与登录分开）
_DESK_FAILS: dict[str, dict] = {}    # ip -> {fails, until, rounds}
_DESK_GLOBAL = {"fails": 0, "until": 0.0}


def _totp_step(secret: str, code: str) -> int:
    """返回命中的时间步；未命中返回 -1。允许 ±1 个窗口（手机时钟漂移）。"""
    now = time.time()
    for delta in (-config.PORTAL_TOTP_PERIOD, 0, config.PORTAL_TOTP_PERIOD):
        t = now + delta
        try:
            if hmac.compare_digest(totp(secret, config.PORTAL_TOTP_DIGITS, config.PORTAL_TOTP_PERIOD, t), code):
                return int(t // config.PORTAL_TOTP_PERIOD)
        except Exception:
            return -1
    return -1


def desk_login(vault: dict, password: str, code: str) -> tuple[bool, str]:
    """工作台登录：面板密码 + TOTP 双因子。TOTP 带重放防护。"""
    global _DESK_LAST_STEP
    p = vault.get("portal") or {}
    secret = p.get("totp_secret")
    if not secret or not p.get("pw_hash") or not p.get("pw_salt"):
        return False, "not_configured"
    if not re.fullmatch(r"\d{6}", code or ""):
        return False, "bad_format"

    try:
        salt = base64.b64decode(p["pw_salt"])
        want = base64.b64decode(p["pw_hash"])
    except Exception:
        return False, "corrupt"
    if not hmac.compare_digest(portal_hash(password or "", salt), want):
        return False, "bad_password"

    step = _totp_step(secret, code)
    if step < 0:
        return False, "bad_totp"
    with _DESK_LOCK:
        if step <= _DESK_LAST_STEP:
            return False, "replayed"
        _DESK_LAST_STEP = step
    return True, "ok"


def reveal_login(vault: dict, code: str) -> tuple[bool, str]:
    """查看明文的二次验证：只验 TOTP，但用**独立的**重放计数。

    这样刚登录用过的那个码，还能立刻用于一次"查看密码"，不必干等 30 秒。
    """
    global _REVEAL_LAST_STEP
    p = vault.get("portal") or {}
    secret = p.get("totp_secret")
    if not secret:
        return False, "not_configured"
    if not re.fullmatch(r"\d{6}", code or ""):
        return False, "bad_format"
    step = _totp_step(secret, code)
    if step < 0:
        return False, "bad_totp"
    with _DESK_LOCK:
        if step <= _REVEAL_LAST_STEP:
            return False, "replayed"
        _REVEAL_LAST_STEP = step
    return True, "ok"


def desk_global_locked() -> int:
    with _DESK_LOCK:
        left = _DESK_GLOBAL["until"] - time.time()
        return int(left) if left > 0 else 0


def desk_locked(ip: str) -> int:
    with _DESK_LOCK:
        st = _DESK_FAILS.get(ip)
        if not st:
            return 0
        left = st.get("until", 0) - time.time()
        return int(left) if left > 0 else 0


def desk_note_fail(ip: str) -> int:
    """逐次加重：5→10→20→40 分钟；同时有全局熔断，防多 IP 分布式试码。"""
    now = time.time()
    with _DESK_LOCK:
        g = _DESK_GLOBAL
        g["fails"] += 1
        if g["fails"] >= config.DESK_GLOBAL_FAIL_LIMIT:
            g["until"] = now + config.DESK_GLOBAL_LOCK
            g["fails"] = 0
        st = _DESK_FAILS.setdefault(ip, {"fails": 0, "until": 0.0, "rounds": 0})
        st["fails"] += 1
        if st["fails"] >= config.PORTAL_MAX_FAILS:
            st["rounds"] = min(st.get("rounds", 0) + 1, 4)
            st["fails"] = 0
            st["until"] = now + config.PORTAL_LOCK_SECONDS * (2 ** (st["rounds"] - 1))
            return int(st["until"] - now)
    return 0


def desk_clear_fails(ip: str) -> None:
    with _DESK_LOCK:
        _DESK_FAILS.pop(ip, None)
        _DESK_GLOBAL["fails"] = 0


def desk_issue(ip: str) -> tuple[str, int]:
    tok = secrets.token_urlsafe(32)
    now = time.time()
    with _DESK_LOCK:
        for k in [k for k, v in DESK_TOKENS.items() if v["expires"] < now]:
            DESK_TOKENS.pop(k, None)
        DESK_TOKENS[tok] = {"expires": now + config.DESK_ABS_TTL,
                            "idle": now + config.DESK_IDLE_TTL, "ip": ip}
    return tok, config.DESK_ABS_TTL


def desk_check(tok: str, ip: str, touch: bool = False) -> str:
    """'' = 有效。否则返回失效原因。touch=True 只在"真的批了一条"时刷新空闲计时。"""
    if not tok:
        return "no_session"
    now = time.time()
    with _DESK_LOCK:
        s = DESK_TOKENS.get(tok)
        if not s:
            return "no_session"
        if s["expires"] < now:
            DESK_TOKENS.pop(tok, None)
            return "abs_expired"
        if s["idle"] < now:
            DESK_TOKENS.pop(tok, None)
            return "idle_timeout"
        if s["ip"] != ip:
            return "ip_mismatch"
        if touch:
            s["idle"] = now + config.DESK_IDLE_TTL
        return ""


def desk_drop(tok: str) -> None:
    with _DESK_LOCK:
        DESK_TOKENS.pop(tok, None)


_TEMPLATE_DIR = Path(__file__).with_name("templates")
_DASH_HTML = (_TEMPLATE_DIR / "dashboard.html").read_bytes().decode("utf-8")
_LOGIN_HTML = (_TEMPLATE_DIR / "login.html").read_bytes().decode("utf-8")


def _dashboard_page() -> str:
    return (_DASH_HTML
            .replace("__VERSION__", VERSION)
            .replace("__POLL__", str(config.DESK_POLL_MS))
            .replace("__IDLE__", str(config.DESK_IDLE_TTL * 1000))
            .replace("__MASK__", str(config.REVEAL_MASK_SECONDS))
            .replace("__TTL_MIN__", str(config.DESK_ABS_TTL // 60))
            .replace("__IDLE_MIN__", str(config.DESK_IDLE_TTL // 60)))


def login_page(locked: bool = False) -> str:
    """独立登录页：无会话时由 server.do_GET 直接下发，只替换版本号。

    与 _dashboard_page() 同源同风格；模板改动必须按整段替换，禁止格式化。
    locked=True 时多一行说明：服务重启后保险库是锁着的，登录会一并解锁（REQ-306）。
    不新增任何输入框——主密码本来就要输，解锁只是顺手做了。
    """
    note = ('  <p class="hint" style="margin:12px 0 0">'
            '服务刚重启，输入密码后会一并解锁保险库</p>') if locked else ""
    return (_LOGIN_HTML
            .replace("__LOCKED_NOTE__", note)
            .replace("__VERSION__", VERSION))


