# -*- coding: utf-8 -*-
"""Agent 密钥体系（REQ-116）。

背景：v1.1.2 之前只有一个全局 Bearer（`/var/lib/agentkeyguard/token`），
所有 Agent 共用，且 `/skill` 文档里任何人拿到就能用——等于没有边界。

现在改成：

- vault 里维护 `agents` 表，一个 Agent 一条记录；
- 密钥只存 `sha256(salt + token)`，明文只在「激活成功」与「重新生成」时返回一次；
- 状态机 `pending → active`，`revoked` 之后永久失效；
- 未激活 / 已吊销的密钥**在鉴权层直接 403**，不会进入审批队列；
- 旧全局 token 在首次鉴权时自动登记为 `legacy` agent 并保持 `active`，
  避免升级瞬间把现有集成全打成 401。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

LEGACY_ID = "ag_legacy"
STATUSES = ("pending", "active", "revoked")

# 当前请求所属的 Agent（线程局部）。HTTP 服务是「一个请求一个线程」，
# 所以鉴权时把这条记录挂到线程上，审批和审计就能直接取到「这是哪个会话」，
# 不必给 ssh/pg/git 三个适配器各加一遍参数。
_CTX = threading.local()

# 票据核销必须串行：同一链接被并发打开时，check-then-set 会让两次都成功，
# 意外签发两条密钥。锁只保护内存里这几百字节，不会成为瓶颈。
_TICKET_LOCK = threading.RLock()


def set_current(rec: dict | None) -> None:
    _CTX.label = str((rec or {}).get("name") or "")
    _CTX.agent_id = str((rec or {}).get("id") or "")


def current_label() -> str:
    """当前请求的密钥签名（主人创建密钥时起的名字）；没有就返回空串。"""
    return getattr(_CTX, "label", "") or ""


def current_id() -> str:
    return getattr(_CTX, "agent_id", "") or ""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _table(vault: dict) -> dict:
    return vault.setdefault("agents", {})


def _digest(salt: str, token: str) -> str:
    return hashlib.sha256((salt + token).encode("utf-8")).hexdigest()


def list_agents(vault: dict) -> list:
    """对外视图：不含 token 哈希与 salt，只留可判断的信息。"""
    out = []
    for aid, rec in sorted(_table(vault).items()):
        out.append({
            "id": aid,
            "name": rec.get("name", ""),
            "status": rec.get("status", ""),
            "legacy": bool(rec.get("legacy")),
            "token_tail": rec.get("token_tail", ""),
            "self_intro": rec.get("self_intro", ""),
            "created_at": rec.get("created_at", ""),
            "last_seen": rec.get("last_seen", ""),
            "ip": rec.get("ip", ""),
        })
    return out


def get(vault: dict, agent_id: str) -> dict | None:
    return _table(vault).get(str(agent_id or ""))


def create_pending(vault: dict, name: str, self_intro: str, ip: str) -> str:
    """登记一条待审批的接入请求，返回 agent_id。"""
    aid = "ag_" + secrets.token_hex(6)
    _table(vault)[aid] = {
        "name": (name or "").strip()[:64] or "agent",
        "status": "pending",
        "salt": "",
        "token_hash": "",
        "token_tail": "",
        "self_intro": (self_intro or "").strip()[:1000],
        "created_at": _now(),
        "last_seen": "",
        "ip": ip or "",
        "legacy": False,
    }
    return aid


def drop(vault: dict, agent_id: str) -> None:
    _table(vault).pop(str(agent_id or ""), None)


def _issue(rec: dict) -> str:
    """给记录签发新密钥：明文返回一次，只落哈希与尾号。"""
    token = secrets.token_urlsafe(32)
    rec["salt"] = secrets.token_hex(8)
    rec["token_hash"] = _digest(rec["salt"], token)
    rec["token_tail"] = token[-4:]
    return token


def activate(vault: dict, agent_id: str) -> str | None:
    rec = get(vault, agent_id)
    if not rec or rec.get("status") == "revoked":
        return None
    token = _issue(rec)
    rec["status"] = "active"
    rec["activated_at"] = _now()
    return token


def revoke(vault: dict, agent_id: str) -> bool:
    rec = get(vault, agent_id)
    if not rec:
        return False
    rec["status"] = "revoked"
    rec["token_hash"] = ""
    rec["salt"] = ""
    rec["revoked_at"] = _now()
    # legacy 是升级过渡用的占位：吊销即彻底清除，并留下标记，
    # 否则下次鉴权会把它重新登记成 active（老 bug：越吊销越出现）。
    if str(agent_id) == LEGACY_ID:
        _table(vault).pop(LEGACY_ID, None)
        vault["legacy_dropped"] = True
    return True


def find_by_token(vault: dict, token: str) -> dict | None:
    """按明文密钥反查记录，命中且 active 才返回（附 id）。"""
    token = (token or "").strip()
    if not token:
        return None
    for aid, rec in _table(vault).items():
        if rec.get("status") != "active":
            continue
        h = rec.get("token_hash") or ""
        if not h:
            continue
        if hmac.compare_digest(_digest(rec.get("salt") or "", token), h):
            return {"id": aid, **rec}
    return None


# ────────────────────────── 一次性接入票据 ──────────────────────────
# 目的：主人不必先复制 skill 地址、再复制密钥两次操作。点一次「更新密钥」得到
# 一条带票据的链接，Agent 打开它：既读到 skill 文档，又当场换到一条可用密钥。
#
# 约束（缺一不可，否则等于把密钥写在明处）：
#   1. 只存 sha256(salt+票据)，明文只在生成时返回一次；
#   2. 10 分钟过期；
#   3. 只能核销一次，核销即作废（阅后即焚）；
#   4. 核销成功才签发密钥，且新密钥只出现在那一次响应里。

TICKET_TTL = 600          # 10 分钟
TICKET_KEY = "agent_tickets"


def _tickets(vault: dict) -> dict:
    return vault.setdefault(TICKET_KEY, {})


def _purge_tickets(vault: dict) -> None:
    now = time.time()
    ts = _tickets(vault)
    for k in [k for k, v in ts.items()
              if v.get("used") or float(v.get("expires") or 0) < now]:
        ts.pop(k, None)


def issue_ticket(vault: dict, name: str = "", ip: str = "") -> tuple[str, int]:
    """生成一张一次性票据，返回 (明文票据, 有效秒数)。调用方负责落盘。"""
    _purge_tickets(vault)
    token = secrets.token_urlsafe(32)
    salt = secrets.token_hex(8)
    now = time.time()
    tid = "tk_" + secrets.token_hex(6)
    _tickets(vault)[tid] = {
        "salt": salt,
        "hash": _digest(salt, token),
        "name": (name or "").strip()[:64] or "一次性接入",
        "created": now,
        "expires": now + TICKET_TTL,
        "used": False,
        "ip": ip or "",
    }
    return token, TICKET_TTL


def redeem_ticket(vault: dict, token: str, ip: str = "") -> tuple[str | None, str]:
    """核销票据并签发密钥。

    返回 (新密钥, "") 表示成功；(None, 原因) 表示失败。
    票据一旦被核销立即作废——浏览器先打开过一次，Agent 就用不了了。
    """
    token = (token or "").strip()
    if not token:
        return None, "缺少票据"
    _purge_tickets(vault)
    now = time.time()
    with _TICKET_LOCK:
        for tid, rec in list(_tickets(vault).items()):
            if rec.get("used"):
                continue
            if float(rec.get("expires") or 0) < now:
                _tickets(vault).pop(tid, None)
                continue
            if not hmac.compare_digest(_digest(rec.get("salt") or "", token),
                                       rec.get("hash") or ""):
                continue
            # 命中：持锁先把票据作废再签发密钥，并发下第二个请求只会看到 used=True
            rec["used"] = True
            rec["used_at"] = now
            rec["used_ip"] = ip or ""
            aid = create_pending(vault, rec.get("name") or "一次性接入",
                                 "通过一次性接入链接接入（主人主动生成）", ip)
            issued = activate(vault, aid)
            _tickets(vault).pop(tid, None)
            if not issued:
                return None, "签发密钥失败"
            return issued, ""
    return None, "链接已使用或已过期"


def touch(vault: dict, agent_id: str, ip: str) -> None:
    rec = get(vault, agent_id)
    if not rec:
        return
    rec["last_seen"] = _now()
    if ip:
        rec["ip"] = ip


def ensure_legacy(vault: dict, legacy_token: str) -> bool:
    """把旧全局 token 登记成 legacy agent（只在真正用到旧 token 时做一次）。

    返回 True 表示本次做了迁移，调用方负责落盘。
    """
    if not legacy_token:
        return False
    agents = _table(vault)
    # 吊销过的 legacy 永不复活：标记落盘后连占位都不再生成
    if vault.get("legacy_dropped"):
        agents.pop(LEGACY_ID, None)
        return False
    rec = agents.get(LEGACY_ID)
    if rec:
        if rec.get("status") == "revoked":
            agents.pop(LEGACY_ID, None)
            vault["legacy_dropped"] = True
            return True          # 有变化，调用方落盘
        return False
    agents[LEGACY_ID] = {
        "name": "legacy",
        "status": "active",
        "salt": "",
        "token_hash": "",
        "token_tail": legacy_token[-4:] if len(legacy_token) >= 8 else "",
        "self_intro": "v1.1.x 遗留的全局密钥，仅为平滑升级保留，建议尽快吊销并改用握手激活",
        "created_at": _now(),
        "last_seen": "",
        "ip": "",
        "legacy": True,
        "plain_token": legacy_token,
    }
    return True


def drop_unused_legacy(vault: dict) -> bool:
    """1.4：从未使用过的 legacy 占位不再常驻（升级后列表里的历史噪音）。

    真正在用的旧 token（last_seen 有值）保留；吊销过的由 legacy_dropped 处理。
    返回 True 表示有改动，调用方负责落盘。
    """
    if vault.get("legacy_dropped"):
        return False
    rec = _table(vault).get(LEGACY_ID)
    if rec and rec.get("status") == "active" and not rec.get("last_seen"):
        _table(vault).pop(LEGACY_ID, None)
        return True
    return False


def legacy_matches(vault: dict, token: str) -> bool:
    """legacy agent 的明文比对（仅此一条允许存明文，用于平滑迁移）。"""
    rec = _table(vault).get(LEGACY_ID) or {}
    if rec.get("status") != "active":
        return False
    plain = rec.get("plain_token") or ""
    return bool(plain) and hmac.compare_digest(plain, (token or "").strip())
