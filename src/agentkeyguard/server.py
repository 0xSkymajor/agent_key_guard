# -*- coding: utf-8 -*-
"""HTTP 服务：来源 IP 白名单与 Broker 路由（汇聚层）。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

依赖方向：server 只向上 import 所有业务模块，**任何业务模块都不得反向 import server**。
IP 白名单状态（ALLOWED_CIDRS / TRUSTED_PROXIES / _ALLOWED_NETS 等）就住在本模块，
cli 运行期通过 server.ALLOWED_CIDRS = ... 改写，函数按模块全局动态读取。
"""
from __future__ import annotations

import base64
import datetime
import hmac
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from . import (VERSION, adapters, agents, auth, config, domains, network, notify,
               rules, services, setup, skill, tls, transport as transport_mod,
               unlock, unlock_api)
from .approval import (PENDING_APPROVALS, _PENDING_LOCK, HISTORY_MAX,
                       ask_approval, pending_head, pending_groups,
                       history_list, history_clear)
from .dashboard import (portal_configured, _page_gone, _page_decided,
                        _page_pending, _dashboard_page, login_page)
# 说明：SQL 分级、规则匹配已随适配器搬走；这里保留 ssh_exec 是因为适配器执行时
# 通过 `server.ssh_exec` 取用（自检会 monkeypatch 它，属有意保留的可替换测试缝）。
from .ssh_handler import ssh_exec  # noqa: F401
from .storage import (audit, ensure_token, read_audit_tail, read_vault_with_key,
                      save_vault_with_key)
from .setup_ui import (setup_page, done_page, gone_page, https_landing_page,
                       setup_closed_page)

# 注册内置凭证适配器（pg / ssh / git）。新增类型只需在 adapters.load_builtin()
# 里加一个模块导入，本文件不再出现 `type == "xxx"` 的分支（REQ-106）。
adapters.load_builtin()


ALLOWED_CIDRS = ["127.0.0.1/32", "::1/128", "192.168.8.0/24"]


IP_GUARDED_PREFIXES = ("/health", "/profiles", "/pg/", "/ssh/", "/git/",
                       "/admin/")


PORTAL_IP_GUARD = False          # --lock-portal 时把面板也纳入白名单


# cli.serve() 启动后把 server 实例注册到这里，供 setup 完成后热替换 TLS（REQ-111）
SERVER = None


TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def apply_vault(vault: dict, kek) -> None:
    """把解出的 vault 挂到进程上，并做一次历史迁移与配置刷新。

    启动时**不会**自动调用它：服务以 locked 状态起来，等主人登录解锁时才走这里。
    这样「磁盘上没有任何能直接解密的东西」才成立（REQ-306）。
    """
    Broker.vault = vault
    Broker.key = kek
    Broker.locked = False
    Broker.token = ensure_token()
    setup.ensure_owner_state(vault)

    # 历史数据迁移：锁定态下拿不到 vault，所以这些原本在 cli 启动时做的事挪到这里
    migrated = purge_legacy_gitea_settings(vault)
    for prof in (vault.get("profiles") or {}).values():
        if prof.pop("source", None) is not None:
            migrated.append("profile.source")
    # 清理旧版「Bark 保存后自动落服务」留下的 builtin=notice 服务（REQ-148 砍掉该功能）。
    # 它带系统专属标记 builtin="notice"，与用户手动加的服务可精确区分，删了不误伤。
    notice_sids = [sid for sid, s in (vault.get("services") or {}).items()
                   if s.get("builtin") == "notice"]
    if notice_sids:
        svcs = vault.setdefault("services", {})
        for sid in notice_sids:
            svcs.pop(sid, None)
        migrated.append("bark-notice-service")
    if migrated:
        save_vault_with_key(Broker.key, vault)
        print(f"  [迁移] {', '.join(migrated)}", flush=True)

    settings = vault.get("settings") or {}
    if settings.get("bark"):
        config.BARK_BASE = str(settings["bark"]).rstrip("/")
    if settings.get("public_base"):
        config.PUBLIC_BASE = str(settings["public_base"]).rstrip("/")
    if settings.get("approval_timeout"):
        config.APPROVAL_TIMEOUT = int(settings["approval_timeout"])
    # 通知渠道同步到运行期配置（REQ-148）：bark 是保留字，其余是 "preset:name"
    config.NOTIFY_CHANNELS = list(settings.get("notify_channels") or ["bark"])
    config.NOTIFY = list(settings.get("notify") or [])

    # 规则覆盖层（改层 + 自定义规则）住在 vault 里，解锁即注入。
    # 晚于此处的首批 Agent 请求会漏掉用户规则，所以放在 apply_vault 末尾。
    sync_rule_overrides(vault)


def sync_rule_overrides(vault: dict) -> None:
    """把 vault 的 settings.rule_layout / custom_rules 注入规则引擎。

    rules.json 保持只读（dpkg conffile），用户态叠加全在这里发生。
    """
    s = (vault or {}).get("settings") or {}
    try:
        rules.set_overrides(layout=s.get("rule_layout") or {},
                            customs=s.get("custom_rules") or [])
    except Exception as e:                             # noqa: BLE001
        print(f"  [规则] 覆盖层注入失败：{type(e).__name__}: {e}", flush=True)


def reload_after_setup(vault: dict | None = None, kek=None) -> bool:
    """初始化完成 / 换发证书后，让新状态**在当前进程内**生效（REQ-111）。

    与旧版的区别：不再从磁盘读 master.key 重解 vault —— 那条路已经删掉了。
    初始化时由 `setup.finish()` 把 (vault, kek) 直接交进来；
    换发证书时只重建 TLS，不动数据（调用方不传参即可）。
    """
    if vault is not None and kek is not None:
        apply_vault(vault, kek)

    ctx = None
    if config.TLS_SERVER_CERT.exists() and config.TLS_SERVER_KEY.exists():
        try:
            ctx = tls.tls_context(config.TLS_SERVER_CERT, config.TLS_SERVER_KEY)
        except Exception as e:  # noqa: BLE001
            print(f"  [reload] 重建 TLS 上下文失败：{type(e).__name__}: {e}", flush=True)
    if SERVER is not None:
        SERVER.set_ssl_ctx(ctx)
    if ctx and SERVER is None:
        # 理论上不会发生：cli.serve 会把实例注册进 SERVER。真出现说明接线漏了，
        # 此时 HTTPS 仍然不可用，必须说清楚，不要假装"已生效"。
        print("  [reload] 未持有 server 实例，TLS 未生效（需要重启服务）", flush=True)
        return False
    print(f"  [reload] 初始化完成，已热生效（TLS {'on' if ctx else 'off'}）", flush=True)
    return True


def _next_qs(raw_path: str) -> str:
    """把原始路径编进 next 参数。

    只放行 /，? & = 必须编码：它们在 query 值里会被当成新的分隔符，
    /approve?id=1 会被截断成 next=/approve。前端 safeNext() 负责还原并再校验一次。
    """
    return urllib.parse.quote(raw_path, safe="/")


def get_real_ip(handler) -> str:
    """取真实来源 IP。

    ⚠ 只在**请求确实来自本地反向代理**时才采信 X-Forwarded-For / X-Real-IP。
    否则任何能直连 7700 的机器都能伪造一个头，把自己伪装成白名单内的 IP。
    """
    peer = handler.client_address[0]
    if peer not in TRUSTED_PROXIES:
        return peer
    xff = handler.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    real = handler.headers.get("X-Real-IP", "")
    if real.strip():
        return real.strip()
    return peer


def _parse_net(spec: str):
    """把 '192.0.2.10' 或 '192.0.2.0/24' 解析成网络对象；非法返回 None。"""
    try:
        return ipaddress.ip_network(spec.strip(), strict=False)
    except ValueError:
        return None


_ALLOWED_NETS = []          # 启动时与 --allow-ip 变更时重建


def rebuild_allowed_nets() -> None:
    global _ALLOWED_NETS
    nets = []
    for spec in ALLOWED_CIDRS:
        n = _parse_net(spec)
        if n is None:
            print(f"  [警告] 白名单条目非法，已忽略: {spec!r}", flush=True)
            continue
        nets.append(n)
    _ALLOWED_NETS = nets


def ip_allowed(ip: str, path: str = "/") -> bool:
    """路径决定是否需要白名单；需要时再按 CIDR 比对。"""
    need = path.startswith(IP_GUARDED_PREFIXES)
    if not need and PORTAL_IP_GUARD and path.startswith(("/dashboard", "/api/")):
        need = True
    if not need:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped          # ::ffff:192.0.2.10 统一按 IPv4 判
    nets = _ALLOWED_NETS or [n for n in (_parse_net(s) for s in ALLOWED_CIDRS) if n]
    for net in nets:
        if addr.version == net.version and addr in net:
            return True
    return False


LEGACY_GITEA_KEYS = ("gitea_base", "gitea_user", "gitea_repo", "gitea_token")


def purge_legacy_gitea_settings(vault: dict) -> list:
    """清掉旧版「设置 → Gitea」的残留键。

    Gitea 凭证已与 pg / ssh 同级，只在凭证页维护。设置里那几个键留着只会让人
    以为还有第二个配置入口——所以不是「隐藏」，是**彻底删掉**。
    返回被清掉的键名，供审计留痕。
    """
    s = vault.get("settings") or {}
    return [k for k in LEGACY_GITEA_KEYS if s.pop(k, None) is not None]


class Broker(BaseHTTPRequestHandler):
    server_version = "agentkeyguard"
    sys_version = ""

    vault: dict = {}
    token: str = ""
    # 解锁后缓存 KEK（bytearray 便于原地清零）；锁定态为 None。
    # 磁盘上不再有 master.key，重启后必须由主密码重新派生（REQ-306）。
    key: bytes | bytearray | None = None
    # vault 存在但尚未解密：除白名单外全部 423
    locked: bool = True

    def log_message(self, fmt, *args):      # 不让默认访问日志污染终端
        pass

    # ---- 工具 ----
    def _write_out(self, code: int, ctype: str, raw: bytes,
                   extra: dict | None = None) -> None:
        """统一写出响应。

        客户端中途断开（关标签页、切 App、浏览器放弃等待）会抛 BrokenPipeError /
        ConnectionResetError。这不是错误，只是对端走了，必须静默收场，
        否则日志里会刷一堆无害的栈。
        """
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            cookie = getattr(self, "_auth_cookie", "")
            if cookie:
                self.send_header("Set-Cookie", cookie)
                self._auth_cookie = ""
            self.end_headers()
            if raw:
                self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _send(self, code: int, obj) -> None:
        self._write_out(code, "application/json; charset=utf-8",
                        json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))

    def _send_html(self, code: int, body: str) -> None:
        self._write_out(code, "text/html; charset=utf-8", body.encode("utf-8"))

    def _redirect(self, to: str) -> None:
        self._write_out(302, "text/plain; charset=utf-8", b"", {"Location": to})

    def _is_https(self) -> bool:
        conn = getattr(self, "connection", None)
        return transport_mod.is_https(conn) if conn is not None else False

    def _https_url(self, path: str = "/dashboard") -> str:
        host = self.headers.get("Host") or f"{network.local_ip()}:{self.server.server_address[1]}"
        return f"https://{host}{path}"

    def _health_get(self):
        # initialized 仍只看内存里的 vault（语义务必保持单一判据）；
        # 锁定态下它是 False，但会同时给出 locked=True，
        # 运维看到这一对就知道是「锁着」而不是「没装」。
        return self._send(200, {
            "ok": True, "version": VERSION,
            "initialized": portal_configured(self.vault),
            "locked": bool(Broker.locked),
            "profiles": sorted(self.vault.get("profiles", {})),
        })

    # locked 态仍可访问的路径：健康检查、公开证书、登录与解锁入口、两份 Markdown 规范
    _LOCKED_OK = ("/health", "/ca.crt", "/ca.mobileconfig", "/login", "/service-spec",
                  "/api/unlock/password", "/api/me", "/api/lock", "/api/logout")

    def _locked_guard(self, path: str) -> bool:
        """锁定态统一拦截。返回 True 表示已经回包，调用方直接 return。

        选 423 而不是 401：401 会让 Agent 判定密钥失效、跑去重新申请接入；
        423 明确表达「暂时锁着，等主人解锁后再重试」，语义不混淆。
        """
        if not Broker.locked:
            return False
        if path.startswith(self._LOCKED_OK):
            return False
        if path in ("", "/", "/dashboard", "/approve-desk", "/portal"):
            self._redirect("/login")
            return True
        self._send(423, {
            "error": "vault_locked",
            "message": "保险库已锁定：服务重启后需要主人在控制台登录一次，"
                       "解锁后重试即可，不要重新申请密钥",
            "retry_after": 60,
        })
        return True

    def _public_base(self) -> str:
        """对外地址三级取值（REQ-114）：手动设置 > 本次请求的 Host > 探测值。

        手动设置一律采信，**包括 127.0.0.1**：Agent 装在本机时，回环地址才是该下发给
        它的地址。此前这里把回环当成「没配置」跳过，用户明明填了 127.0.0.1 仍会被
        换成局域网 IP，属于无视配置。
        手机可达性不在这里兜底——审批推送单独走 `approval.push_base()`。
        """
        configured = str((self.vault.get("settings") or {}).get("public_base") or "").strip()
        if configured:
            return configured.rstrip("/")
        base = (config.PUBLIC_BASE or "").rstrip("/")
        # 非哨兵值即视为配过；等于哨兵值时只有环境变量显式设置才算（用户就想用回环）
        if base and (base != config.DEFAULT_PUBLIC_BASE
                     or (os.environ.get("AGENTKEYGUARD_PUBLIC_BASE") or "").strip()):
            return base
        host = (self.headers.get("Host") or "").strip()
        if host and not host.startswith(("127.0.0.1", "localhost", "[::1]")):
            return f"https://{host}"
        return f"http://{network.local_ip()}:{self.server.server_address[1]}"

    def _skill_public(self):
        """固定 URL、无 token；人类拿 MD，Agent 用 Accept: application/json。

        带 `?t=<票据>` 时走一次性接入：核销票据、当场签发一条新密钥，
        密钥只出现在这一次响应里，之后链接立即失效（阅后即焚）。
        """
        if not setup.has_admin():
            return self._send(503, {"error": "setup_required"})
        base = self._public_base()
        ticket = self._q("t")
        issued = ""
        if ticket:
            issued, why = agents.redeem_ticket(self.vault, ticket, self._ip())
            if not issued:
                audit({"event": "skill_ticket_fail", "reason": why, "src": self._ip()})
                return self._send(410, {
                    "error": why,
                    "hint": "请回控制台「Agent 接入 → 更新密钥」重新生成一条链接",
                })
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "skill_ticket_ok", "src": self._ip()})
        if "application/json" in self.headers.get("Accept", "").lower():
            payload = skill.render_json(self.vault, base)
            if issued:
                payload["agent_token"] = issued
                payload["agent_token_note"] = (
                    "本次一次性链接已核销，密钥只出现这一次；"
                    "放在 Authorization: Bearer 里使用，不要再请求本链接")
            body = json.dumps(payload, ensure_ascii=False, indent=2)
            ctype = "application/json; charset=utf-8"
        else:
            body = skill.render(self.vault, base)
            if issued:
                body = ("> ⚠ 本次一次性链接已核销，下面是你的密钥，**只出现这一次**：\n\n"
                        f"```\n{issued}\n```\n\n"
                        "> 用法：`Authorization: Bearer <上面的密钥>`。不要再请求本链接。\n\n"
                        + body)
            ctype = "text/markdown; charset=utf-8"
        ip = self._ip()
        tok, rec = skill.trace(self.headers, fallback=f"ip:{ip}")
        audit({"event": "skill", "agent_id": rec["agent_id"],
               "task_id": rec["task_id"], "src": ip})
        return self._write_out(200, ctype, body.encode("utf-8"),
                               {"X-Trace-Token": tok, "Cache-Control": "no-store"})

    def _service_spec_text(self) -> str:
        """服务开发规范（Markdown）：把模板里的网关占位换成真实地址。

        模板是纯说明、不含任何密钥，和 /skill 一样可以直接丢给 AI 读。
        """
        p = Path(__file__).with_name("templates") / "SERVICE_DEV_SPEC.md.tmpl"
        if not p.exists():
            return ""
        text = p.read_text(encoding="utf-8")
        try:
            base = self._public_base()
        except Exception:              # noqa: BLE001 —— 锁定态下 vault 可能不可用
            base = ""
        if base:
            text = text.replace("https://<网关地址>:<端口>", base)
        return text

    def _service_spec_get(self):
        """GET /service-spec：浏览器打开就是 Markdown 文档，`?download=1` 才下载。

        以前只能在控制台里 fetch+blob 下载，想把它丢给 AI 还得先存文件；
        现在与 /skill 同一套「打开即读」语义。
        """
        text = self._service_spec_text()
        if not text:
            return self._send(404, {"error": "not_found"})
        extra = {"Cache-Control": "no-store"}
        if self._q("download"):
            extra["Content-Disposition"] = 'attachment; filename="SERVICE_DEV_SPEC.md"'
        return self._write_out(200, "text/markdown; charset=utf-8",
                               text.encode("utf-8"), extra)

    def handle_one_request(self) -> None:
        """兜底：任何处理路径上的客户端断开都不冒泡到 handle_error()。"""
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _ip(self) -> str:
        """真实来源 IP（反代后面取 X-Forwarded-For，否则取 TCP 对端）。"""
        return get_real_ip(self)

    def _resolve_agent(self):
        """把 Bearer 解析成 agents 表里的记录；未激活/已吊销/未知一律 None（REQ-116）。

        旧全局 token 在首次鉴权时自动登记为 legacy agent，避免升级把现有集成打成 401。
        """
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return None
        tok = h[7:].strip()
        if not tok:
            return None
        # 旧全局 token 只在真正被使用时才登记；普通 Agent 的请求不该凭空造出一条 legacy
        if tok == self.token and agents.ensure_legacy(self.vault, self.token):
            try:
                save_vault_with_key(Broker.key, self.vault)
            except Exception:              # noqa: BLE001
                pass
        rec = agents.find_by_token(self.vault, tok)
        if rec is None and agents.legacy_matches(self.vault, tok):
            legacy = agents.get(self.vault, agents.LEGACY_ID) or {}
            rec = {"id": agents.LEGACY_ID, **legacy}
        return rec

    def _authorized(self) -> bool:
        rec = self._resolve_agent()
        if not rec:
            return False
        # 把「这条密钥的主人起的名字」挂到当前线程，审批卡片与审计直接取用
        agents.set_current(rec)
        agents.touch(self.vault, rec["id"], self._ip())
        return True

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 2 * 1024 * 1024:
            raise ValueError("请求体为空或过大")
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def _pub_profile(self, p: dict) -> dict:
        return {k: v for k, v in p.items() if k not in config.SECRET_KEYS}

    # ---- /approve 手机确认页（不需要 Bearer token，靠 request_id 定位） ----
    def _q(self, key: str) -> str:
        qs = urllib.parse.urlsplit(self.path).query
        return (urllib.parse.parse_qs(qs).get(key) or [""])[0]

    def _approve_get(self):
        rid = self._q("id")
        with _PENDING_LOCK:
            e = PENDING_APPROVALS.get(rid)
            snap = dict(e) if e else None
        if not snap:
            return self._send_html(404, _page_gone())
        if snap.get("decision"):
            return self._send_html(200, _page_decided(snap))
        return self._send_html(200, _page_pending(rid, snap))

    def _approve_post(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 65536:
            return self._send_html(400, _page_gone())
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        rid = (form.get("id") or [""])[0]
        dec = (form.get("decision") or [""])[0].lower()
        reason = (form.get("reason") or [""])[0].strip()[:500]
        with _PENDING_LOCK:
            e = PENDING_APPROVALS.get(rid)
            if not e:
                return self._send_html(404, _page_gone())
            if e.get("decision"):                     # 重复提交，展示已有结论
                return self._send_html(200, _page_decided(dict(e)))
            if dec not in ("yes", "no"):
                return self._send_html(400, _page_gone())
            e["decision"] = dec
            e["decided_at"] = time.time()
            if dec == "no":
                e["reason"] = reason
            e["event"].set()
            snap = dict(e)
        audit({"event": "approval", "request_id": rid, "decision": dec,
               "kind": snap.get("kind"), "profile": snap.get("profile"),
               "src": self._ip(),
               **({"reason": reason} if dec == "no" and reason else {})})
        return self._send_html(200, _page_decided(snap))

    # ---- /admin/reload：加完机器不用重启，也不用重输主密码 ----
    def _handle_reload(self):
        if not Broker.key:
            return self._send(500, {"error": "服务没有缓存解锁密钥，无法热加载；请重启 serve"})
        try:
            data = read_vault_with_key(Broker.key)
        except Exception as e:              # noqa: BLE001
            return self._send(500, {
                "error": f"重新解密失败: {type(e).__name__}: {e}",
                "hint": "如果刚换过主密码，这是正常现象——serve 缓存的是旧密钥，重启即可",
            })
        Broker.vault = data
        names = sorted(data.get("profiles", {}))
        audit({"event": "reload", "profiles": names, "src": self._ip()})
        print(f"  [热加载] 已重载 {len(names)} 个 profile: {', '.join(names)}", flush=True)
        return self._send(200, {"reloaded": True, "profiles": names})

    # ---- IP 白名单：在一切鉴权之前 ----
    def _reject_if_ip_denied(self) -> bool:
        ip = self._ip()
        if ip_allowed(ip, self.path):
            return False
        try:                       # 把请求体读掉，否则客户端收到的是 RST 而不是 403
            n = int(self.headers.get("Content-Length") or 0)
            if 0 < n <= 65536:
                self.rfile.read(n)
        except Exception:
            pass
        audit({"event": "deny", "reason": "ip_not_allowed", "ip": ip, "path": self.path})
        print(f"  [拒绝] 来源 {ip} 不在白名单 → {self.path}", flush=True)
        self._send(403, {"error": "source ip not allowed", "ip": ip})
        return True

    # ---- bootstrap（无 vault 时） ----
    def _bootstrap_get(self):
        # 先去 query 再比对：/setup?next=x、/?from=bark 这类都要能命中路由
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            return self._send(200, {"ok": True, "version": VERSION,
                                    "mode": "bootstrap", "initialized": False})
        # 根路径必须和 /dashboard 一起跳 /setup：postinst 打印的正是
        # http://IP:7700/，少了它用户第一眼看到的是 404（P5）
        if path in ("", "/", "/dashboard", "/login", "/approve-desk", "/portal"):
            return self._redirect("/setup")
        if path == "/setup":
            if setup.has_admin():
                # 已初始化：明说「向导已关闭」并给出 /dashboard 去处。
                # 不复用 gone_page()——那是「一次性凭证页过期」的文案，
                # 贴在已完成初始化的用户脸上像 HTML 残留（P2）
                return self._send_html(410, setup_closed_page())
            return self._send_html(200, setup_page())
        if path.startswith("/setup/done"):
            data = setup.take_done(self._q("token"))
            if not data:
                return self._send_html(410, gone_page())
            return self._send_html(200, done_page(data))
        if path == "/ca.crt":
            p = config.CA_DIR / "ca.crt"
            if not p.exists():
                return self._send(404, {"error": "no_ca"})
            return self._write_out(200, "application/x-x509-ca-cert", p.read_bytes(),
                                   {"Content-Disposition": 'attachment; filename="ca.crt"'})
        if path == "/ca.mobileconfig":
            try:
                _ca_key, ca_cert = tls.load_ca(config.CA_DIR)
                mc = tls.root_mobileconfig(tls.cert_der(ca_cert))
            except Exception as e:  # noqa: BLE001
                return self._send(404, {"error": f"no_ca: {e}"})
            return self._write_out(200, "application/x-apple-aspen-config", mc,
                                   {"Content-Disposition":
                                    'attachment; filename="akg-root-ca.mobileconfig"'})
        if path.startswith("/setup/download/"):
            kind = path.rsplit("/", 1)[-1]
            data = setup.take_download(self._q("token"), kind)
            if data is None:
                return self._send(404, {"error": "download_expired"})
            ctype = {
                "ca": "application/x-x509-ca-cert",
                "mobileconfig": "application/x-apple-aspen-config",
            }.get(kind, "application/octet-stream")
            fname = {
                "ca": "ca.crt",
                "mobileconfig": "akg-root-ca.mobileconfig",
            }.get(kind, kind)
            return self._write_out(200, ctype, data, {
                "Content-Disposition": f'attachment; filename="{fname}"'})
        if path == "/setup/qrcode.min.js":
            p = Path(__file__).with_name("templates") / "qrcode.min.js"
            if not p.exists():
                return self._send(404, {"error": "no_qr"})
            return self._write_out(200, "application/javascript; charset=utf-8",
                                   p.read_bytes())
        return self._send(404, {"error": "not_found"})

    def _bootstrap_post(self):
        try:
            req = self._body()
        except Exception as e:  # noqa: BLE001
            return self._send(400, {"error": f"bad_request: {e}"})
        try:
            if self.path == "/api/setup/totp/new":
                return self._send(200, setup.new_totp())
            if self.path == "/api/setup/master":
                setup.set_master(str(req.get("master") or ""))
                return self._send(200, {"ok": True})
            if self.path == "/api/setup/username":
                setup.set_username(str(req.get("username") or ""))
                return self._send(200, {"ok": True, "username": setup.DRAFT["username"]})
            if self.path == "/api/setup/totp/verify":
                ok = setup.verify_totp(str(req.get("secret") or ""),
                                       str(req.get("totp") or ""))
                return self._send(200 if ok else 400, {"ok": ok})
            if self.path == "/api/setup/totp":
                setup.set_totp(str(req.get("secret") or ""))
                return self._send(200, {"ok": True})
            if self.path == "/api/setup/storage":
                setup.set_storage(str(req.get("bark") or ""),
                                  str(req.get("public_base") or ""),
                                  int(req.get("timeout") or 300),
                                  agent_name=str(req.get("agent_name") or ""))
                return self._send(200, {"ok": True})
            if self.path == "/api/setup/profiles":
                setup.set_profiles(req.get("profiles") or {})
                return self._send(200, {"ok": True})
            if self.path == "/api/setup/finish":
                port = self.server.server_address[1]
                out = {"ok": True, **setup.finish(self._ip(), port)}
                self._send(200, out)
                # 回包之后再热生效：当前响应仍走 HTTP 连接，下一个请求就能用 HTTPS 了。
                # vault 与 KEK 由 finish() 直接交出，不再从磁盘读 master.key。
                reload_after_setup(*setup.last_unlock())
                return
        except setup.SetupError as e:
            # error 供日志/自动化，message 是给用户看的中文（REQ-108）
            return self._send(400, {"error": e.code, "message": e.message})
        return self._send(404, {"error": "not_found"})

    # ---- GET ----
    def do_GET(self):
        if self._reject_if_ip_denied():
            return
        # self.path 含 query，路由匹配一律用去 query 的 path；
        # 否则 /dashboard?next=x 会漏判而落到 _authorized() 变成 401 JSON。
        path = urllib.parse.urlsplit(self.path).path
        # 浏览器标签页图标：内联 SVG 文件，两种模式都要能取到
        if path in ("/favicon.svg", "/favicon.ico"):
            fav = os.path.join(os.path.dirname(__file__), "templates", "favicon.svg")
            try:
                with open(fav, "rb") as fh:
                    data = fh.read()
            except OSError:
                return self._send(404, {"error": "no_favicon"})
            return self._write_out(200, "image/svg+xml", data,
                                   {"Cache-Control": "public, max-age=604800"})
        if (path == "/setup" or path.startswith("/setup/")
                or path in ("/ca.crt", "/ca.mobileconfig")):
            return self._bootstrap_get()
        if not config.VAULT_PATH.exists():
            return self._bootstrap_get()
        if not setup.has_admin():
            if path in ("/dashboard", "/login", "/approve-desk", "/portal"):
                return self._redirect("/setup")
            if path.startswith("/api/"):
                return self._send(401, {"error": "setup_required"})
            if path in ("/skill", "/service-spec", "/service-spec.md"):
                return self._send(503, {"error": "setup_required"})
        if not self._is_https():
            return self._http_get()
        # 锁定态统一拦截（REQ-306）：HTTP 落地页不受影响，它不读 vault
        if self._locked_guard(path):
            return
        if path in ("/approve-desk", "/portal"):
            return self._redirect("/dashboard")
        if path in ("", "/"):
            # REQ-124：根路径按登录态分流。此前这里没有分支，会一路落到下面的
            # _authorized() 判断，浏览器打开首页看到的是 {"error":"unauthorized"}。
            if not setup.has_admin():
                return self._redirect("/setup")
            return self._redirect("/dashboard" if auth.current(self) else "/login")
        # 登录页必须先在 dashboard 之前判断：已登录回控制台，未登录才渲染表单。
        if path == "/login":
            if auth.current(self):
                return self._redirect("/dashboard")
            return self._send_html(200, login_page(locked=Broker.locked))
        if path == "/dashboard":
            if not auth.current(self):
                return self._redirect("/login?next=" + _next_qs(self.path))
            auth.set_https_hint(self)
            return self._send_html(200, _dashboard_page())
        if path.startswith("/approve"):
            if not auth.current(self):
                return self._redirect("/login?next=" + _next_qs(self.path))
            return self._approve_get()
        if path == "/health":
            return self._health_get()
        if path in ("/skill", "/skill.md"):
            return self._skill_public()
        if path in ("/service-spec", "/service-spec.md"):
            return self._service_spec_get()
        if path.startswith("/api/service/env"):
            return self._service_env_get()
        if path.startswith("/api/"):
            if unlock_api.handle_get(self, self.path):
                return
            return self._api_get()
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if path == "/profiles":
            return self._send(200, {
                "profiles": {n: self._pub_profile(p)
                             for n, p in self.vault.get("profiles", {}).items()}
            })
        return self._send(404, {"error": "not_found"})

    def _http_get(self):
        """HTTP 侧：首次配置/根证书落地，不暴露登录与业务 API。"""
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/service/env"):
            return self._service_env_get()
        if path == "/health":
            return self._health_get()
        if path in ("/skill", "/skill.md"):
            return self._skill_public()
        if path in ("/service-spec", "/service-spec.md"):
            return self._redirect(self._https_url(self.path))
        if path.startswith("/api/"):
            return self._send(403, {"error": "https_required"})
        if path.startswith("/approve"):
            return self._redirect(self._https_url(self.path))
        if path in ("/approve-desk", "/portal"):
            return self._redirect("/dashboard")
        if path in ("/", "/dashboard", "/login"):
            if not setup.has_admin():
                return self._redirect("/setup")
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if "http" in q:
                auth.clear_https_hint(self)
            elif "https" in q:
                auth.set_https_hint(self)
                return self._redirect(self._https_url("/dashboard"))
            elif auth.has_https_hint(self):
                return self._redirect(self._https_url("/dashboard"))
            return self._send_html(200, https_landing_page(
                self._https_url("/dashboard")))
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path == "/profiles":
            return self._send(200, {
                "profiles": {n: self._pub_profile(p)
                             for n, p in self.vault.get("profiles", {}).items()}
            })
        return self._send(404, {"error": "not_found"})

    # ---- POST ----
    def do_POST(self):
        if self._reject_if_ip_denied():
            return
        if not config.VAULT_PATH.exists():
            return self._bootstrap_post()
        if not setup.has_admin():
            if self.path.startswith("/api/setup"):
                return self._bootstrap_post()
            return self._send(401, {"error": "setup_required"})
        if self._locked_guard(urllib.parse.urlsplit(self.path).path):
            return
        if self.path == "/api/service/env":
            try:
                req = self._body()
            except Exception as e:  # noqa: BLE001
                return self._send(400, {"error": f"bad_request: {e}"})
            return self._service_env_post(req)
        if self.path == "/api/skill/activate":
            # Agent 首次接入：无会话，靠 IP 白名单 + 人工审批把关（REQ-116）
            return self._api_skill_activate()
        if not self._is_https():
            if self.path.startswith("/approve"):
                return self._redirect(self._https_url(self.path))
            if self.path == "/admin/reload":
                if not self._authorized():
                    return self._send(401, {"error": "unauthorized"})
                return self._handle_reload()
            if self.path.startswith("/api/"):
                return self._send(403, {"error": "https_required"})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            return self._agent_post()
        # HTTPS
        if self.path.startswith("/approve"):
            # 手机 Bark 落地页是普通表单，靠 SameSite=Strict 防跨站；
            # Dashboard 的 /api/approve 仍然走 auth.require（CSRF）。
            if not auth.current(self):
                return self._send(401, {"error": "login_required"})
            return self._approve_post()
        if self.path == "/admin/reload":
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            return self._handle_reload()
        if self.path.startswith("/api/"):
            try:
                req = self._body()
            except Exception as e:                # noqa: BLE001
                return self._send(400, {"error": f"bad_request: {e}"})
            if unlock_api.handle_post(self, self.path, req):
                return
            if not auth.require(self):
                return
            if self.path == "/api/pending":
                return self._api_pending(req)
            if self.path == "/api/services":
                return self._api_services_save(req)
            if self.path == "/api/services/issue":
                return self._api_services_issue(req)
            if self.path == "/api/services/revoke":
                return self._api_services_revoke(req)
            if self.path == "/api/services/delete":
                return self._api_services_delete(req)
            if self.path == "/api/services/env/delete":
                return self._api_service_env_delete(req)
            if self.path == "/api/service/decision":
                return self._api_service_decision(req)
            if self.path == "/api/approve":
                return self._api_approve(req)
            if self.path == "/api/history/clear":
                return self._api_history_clear(req)
            if self.path == "/api/profiles":
                return self._api_profiles_save(req)
            if self.path == "/api/profiles/delete":
                return self._api_profiles_delete(req)
            if self.path == "/api/profiles/test":
                return self._api_profiles_test(req)
            if self.path == "/api/profiles/reveal":
                return self._api_profiles_reveal(req)
            if self.path == "/api/settings":
                return self._api_settings_save(req)
            if self.path == "/api/notify":
                return self._api_notify(req)
            if self.path == "/api/bark/test":
                return self._api_bark_test(req)
            if self.path == "/api/skill/ticket":
                return self._api_skill_ticket(req)
            if self.path == "/api/security/rules":
                return self._api_security_rules_set(req)
            if self.path == "/api/security/rules/move":
                return self._api_security_rule_move(req)
            if self.path == "/api/security/rules/add":
                return self._api_security_rule_add(req)
            if self.path == "/api/security/rules/delete":
                return self._api_security_rule_delete(req)
            if self.path == "/api/security/rules/test":
                return self._api_security_rule_test(req)
            if self.path == "/api/agents/revoke":
                return self._api_agent_revoke(req)
            if self.path == "/api/agents/delete":
                return self._api_agent_delete(req)
            return self._send(404, {"error": "not_found"})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        return self._agent_post()

    def _agent_post(self):
        try:
            req = self._body()
        except Exception as e:              # noqa: BLE001
            return self._send(400, {"error": f"bad_request: {e}"})
        src = self._ip()
        try:
            # 前缀派发（REQ-106 收官）：/pg/query、/mysql/query、/ssh/exec、
            # /git/exec、/redis/cmd 都走同一入口——seg[0] 查适配器、seg[1] 查动作。
            # 以后加类型只加适配器模块，server.py 这里一行不用改。
            seg = self.path.strip("/").split("/")
            if len(seg) == 2 and seg[1] == "databases":
                return self._adapter_databases(req, src)
            if len(seg) == 2:
                adapter = adapters.get(seg[0])
                if adapter and adapter.executes:
                    return adapter.execute(self, req, src)
            return self._send(404, {"error": "not_found"})
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "path": self.path, "src": src,
                   "error": f"{type(e).__name__}: {e}"})
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    # ---- 面板 API（独立鉴权通道：只看 view_token，永不看 Bearer） ----
    def _portal_profiles(self) -> list:
        out = []
        for name, p in sorted(self.vault.get("profiles", {}).items()):
            out.append({
                "name": name,
                "type": p.get("type"),
                "host": p.get("host"),
                "port": p.get("port"),
                "user": p.get("user"),
                "database": p.get("database"),
                "url": p.get("url"),
                # git 凭证只记站点；仓库名由 /git/exec 的 url 带，
                # 所以列表里只展示 base，不再回传 owner/repo/branch
                "base": p.get("base"),
                # 与 reveal 用同一份白名单：列表说「有什么」，点开就该看到什么
                "secrets": sorted(k for k in config.SECRET_KEYS if p.get(k)),
            })
        return out



    # ---- 工作台 API（第三条鉴权通道：只认 desk_token，不读 Bearer/view_token） ----

    def _api_pending(self, req: dict):
        return self._send(200, {"pending": pending_head()})

    def _api_approve(self, req: dict):
        ip = self._ip()
        dec = str(req.get("decision") or "").lower()
        if dec not in ("yes", "no"):
            return self._send(400, {"error": "decision 必须是 yes 或 no"})

        # 批量批准：request_ids 优先；未传则退回单条 request_id，旧前端语义不变
        raw = req.get("request_ids")
        if isinstance(raw, list) and raw:
            rids = [str(r) for r in raw][:50]
        else:
            rids = [str(req.get("request_id") or "")]

        decided = 0
        for rid in rids:
            snap = None
            with _PENDING_LOCK:
                e = PENDING_APPROVALS.get(rid)
                if not e or e.get("decision"):
                    continue
                e["decision"] = dec
                e["decided_at"] = time.time()
                if dec == "no":
                    e["reason"] = str(req.get("reason") or "")[:500]
                e["event"].set()
                snap = dict(e)
            decided += 1
            # 每条都要独立落审计：一次点击覆盖 N 次执行时，事后必须能逐条追溯
            audit({"event": "approval", "request_id": rid, "decision": dec,
                   "kind": snap.get("kind"), "profile": snap.get("profile"),
                   "title": snap.get("title"), "agent": snap.get("agent", ""),
                   "batch": len(rids), "src": ip,
                   **({"reason": snap.get("reason")} if dec == "no" else {})})
            _why = (f"（原因：{snap['reason']}）"
                    if dec == "no" and snap.get("reason") else "")
            print(f"  [工作台] {ip} {'同意' if dec == 'yes' else '拒绝'}  "
                  f"[{snap.get('title')}]{_why}", flush=True)

        if not decided:
            if len(rids) == 1:
                return self._send(404, {"error": "请求不存在或已处理",
                                        "pending": pending_head()})
            return self._send(200, {"ok": True, "decided": 0, "already": True,
                                    "pending": pending_head()})
        return self._send(200, {"ok": True, "decided": decided,
                                "pending": pending_head()})

    # ---- 历史记录（只读展示，与排队完全无关） ----
    def _api_get(self):
        base = urllib.parse.urlsplit(self.path).path
        s = auth.current(self)
        ip = self._ip()
        if base == "/api/me":
            return self._send(200, {
                "unlocked": bool(s),
                "csrf": (s or {}).get("csrf", ""),
                "username": (self.vault.get("portal") or {}).get("username", "admin"),
                "root_ca": "/ca.crt",
                # 本机默认域名：前端不再写字面量，一律用这个渲染（REQ-141）
                "default_domain": domains.host_domain(),
                # 锁定态：控制台据此提示「登录会一并解锁」，不新增输入框
                "locked": bool(Broker.locked),
                # 底部会话状态条：勾选档只显示「保持登录中」，不勾档按 idle_in 倒计时
                "session": ({
                    "sid": s["sid"],
                    "remember": bool(s.get("remember")),
                    "device": s.get("device", ""),
                    "idle": (config.SESSION_IDLE_KEEP if s.get("remember")
                             else config.SESSION_IDLE),
                    "idle_in": auth.idle_in(s),
                } if s else None),
            })
        if not s:
            return self._send(401, {"error": "login_required"})
        if base == "/api/security/rules":
            # 规则面板：绝对屏蔽 + 灵魂三问两块一次取回（v1.3.2）
            return self._send(200, self._rules_payload())
        if base == "/api/pending":
            # pending 保留单条语义（徽标与旧前端兼容）；groups 供工作台分组渲染
            return self._send(200, {"pending": pending_head(),
                                    "groups": pending_groups()})
        if base == "/api/services":
            return self._send(200, {"services": services.list_services(self.vault)})
        if base == "/api/service/pending":
            return self._send(200, {"pending": services.pending_head()})
        if base == "/api/skill":
            return self._send(200, {"url": f"{self._public_base()}/skill"})
        if base == "/api/agents":
            return self._send(200, {"agents": skill.list_traces()})
        if base == "/api/docs/service-spec":
            text = self._service_spec_text()
            if not text:
                return self._send(404, {"error": "not_found"})
            return self._write_out(200, "text/markdown; charset=utf-8",
                                   text.encode("utf-8"),
                                   {"Content-Disposition":
                                    'attachment; filename="SERVICE_DEV_SPEC.md"'})
        if base == "/api/profiles":
            return self._send(200, {"profiles": self._portal_profiles()})
        if base == "/api/settings":
            return self._send(200, {"settings": self._settings_public()})
        if base == "/api/sessions":
            # 在线会话 + 近期记录。history 只从审计尾部倒读，不整文件读入。
            rows = auth.list_sessions(self)
            return self._send(200, {
                "count": len(rows),
                "online": sum(1 for r in rows if r["online"]),
                "max": max(1, config.SESSION_MAX),
                "idle": config.SESSION_IDLE,
                "idle_keep": config.SESSION_IDLE_KEEP,
                "online_span": config.SESSION_ONLINE,
                "bye_grace": config.SESSION_BYE_GRACE,
                "sessions": rows,
                "history": read_audit_tail(20, auth.SESSION_EVENTS),
            })
        if base == "/api/network/addresses":
            return self._send(200, self._addresses_payload())
        if base == "/api/skill/agents":
            # 一次性清理：从未用过的 legacy 占位（1.4 起不再预置），只在真正用到旧
            # token 时才会重新登记；吊销过的由 legacy_dropped 永久拦掉。
            if agents.drop_unused_legacy(self.vault):
                try:
                    save_vault_with_key(Broker.key, self.vault)
                except Exception:              # noqa: BLE001
                    pass
            return self._send(200, {"agents": agents.list_agents(self.vault)})
        if base == "/api/tls/status":
            return self._send(200, tls.ca_status(
                config.CA_DIR, config.TLS_SERVER_CERT,
                self.headers.get("Host", ""), "/ca.crt"))
        if base == "/api/history":
            return self._send(200, {"history": history_list(), "limit": HISTORY_MAX})
        if base == "/api/panel":
            return self._send(200, {"profiles": self._portal_profiles()})
        return self._send(404, {"error": "not_found"})

    def _service_base(self) -> str:
        port = self.server.server_address[1]
        return (config.PUBLIC_BASE.rstrip("/") if config.PUBLIC_BASE
                else f"https://{network.local_ip()}:{port}")

    def _service_env_get(self):
        keys = [k for k in self._q("keys").split(",") if k] or None
        env, err, status = services.request_env(
            self.vault, self._q("token"), keys, self._ip(),
            self.headers.get("User-Agent", ""))
        if status != 200:
            return self._send(status, {"error": err})
        return self._write_out(200, "application/json; charset=utf-8",
                               json.dumps({"env": env}, ensure_ascii=False).encode("utf-8"),
                               {"Cache-Control": "no-store"})

    def _service_env_post(self, req: dict):
        keys = req.get("keys")
        if isinstance(keys, str):
            keys = [k for k in keys.split(",") if k]
        env, err, status = services.request_env(
            self.vault, str(req.get("token") or ""), keys, self._ip(),
            self.headers.get("User-Agent", ""))
        if status != 200:
            return self._send(status, {"error": err})
        return self._write_out(200, "application/json; charset=utf-8",
                               json.dumps({"env": env}, ensure_ascii=False).encode("utf-8"),
                               {"Cache-Control": "no-store"})

    def _api_services_issue(self, req: dict):
        try:
            svc, token = services.create_service(
                self.vault, str(req.get("name") or ""), req.get("env") or {})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "service_issue", "id": svc["id"],
               "name": svc["name"], "src": self._ip()})
        return self._send(200, {
            "id": svc["id"], "name": svc["name"], "token": token,
            "env_keys": svc["env_keys"],
            "url": f"{self._service_base()}/api/service/env?token={token}",
        })

    def _api_services_save(self, req: dict):
        sid = str(req.get("id") or "")
        try:
            ok = services.update_service(self.vault, sid, req.get("env") or {})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        if not ok:
            return self._send(404, {"error": "not_found"})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "service_update", "id": sid, "src": self._ip()})
        return self._send(200, {"ok": True,
                                "services": services.list_services(self.vault)})

    def _api_services_revoke(self, req: dict):
        sid = str(req.get("id") or "")
        if not services.revoke_service(self.vault, sid):
            return self._send(404, {"error": "not_found"})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "service_revoke", "id": sid, "src": self._ip()})
        return self._send(200, {"ok": True,
                                "services": services.list_services(self.vault)})

    def _api_services_delete(self, req: dict):
        sid = str(req.get("id") or "")
        name = ""
        for s in services.list_services(self.vault):
            if s["id"] == sid:
                name = s["name"]
                break
        if not services.delete_service(self.vault, sid):
            return self._send(404, {"error": "not_found"})
        save_vault_with_key(Broker.key, self.vault)
        # 删记录是不可逆的，审计里带名字，事后能对上是谁
        audit({"event": "service_delete", "id": sid, "name": name,
               "src": self._ip()})
        return self._send(200, {"ok": True,
                                "services": services.list_services(self.vault)})

    def _api_service_env_delete(self, req: dict):
        """删单个键值对：Bark 的历史一条条删，不用把整个服务清掉。"""
        sid = str(req.get("id") or "")
        key = str(req.get("key") or "")
        if not services.delete_env_key(self.vault, sid, key):
            return self._send(404, {"error": "not_found"})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "service_env_delete", "id": sid, "key": key, "src": self._ip()})
        return self._send(200, {"ok": True,
                                "services": services.list_services(self.vault)})

    def _api_service_decision(self, req: dict):
        rid = str(req.get("request_id") or "")
        dec = str(req.get("decision") or "").lower()
        if dec not in ("yes", "no"):
            return self._send(400, {"error": "decision 必须是 yes 或 no"})
        if not services.decide(rid, dec, str(req.get("reason") or "")):
            return self._send(404, {"error": "not_found"})
        audit({"event": "service_env_decision", "request_id": rid,
               "decision": dec, "src": self._ip()})
        return self._send(200, {"ok": True, "pending": services.pending_head()})

    def _api_profiles_save(self, req: dict):
        name = str(req.get("name") or "").strip()
        if not name or len(name) > 32 or any(c in name for c in " /\\"):
            return self._send(400, {"error": "bad_profile_name"})
        prof = self._profile_from_req(req)
        if prof is None:
            return self._send(400, {"error": "bad_profile"})
        old = (self.vault.get("profiles") or {}).get(name) or {}
        # 同类型覆盖时，留空的密钥沿用旧值：否则「只想改个分支」会把 token 清掉
        if old.get("type") == prof.get("type"):
            for k in config.SECRET_KEYS:
                if not prof.get(k) and old.get(k):
                    prof[k] = old[k]
        # git 凭证的 Token 只来自凭证本身：设置页不再有第二个来源，
        # 免得「到底哪个 token 在生效」变成猜谜
        if prof.get("type") == "git":
            prof["token"] = str(prof.get("token") or "").strip()
        self.vault.setdefault("profiles", {})[name] = prof
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "profile_save", "name": name,
               "type": prof.get("type"), "src": self._ip()})
        return self._send(200, {"ok": True, "name": name})

    def _profile_from_req(self, req: dict):
        """按 `type` 查适配器构造 profile；未知类型返回 None（= bad_profile）。"""
        adapter = adapters.get(str(req.get("type") or ""))
        return adapter.build_profile(req) if adapter else None

    def _api_profiles_delete(self, req: dict):
        name = str(req.get("name") or "")
        prof = self.vault.get("profiles", {}).pop(name, None)
        if not prof:
            return self._send(404, {"error": "not_found"})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "profile_delete", "name": name, "src": self._ip()})
        return self._send(200, {"ok": True})

    def _api_profiles_test(self, req: dict):
        """连通性测试：不落盘、不写日志、不返回密钥。"""
        name = str(req.get("name") or "").strip()
        prof = None
        if req.get("type"):
            prof = self._profile_from_req(req)
        elif name:
            prof = (self.vault.get("profiles") or {}).get(name)
        if not prof:
            return self._send(404, {"error": "profile_not_found"})
        # git 凭证只记站点，要测具体仓库时由请求带 url —— 只用于本次测试，
        # 不落盘、不进 vault（凭证字段保持三条）
        if prof.get("type") == "git" and req.get("url"):
            prof = {**prof, "url": str(req.get("url")).strip()}
        started = time.time()
        try:
            kind = prof.get("type")
            adapter = adapters.get(kind)
            if adapter is None:
                raise ValueError("unsupported_profile_type")
            adapter.test(prof)
            elapsed = int((time.time() - started) * 1000)
            audit({"event": "profile_test", "name": name, "type": kind,
                   "ok": True, "src": self._ip()})
            return self._send(200, {"ok": True, "elapsed_ms": elapsed})
        except Exception as e:  # noqa: BLE001
            elapsed = int((time.time() - started) * 1000)
            audit({"event": "profile_test", "name": name,
                   "ok": False, "src": self._ip()})
            return self._send(200, {"ok": False, "elapsed_ms": elapsed,
                                    "error": f"{type(e).__name__}: {e}"})

    def _api_profiles_reveal(self, req: dict):
        """查看凭证密钥：会话 + CSRF + 仅 TOTP，不要求主密码。"""
        name = str(req.get("name") or "").strip()
        code = str(req.get("totp") or "").strip()
        p = self.vault.get("portal") or {}
        if not p.get("totp_secret") or not setup.verify_totp(
                str(p["totp_secret"]), code):
            audit({"event": "profile_reveal", "name": name,
                   "ok": False, "src": self._ip()})
            return self._send(403, {"error": "bad_totp"})
        prof = (self.vault.get("profiles") or {}).get(name)
        if not prof:
            return self._send(404, {"error": "not_found"})
        secrets = {k: prof[k] for k in config.SECRET_KEYS if prof.get(k)}
        audit({"event": "profile_reveal", "name": name,
               "ok": True, "src": self._ip()})
        return self._write_out(200, "application/json; charset=utf-8",
                               json.dumps({"name": name, "secrets": secrets},
                                          ensure_ascii=False).encode("utf-8"),
                               {"Cache-Control": "no-store"})

    def _reissue_cert_for(self, public_base: str) -> dict:
        """public_base 变了就换发服务器证书，并把新 SSLContext 热替换进传输层（REQ-112）。"""
        ips, dns = setup.san_lists(public_base)
        try:
            tls.reissue_server_cert(config.CA_DIR, config.DATA_DIR / "tls", ips, dns)
            ctx = tls.tls_context(config.TLS_SERVER_CERT, config.TLS_SERVER_KEY)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if SERVER is not None:
            SERVER.set_ssl_ctx(ctx)
        print(f"  [tls] 已按 {public_base} 换发证书 SAN={ips + dns}", flush=True)
        return {"ok": True, "san_ips": ips, "san_dns": dns}

    def _api_skill_activate(self):
        """Agent 握手激活：登记 pending → 推审批 → 通过则返回一次性密钥。"""
        try:
            req = self._body()
        except Exception as e:              # noqa: BLE001
            return self._send(400, {"error": f"bad_request: {e}"})
        name = str(req.get("name") or "").strip()[:64]
        intro = str(req.get("self_intro") or "").strip()[:1000]
        if not name:
            return self._send(400, {"error": "需要 name（Agent 名字）"})
        if len(intro) < 10:
            return self._send(400, {
                "error": "需要 self_intro（≥10 字）：我是谁、从哪来、要干什么、正在建立连接",
            })
        aid = agents.create_pending(self.vault, name, intro, self._ip())
        save_vault_with_key(Broker.key, self.vault)
        res: dict = {}
        ok = ask_approval("skill.activate", name, f"来自 {self._ip()}",
                          f"Agent 自述：\n{intro}", self._ip(),
                          title=f"Agent「{name}」请求接入", force=True,
                          dangerous=False, out=res)
        if not ok:
            agents.drop(self.vault, aid)
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "skill_activate", "ok": False, "name": name,
                   "reason": res.get("reason", ""), "src": self._ip()})
            return self._send(403, {"error": "主人拒绝", "type": "user_denied",
                                    "reason": res.get("reason") or ""})
        if res.get("duplicate"):
            # 同一条接入请求被重发：前一条已经完成接入，但密钥只在它的响应里出现过一次。
            # 这里不重复签发，把刚建的占位记录收掉，提示重走一次性链接。
            agents.drop(self.vault, aid)
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "skill_activate", "ok": True, "duplicate": True,
                   "name": name, "src": self._ip()})
            return self._send(409, {
                "error": "同一接入请求已处理，本次不重复签发",
                "duplicate": True,
                "hint": "密钥只在首次响应里显示一次；没拿到就重新生成一次性接入链接",
            })
        token = agents.activate(self.vault, aid)
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "skill_activate", "ok": True, "agent_id": aid,
               "name": name, "src": self._ip()})
        return self._send(200, {"ok": True, "agent_id": aid, "token": token,
                                "warning": "密钥只显示这一次，请立即保存"})

    def _api_skill_ticket(self, req: dict):
        """生成一次性接入链接：10 分钟、只能打开一次、打开即签发密钥。

        这样主人不用「先复制 skill 地址、再复制密钥」两步：给 Agent 一条链接就够。
        """
        token, ttl = agents.issue_ticket(
            self.vault, str(req.get("name") or ""), self._ip())
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "skill_ticket_issue", "src": self._ip(), "ttl": ttl})
        return self._send(200, {
            "ok": True,
            "url": f"{self._public_base()}/skill?t={urllib.parse.quote(token)}",
            "expires_in": ttl,
        })

    # ---- 规则面板（v1.3.2）：两块规则 + 开关 / 搬层 / 新增 / 删除 / 试运行 ----
    def _rules_payload(self) -> dict:
        """一次取回两块：绝对屏蔽（blocked）与灵魂三问（dangerous）。"""
        s = self.vault.get("settings") or {}
        off = set(s.get("rules_off") or [])
        ref_off = set(s.get("reflection_off") or [])
        blocked = rules.list_layer("blocked", off)
        dangerous = rules.list_layer("dangerous", None, ref_off)
        return {
            "rules": blocked,                 # 旧前端的字段名，保持兼容
            "blocked": blocked,
            "dangerous": dangerous,
            "counts": {
                "blocked": len(blocked),
                "dangerous": len(dangerous),
                "reflection_on": sum(1 for r in dangerous if r["reflection"]),
            },
        }

    def _rule_meta_of(self, name: str) -> dict:
        """在编译结果里找一条规则（含自定义），找不到返回空字典。"""
        for layer in rules.RULE_LAYERS:
            for r in rules.list_layer(layer):
                if r["name"] == name:
                    return r
        return {}

    def _verify_master(self, req: dict, event: str, name: str = "") -> bool:
        """放宽类操作统一走密码 + 动态码，失败即审计。"""
        ok, why = unlock.verify_password(
            self.vault, str(req.get("master") or ""), str(req.get("totp") or ""))
        if not ok:
            audit({"event": f"{event}_deny", "name": name,
                   "reason": why, "src": self._ip()})
        return ok

    def _api_security_rules_set(self, req: dict):
        """开关一条规则。两层「关闭」的含义不同，别混：

        · blocked   关闭 = 完全不拦截
        · dangerous 关闭 = 跳过自审（428），**审批照旧** —— 人还能拦
        两种关闭都是放宽，要密码 + 动态码；重新开启是收紧，直接生效。
        """
        name = str(req.get("name") or "").strip()
        enabled = bool(req.get("enabled"))
        if not name:
            return self._send(400, {"error": "缺少规则名"})
        if rules.is_locked_rule(name):
            return self._send(400, {
                "error": "rule_locked",
                "message": "这是自保护规则，关掉等于把钥匙递出去，不允许关闭",
            })
        meta = self._rule_meta_of(name)
        if not meta:
            return self._send(404, {"error": "没有这条规则"})
        layer = meta["layer"]
        if layer not in ("blocked", "dangerous"):
            return self._send(400, {"error": "该层规则不在面板里调整"})
        if not enabled and not self._verify_master(req, "security_rule", name):
            return self._send(403, {"error": "密码或动态码错误"})
        s = self.vault.setdefault("settings", {})
        key = "rules_off" if layer == "blocked" else "reflection_off"
        off = set(s.get(key) or [])
        if enabled:
            off.discard(name)
        else:
            off.add(name)
        s[key] = sorted(off)
        save_vault_with_key(Broker.key, self.vault)
        sync_rule_overrides(self.vault)
        audit({"event": "security_rule", "name": name, "layer": layer,
               "enabled": enabled, "src": self._ip()})
        return self._send(200, {"ok": True, "layer": layer, "enabled": enabled})

    def _api_security_rule_move(self, req: dict):
        """把一条内置规则搬到另一层。

        方向不对称：blocked → dangerous 是放宽（从绝对拒绝变成"自审后可审批"），
        必须密码 + 动态码；反向是收紧，直接生效。
        """
        name = str(req.get("name") or "").strip()
        target = str(req.get("layer") or "").strip()
        if target not in ("blocked", "dangerous"):
            return self._send(400, {"error": "只能移到屏蔽层或灵魂三问层"})
        if rules.is_locked_rule(name):
            return self._send(400, {"error": "rule_locked",
                                    "message": "自保护规则不允许搬动"})
        meta = self._rule_meta_of(name)
        if not meta:
            return self._send(404, {"error": "没有这条规则"})
        if meta["custom"]:
            return self._send(400, {"error": "自定义规则请直接删除后重建，不支持搬层"})
        src = meta["layer"]
        if src not in ("blocked", "dangerous"):
            return self._send(400, {"error": "该层规则不在面板里调整"})
        if src == target:
            return self._send(400, {"error": "规则已在该层"})
        downgrade = src == "blocked" and target == "dangerous"
        if downgrade and not self._verify_master(req, "security_rule_move", name):
            return self._send(403, {"error": "密码或动态码错误"})
        s = self.vault.setdefault("settings", {})
        layout = dict(s.get("rule_layout") or {})
        if target == rules.builtin_layer(name):
            layout.pop(name, None)          # 搬回出厂层就不必留覆盖
        else:
            layout[name] = target
        s["rule_layout"] = layout
        # 搬动后复位为开启：否则会出现「显示开启、实际仍被跳过」的隐形状态
        off = set(s.get("rules_off") or [])
        off.discard(name)
        s["rules_off"] = sorted(off)
        roff = set(s.get("reflection_off") or [])
        roff.discard(name)
        s["reflection_off"] = sorted(roff)
        save_vault_with_key(Broker.key, self.vault)
        sync_rule_overrides(self.vault)
        audit({"event": "security_rule_move", "name": name, "from": src,
               "to": target, "src_ip": self._ip()})
        return self._send(200, {"ok": True, "name": name, "layer": target})

    def _api_security_rule_add(self, req: dict):
        """新增一条自定义规则。收紧动作，不需要密码。"""
        name = str(req.get("name") or "").strip()
        layer = str(req.get("layer") or "blocked").strip()
        if not rules.NAME_RE.match(name):
            return self._send(400, {
                "error": "规则名只能含字母、数字、下划线、点和短横，最长 64 位"})
        if rules.is_locked_rule(name):
            return self._send(400, {"error": "self_protect_ 是保留前缀"})
        if layer not in ("blocked", "dangerous"):
            return self._send(400, {"error": "只能放进屏蔽层或灵魂三问层"})
        if self._rule_meta_of(name):
            return self._send(400, {"error": "规则名与现有规则重复"})
        s = self.vault.setdefault("settings", {})
        customs = list(s.get("custom_rules") or [])
        if len(customs) >= rules.CUSTOM_MAX:
            return self._send(400, {"error": f"自定义规则最多 {rules.CUSTOM_MAX} 条"})
        kws = [str(x).strip()[:100] for x in (req.get("keywords") or [])
               if str(x).strip()][:20]
        pat = str(req.get("pattern") or "").strip()
        all_of = [str(x).strip() for x in (req.get("all_of") or [])
                  if str(x).strip()][:6]
        if not kws and not pat and not all_of:
            return self._send(400, {"error": "请至少填一个关键词，或展开高级写正则"})
        if len(pat) > 500:
            return self._send(400, {"error": "正则最长 500 字符"})
        for p in ([pat] if pat else []) + all_of:
            try:
                re.compile(p)
            except re.error as e:
                return self._send(400, {"error": f"正则无法编译：{e}"})
        scope = [str(x).strip().lower() for x in (req.get("scope") or ["shell"])
                 if str(x).strip()]
        if not scope:
            scope = ["shell"]
        item = {
            "name": name,
            "layer": layer,
            "scope": scope,
            "desc": str(req.get("desc") or "").strip()[:200],
            "created": int(time.time()),
        }
        if kws:
            item["keywords"] = kws
        if pat:
            item["pattern"] = pat
        if all_of:
            item["all_of"] = all_of
        customs.append(item)
        s["custom_rules"] = customs
        save_vault_with_key(Broker.key, self.vault)
        sync_rule_overrides(self.vault)
        audit({"event": "security_rule_add", "name": name, "layer": layer,
               "src_ip": self._ip()})
        return self._send(200, {"ok": True, "rule": item})

    def _api_security_rule_delete(self, req: dict):
        """删除自定义规则。删掉一条拦截是放宽，要密码 + 动态码。"""
        name = str(req.get("name") or "").strip()
        s = self.vault.setdefault("settings", {})
        customs = list(s.get("custom_rules") or [])
        if not any(c.get("name") == name for c in customs):
            return self._send(400, {"error": "只有自定义规则可以删除"})
        if not self._verify_master(req, "security_rule_delete", name):
            return self._send(403, {"error": "密码或动态码错误"})
        s["custom_rules"] = [c for c in customs if c.get("name") != name]
        for key in ("rules_off", "reflection_off"):
            left = set(s.get(key) or [])
            left.discard(name)
            s[key] = sorted(left)
        layout = dict(s.get("rule_layout") or {})
        layout.pop(name, None)
        s["rule_layout"] = layout
        save_vault_with_key(Broker.key, self.vault)
        sync_rule_overrides(self.vault)
        audit({"event": "security_rule_delete", "name": name, "src_ip": self._ip()})
        return self._send(200, {"ok": True})

    def _api_security_rule_test(self, req: dict):
        """试运行：只回显命中结果，不写库、不建待审批、不发推送。"""
        cmd = str(req.get("cmd") or "")
        scope = str(req.get("scope") or "shell")
        draft = req.get("draft") if isinstance(req.get("draft"), dict) else None
        if draft and draft.get("layer") not in ("blocked", "dangerous"):
            draft = dict(draft)
            draft["layer"] = "blocked"
        hit = rules.try_match(cmd, scope, draft)
        return self._send(200, {"ok": True, "hit": hit or None, "cmd": cmd[:200]})

    def _api_agent_revoke(self, req: dict):
        aid = str(req.get("id") or "")
        if not agents.revoke(self.vault, aid):
            return self._send(404, {"error": "没有该 Agent"})
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "agent_revoke", "agent_id": aid, "src": self._ip()})
        return self._send(200, {"ok": True})

    def _api_agent_delete(self, req: dict):
        """删除一条 Agent 记录：只允许删已吊销的。

        吊销是「停用但留痕」，删除是「把这一行抹掉」。限制在 revoked 状态，
        避免手快点掉一条正在工作的密钥（那种情况该先吊销，再删）。
        """
        aid = str(req.get("id") or "")
        rec = agents.get(self.vault, aid)
        if not rec:
            return self._send(404, {"error": "没有该 Agent"})
        if rec.get("status") != "revoked":
            return self._send(400, {
                "error": "只能删除已吊销的 Agent",
                "hint": "正在使用或待审批的请先吊销，再删除",
            })
        agents.drop(self.vault, aid)
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "agent_delete", "agent_id": aid, "src": self._ip()})
        return self._send(200, {"ok": True})

    def _addresses_payload(self) -> dict:
        """AdGuard 式地址清单（REQ-125）：把能用的入口一次列全，标注谁能用。"""
        port = self.server.server_address[1]
        lan = network.lan_addresses()
        detected = (lan[0]["ip"] if lan else network.local_ip())
        mode = network.net_mode()
        # 只列「真正能访问到」的入口：局域网 IP / 回环 / localhost / 域名。
        # Docker、br-、veth 之类的虚拟网卡对访问没有意义，直接不进列表。
        items = []
        for a in lan:
            if a["virtual"]:
                continue
            items.append({
                "url": f"https://{a['ip']}:{port}", "kind": "lan",
                "label": "局域网 " + a["iface"],
                "local": True, "phone": True,
                "note": "需要放行端口",
            })
        items.append({
            "url": f"http://127.0.0.1:{port}", "kind": "loopback",
            "label": "本机回环", "local": True, "phone": False,
            "note": "只有跑服务这台机器能用",
        })
        items.append({
            "url": f"http://localhost:{port}", "kind": "localhost",
            "label": "localhost 别名", "local": True, "phone": False,
            "note": "浏览器强制解析到回环，不用改 DNS",
        })
        items.append({
            "url": f"https://{domains.host_domain()}:{port}", "kind": "domain",
            "label": "域名", "local": False, "phone": True,
            "note": "需 DNS 指向本机；证书 SAN 已包含",
        })
        base = (config.PUBLIC_BASE or "").rstrip("/")
        effective = self._public_base()
        # 设置里填的地址如果和某条探测结果同址，就地标记，避免同一行出现两次
        for it in items:
            if base and it["url"].rstrip("/") == base:
                old_label = it["label"]
                it["kind"] = "configured"
                it["label"] = "当前生效（设置里填的）" + (" · " + old_label if old_label else "")
                it["phone"] = True
                it["note"] = "审批链接与证书都用它"
        if base and base not in [i["url"].rstrip("/") for i in items]:
            items.append({"url": base, "kind": "configured", "label": "当前生效（设置里填的）",
                          "local": True, "phone": True, "note": "审批链接与证书都用它"})
        if effective and effective.rstrip("/") not in [i["url"].rstrip("/") for i in items]:
            items.append({"url": effective, "kind": "effective", "label": "本次生效地址",
                          "local": True, "phone": True,
                          "note": "按当前访问地址自动推断，不代表手机一定可达"})
        # WSL 的两种网络形态结论相反：mirrored 与 Windows 共用地址（手机可达），
        # NAT 才是「只有本机可达、必须端口转发」的那一种。
        warning = notice = ""
        if network.is_wsl() and mode == "nat":
            warning = ("检测到 WSL NAT 网络：这些地址只有本机能访问，手机连不上。"
                       "要手机可用请改 Windows 的 .wslconfig 开 networkingMode=mirrored，"
                       "或在 Windows 上做端口转发（netsh interface portproxy）。")
        elif network.is_wsl() and mode == "mirrored":
            notice = ("WSL 镜像网络：WSL 与 Windows 共用同一 IP。手机能否打开取决于 Windows 防火墙"
                      "是否放行该入站端口；打不开就先查防火墙，仍不通再考虑 NAT + 端口转发。")
        return {
            "items": items,
            "detected_ip": detected,
            "configured": base,
            "effective": effective,
            "runtime": {
                "is_wsl": network.is_wsl(),
                "net_mode": mode,
                "warning": warning,
                "notice": notice,
            },
        }

    def _api_bark_test(self, req: dict):
        """用请求体里的 Bark 地址直接发一条测试推送（不保存也能测）。"""
        url = config.normalize_bark(
            req.get("bark") or (self.vault.get("settings") or {}).get("bark"))
        if not url:
            return self._send(400, {"ok": False, "error": "先填写 Bark 地址"})
        # Bark 的接口形状是 {server}/{device_key}/{title}/{body}。
        # normalize_bark 已把三种写法（完整 URL / 域名+key / 纯 key）统一成
        # {server}/{device_key}，这里只补尾斜杠再拼 —— 否则只粘 key 会被当成
        # 域名，拼出 https://<key>/ 然后必然连不上（P6）。
        url += "/"
        try:
            title = urllib.parse.quote("AgentKeyGuard 测试")
            body = urllib.parse.quote("这是一条测试推送，收到即表示配置正确")
            with urllib.request.urlopen(f"{url}{title}/{body}", timeout=8) as r:
                r.read(64)
        except urllib.error.HTTPError as e:
            audit({"event": "bark_test", "ok": False, "code": e.code, "src": self._ip()})
            return self._send(200, {"ok": False, "error": f"HTTP {e.code}"})
        except Exception as e:                       # noqa: BLE001
            audit({"event": "bark_test", "ok": False,
                   "error": type(e).__name__, "src": self._ip()})
            return self._send(200, {"ok": False, "error": f"连接失败：{type(e).__name__}"})
        audit({"event": "bark_test", "ok": True, "src": self._ip()})
        return self._send(200, {"ok": True})

    def _settings_public(self) -> dict:
        """设置对外视图：旧版 Gitea 键一律不返回（已彻底移出设置）。"""
        s = dict(self.vault.get("settings") or {})
        for k in LEGACY_GITEA_KEYS:
            s.pop(k, None)
        return s

    def _api_settings_save(self, req: dict):
        s = self.vault.setdefault("settings", {})
        reissue = None
        if "bark" in req:
            # 保存与测试走同一个归一化，避免「测试能通、保存后又推不出去」（P6）
            s["bark"] = config.normalize_bark(req.get("bark"))
            config.BARK_BASE = s["bark"]
            # 注意：Bark 不再落成服务里的键值对（REQ-148 砍掉「自动落服务」），
            # 它只是通知渠道之一，地址只存在 settings.bark。
        if "public_base" in req:
            new_base = str(req.get("public_base") or "").strip().rstrip("/")
            old_base = str(s.get("public_base") or "").strip().rstrip("/")
            s["public_base"] = new_base
            config.PUBLIC_BASE = new_base or config.PUBLIC_BASE
            if new_base and new_base != old_base:
                # 地址变了，证书 SAN 必须跟着变，否则手机拿到的还是旧 SAN
                reissue = self._reissue_cert_for(new_base)
        if "approval_timeout" in req:
            s["approval_timeout"] = max(30, min(3600, int(req.get("approval_timeout") or 300)))
            config.APPROVAL_TIMEOUT = s["approval_timeout"]
        # 旧前端可能还在提交 gitea_*：一律丢弃，不让它们复活
        purge_legacy_gitea_settings(self.vault)
        save_vault_with_key(Broker.key, self.vault)
        audit({"event": "settings_save", "src": self._ip()})
        out = {"ok": True, "settings": self._settings_public(),
               "services": services.list_services(self.vault)}
        if reissue is not None:
            out["tls"] = reissue
        return self._send(200, out)

    # ---- 通知渠道（REQ-148）----
    def _sync_notify(self) -> None:
        """把 vault.settings 里的通知渠道同步到运行期 config。"""
        s = self.vault.get("settings") or {}
        config.NOTIFY_CHANNELS = list(s.get("notify_channels") or ["bark"])
        config.NOTIFY = list(s.get("notify") or [])

    def _notify_public(self) -> list:
        """通知渠道对外视图：secret 只回显「是否已配置」，绝不回明文。"""
        s = self.vault.get("settings") or {}
        channels = s.get("notify") or []
        active = s.get("notify_channels") or []
        out = []
        for c in channels:
            preset = c.get("preset") or "custom"
            name = c.get("name") or ""
            out.append({
                "name": name,
                "preset": preset,
                "url": c.get("url") or "",
                "has_secret": bool(c.get("secret")),
                "enabled": f"{preset}:{name}" in active,
            })
        return out

    def _api_notify(self, req: dict):
        """通知渠道的增删改（REQ-148）。Agent 不可见、不可调用，只走人面认证。"""
        action = str(req.get("action") or "list")
        s = self.vault.setdefault("settings", {})
        channels = s.setdefault("notify", [])
        # 默认 ["bark"]：与 apply_vault 的 `or ["bark"]` 口径一致。
        # 之前这里默认 []，第一次调接口会把 Bark 从「默认启用」误写成「停用」。
        active = s.setdefault("notify_channels", ["bark"])

        if action == "save":
            name = (req.get("name") or "").strip()
            if not name or len(name) > 32 or any(c in name for c in " /\\:"):
                return self._send(400, {"error": "渠道名 1~32 字，且不含空格 / 斜杠 / 冒号"})
            url = (req.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                return self._send(400, {"error": "地址必须以 http(s):// 开头"})
            preset = str(req.get("preset") or "custom").lower()
            if preset not in notify.PRESETS:
                return self._send(400, {"error": "未知预设"})
            secret = (req.get("secret") or "").strip()
            existing = next((c for c in channels if c.get("name") == name), None)
            if existing:
                old_key = f"{existing.get('preset') or 'custom'}:{name}"
                existing["preset"] = preset
                existing["url"] = url
                if secret:                       # 留空 = 不改
                    existing["secret"] = secret
                # 预设变了，notify_channels 里的旧 key 要跟着换
                if old_key in active:
                    active[:] = [f"{preset}:{name}" if a == old_key else a
                                 for a in active]
            else:
                channels.append({"name": name, "preset": preset, "url": url,
                                 "secret": secret})
                active.append(f"{preset}:{name}")     # 新渠道默认启用
            self._sync_notify()
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "notify_save", "name": name, "preset": preset,
                   "src": self._ip()})
            return self._send(200, {"ok": True, "channels": self._notify_public()})

        if action == "delete":
            name = (req.get("name") or "").strip()
            before = len(channels)
            channels[:] = [c for c in channels if c.get("name") != name]
            if len(channels) == before:
                return self._send(404, {"error": "渠道不存在"})
            active[:] = [a for a in active if not a.endswith(":" + name)]
            self._sync_notify()
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "notify_delete", "name": name, "src": self._ip()})
            return self._send(200, {"ok": True, "channels": self._notify_public()})

        if action == "toggle":
            name = (req.get("name") or "").strip()
            enabled = bool(req.get("enabled"))
            # Bark 是保留字，直接开关 notify_channels 里的 "bark"，与 webhook 渠道同构
            if name == "bark":
                if enabled and "bark" not in active:
                    active.append("bark")
                if not enabled and "bark" in active:
                    active.remove("bark")
                self._sync_notify()
                save_vault_with_key(Broker.key, self.vault)
                audit({"event": "notify_toggle", "name": "bark", "enabled": enabled,
                       "src": self._ip()})
                return self._send(200, {"ok": True, "bark_enabled": "bark" in active,
                                        "channels": self._notify_public()})
            chan = next((c for c in channels if c.get("name") == name), None)
            if not chan:
                return self._send(404, {"error": "渠道不存在"})
            key = f"{chan.get('preset') or 'custom'}:{name}"
            if enabled and key not in active:
                active.append(key)
            if not enabled and key in active:
                active.remove(key)
            self._sync_notify()
            save_vault_with_key(Broker.key, self.vault)
            audit({"event": "notify_toggle", "name": name, "enabled": enabled,
                   "src": self._ip()})
            return self._send(200, {"ok": True, "channels": self._notify_public()})

        # 默认 action=list
        return self._send(200, {"bark_enabled": "bark" in active,
                                "channels": self._notify_public()})

    def _api_history_clear(self, req: dict):
        ip = self._ip()
        n = history_clear()
        audit({"event": "history_clear", "count": n, "src": ip})
        print(f"  [工作台] {ip} 清空历史 {n} 条", flush=True)
        return self._send(200, {"cleared": n})














    # ---- databases（pg / mysql 通用列库） ----
    def _adapter_databases(self, req: dict, src: str):
        """列出某凭证能访问的库（REQ-147）。只读，不落盘、不弹审批。

        通过凭证的 type 查适配器再调 list_databases——pg 走 pg_database、
        mysql 走 SHOW DATABASES，server 不关心具体是哪种数据库。
        """
        name = (req.get("profile") or "").strip()
        if not name:
            return self._send(400, {"error": "需要 profile"})
        prof = (self.vault.get("profiles") or {}).get(name)
        if not prof:
            return self._send(404, {"error": f"没有 profile: {name}"})
        adapter = adapters.get(prof.get("type") or "")
        fn = getattr(adapter, "list_databases", None) if adapter else None
        if fn is None:
            return self._send(400, {"error": "该凭证类型不支持列库"})
        try:
            dbs = fn(prof)
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "kind": "databases", "profile": name,
                   "error": f"{type(e).__name__}: {e}", "src": src})
            return self._send(502, {"error": f"数据库错误: {type(e).__name__}: {e}"})
        audit({"event": "ok", "kind": "databases", "profile": name,
               "count": len(dbs), "src": src})
        return self._send(200, {"databases": dbs})
