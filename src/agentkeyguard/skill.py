# -*- coding: utf-8 -*-
"""动态 Skill（JSON/MD）+ 短期 Agent Trace。"""
from __future__ import annotations

import datetime
import json
import secrets
import threading
import time
from pathlib import Path

from . import config

_LOCK = threading.Lock()
TRACES: dict[str, dict] = {}
TRACE_TTL = 300


def _mask_host(host) -> str:
    parts = str(host or "").split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return str(host or "")


def _rules_summary() -> str:
    try:
        data = json.loads(Path(config.RULES_PATH).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return "- 规则文件不可读；仅受默认策略约束。"
    lines = []
    for key, label in (("blocked", "绝对禁区"), ("dangerous", "高危"),
                       ("interactive", "交互式")):
        items = data.get(key) or []
        names = [str(x.get("name") if isinstance(x, dict) else x) for x in items]
        tail = f"（{', '.join(names[:5])}…）" if names else ""
        lines.append(f"- {label}: {len(items)} 条{tail}")
    return "\n".join(lines)


def _git(vault: dict) -> dict:
    """Git 凭证清单——设置页已不再有 Gitea 配置，这里是唯一来源。"""
    items = [{"name": n, "base": p.get("base", ""), "user": p.get("user", "")}
             for n, p in sorted((vault.get("profiles") or {}).items())
             if p.get("type") == "git"]
    return {
        "profiles": items,
        # Token 不在 Agent 侧：私钥/令牌文件落在 AI 可读的机器上等于明文（开发规范 规范 1）
        "token": "不由 Agent 持有——存在 Broker 的 git 凭证里，由 Broker 代跑",
        "repo_url": "由你在每次请求的 url 字段里给出（仓库名常变，所以不写进凭证）；"
                    "必须与凭证登记的站点同源，跨站点会被拒",
        "commands": [
            "# 本机不要存 token 文件；clone / pull / push 一律走 Broker 的 /git/exec",
            'curl -H "Authorization: Bearer $AKG_AGENT_TOKEN" -X POST "$AKG_BASE/git/exec" \\',
            '     -d \'{"profile":"<git 凭证名>","url":"<完整仓库地址>","action":"pull"}\'',
        ],
    }


def _profiles_json(vault: dict) -> list:
    out = []
    for name, p in sorted((vault.get("profiles") or {}).items()):
        out.append({
            "name": name,
            "type": p.get("type"),
            "permissions": (["read"] if p.get("readonly") else ["read", "write"]),
            # git 凭证存的是站点 base（没有 host），这里直接给 base、不做 IP 掩码，
            # 否则列表里会出现空 host，AI 看不出这条凭证连的是哪个站点
            "host": (p.get("base") if p.get("type") == "git"
                     else _mask_host(p.get("host"))),
            "port": p.get("port"),
            "user": p.get("user"),
            # 库名降级为默认库后，优先取 default_database（旧字段 database 兜底）
            "database": p.get("default_database") or p.get("database"),
            "db": p.get("db"),
            "url": p.get("url"),
        })
    return out


def render_json(vault: dict, base: str) -> dict:
    """Agent 用 Accept: application/json 读取；实时、无缓存、无密钥。"""
    return {
        "skill": f"{base}/skill",
        "base": base,
        "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "agent_access": {
            "preferred": "application/json",
            "human": "text/markdown",
            "token": "不提供；Git Token 存在 Broker 的 git 凭证里，Agent 只提交动作",
            "locked": "423 表示服务锁定（主人重启后待登录解锁），不是密钥失效；"
                      "等一会儿重试即可，不要重新申请密钥",
        },
        "profiles": _profiles_json(vault),
        "services": services_summary(vault),
        "git": _git(vault),
    }


def services_summary(vault: dict) -> list:
    """services 是 sid -> 记录 的字典，这里统一转成列表（与 services.list_services 同口径）。"""
    return [
        {"name": s.get("name"), "env_keys": s.get("env_keys", []),
         "revoked": bool(s.get("revoked"))}
        for _sid, s in sorted((vault.get("services") or {}).items())
    ]


def _git_md(vault: dict) -> str:
    g = _git(vault)
    lines = [
        "- Token：**不由 Agent 持有**。Token 存在 Broker 的 git 凭证里，Agent 只提交动作，",
        "  由 Broker 带 Token 执行。本机不要保存任何 token / 私钥文件——AI 能读的磁盘就等于明文。",
        "- 仓库地址：由你在请求的 `url` 字段里给，必须与凭证登记的站点同源；",
        "  仓库改名或换仓库都不用改凭证。",
    ]
    if g["profiles"]:
        lines.append("- 可用 git 凭证：")
        for p in g["profiles"]:
            who = f"（用户 {p['user']}）" if p.get("user") else ""
            lines.append(f"  - `{p['name']}` → 站点 `{p['base']}`{who}")
    else:
        lines.append("- 尚无 git 凭证：请主人在「凭证」页添加（站点地址 + 用户名 + Token）。")
    lines += ["", "```bash", *g["commands"], "```"]
    return "\n".join(lines)


def render(vault: dict, base: str) -> str:
    tmpl_path = Path(__file__).with_name("templates") / "SKILL.md.tmpl"
    try:
        tmpl = tmpl_path.read_text(encoding="utf-8")
    except OSError:
        tmpl = "# AgentKeyGuard Skill\n\nBase: {{BASE}}\n\n{{PROFILES}}\n\n{{RULES}}\n"
    lines = []
    for name, p in sorted((vault.get("profiles") or {}).items()):
        lines.append(f"- `{name}` · {p.get('type')} · "
                     f"{_mask_host(p.get('host'))}:{p.get('port', '')}")
    profiles = "\n".join(lines) or "- （暂无 profile）"
    services = "\n".join(
        f"- `{s.get('name')}` · keys: {', '.join(s.get('env_keys') or [])}"
        for s in services_summary(vault)) or "- （暂无服务）"
    return (tmpl.replace("{{BASE}}", base)
                .replace("{{PROFILES}}", profiles)
                .replace("{{SERVICES}}", services)
                .replace("{{DEVICES}}", "")
                .replace("{{GIT}}", _git_md(vault))
                .replace("{{RULES}}", _rules_summary())
                .replace("{{DATE}}",
                         datetime.datetime.now().astimezone().isoformat(timespec="seconds")))


def trace(headers, fallback: str = "unknown") -> tuple[str, dict]:
    """记一条短期读取痕迹。

    `X-Agent-Id` 是 Agent 自报的名字；它常常不带（curl、脚本、没配置的客户端），
    以前一律落成 `unknown`，列表里就全是看不出谁是谁。调用方现在会把来源 IP
    传进 fallback，未自报的显示成 `ip:192.168.x.x`，至少能分清是几台机器。
    """
    agent_id = str(headers.get("X-Agent-Id") or fallback or "unknown")[:80]
    task_id = str(headers.get("X-Task-Id") or "")[:80]
    now = time.time()
    with _LOCK:
        for k in [k for k, v in TRACES.items() if v["expires"] < now]:
            TRACES.pop(k, None)
        tok = secrets.token_urlsafe(24)
        rec = {"agent_id": agent_id, "task_id": task_id,
               "created": now, "expires": now + TRACE_TTL}
        TRACES[tok] = rec
    return tok, rec


def list_traces() -> list:
    now = time.time()
    with _LOCK:
        for k in [k for k, v in TRACES.items() if v["expires"] < now]:
            TRACES.pop(k, None)
        return [{"token": k[:12], **v} for k, v in
                sorted(TRACES.items(), key=lambda kv: kv[1]["created"], reverse=True)]
