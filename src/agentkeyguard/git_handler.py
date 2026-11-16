# -*- coding: utf-8 -*-
"""Git 通道执行器（REQ-107）。

安全要点（按优先级）：

1. **凭据绝不进 argv**：URL 里不带 token，改用 `GIT_ASKPASS` + 环境变量传递，
   避免 `ps` / journal / 审计里出现明文；
2. **不用 shell**：`subprocess.run(list, shell=False)`，参数逐个校验，
   拒绝 `--upload-pack` / `--receive-pack` / `-c` 这类可注入配置的参数；
3. **动作白名单**：只允许 clone/pull/fetch/log/status/diff/branch/checkout/commit/push，
   其余一律拒绝，不提供任意 git 参数的自由度；
4. **危险动作走审批**：规则表里 `git_force` / `git_push_delete` 命中即要求人工确认；
5. **工作目录隔离**：每个 profile×仓库 一个目录，首次自动 clone，输出截断 64KB；
6. **仓库地址由请求带，但同源锁死**：凭证只记「站点 + 用户 + token」，
   仓库名经常变所以不进服务端；但放开 URL 等于放开 token 的去向，
   必须校验 scheme/host/port 与登记站点一致（见 `resolve_url`）。
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
import urllib.parse
from pathlib import Path

from . import config
from .rules import match_rule
from .storage import audit

ACTIONS = {"clone", "pull", "fetch", "log", "status", "diff",
           "branch", "checkout", "commit", "push", "ls-remote"}

# 读类动作：放行 + 审计，不弹审批
READ_ACTIONS = {"clone", "pull", "fetch", "log", "status", "diff", "branch", "ls-remote"}

# 任何参数里出现这些片段直接拒绝：它们能把任意程序塞进 git 的子进程
BAD_ARG_PREFIX = ("--upload-pack", "--receive-pack", "--exec=", "-c", "--config")
BAD_ARG_CHARS = ("\n", "\r", "\x00")

MAX_OUT = 64 * 1024       # 单次输出上限
TIMEOUT = 120             # 子进程超时（秒）


class GitError(RuntimeError):
    pass


def _git_root() -> Path:
    """所有 git 相关落盘都在这里：工作目录、askpass、隔离的 gitconfig。"""
    d = Path(config.DATA_DIR) / "git"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _slug(url: str) -> str:
    """把仓库地址压成目录名：owner/repo → owner__repo。"""
    path = urllib.parse.urlsplit(url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    s = re.sub(r"[^A-Za-z0-9._-]+", "__", path).strip("._-")
    return s[:80] or "repo"


def _repo_dir(name: str, slug: str = "") -> Path:
    """profile 的工作目录。带 slug 时按仓库再分一层：
    一个凭证要能服务多个仓库，只用 profile 名会互相踩。"""
    d = _git_root() / (f"{name}__{slug}" if slug else name)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _askpass_script() -> Path:
    """写一个极小的 askpass：用户名取 AKG_GIT_USER，其余当密码返回 token。

    脚本本身不含任何凭据，凭据只在进程环境里，进程退出即消失。
    """
    p = _git_root() / "askpass.sh"
    if not p.exists():
        p.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  *sername*|*ser\\ name*) printf "%s\\n" "${AKG_GIT_USER:-example-bot}" ;;\n'
            '  *) printf "%s\\n" "${AKG_GIT_TOKEN:-}" ;;\n'
            "esac\n",
            encoding="utf-8")
        p.chmod(0o700)
    return p


def _env(profile: dict) -> dict:
    env = dict(os.environ)
    # 隔离用户级配置：避免 ~/.gitconfig 里的 credential helper 或 insteadOf 干扰
    gitcfg = _git_root() / "gitconfig"
    if not gitcfg.exists():
        gitcfg.write_text("[credential]\n\thelper =\n", encoding="utf-8")
    env["GIT_CONFIG_GLOBAL"] = str(gitcfg)
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = str(_askpass_script())
    env["AKG_GIT_USER"] = profile.get("user") or "example-bot"
    env["AKG_GIT_TOKEN"] = profile.get("token") or ""
    env["LC_ALL"] = "C"
    return env


def _remote(profile: dict) -> str:
    """旧库兼容：base + repo 拼装。新写入的凭证不再存 repo，这里只读不回写。"""
    base = str(profile.get("base") or "").rstrip("/")
    repo = str(profile.get("repo") or "")
    if base.endswith(".git"):
        return base
    return f"{base}/{repo}.git"


def _origin(url: str) -> tuple:
    """(scheme, host, port)：端口按协议补默认值，避免 443 与空值被当成不同源。"""
    p = urllib.parse.urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port
    except ValueError:                 # 端口写成非法值时当作没写，最终会不同源被拒
        port = None
    return scheme, (p.hostname or "").lower(), port or (443 if scheme == "https" else 80)


def resolve_url(profile: dict, req_url: str = "") -> str:
    """确定本次要操作的仓库地址。

    凭证只记「站点 + 用户 + token」，仓库名由请求带（经常变）。但放开 URL
    等于放开 token 的去向，所以这里锁死同源，只放开路径：
      · 必须是 http/https
      · 拒绝 userinfo（`http://x:y@host/` 能做视觉欺骗）
      · scheme/host/port 必须与 profile.base 完全一致
    旧库里的 repo 字段仍可兜底（请求没带 url 时），保证升级瞬间不炸。
    """
    url = str(req_url or "").strip()
    if not url:
        legacy = _remote(profile) if profile.get("repo") else ""
        if legacy:
            return legacy
        raise GitError("需要 url：完整仓库地址，"
                       "如 http://192.0.2.10:3000/example-org/agent_key_guard.git")
    if url.startswith("-") or any(c in url for c in BAD_ARG_CHARS):
        raise GitError("url 不合法")
    p = urllib.parse.urlsplit(url)
    if (p.scheme or "").lower() not in ("http", "https"):
        raise GitError("url 必须以 http:// 或 https:// 开头")
    if p.username or p.password:
        raise GitError("url 里不能带用户名或密码，凭据由 Broker 注入")
    if not p.path or p.path == "/":
        raise GitError("url 里缺少仓库路径")
    base = str(profile.get("base") or "").strip()
    if not base:
        raise GitError("这条 git 凭证没有登记站点地址")
    if _origin(url) != _origin(base):
        raise GitError("仓库地址与凭证登记的站点不同源")
    return url


def _check_args(args: list) -> list:
    out = []
    for a in args or []:
        s = str(a)
        if any(c in s for c in BAD_ARG_CHARS):
            raise GitError("参数里不允许换行或空字节")
        low = s.lower()
        if any(low.startswith(p) for p in BAD_ARG_PREFIX):
            raise GitError(f"参数被拒绝：{s}")
        out.append(s)
    return out


def handle(srv, req: dict, src: str) -> None:
    name = str(req.get("profile") or "").strip()
    action = str(req.get("action") or "").strip().lower()
    if not name or not action:
        return srv._send(400, {"error": "需要 profile 与 action"})

    prof = (srv.vault.get("profiles") or {}).get(name)
    if not prof or prof.get("type") != "git":
        return srv._send(404, {"error": f"没有 git profile: {name}"})
    if action not in ACTIONS:
        return srv._send(400, {"error": f"不支持的 action: {action}",
                               "allowed": sorted(ACTIONS)})
    try:
        extra = _check_args(req.get("args") or [])
    except GitError as e:
        return srv._send(400, {"error": str(e)})

    try:
        remote = resolve_url(prof, req.get("url"))
    except GitError as e:
        return srv._send(400, {"error": str(e)})
    workdir = _repo_dir(name, _slug(remote))
    branch = str(req.get("branch") or prof.get("default_branch") or "main").strip() or "main"

    if action == "clone":
        argv = ["git", "clone", remote, "."]
    else:
        if not (workdir / ".git").exists():
            return srv._send(409, {"error": "仓库尚未初始化，请先执行 action=clone"})
        argv = ["git", action] + extra
        if action == "push" and branch and "--" not in " ".join(extra):
            argv += ["origin", branch]

    # 分级判定：把整条命令拼成字符串交给规则引擎（git 通道）
    joined = " ".join([shlex.quote(x) for x in argv[2:]] or argv[1:])
    layer, label = match_rule(f"git {action} {joined}", "git")
    if layer == "blocked":
        audit({"event": "deny", "kind": "git.exec", "profile": name,
               "reason": "system_blocked", "rule": label, "src": src})
        return srv._send(403, {"error": "系统拦截", "reason": label,
                               "type": "system_blocked"})

    reflect = ""
    if layer == "dangerous":
        reflect = str(req.get("self_reflection") or "").strip()[:1000]
        if not reflect:
            audit({"event": "deny", "kind": "git.exec", "profile": name,
                   "reason": "self_reflection_required", "rule": label, "src": src})
            return srv._send(428, {
                "error": "高危操作需自我反思",
                "instruction": "请先思考并回答：1. 我是谁？2. 我在哪儿？3. 我打算干什么？"
                               "想清楚还要不要继续。如果确认继续，请在下次请求的 "
                               "'self_reflection' 字段中带上你的思考结果。",
                "rule": label,
            })

    if action not in READ_ACTIONS or layer == "dangerous":
        from . import server as server_mod
        target = remote
        res: dict = {}
        if not server_mod.ask_approval("git.exec", name, target,
                                       f"git {action} {remote}\n{' '.join(extra)[:1200]}",
                                       src,
                                       title=(req.get("title") or ""),
                                       dangerous=(layer == "dangerous"),
                                       self_reflection=reflect, out=res):
            audit({"event": "denied", "kind": "git.exec", "profile": name,
                   "cmd": joined[:500], "src": src, "reason": res.get("reason", "")})
            return srv._send(403, {"error": "用户拒绝",
                                   "reason": res.get("reason") or "",
                                   "type": "user_denied"})

        if res.get("duplicate"):
            return srv._send(200, {"ok": True, "duplicate": True,
                                   "note": "同一操作已由前一条相同请求处理，本次未重复执行"})

    t0 = time.time()
    try:
        cp = subprocess.run(argv, cwd=str(workdir), env=_env(prof), shell=False,
                            capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        audit({"event": "error", "kind": "git.exec", "profile": name,
               "error": "timeout", "src": src})
        return srv._send(502, {"error": f"git 执行超时（>{TIMEOUT}s）"})
    except Exception as e:                      # noqa: BLE001
        audit({"event": "error", "kind": "git.exec", "profile": name,
               "error": f"{type(e).__name__}: {e}", "src": src})
        return srv._send(502, {"error": f"git 执行失败：{type(e).__name__}: {e}"})

    out = _scrub(cp.stdout.decode("utf-8", "replace"), prof)[:MAX_OUT]
    err = _scrub(cp.stderr.decode("utf-8", "replace"), prof)[:MAX_OUT]
    elapsed = int((time.time() - t0) * 1000)
    audit({"event": "ok", "kind": "git.exec", "profile": name,
           "action": action, "exit": cp.returncode, "src": src, "ms": elapsed})
    return srv._send(200, {"exit_code": cp.returncode, "stdout": out, "stderr": err,
                           "action": action, "url": remote,
                           "elapsed_ms": elapsed})


def _scrub(text: str, profile: dict) -> str:
    tok = profile.get("token") or ""
    if tok:
        text = text.replace(tok, "***")
    return text
