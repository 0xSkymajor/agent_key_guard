# -*- coding: utf-8 -*-
"""审批：Bark 推送、终端回落、审批队列与历史。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

依赖边界：本模块**不 import dashboard**（审批页 HTML 归 dashboard，server 同时
import 两者即可）。只依赖 config（可变常量，调用期读取）与 storage.audit。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid

from . import agents, config
from .notify import push_webhook
from .storage import audit


# ── 审批队列（原样保留：自检脚本会直接读写它）──
PENDING_APPROVALS: dict[str, dict] = {}
_PENDING_LOCK = threading.RLock()      # 可重入：持锁时读队列不会自锁

# 审批卡片上的兜底标题：Agent 没写 title 时，至少让主人看懂在做什么
_KIND_CN = {
    "ssh.exec": "执行命令",
    "pg.query": "查询数据库",
    "git.exec": "Git 操作",
}
_TERM_LOCK = threading.Lock()          # 仅用于"回落终端确认"时串行化 input()


def push_base() -> str:
    """审批链接用的地址：必须手机可达。

    控制台与 Agent 接入可以配成 127.0.0.1（本机 Agent 就该用回环），但手机点不开回环，
    所以推送链接单独取值：配置是回环就回退到本机局域网 IP。
    """
    base = (config.PUBLIC_BASE or "").rstrip("/")
    host = ""
    try:
        host = (urllib.parse.urlsplit(base).hostname or "").strip().lower()
    except ValueError:
        host = ""
    if base and host not in ("127.0.0.1", "localhost", "::1"):
        return base
    from . import network        # 延迟导入：本模块的依赖边界仍只保留 config/storage
    ip = network.local_ip() or "127.0.0.1"
    return f"https://{ip}:{config.PORT}"


def approval_code(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:4].upper()


def approval_identity(kind: str, profile: str, target: str, detail: str,
                      agent: str = "") -> str:
    """同一动作的指纹，用来吸收「客户端把同一条请求发了两遍」。

    为什么需要：审批要等主人（最长 5 分钟），这期间客户端可能因为自己那层的
    超时/重试把**完全相同的请求**再发一次。以前这会在工作台上变成两张卡、
    「批准全部 2 条」，同一件事批一次却执行两遍。指纹只认「同一 Agent、
    同一类型、同一目标、同一条命令/语句」，换 Agent 或换命令都不合并。
    """
    raw = "\x1f".join((kind or "", profile or "", target or "",
                       (detail or "").strip(), agent or ""))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def push_bark(rid: str, kind: str, profile: str, target: str,
              detail: str, title: str = "", dangerous: bool = False,
              base: str = "", quiet: bool = False) -> bool:
    """推送一条到手机。成功返回 True。失败只打印原因，不抛异常。

    base：临时指定推送根地址，覆盖全局 BARK_BASE（空串 = 用全局）。

    为什么需要这个参数：向导第 2 步要在**写入 .env 之前**先发一条测试推送，
    确认这条通道真的通，用户点了「收到」才落盘。没有 base 就只能二选一：
    先污染全局 BARK_BASE（隐藏状态，向导退出后仍生效，误导后续判断），
    或者先落盘再验证（那就违背了「确认后才写」）。两者都不行。

    quiet：不打印失败原因（返回值照旧）。serve 里要日志，向导里不要 ——
    那几个 print 会把 HTTP 状态码、异常原文直接吐到向导界面上，和
    「底层异常不进界面」的纪律冲突。UI 层只认 WIZ_ERR_NET 那一句。
    """
    def _log(msg: str) -> None:
        if not quiet:
            print(msg, flush=True)

    root = config.normalize_bark(base or config.BARK_BASE)
    if not root:
        _log("  [Bark] 未配置 AGENTKEYGUARD_BARK，跳过推送")
        return False

    # 统一指向常驻工作台：点通知不再每次都新开一个标签页
    approve_url = f"{push_base()}/dashboard"
    head = title or f"{kind} → {profile}"
    # 手机通知第一眼就能看出是哪个会话在请求，多开时不会认错
    _label = agents.current_label()
    if _label:
        head = f"[{_label}] {head}"
    if dangerous:
        head = "🚨🚨 高危操作！" + head
    body = head if len(head) <= 80 else head[:77] + "..."
    path = "/{}/{}".format(
        urllib.parse.quote("凭证代理审批", safe=""),
        urllib.parse.quote(body, safe=""),
    )
    qs = urllib.parse.urlencode({
        "url": approve_url,
        "group": "agentkeyguard",
        "level": "timeSensitive",
    })
    url = f"{root}{path}?{qs}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "agentkeyguard/0.8"})
        with urllib.request.urlopen(req, timeout=8) as r:
            raw = r.read().decode("utf-8", "replace")
        try:
            data = json.loads(raw)
        except ValueError:
            _log(f"  [Bark] 返回非 JSON: {raw[:160]}")
            return False
        if data.get("code") != 200:
            _log(f"  [Bark] 推送失败: {raw[:200]}")
            return False
        return True
    except Exception as e:                                   # noqa: BLE001
        _log(f"  [Bark] 推送异常: {type(e).__name__}: {e}")
        return False


def push_channels(entry: dict) -> bool:
    """遍历通知渠道推送一条审批。任一渠道成功即返回 True。

    `bark` 是保留字，走 push_bark；其余是 `preset:name`，按名字反查
    `config.NOTIFY` 找渠道详情后走 `notify.push_webhook`。
    单条渠道失败只记日志，不阻塞其他渠道，也不让审批本身失败。
    """
    rid = entry["request_id"]
    kind = entry["kind"]
    profile = entry["profile"]
    target = entry["target"]
    detail = entry["detail"]
    title = entry["title"]
    dangerous = bool(entry.get("dangerous"))

    # 标题统一加签名与高危前缀（与 push_bark 内部保持一致）
    head = title
    _label = entry.get("agent") or ""
    if _label:
        head = f"[{_label}] {head}"
    if dangerous:
        head = "🚨🚨 高危操作！" + head

    approve_url = f"{push_base()}/dashboard"
    any_ok = False
    for ch in list(config.NOTIFY_CHANNELS or ["bark"]):
        if ch == "bark":
            if push_bark(rid, kind, profile, target, detail, title,
                         dangerous=dangerous):
                any_ok = True
            continue
        if ":" not in ch:
            continue
        preset, name = ch.split(":", 1)
        chan = next((c for c in (config.NOTIFY or [])
                     if c.get("name") == name), None)
        if not chan:
            print(f"  [通知] 渠道 {name} 不存在，跳过", flush=True)
            continue
        if push_webhook(chan, head, detail, approve_url):
            any_ok = True
    return any_ok


# ── 终端回落：带超时的行读取 ──
# Windows 没有 select，只能用线程做阻塞读。线程必须**常驻**：
# 每次调用都新建线程的话，超时后那个线程会一直阻塞在 stdin 上，
# 下一次调用时它会抢走本该属于本次的输入（v0.10.4 自检实测抓到），
# 而且它会一直持有 TextIOWrapper 的内部锁，让 close() 死锁。
_TERM_Q = None                     # queue.Queue，读到的行往里丢
_TERM_PUMP = None                  # 常驻读取线程
_TERM_EOF = False                  # stdin 读到 EOF 后置位，之后一律按"无输入"处理
_TERM_PUMP_LOCK = threading.Lock()


def _term_pump(stream, q) -> None:
    """常驻读取线程：把 stream 的每一行丢进 q；读到 EOF 就置位 _TERM_EOF 并退出。"""
    global _TERM_EOF
    while True:
        try:
            line = stream.readline()
        except Exception:
            line = ""
        if line == "":
            _TERM_EOF = True
            return
        q.put(line)


def _readline_timeout(prompt: str, timeout: float) -> "str | None":
    """带超时的终端读取。

    返回读到的整行（可能是空串，表示用户直接回车 = 拒绝）；
    超时返回 None；stdin 不可读（后台跑 / 重定向到 /dev/null）抛 EOFError。

    为什么必须自己实现：内置 input 没有超时参数，一旦 Bark 推送失败、
    又没人坐在终端前，审批线程就会被无限期挂住 —— v0.10.4 修的就是这个。
    POSIX 用 select 等可读，超时直接返回，不留任何残留线程；
    Windows 没有 select，走上面的常驻读取线程 + 队列。
    """
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    except Exception:
        raise EOFError("stdout 不可写") from None

    if os.name == "nt":
        import queue as _queue
        global _TERM_Q, _TERM_PUMP
        with _TERM_PUMP_LOCK:
            if _TERM_Q is None or _TERM_PUMP is None or not _TERM_PUMP.is_alive():
                if _TERM_EOF:
                    raise EOFError("stdin 已关闭")
                _TERM_Q = _queue.Queue()
                _TERM_PUMP = threading.Thread(
                    target=_term_pump, args=(sys.stdin, _TERM_Q), daemon=True)
                _TERM_PUMP.start()
            q = _TERM_Q
        try:
            return q.get(timeout=max(0.0, timeout))
        except _queue.Empty:
            # 队列空 + 线程也退了 ⇒ stdin 真的关了，不是超时
            if _TERM_PUMP is None or not _TERM_PUMP.is_alive():
                raise EOFError("stdin 已关闭") from None
            return None

    try:
        fd = sys.stdin.fileno()
    except Exception:
        raise EOFError("stdin 没有 fileno，无法做超时等待") from None
    import select
    try:
        ready, _, _ = select.select([fd], [], [], max(0.0, timeout))
    except OSError:
        raise EOFError("stdin 不可 select") from None
    if not ready:
        return None
    line = sys.stdin.readline()
    if line == "":
        raise EOFError("stdin 已关闭")
    return line


def ask_approval(kind: str, profile: str, target: str, detail: str,
                 source: str, force: bool = False, title: str = "",
                 dangerous: bool = False, self_reflection: str = "",
                 reflection_off: bool = False,
                 out: "dict | None" = None) -> bool:
    """推送手机 → 挂起等待工作台/确认页回调。超时或推送失败都有兜底。

    终端回落有 TERMINAL_TIMEOUT 秒超时，超时按拒绝并落审计
    reason=terminal_timeout —— 绝不允许审批线程被无限期挂住。

    force=True 时**无视 AUTO_YES**，用于 SSH —— 提权面太大，不允许任何豁免。
    title 由 Agent 提供（≤30 字意图摘要），没给就回退到 "kind → profile"。

    dangerous=True（命中 rules.json 的 dangerous 层且自审已通过）时：
      · Bark 标题加 🚨🚨 高危操作！前缀，工作台卡片顶部出红色横幅；
      · Agent 的 self_reflection 原文一起进卡片，用黄色区块展示，
        标题"🤖 Agent 的自我反思"——让主人确认它没犯迷糊。
    reflection_off=True 表示主人在「灵魂三问」块关掉了这条规则的自审：
    没有反思原文可展示，卡片改成提示"本条规则已关闭自审，仍在此等待审批"，
    免得出现一块空白的黄色区域让人以为是显示故障。
    out 非空时回填 {"ok","decision","reason"}，供调用方做拒绝原因透传。
    """
    if config.AUTO_YES and not force:
        print("  [审批] --yes 已开启，自动放行", flush=True)
        return True

    # 兜底也要说人话：Agent 不传 title 时，别把 `ssh.exec → 192.0.2.11` 这种
    # 机器话甩给主人——历史里一长串一样的东西就是这么来的。
    title = re.sub(r"\s+", " ", (title or "").strip())[:40]
    if not title:
        title = f"{_KIND_CN.get(kind, kind)} · {profile}"

    rid = uuid.uuid4().hex[:10]
    ev = threading.Event()
    entry = {
        "request_id": rid,
        "event": ev,
        "decision": None,
        "created": time.time(),
        "kind": kind,
        "profile": profile,
        "target": target,
        "detail": detail,
        "source": source,
        "title": title,
        # 这条密钥的名字（主人生成密钥时写的签名）：多会话并行时靠它区分谁在请求
        "agent": agents.current_label(),
        "code": approval_code(kind, profile, detail),
        "dangerous": bool(dangerous),
        "self_reflection": (self_reflection or "")[:1000],
        "reflection_off": bool(reflection_off),
        "reason": "",                          # 用户拒绝时填，透传给 Agent
        # 并发去重指纹：客户端重试同一条请求时，不再新开一张卡
        "identity": approval_identity(kind, profile, target, detail,
                                      agents.current_label()),
    }
    with _PENDING_LOCK:
        twin = next((o for o in PENDING_APPROVALS.values()
                     if not o.get("decision")
                     and o.get("identity") == entry["identity"]), None)
        if twin is None:
            PENDING_APPROVALS[rid] = entry
            audit({"event": "pending_created", "request_id": rid,
                   "code": entry["code"], "kind": kind, "profile": profile,
                   "agent": entry["agent"], "identity": entry["identity"],
                   "src": source})

    if twin is not None:
        # 已经有一条一模一样的在等主人：复用它的结论，自己不再推送、不再执行。
        # 调用方看 out["duplicate"] 决定「不要重复执行」，所以同一件事只做一遍。
        print(f"  [去重] 同一动作已在等待审批（{twin.get('request_id')}），"
              f"复用，不重复推送", flush=True)
        audit({"event": "approval_dedupe", "request_id": rid,
               "owner": twin.get("request_id"), "kind": kind,
               "profile": profile, "identity": entry["identity"], "src": source})
        twin["event"].wait(timeout=config.APPROVAL_TIMEOUT)
        decision = twin.get("decision") or "timeout"
        ok = decision == "yes"
        if out is not None:
            out["ok"] = ok
            out["decision"] = decision
            out["reason"] = str(twin.get("reason") or "")
            out["duplicate"] = True        # 让适配器跳过执行，避免同一动作跑两遍
        return ok

    print("\n" + "─" * 68, flush=True)
    if dangerous:
        print("  🚨🚨  高危操作（命中 rules.json dangerous 层，已要求自我反思）  🚨🚨",
              flush=True)
        if entry["self_reflection"]:
            print(f"  🤖 Agent 的自我反思：{entry['self_reflection']}", flush=True)
    print(f"  [需批准] [{title}]", flush=True)
    if entry["agent"]:
        print(f"  来自   {entry['agent']}", flush=True)
    print(f"  类型   {kind}  →  {profile}", flush=True)
    print(f"  目标   {target}", flush=True)
    for line in detail.splitlines()[:14]:
        print(f"         {line}", flush=True)
    print(f"  请求码 {entry['code']}    来源 {source}", flush=True)
    print(f"  控制台 {push_base()}/dashboard   单条 {push_base()}/approve?id={rid}",
          flush=True)

    ok = False
    term_reason = None          # terminal_timeout / terminal_eof，供 finally 用
    try:
        if push_channels(entry):
            print(f"  已推送至手机，挂起等待批准…… (id={rid}，{config.APPROVAL_TIMEOUT}s 超时)",
                  flush=True)
            if not ev.wait(timeout=config.APPROVAL_TIMEOUT):
                print("  审批超时，拒绝", flush=True)
                ok = False
            else:
                ok = entry.get("decision") == "yes"
                print(f"  → 手机返回：{'已批准' if ok else '已拒绝'}", flush=True)
        else:
            # 网络断了也不能把整个服务卡死 —— 回落到终端（带超时，见 _readline_timeout）
            print("  通知推送失败，回落到终端确认", flush=True)
            entry["terminal"] = True
            with _TERM_LOCK:
                try:
                    line = _readline_timeout("  允许? [y/N] ", config.TERMINAL_TIMEOUT)
                except (EOFError, KeyboardInterrupt):
                    line, term_reason = None, "terminal_eof"
                else:
                    if line is None:
                        term_reason = "terminal_timeout"
            if term_reason:
                # 没人在终端前 → 一律拒绝。fail-closed，绝不让线程干等。
                audit({"event": "deny", "reason": term_reason, "request_id": rid,
                       "kind": kind, "profile": profile, "target": target,
                       "waited": config.TERMINAL_TIMEOUT})
                print(f"  → 终端无输入（{term_reason}），按拒绝处理", flush=True)
                ok = False
            else:
                ok = line.strip().lower() in ("y", "yes")
                print(f"  → {'已批准' if ok else '已拒绝'}", flush=True)
    finally:
        with _PENDING_LOCK:
            PENDING_APPROVALS.pop(rid, None)
        decision = entry.get("decision") or term_reason or "timeout"
        if out is not None:
            out["ok"] = ok
            out["decision"] = decision
            out["reason"] = str(entry.get("reason") or "")
        # 无论走工作台、单条页、超时还是异常，都在这里统一落一条历史
        history_add(entry, decision, source)
    return ok


def _snapshot(rid: str, e: dict, now: float, queue: int) -> dict:
    """把一条内部 entry 拍成对外的快照（不含 event/decision 等运行时对象）。"""
    return {
        "request_id": rid,
        "title": e.get("title", ""),
        "kind": e.get("kind"),
        "profile": e.get("profile"),
        "target": e.get("target"),
        "detail": e.get("detail", ""),
        "source": e.get("source"),
        "agent": e.get("agent", ""),
        "code": e.get("code"),
        "dangerous": bool(e.get("dangerous")),
        "self_reflection": e.get("self_reflection", ""),
        "waiting_s": int(now - e.get("created", now)),
        "timeout_s": int(config.APPROVAL_TIMEOUT),
        "queue": queue,
    }


def pending_head() -> dict | None:
    """串行审批的核心：只返回 created 最早的那一条，外加队列长度。

    保留这个语义是为了兼容徽标轮询与「单条批准」——`groups` 是加法，不是替换。
    """
    now = time.time()
    with _PENDING_LOCK:
        items = [(k, v) for k, v in PENDING_APPROVALS.items() if not v.get("decision")]
    if not items:
        return None
    items.sort(key=lambda kv: kv[1].get("created", 0))
    rid, e = items[0]
    return _snapshot(rid, e, now, len(items))


def pending_groups() -> list[dict]:
    """按「会话签名 + 类型 + 凭证」聚合等待中的审批。

    为什么需要：一条任务要分批执行时（比如大文件分 3 批上传到同一台机器），
    会连着产生 3 条同类审批，逐条点三次纯属折磨。
    折叠的边界必须收紧——跨签名、跨类型、跨凭证一律不许合，
    否则一次点击等于批准了不同目标上的操作。
    """
    now = time.time()
    with _PENDING_LOCK:
        items = [(k, dict(v)) for k, v in PENDING_APPROVALS.items()
                 if not v.get("decision")]
    if not items:
        return []
    items.sort(key=lambda kv: kv[1].get("created", 0))
    total = len(items)
    groups: dict[tuple, dict] = {}
    for rid, e in items:
        key = (e.get("agent") or "", e.get("kind") or "", e.get("profile") or "")
        g = groups.get(key)
        if g is None:
            groups[key] = {
                "key": "|".join(key),
                "agent": key[0],
                "kind": key[1],
                "profile": key[2],
                "count": 1,
                "rids": [rid],
                "first": _snapshot(rid, e, now, total),
            }
        else:
            g["count"] += 1
            g["rids"].append(rid)
    return list(groups.values())


# ────────────────────────────── 审批历史（与排队逻辑完全解耦） ──────────────────────────────
# 独立的列表 + 独立的锁：pending_head() 永远不碰这里，这里也永远不碰 PENDING_APPROVALS。
# 只存展示需要的字段，不存任何凭证。重启即丢，符合"内存里就够"的定位。

APPROVAL_HISTORY: list[dict] = []
_HISTORY_LOCK = threading.Lock()
HISTORY_MAX = 50


def history_add(entry: dict, decision: str, src: str) -> None:
    now = time.time()
    rec = {
        "request_id": entry.get("request_id", ""),
        "title": entry.get("title", ""),
        "kind": entry.get("kind"),
        "profile": entry.get("profile"),
        "target": entry.get("target"),
        "detail": entry.get("detail", ""),
        "source": entry.get("source"),
        "agent": entry.get("agent", ""),
        "code": entry.get("code"),
        "dangerous": bool(entry.get("dangerous")),
        "self_reflection": entry.get("self_reflection", ""),
        "reason": entry.get("reason", ""),
        "decision": decision,                      # yes / no / timeout
        "decided_at": now,
        "waited_s": int(now - entry.get("created", now)),
        "src": src,
    }
    with _HISTORY_LOCK:
        APPROVAL_HISTORY.append(rec)
        del APPROVAL_HISTORY[:-HISTORY_MAX]        # 只保留最近 HISTORY_MAX 条


def history_list() -> list:
    """最新的在前，给前端直接渲染。"""
    with _HISTORY_LOCK:
        return list(reversed(APPROVAL_HISTORY))


def history_clear() -> int:
    with _HISTORY_LOCK:
        n = len(APPROVAL_HISTORY)
        APPROVAL_HISTORY.clear()
    return n
