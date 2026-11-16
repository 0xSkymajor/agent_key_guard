# -*- coding: utf-8 -*-
"""规则引擎：rules.json 三级拦截（blocked / dangerous / interactive）。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

⚠️ rules.json 路径必须"调用期读取" config.RULES_PATH（不固化），
否则 selftest 换到临时规则文件时不会生效。
"""
from __future__ import annotations

import copy
import json
import os
import re
import threading
from pathlib import Path

from . import config

# ── 分级拦截规则（rules.json，热更新） ──
# 三层语义，按严重度从高到低：
#   blocked      绝对禁区：直接 403，**不弹审批**。删库/删系统目录/反弹 shell 走这里 ——
#                这类操作一旦发生就不可逆，必须由人手动执行；Agent 失控时它点不到
#                你的手机，只有彻底挡住才安全。
#   dangerous    高危操作：先回 428 要求 Agent 自我反思（self_reflection），
#                反思通过才推手机审批。重启、强杀进程、rm -rf 业务目录走这里。
#   interactive  交互式命令：直接 400。会挂起到超时的命令没有审批价值。
_RULES_LOCK = threading.Lock()
_RULES_CACHE: dict = {"mtime": None, "rules": None}
RULE_LAYERS = ("blocked", "dangerous", "interactive")
_RULE_SEV = {"": 0, "interactive": 1, "dangerous": 2, "blocked": 3}

# ── 用户态覆盖层（存 vault，不落 rules.json） ──
# rules.json 装在 /etc 下是 dpkg conffile，面板写它会在升级时打架，也会被
# self_protect_broker_code 这条规则拦住自己的设计前提。所以：
#   · 内置规则文件只读
#   · 改层、新增规则全部叠加在编译前，由 server 在解锁成功 / 保存后注入
#   layout  {"规则名": "blocked"|"dangerous"}   内置规则被改过的层
#   customs [{"name","layer","scope","keywords|pattern|all_of","desc"}]
_OVERRIDES: dict = {"layout": {}, "customs": []}
CUSTOM_MAX = 100
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def set_overrides(layout: dict | None = None, customs: list | None = None,
                  force: bool = True) -> None:
    """注入用户态覆盖层。force=True 时立刻重编译，避免"改完不生效"。"""
    with _RULES_LOCK:
        _OVERRIDES["layout"] = dict(layout or {})
        _OVERRIDES["customs"] = copy.deepcopy(list(customs or []))
        _RULES_CACHE["rules"] = None
        _RULES_CACHE["mtime"] = None
    if force:
        load_rules(force=True)


def get_overrides() -> dict:
    with _RULES_LOCK:
        return {"layout": dict(_OVERRIDES["layout"]),
                "customs": copy.deepcopy(_OVERRIDES["customs"])}

# rules.json 丢失/损坏时的兜底：只留最要命的几条。fail-closed 但不停服。
_FALLBACK_RULES = {
    "blocked": [
        {"name": "fallback_drop_db", "pattern": r"(?i)\bdrop\s+database\b"},
        {"name": "fallback_rm_rf_root",
         "pattern": r"(?i)\brm\s+-[a-z]*[rf][a-z]*\s+/(?:\s|$)"},
    ],
    "dangerous": [
        {"name": "fallback_reboot",
         "pattern": r"(?i)(?:^|[\s;&|(])(reboot|shutdown|poweroff|halt)\b"},
        {"name": "fallback_kill9", "pattern": r"(?i)\bkill(all)?\s+-9\b"},
    ],
    "interactive": [
        {"name": "fallback_shell",
         "pattern": r"(?i)^\s*(sudo\s+-[is]|su|bash\s+-i|sh\s+-i|vi|vim|nano|top|htop)\b"},
    ],
}


# 自保护规则永远不可关闭：能被关掉的防护等于没有防护，
# 而这几条挡的正是「Agent 读走 vault / 改掉规则文件」。
def is_locked_rule(name: str) -> bool:
    return str(name or "").startswith("self_protect_")


# 规则的展示信息（说明、通道），供敏感权限面板渲染。
# 单独存一份而不是塞进匹配用的元组里：那会破坏所有解包处。
_RULE_META: dict[str, dict] = {}


def desc_of(name: str) -> str:
    """取一条规则的中文说明，用于 403 响应与审批卡片。"""
    return str((_RULE_META.get(str(name or "")) or {}).get("desc") or "")


def list_layer(layer: str, off: set[str] | None = None,
               reflection_off: set[str] | None = None) -> list[dict]:
    """列出某一层的规则与开关状态，供设置页的「屏蔽 / 灵魂三问」两块使用。

    两层语义不同，字段也分开给，别混用：
      · blocked  关闭 = 完全不拦截，看 `enabled`
      · dangerous 永不停止匹配，"关闭"只是跳过自审（428），看 `reflection`
    自保护规则恒为开启且不可搬动（locked）。
    """
    if layer not in RULE_LAYERS:
        return []
    load_rules()
    off = set(off or ())
    reflection_off = set(reflection_off or ())
    out = []
    for _comp, name, scopes in load_rules()[layer]:
        meta = _RULE_META.get(name) or {}
        locked = is_locked_rule(name)
        custom = bool(meta.get("custom"))
        if layer == "blocked":
            # 自保护规则恒为开启，不读用户设置
            enabled = True if locked else (name not in off)
            reflection = True
        elif layer == "dangerous":
            # 关键：dangerous 永不因开关被跳过，关的只是自审
            enabled = True
            reflection = name not in reflection_off
        else:
            enabled = name not in off
            reflection = True
        out.append({
            "name": name,
            "desc": meta.get("desc") or "",
            "scope": meta.get("scope") or ["*"],
            "layer": layer,
            "locked": locked,
            "custom": custom,
            "enabled": enabled,
            "reflection": reflection,
        })
    out.sort(key=lambda x: (not x["locked"], not x["custom"], x["name"]))
    return out


def list_blocked(off: set[str] | None = None) -> list[dict]:
    """兼容旧调用：只取绝对屏蔽层。"""
    return list_layer("blocked", off)


def builtin_layer(name: str) -> str:
    """rules.json 里这条规则原本属于哪层（不看用户覆盖层）。"""
    try:
        data = json.loads(Path(config.RULES_PATH).read_bytes().decode("utf-8"))
    except Exception:                              # noqa: BLE001
        data = _FALLBACK_RULES
    if not isinstance(data, dict):
        data = _FALLBACK_RULES
    for layer in RULE_LAYERS:
        for it in data.get(layer) or []:
            if isinstance(it, dict) and str(it.get("name") or "") == str(name or ""):
                return layer
    return ""


def needs_reflection(name: str, reflection_off: set[str] | None = None) -> bool:
    """这条 dangerous 规则是否仍要求 Agent 先回答灵魂三问。

    只在越权放宽的意义上回答"否"——返回 False 时该操作**依然要审批**，
    只是省掉 428 那一次往返。永远不要把它当成"可以放行"。
    """
    return str(name or "") not in set(reflection_off or ())


def _compile_layer(items, layer: str = "", meta: dict | None = None) -> list:
    """编译一层规则 → [(编译后的正则列表, 规则名, scope 集合)]。

    scope 为 None 表示「全通道」（等价于 `["*"]`）；否则只在该通道生效。
    旧 rules.json 没有 scope 字段时按全通道处理，保证升级不炸（REQ-105）。

    `meta` 默认写全局 _RULE_META；试运行传一份临时 dict，避免草稿规则
    污染线上规则的说明与来源标记。
    """
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        pats = it.get("all_of") or [it.get("pattern") or ""]
        pats = [p for p in pats if p]
        if not pats:
            continue
        try:
            comp = [re.compile(p) for p in pats]
        except re.error as e:
            print(f"  [规则] 跳过无效正则 {it.get('name')}: {e}", flush=True)
            continue
        raw_scope = it.get("scope")
        if raw_scope is None:
            # 旧表兼容：没写 scope 时按规则名前缀推断通道，
            # 免得自定义的 sql_* 规则继续误伤 shell（REQ-105）
            _nm = str(it.get("name") or "")
            if _nm.startswith("sql_"):
                raw_scope = ["sql"]
            elif _nm.startswith("git_"):
                raw_scope = ["git"]
            else:
                # 其余规则默认只作用于 shell 通道——这是它们历史上的用武之地；
                # 需要跨通道的规则（如 self_protect_*）必须显式写 "scope": ["*"]
                raw_scope = ["shell"]
        if isinstance(raw_scope, str):
            raw_scope = [raw_scope]
        if not raw_scope or "*" in raw_scope:
            scopes = None
        else:
            scopes = {str(x).strip().lower() for x in raw_scope if str(x).strip()}
            if not scopes:
                scopes = None
        _nm = str(it.get("name") or pats[0])
        (meta if meta is not None else _RULE_META)[_nm] = {
            "desc": str(it.get("desc") or ""),
            "scope": sorted(scopes) if scopes else ["*"],
            "layer": layer,
            "custom": bool(it.get("_custom")),
        }
        out.append((comp, _nm, scopes))
    return out


def _custom_to_item(c: dict) -> dict | None:
    """把一条自定义规则转成编译用的条目。

    keywords 优先：每个词 re.escape 后用 | 连接，天然免疫正则元字符，
    让不会写正则的人也能安全地叉掉一个命令片段。
    """
    if not isinstance(c, dict):
        return None
    name = str(c.get("name") or "").strip()
    if not name:
        return None
    item = {"name": name, "desc": str(c.get("desc") or ""),
            "scope": c.get("scope") or ["shell"], "_custom": True}
    kws = [str(k).strip() for k in (c.get("keywords") or []) if str(k).strip()]
    if kws:
        item["pattern"] = "(?i)(?:" + "|".join(re.escape(k) for k in kws) + ")"
        return item
    all_of = [str(p).strip() for p in (c.get("all_of") or []) if str(p).strip()]
    if all_of:
        item["all_of"] = all_of
        return item
    pat = str(c.get("pattern") or "").strip()
    if pat:
        item["pattern"] = pat
        return item
    return None


def _apply_overrides(data: dict) -> dict:
    """把「改层」与「自定义规则」叠加到内置表上。传入的 data 必须是副本。"""
    layout = _OVERRIDES.get("layout") or {}
    if layout:
        moved: dict[str, list] = {}
        for layer in RULE_LAYERS:
            keep = []
            for it in data.get(layer) or []:
                nm = str(it.get("name") or "") if isinstance(it, dict) else ""
                tgt = layout.get(nm)
                if tgt in RULE_LAYERS and tgt != layer:
                    moved.setdefault(tgt, []).append(it)
                else:
                    keep.append(it)
            data[layer] = keep
        for tgt, lst in moved.items():
            data.setdefault(tgt, [])
            data[tgt].extend(lst)
    for c in _OVERRIDES.get("customs") or []:
        layer = str((c or {}).get("layer") or "") if isinstance(c, dict) else ""
        if layer not in RULE_LAYERS:
            continue
        it = _custom_to_item(c)
        if it:
            data.setdefault(layer, [])
            data[layer].append(it)
    return data


def load_rules(force: bool = False) -> dict:
    """读 rules.json。文件没变就直接返回缓存；改了立刻重解析（热更新，不用重启）。"""
    rules_path = config.RULES_PATH          # 调用期读取：selftest 可指向临时文件
    try:
        mt = os.stat(rules_path).st_mtime_ns
    except OSError:
        mt = None
    with _RULES_LOCK:
        cached = _RULES_CACHE["rules"]
        if not force and cached is not None and mt == _RULES_CACHE["mtime"]:
            return cached
        data = None
        try:
            data = json.loads(Path(rules_path).read_bytes().decode("utf-8"))
        except FileNotFoundError:
            print(f"  [规则] {rules_path} 不存在，使用内置兜底规则", flush=True)
        except Exception as e:                    # noqa: BLE001
            print(f"  [规则] {rules_path} 解析失败（{type(e).__name__}: {e}），"
                  f"使用内置兜底规则", flush=True)
        if not isinstance(data, dict) or not any(data.get(k) for k in RULE_LAYERS):
            data = copy.deepcopy(_FALLBACK_RULES)   # 不能直接改全局兜底表
        else:
            data = copy.deepcopy(data)
        data = _apply_overrides(data)               # 用户态叠加：改层 + 自定义规则
        _RULE_META.clear()           # 跟着重解析一起刷新，避免旧规则说明残留
        rules = {layer: _compile_layer(data.get(layer), layer) for layer in RULE_LAYERS}
        _RULES_CACHE["mtime"] = mt
        _RULES_CACHE["rules"] = rules
        return rules


def match_rule(cmd: str, scope: str = "", off: set[str] | None = None) -> tuple[str, str]:
    """按 blocked → dangerous → interactive 的顺序匹配，返回 (层级, 规则名)。

    没命中返回 ("", "")。all_of 规则要求列表里每一条都命中（AND），
    用来表达"rm 且带 -rf 且目标是根目录"这类多条件，避免写巨型正则。

    `scope` 是通道标识（`sql` / `shell` / `git`）。传空表示不按通道过滤，
    保留给自检与历史调用；生产通道必须传自己的 scope，否则 SQL 规则会误伤
    shell 命令（REQ-105 修的就是这个）。
    """
    if not cmd or not cmd.strip():
        return "", ""
    s = cmd.strip()
    want = (scope or "").strip().lower()
    skip = set(off or ())
    rules_dict = load_rules()
    for layer in RULE_LAYERS:
        for comp, name, scopes in rules_dict[layer]:
            # 只有绝对屏蔽层读 `rules_off`：关闭 = 不再拦。
            # dangerous 层**永远不因开关被跳过**——那一层的"关闭"只是免掉自审，
            # 审批照旧（见 needs_reflection）。若这里对 dangerous 也 skip，
            # 关掉自审就等于放行，属于最严重的安全回归。
            if layer == "blocked" and name in skip and not is_locked_rule(name):
                continue
            if want and scopes is not None and want not in scopes:
                continue
            if all(r.search(s) for r in comp):
                return layer, name
    return "", ""


def try_match(cmd: str, scope: str = "", draft: dict | None = None) -> dict:
    """试运行：用「当前覆盖层 + 一条草稿规则」跑一次匹配。

    独立编译，不碰 _RULES_CACHE / _RULE_META，不写库、不建待审批、不发推送。
    返回 {"layer","name","desc","custom"}；未命中返回 {}。
    """
    if not cmd or not cmd.strip():
        return {}
    s = cmd.strip()
    want = (scope or "").strip().lower()
    try:
        data = json.loads(Path(config.RULES_PATH).read_bytes().decode("utf-8"))
    except Exception:                              # noqa: BLE001
        data = None
    if not isinstance(data, dict) or not any(data.get(k) for k in RULE_LAYERS):
        data = copy.deepcopy(_FALLBACK_RULES)
    else:
        data = copy.deepcopy(data)
    data = _apply_overrides(data)
    if isinstance(draft, dict):
        _layer = str(draft.get("layer") or "")
        _it = _custom_to_item(draft)
        if _layer in RULE_LAYERS and _it:
            data.setdefault(_layer, [])
            data[_layer].append(_it)
    meta: dict = {}
    compiled = {layer: _compile_layer(data.get(layer), layer, meta=meta)
                for layer in RULE_LAYERS}
    for layer in RULE_LAYERS:
        for comp, name, scopes in compiled[layer]:
            if want and scopes is not None and want not in scopes:
                continue
            if all(r.search(s) for r in comp):
                m = meta.get(name) or {}
                return {"layer": layer, "name": name,
                        "desc": m.get("desc") or "",
                        "custom": bool(m.get("custom"))}
    return {}
