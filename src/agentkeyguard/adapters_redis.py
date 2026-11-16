# -*- coding: utf-8 -*-
"""Redis 适配器：命令三层白名单（REQ-148）。

- 只读命令：免审批直接执行（GET / MGET / TTL / TYPE / EXISTS / SCAN / INFO ...）
- 写命令：走审批（SET / DEL / EXPIRE / HSET / LPUSH / SADD）
- 禁区：直接 403（FLUSHALL / FLUSHDB / CONFIG / SHUTDOWN / DEBUG / EVAL / KEYS ...）

判断不了的操作不给审批选项——全量 KEYS *、清库、改配置、执行 Lua 脚本，
对小白来说等于「点一下同意就把缓存炸了」，必须硬挡。
"""
from __future__ import annotations

import time

from . import adapters
from .storage import audit

# 读命令：不弹审批
READONLY = {
    "get", "mget", "ttl", "pttl", "type", "exists", "strlen",
    "scan", "info", "dbsize", "hget", "hgetall", "hmget",
    "lrange", "llen", "smembers", "scard", "zrange", "zcard", "zscore",
}
# 写命令：走审批
WRITE = {"set", "del", "expire", "pexpire", "hset", "hdel",
         "lpush", "rpush", "sadd", "srem", "zadd", "zrem"}
# 禁区：直接拒绝
FORBIDDEN = {
    "flushall", "flushdb", "config", "shutdown", "debug", "eval", "evalsha",
    "script", "migrate", "slaveof", "replicaof", "keys", "save", "bgsave",
    "bgrewriteaof", "acl", "cluster", "restore", "monitor", "sync", "psync",
}

# redis-py 的 DEL 方法名是 delete（del 是 Python 关键字）
_METHOD = {"del": "delete"}

# 单条命令最大返回条数：防止 LRANGE 0 -1 / SMEMBERS 这类把整个 key 拖回来
_MAX_ITEMS = 500


def _ser(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    if isinstance(v, (list, tuple)):
        return [_ser(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _ser(x) for k, x in v.items()}
    return str(v)


def _scan_args(args: list[str]):
    """从 SCAN 的位置参数里抠出 cursor / MATCH / COUNT。"""
    cursor = 0
    match = None
    count = None
    if args:
        try:
            cursor = int(args[0])
        except ValueError:
            cursor = 0
    i = 1
    while i < len(args):
        a = args[i].lower()
        if a == "match" and i + 1 < len(args):
            match = args[i + 1]
            i += 2
        elif a == "count" and i + 1 < len(args):
            try:
                count = int(args[i + 1])
            except ValueError:
                count = None
            i += 2
        else:
            i += 1
    return cursor, match, count


class RedisAdapter:
    name = "redis"
    executes = True

    # ---- profile ----
    def build_profile(self, req: dict) -> dict | None:
        try:
            prof = {
                "type": "redis",
                "host": str(req.get("host") or ""),
                "port": int(req.get("port") or 6379),
                "password": str(req.get("password") or ""),
                "db": int(req.get("db") or 0),
                "readonly": bool(req.get("readonly", True)),
            }
        except Exception:  # noqa: BLE001
            return None
        if not prof.get("host"):
            return None
        return prof

    # ---- 连通性测试 ----
    def test(self, profile: dict) -> None:
        try:
            import redis  # noqa: F401
        except ImportError as e:
            raise RuntimeError("缺少 redis，请先安装（pip install redis）") from e
        r = redis.Redis(
            host=profile["host"], port=int(profile.get("port") or 6379),
            password=profile.get("password") or None,
            db=int(profile.get("db") or 0), socket_timeout=5)
        if not r.ping():
            raise RuntimeError("PING 无响应")

    # ---- 执行 ----
    def execute(self, srv, req: dict, src: str) -> None:
        name = (req.get("profile") or "").strip()
        raw = (req.get("cmd") or "").strip()
        if not name or not raw:
            return srv._send(400, {"error": "需要 profile 与 cmd"})

        prof = srv.vault.get("profiles", {}).get(name)
        if not prof or prof.get("type") != "redis":
            return srv._send(404, {"error": f"没有 redis profile: {name}"})

        parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in FORBIDDEN:
            audit({"event": "deny", "kind": "redis.cmd", "profile": name,
                   "reason": "system_blocked", "cmd": raw[:500], "src": src})
            print(f"  [拦截] redis:{name} 命中禁区 [{cmd}]", flush=True)
            return srv._send(403, {"error": "该命令已被拒绝（清库/改配置/执行脚本一律禁止）",
                                   "reason": cmd, "type": "system_blocked"})

        if cmd not in READONLY and cmd not in WRITE:
            return srv._send(400, {"error": f"不支持的 Redis 命令：{cmd}"})

        # SCAN 强制 MATCH + COUNT：没有就是全量扫描的前奏，拒绝
        if cmd == "scan":
            _, _match, _count = _scan_args(args)
            if _match is None or _count is None:
                return srv._send(403, {
                    "error": "SCAN 必须带 MATCH 与 COUNT，例如 SCAN 0 MATCH user:* COUNT 100",
                    "reason": "scan_requires_match_count",
                })

        # 只读凭证不允许写命令
        if prof.get("readonly") and cmd in WRITE:
            audit({"event": "deny", "kind": "redis.cmd", "profile": name,
                   "reason": "readonly_profile", "cmd": raw[:500], "src": src})
            return srv._send(403, {"error": "该 profile 为只读，不允许写命令",
                                   "reason": "readonly_profile"})

        target = (f"{prof.get('host')}:{prof.get('port', 6379)} "
                  f"db={prof.get('db', 0)}")

        # 只读命令免审批；写命令走审批
        from . import server as server_mod

        res: dict = {}
        if cmd in WRITE and not server_mod.ask_approval(
                "redis.cmd", name, target, raw[:1500], src,
                title=(req.get("title") or ""), out=res):
            audit({"event": "denied", "kind": "redis.cmd", "profile": name,
                   "cmd": raw[:500], "src": src, "reason": res.get("reason", "")})
            return srv._send(403, {"error": "用户拒绝",
                                   "reason": res.get("reason") or "",
                                   "type": "user_denied"})

        if res.get("duplicate"):
            return srv._send(200, {"ok": True, "duplicate": True,
                                   "note": "同一操作已由前一条相同请求处理，本次未重复执行"})

        t0 = time.time()
        try:
            import redis
            r = redis.Redis(
                host=prof["host"], port=int(prof.get("port") or 6379),
                password=prof.get("password") or None,
                db=int(prof.get("db") or 0), socket_timeout=10)
            result = self._run(r, cmd, args)
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "kind": "redis.cmd", "profile": name,
                   "error": f"{type(e).__name__}: {e}", "src": src})
            return srv._send(502, {"error": f"Redis 错误: {type(e).__name__}: {e}"})

        truncated = False
        if isinstance(result, list) and len(result) > _MAX_ITEMS:
            result = result[:_MAX_ITEMS]
            truncated = True

        out = {"ok": True, "cmd": cmd, "result": _ser(result),
               "truncated": truncated,
               "elapsed_ms": int((time.time() - t0) * 1000)}
        audit({"event": "ok", "kind": "redis.cmd", "profile": name,
               "cmd": raw[:500], "src": src, "ms": out["elapsed_ms"]})
        return srv._send(200, out)

    # ---- 命令分发 ----
    def _run(self, r, cmd: str, args: list[str]):
        if cmd == "scan":
            cursor, match, count = _scan_args(args)
            cur, keys = r.scan(cursor=cursor, match=match, count=count)
            return {"cursor": cur, "keys": [_ser(k) for k in keys]}
        method = _METHOD.get(cmd, cmd)
        fn = getattr(r, method, None)
        if fn is None:
            raise RuntimeError(f"不支持的 Redis 命令：{cmd}")
        return fn(*args)


adapters.register(RedisAdapter())
