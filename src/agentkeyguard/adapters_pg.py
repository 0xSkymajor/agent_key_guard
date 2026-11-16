# -*- coding: utf-8 -*-
"""PostgreSQL 适配器：profile 构造、连通性测试、SQL 执行（REQ-106 从 server.py 搬出）。

行为与 v1.1.2 完全一致，唯一变化是入口从 `Broker._handle_pg` 变成 `PgAdapter.execute`。
注意：分级拦截（`match_rule`）必须排在只读检查之前，自检对此有源码顺序断言。
"""
from __future__ import annotations

import time

from . import adapters
from .pg_handler import classify_sql, is_dangerous, pg_query
from .rules import match_rule, needs_reflection
from .storage import audit


class PgAdapter:
    name = "pg"
    executes = True

    # ---- profile ----
    def build_profile(self, req: dict) -> dict | None:
        try:
            # 库名从「唯一库」降级为「默认库（可空）」（REQ-147）：请求可带 database 切库，
            # 权限边界交给 DB 账号，网关不再把凭证锁死在一个库上。
            # 兼容旧前端：老表单提交 database，新表单提交 default_database，两者等价。
            _default = str(req.get("default_database") or req.get("database") or "")
            prof = {
                "type": "pg",
                "host": str(req.get("host") or ""),
                "port": int(req.get("port") or 5432),
                "user": str(req.get("user") or ""),
                "password": str(req.get("password") or ""),
                "default_database": _default,
                # 保留旧字段一份：回滚到 1.2.x 时仍读得到，不丢数据
                "database": _default,
                "readonly": bool(req.get("readonly", True)),
                "sslmode": str(req.get("sslmode") or "disable"),
                "approve": bool(req.get("approve", True)),
                "mock": bool(req.get("mock", False)),
            }
        except Exception:  # noqa: BLE001
            return None
        if not prof.get("host") or not prof.get("user"):
            return None
        return prof

    # ---- 连通性测试（由 server 计时与记账） ----
    def test(self, profile: dict) -> None:
        import ssl as _ssl

        import pg8000.dbapi

        kw = dict(host=profile["host"], port=int(profile.get("port") or 5432),
                  user=profile["user"], password=profile.get("password") or "",
                  database=(profile.get("default_database")
                            or profile.get("database") or ""), timeout=5)
        if profile.get("sslmode") and profile["sslmode"] != "disable":
            kw["ssl_context"] = _ssl._create_unverified_context()
        conn = pg8000.dbapi.connect(**kw)
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
        finally:
            conn.close()

    # ---- 执行 ----
    def execute(self, srv, req: dict, src: str) -> None:
        name = (req.get("profile") or "").strip()
        sql = (req.get("sql") or "").strip()
        if not name or not sql:
            return srv._send(400, {"error": "需要 profile 与 sql"})

        prof = srv.vault.get("profiles", {}).get(name)
        if not prof or prof.get("type") != "pg":
            return srv._send(404, {"error": f"没有 pg profile: {name}"})

        kind = classify_sql(sql)
        readonly = bool(prof.get("readonly"))
        # 库名由请求带（REQ-147）：不传则回退凭证默认库，再回退到 pg 的「用户名同名库」
        _db = (req.get("database") or "").strip() or \
            prof.get("default_database") or prof.get("database") or prof.get("user")
        target = (f"{prof.get('host')}:{prof.get('port', 5432)} "
                  f"db={_db} user={prof.get('user')}")

        if is_dangerous(sql):
            audit({"event": "deny", "kind": "pg.query", "profile": name,
                   "reason": "dangerous_function", "sql": sql, "src": src})
            return srv._send(403, {
                "error": "该 SQL 调用了可以读写服务器文件或执行系统命令的函数，已拒绝",
                "reason": "dangerous_function",
            })

        # 分级拦截：DROP DATABASE / TRUNCATE 这类不可逆操作直接挡死，不弹审批。
        # 必须排在只读检查**之前**：否则只读 profile 上会先报 readonly_profile，
        # 把"策略级禁区"降格成"这个 profile 权限不足"，信息量反而变弱。
        _st = getattr(srv, "vault", {}).get("settings") or {}
        layer, label = match_rule(sql, "sql", off=set(_st.get("rules_off") or []))
        if layer == "blocked":
            audit({"event": "deny", "kind": "pg.query", "profile": name,
                   "reason": "system_blocked", "rule": label, "sql": sql, "src": src})
            print(f"  [拦截] pg:{name} 命中绝对禁区 [{label}]", flush=True)
            return srv._send(403, {"error": "系统拦截", "reason": label,
                                   "type": "system_blocked"})
        self_reflection = ""
        reflection_off = False
        if layer == "dangerous":
            reflection_off = not needs_reflection(
                label, set(_st.get("reflection_off") or []))
            self_reflection = str(req.get("self_reflection") or "").strip()[:1000]
            if not self_reflection and not reflection_off:
                audit({"event": "deny", "kind": "pg.query", "profile": name,
                       "reason": "self_reflection_required", "rule": label,
                       "sql": sql, "src": src})
                print(f"  [拦截] pg:{name} 高危操作 [{label}] 缺 self_reflection，回 428",
                      flush=True)
                return srv._send(428, {
                    "error": "高危操作需自我反思",
                    "instruction": "请先思考并回答：1. 我是谁？2. 我在哪儿？3. 我打算干什么？"
                                   "想清楚还要不要继续。如果确认继续，请在下次请求的 "
                                   "'self_reflection' 字段中带上你的思考结果。",
                    "rule": label,
                })

        if readonly and kind != "read":
            audit({"event": "deny", "kind": "pg.query", "profile": name,
                   "reason": "readonly_profile", "classified": kind, "sql": sql, "src": src})
            return srv._send(403, {
                "error": "该 profile 为只读，只允许 SELECT / SHOW / EXPLAIN",
                "classified": kind,
            })

        # 延迟导入：让自检可以照旧 patch server.ask_approval，也避免循环导入
        from . import server as server_mod

        need = kind != "read" or bool(prof.get("approve", True))
        res: dict = {}
        if need and not server_mod.ask_approval(
                "pg.query", name, target, f"SQL[{kind}]:\n{sql[:1500]}", src,
                title=(req.get("title") or ""),
                dangerous=(layer == "dangerous"),
                self_reflection=self_reflection,
                reflection_off=reflection_off, out=res):
            audit({"event": "denied", "kind": "pg.query", "profile": name,
                   "sql": sql, "src": src, "reason": res.get("reason", "")})
            return srv._send(403, {"error": "用户拒绝",
                                   "reason": res.get("reason") or "",
                                   "type": "user_denied"})

        if res.get("duplicate"):
            return srv._send(200, {"ok": True, "duplicate": True,
                                   "note": "同一操作已由前一条相同请求处理，本次未重复执行"})

        t0 = time.time()
        try:
            out = pg_query(prof, sql,
                           req.get("params"),
                           int(req.get("max_rows") or 200),
                           database=(req.get("database") or "").strip() or None)
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "kind": "pg.query", "profile": name,
                   "error": f"{type(e).__name__}: {e}", "src": src})
            return srv._send(502, {"error": f"数据库错误: {type(e).__name__}: {e}"})

        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        audit({"event": "ok", "kind": "pg.query", "profile": name, "classified": kind,
               "sql": sql[:2000], "src": src, "rows": out.get("row_count"),
               "ms": out["elapsed_ms"]})
        return srv._send(200, out)

    # ---- 列库（供 Agent 切换数据库前查看有哪些可连） ----
    def list_databases(self, profile: dict) -> list[str]:
        """列出该账号可见的库（不含模板库）。连 `postgres` 库读 pg_database。"""
        import ssl as _ssl

        from pg8000 import dbapi

        kw = dict(host=profile["host"], port=int(profile.get("port") or 5432),
                  user=profile["user"], password=profile.get("password") or "",
                  database="postgres", timeout=8)
        if profile.get("sslmode") and profile["sslmode"] != "disable":
            kw["ssl_context"] = _ssl._create_unverified_context()
        conn = dbapi.connect(**kw)
        try:
            cur = conn.cursor()
            cur.execute("SELECT datname FROM pg_database "
                        "WHERE datistemplate = false ORDER BY datname")
            return [str(r[0]) for r in cur.fetchall()]
        finally:
            conn.close()


adapters.register(PgAdapter())
