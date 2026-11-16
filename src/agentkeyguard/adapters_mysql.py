# -*- coding: utf-8 -*-
"""MySQL 适配器：与 pg 同构（REQ-148），只换驱动、默认端口与危险函数名单。

SQL 分级（classify_sql）与通用危险函数（is_dangerous）复用 pg_handler；
MySQL 另补三组特有旁路：LOAD_FILE / INTO OUTFILE|DUMPFILE / sys_exec 等。
库名同样从凭证降级为「默认库」，请求可带 database 切库（与 pg 一致的 REQ-147）。
"""
from __future__ import annotations

import re
import time

from . import adapters
from .pg_handler import _jb, classify_sql, is_dangerous
from .rules import match_rule, needs_reflection
from .storage import audit

# MySQL 特有的「读写服务器文件 / 执行系统命令」旁路，pg 的危险名单没有
_MYSQL_DANGER = re.compile(
    r"(?i)\b(load_file\s*\(|into\s+(outfile|dumpfile)|sys_exec\s*\(|"
    r"sys_eval\s*\(|master_pos_wait\s*\()"
)


def _mysql_dangerous(sql: str) -> bool:
    return bool(_MYSQL_DANGER.search(sql))


_MOCK_ROWS = [
    ["600519.SH", "贵州茅台", "2026-10-22", 1683.50],
    ["000858.SZ", "五粮液", "2026-10-22", 142.80],
    ["601318.SH", "中国平安", "2026-10-22", 52.40],
]


def _mock_mysql(sql: str, max_rows: int) -> dict:
    rows = [[i + 1, *r] for i, r in enumerate(_MOCK_ROWS)][:max_rows]
    return {
        "columns": ["id", "symbol", "name", "trade_date", "close"],
        "rows": rows,
        "row_count": len(rows),
        "truncated": False,
        "mock": True,
        "sql_echo": sql,
    }


def _mysql_query(prof: dict, sql: str, params=None, max_rows: int = 200,
                 database: str | None = None) -> dict:
    if prof.get("mock"):
        return _mock_mysql(sql, max_rows)
    import pymysql

    conn = pymysql.connect(
        host=prof["host"], port=int(prof.get("port") or 3306),
        user=prof["user"], password=prof.get("password") or "",
        database=(database or prof.get("default_database")
                  or prof.get("database") or ""),
        charset="utf8mb4", autocommit=False, connect_timeout=15)
    try:
        with conn.cursor() as cur:
            if prof.get("readonly"):
                # 只读保护：下一个事务 READ ONLY，写语句会被 MySQL 拒绝
                cur.execute("SET SESSION TRANSACTION READ ONLY")
            cur.execute(sql, params or ())
            cols = [d[0] for d in (cur.description or [])]
            raw = cur.fetchmany(max_rows + 1) if cur.description else []
            truncated = len(raw) > max_rows
            rows = [[_jb(c) for c in r] for r in raw[:max_rows]]
            rowcount = cur.rowcount
        if prof.get("readonly"):
            conn.rollback()
        else:
            conn.commit()
        return {
            "columns": cols,
            "rows": rows,
            "row_count": len(rows),
            "rowcount_affected": rowcount,
            "truncated": truncated,
        }
    finally:
        conn.close()


class MysqlAdapter:
    name = "mysql"
    executes = True

    # ---- profile ----
    def build_profile(self, req: dict) -> dict | None:
        try:
            _default = str(req.get("default_database") or req.get("database") or "")
            prof = {
                "type": "mysql",
                "host": str(req.get("host") or ""),
                "port": int(req.get("port") or 3306),
                "user": str(req.get("user") or ""),
                "password": str(req.get("password") or ""),
                "default_database": _default,
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

    # ---- 连通性测试 ----
    def test(self, profile: dict) -> None:
        try:
            import pymysql  # noqa: F401
        except ImportError as e:
            raise RuntimeError("缺少 pymysql，请先安装（pip install pymysql）") from e
        conn = pymysql.connect(
            host=profile["host"], port=int(profile.get("port") or 3306),
            user=profile["user"], password=profile.get("password") or "",
            database=(profile.get("default_database") or profile.get("database") or ""),
            connect_timeout=5)
        try:
            with conn.cursor() as cur:
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
        if not prof or prof.get("type") != "mysql":
            return srv._send(404, {"error": f"没有 mysql profile: {name}"})

        kind = classify_sql(sql)
        readonly = bool(prof.get("readonly"))
        _db = (req.get("database") or "").strip() or \
            prof.get("default_database") or prof.get("database") or ""
        target = (f"{prof.get('host')}:{prof.get('port', 3306)} "
                  f"db={_db} user={prof.get('user')}")

        if is_dangerous(sql) or _mysql_dangerous(sql):
            audit({"event": "deny", "kind": "mysql.query", "profile": name,
                   "reason": "dangerous_function", "sql": sql, "src": src})
            return srv._send(403, {
                "error": "该 SQL 调用了可以读写服务器文件或执行系统命令的函数，已拒绝",
                "reason": "dangerous_function",
            })

        _st = getattr(srv, "vault", {}).get("settings") or {}
        layer, label = match_rule(sql, "sql", off=set(_st.get("rules_off") or []))
        if layer == "blocked":
            audit({"event": "deny", "kind": "mysql.query", "profile": name,
                   "reason": "system_blocked", "rule": label, "sql": sql, "src": src})
            print(f"  [拦截] mysql:{name} 命中绝对禁区 [{label}]", flush=True)
            return srv._send(403, {"error": "系统拦截", "reason": label,
                                   "type": "system_blocked"})
        self_reflection = ""
        reflection_off = False
        if layer == "dangerous":
            reflection_off = not needs_reflection(
                label, set(_st.get("reflection_off") or []))
            self_reflection = str(req.get("self_reflection") or "").strip()[:1000]
            if not self_reflection and not reflection_off:
                audit({"event": "deny", "kind": "mysql.query", "profile": name,
                       "reason": "self_reflection_required", "rule": label,
                       "sql": sql, "src": src})
                return srv._send(428, {
                    "error": "高危操作需自我反思",
                    "instruction": "请先思考并回答：1. 我是谁？2. 我在哪儿？3. 我打算干什么？"
                                   "想清楚还要不要继续。如果确认继续，请在下次请求的 "
                                   "'self_reflection' 字段中带上你的思考结果。",
                    "rule": label,
                })

        if readonly and kind != "read":
            audit({"event": "deny", "kind": "mysql.query", "profile": name,
                   "reason": "readonly_profile", "classified": kind, "sql": sql, "src": src})
            return srv._send(403, {
                "error": "该 profile 为只读，只允许 SELECT / SHOW / EXPLAIN",
                "classified": kind,
            })

        from . import server as server_mod

        need = kind != "read" or bool(prof.get("approve", True))
        res: dict = {}
        if need and not server_mod.ask_approval(
                "mysql.query", name, target, f"SQL[{kind}]:\n{sql[:1500]}", src,
                title=(req.get("title") or ""),
                dangerous=(layer == "dangerous"),
                self_reflection=self_reflection,
                reflection_off=reflection_off, out=res):
            audit({"event": "denied", "kind": "mysql.query", "profile": name,
                   "sql": sql, "src": src, "reason": res.get("reason", "")})
            return srv._send(403, {"error": "用户拒绝",
                                   "reason": res.get("reason") or "",
                                   "type": "user_denied"})

        if res.get("duplicate"):
            return srv._send(200, {"ok": True, "duplicate": True,
                                   "note": "同一操作已由前一条相同请求处理，本次未重复执行"})

        t0 = time.time()
        try:
            out = _mysql_query(prof, sql,
                               req.get("params"),
                               int(req.get("max_rows") or 200),
                               database=(req.get("database") or "").strip() or None)
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "kind": "mysql.query", "profile": name,
                   "error": f"{type(e).__name__}: {e}", "src": src})
            return srv._send(502, {"error": f"数据库错误: {type(e).__name__}: {e}"})

        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        audit({"event": "ok", "kind": "mysql.query", "profile": name, "classified": kind,
               "sql": sql[:2000], "src": src, "rows": out.get("row_count"),
               "ms": out["elapsed_ms"]})
        return srv._send(200, out)

    # ---- 列库 ----
    def list_databases(self, profile: dict) -> list[str]:
        import pymysql

        conn = pymysql.connect(
            host=profile["host"], port=int(profile.get("port") or 3306),
            user=profile["user"], password=profile.get("password") or "",
            connect_timeout=8)
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW DATABASES")
                return [str(r[0]) for r in cur.fetchall()]
        finally:
            conn.close()


adapters.register(MysqlAdapter())
