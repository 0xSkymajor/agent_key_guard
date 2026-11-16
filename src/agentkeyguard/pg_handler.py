# -*- coding: utf-8 -*-
"""PostgreSQL：SQL 分类、危险函数检测与查询执行。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。
"""
from __future__ import annotations

import datetime
import decimal
import re

# ────────────────────────────── SQL 分类 ──────────────────────────────

_STRIP = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)
_WRITE_HINT = re.compile(
    r"(?i)\b(insert|update|delete|merge|drop|alter|create|truncate|grant|revoke|"
    r"copy|vacuum|reindex|refresh|cluster|comment|call|do|listen|notify)\b"
)
_READ_HEAD = re.compile(r"(?i)^\s*(select|with|show|explain|values|table)\b")

# 无论什么 profile、无论用户是否点了同意，一律拒绝。
# 这些函数能读服务器文件、执行系统命令、跨库连接，是"只读"最大的旁路。
_DANGER = re.compile(
    r"(?i)\b("
    r"pg_read_file|pg_read_binary_file|pg_write_file|pg_write_binary_file|"
    r"pg_ls_dir|pg_ls_logdir|pg_ls_waldir|pg_ls_tmpdir|pg_stat_file|"
    r"lo_import|lo_export|lo_create|"
    r"dblink|dblink_exec|"
    r"pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|"
    r"pg_log_backend_memory_contexts|"
    r"create\s+extension|alter\s+system|"
    r"copy\s+[^;]*\s+(from|to)\s+program"
    r")\b"
)


def is_dangerous(sql: str) -> bool:
    return bool(_DANGER.search(_STRIP.sub(" ", sql)))


def classify_sql(sql: str) -> str:
    """read / write / multi / unknown。宁可误判为 write，也不放过。"""
    s = _STRIP.sub(" ", sql).strip()
    if not s:
        return "unknown"
    body = s.rstrip(";").strip()
    if ";" in body:
        return "multi"
    if _WRITE_HINT.search(body):
        return "write"
    if _READ_HEAD.match(body):
        return "read"
    return "unknown"


# ────────────────────────────── 结果序列化 ──────────────────────────────

def _jb(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, (datetime.date, datetime.datetime, datetime.time)):
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        return str(v)
    return str(v)


# ────────────────────────────── PostgreSQL ──────────────────────────────

def _mock_pg(prof: dict, sql: str, max_rows: int) -> dict:
    base = [
        ["600519.SH", "贵州茅台", "2026-10-22", 1683.50, 1283012],
        ["000858.SZ", "五粮液", "2026-10-22", 142.80, 933210],
        ["601318.SH", "中国平安", "2026-10-22", 52.40, 2044188],
        ["300750.SZ", "宁德时代", "2026-10-22", 251.30, 771044],
    ]
    rows = [[i + 1, *r] for i, r in enumerate(base)][:max_rows]
    return {
        "columns": ["id", "symbol", "name", "trade_date", "close", "vol"],
        "rows": rows,
        "row_count": len(rows),
        "truncated": False,
        "mock": True,
        "sql_echo": sql,
    }


def pg_query(prof: dict, sql: str, params=None, max_rows: int = 200,
             database: str | None = None) -> dict:
    if prof.get("mock"):
        return _mock_pg(prof, sql, max_rows)

    from pg8000 import dbapi

    ssl_ctx = None
    sslmode = str(prof.get("sslmode", "disable")).lower()
    if sslmode in ("require", "verify-ca", "verify-full"):
        import ssl
        ssl_ctx = ssl.create_default_context()
        if sslmode != "verify-full":
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    conn = dbapi.connect(
        host=prof["host"],
        port=int(prof.get("port", 5432)),
        user=prof["user"],
        password=prof.get("password", ""),
        database=(database or prof.get("default_database")
                  or prof.get("database") or prof["user"]),
        timeout=15,
        ssl_context=ssl_ctx,
    )
    cur = conn.cursor()
    try:
        if prof.get("readonly"):
            # 只读保护：设会话默认事务为只读，然后**当场自证**是否生效。
            # pg8000 没有 autocommit 属性，BEGIN READ ONLY 会被它自己的隐式事务吃掉，
            # 所以走 SET SESSION 这条路，并读回 transaction_read_only 校验；不生效就 fail-closed。
            conn.rollback()
            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            conn.commit()
            cur.execute("SHOW transaction_read_only")
            ro = str((cur.fetchone() or [""])[0]).lower()
            conn.commit()
            if ro != "on":
                raise RuntimeError(
                    f"只读会话未生效（transaction_read_only={ro!r}），已拒绝执行")

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
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
