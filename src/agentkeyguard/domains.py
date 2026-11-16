# -*- coding: utf-8 -*-
"""本机域名：主机名 → <slug>.akg.arpa，可编辑、可校验。

用途只剩一个：给服务器证书提供 SAN 与给 AdGuard 提供重写目标。
（生物识别已移除，域名不再与 WebAuthn 的 RP ID 绑定。）
"""
from __future__ import annotations

import re
import socket

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", (name or "").strip().lower())
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return (s[:32].strip("-") or "owner")


def default_domain(name: str) -> str:
    return f"{slug(name)}.akg.arpa"


def host_domain() -> str:
    """宿主机名首段 + .akg.arpa；空/localhost 回退 agentkeyguard。"""
    first = (socket.gethostname() or "").split(".")[0]
    s = slug(first)
    if not s or s == "localhost":
        s = "agentkeyguard"
    return f"{s}.akg.arpa"


def validate_domain(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    if not d or len(d) > 253:
        raise ValueError("bad_domain")
    labels = d.split(".")
    if len(labels) < 2:
        raise ValueError("bad_domain")
    for label in labels:
        if not _LABEL.match(label):
            raise ValueError("bad_domain")
    return d


def origin(domain: str, port: int) -> str:
    return f"https://{validate_domain(domain)}:{int(port)}"
