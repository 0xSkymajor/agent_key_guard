# -*- coding: utf-8 -*-
"""凭证适配器注册表（REQ-106）。

目标：新增一种凭证类型 = 新增一个模块 + 在 `load_builtin()` 里加一行导入，
`server.py` 里不再出现任何 `type == "xxx"` 的判断分支。

每个适配器实现四件事：

- `build_profile(req)`：从面板提交的原始 dict 构造并校验 profile，非法返回 None；
- `test(profile)`：连通性探测，失败抛异常（HTTP 响应与计时由 server 负责）；
- `execute(srv, req, src)`：真正执行，结果通过 `srv._send()` 回包；
- `executes`：是否具备执行通道（三种内置类型都有：postgres 查询、ssh 命令、git 操作）。

约定：适配器内部需要用到 server 模块的函数（`ask_approval` 等）时，**在函数体内延迟导入**
`from . import server` 再取属性。这样做有两个原因：避免 server ↔ adapter 循环导入；
让自检可以照旧 monkeypatch `server.ask_approval` / `server.ssh_exec` 这两个替换点。
"""
from __future__ import annotations

from typing import Protocol


class Adapter(Protocol):
    name: str
    executes: bool

    def build_profile(self, req: dict) -> dict | None: ...
    def test(self, profile: dict) -> None: ...
    def execute(self, srv, req: dict, src: str) -> None: ...


_REGISTRY: dict[str, Adapter] = {}


def register(adapter: Adapter) -> Adapter:
    """注册一个适配器；同名后注册者覆盖先注册者（便于测试替换）。"""
    _REGISTRY[str(adapter.name)] = adapter
    return adapter


def get(name: str) -> Adapter | None:
    return _REGISTRY.get(str(name or ""))


def names() -> list[str]:
    return sorted(_REGISTRY)


def executing_names() -> list[str]:
    return sorted(n for n, a in _REGISTRY.items() if a.executes)


_LOADED = False


def load_builtin() -> None:
    """导入内置适配器以触发注册。重复调用安全。"""
    global _LOADED
    if _LOADED:
        return
    from . import (adapters_git, adapters_mysql, adapters_pg,  # noqa: F401
                   adapters_redis, adapters_ssh)
    _LOADED = True
