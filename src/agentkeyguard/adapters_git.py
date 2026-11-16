# -*- coding: utf-8 -*-
"""Git 适配器：声明 git 类型凭证，并把执行委托给 `git_handler`（REQ-107）。

profile 字段：base（站点地址）/ user / token —— 就这三条
- 仓库名不进服务端：它经常变（改名、开新库），由 `/git/exec` 的 `url`
  参数带上，服务端只校验「与 base 同源」然后注入凭据；
- 旧库里的 `repo` / `owner` / `default_branch` 仍可读（兜底），但不再写入；
- `test()` 用 `git ls-remote` 验证站点与凭据，不需要登录审批；
- `execute()` 延迟导入 `git_handler`，执行真正的 git 子命令。
"""
from __future__ import annotations

import subprocess

from . import adapters


class GitAdapter:
    name = "git"
    executes = True

    def build_profile(self, req: dict) -> dict | None:
        try:
            prof = {
                "type": "git",
                "base": str(req.get("base") or "").strip().rstrip("/"),
                "user": str(req.get("user") or "").strip(),
                "token": str(req.get("token") or "").strip(),
            }
        except Exception:  # noqa: BLE001
            return None
        if not prof["base"]:
            return None
        if not prof["base"].startswith(("http://", "https://")):
            prof["base"] = "https://" + prof["base"]
        return prof

    def test(self, profile: dict) -> None:
        """`git ls-remote` 探活：只读、不需要审批、不产生副作用。

        凭据注入复用 git_handler 的 askpass 方案，避免两处实现漂移。
        """
        from . import git_handler

        # 有 url 就测那个仓库；没有则回退旧库的 repo 字段，
        # 两者都缺时 resolve_url 会明确报「需要 url」，不会静默失败
        url = git_handler.resolve_url(profile, profile.get("url") or "")
        out = subprocess.run(["git", "ls-remote", "--heads", url],
                             capture_output=True, text=True, timeout=15,
                             env=git_handler._env(profile), shell=False)
        if out.returncode != 0:
            raise RuntimeError(git_handler._scrub(out.stderr or "ls-remote 失败", profile))

    def execute(self, srv, req: dict, src: str) -> None:
        from . import git_handler          # 延迟导入，避免与 git_handler 互相依赖

        return git_handler.handle(srv, req, src)



adapters.register(GitAdapter())
