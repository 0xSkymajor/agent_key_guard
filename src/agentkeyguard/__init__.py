# -*- coding: utf-8 -*-
"""agentkeyguard —— 极简本地凭证代理（模块化包）。

一句话：远端 Agent 通过 HTTP 请求使用 PostgreSQL / SSH，
凭证明文只在守护进程内存里出现一次，永不回传、永不落盘、永不进 argv。

威胁模型（按用户确认的基线）：
  - 家庭内网，无公网映射，不做同机提权防护
  - 唯一要防的是：云端 LLM（Agent）看到明文密码
  - 因此：接口只返回结果，凭证不进任何响应体、日志、命令行参数
"""
from __future__ import annotations

VERSION = "v1.4.4-rc1"

__version__ = VERSION
