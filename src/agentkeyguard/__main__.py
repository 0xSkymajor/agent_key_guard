# -*- coding: utf-8 -*-
"""``python -m agentkeyguard`` 入口，转发到 cli.main。

拆包阶段先占位；cli 模块在后续阶段落地后，此转发即生效。
"""
from __future__ import annotations

from agentkeyguard.cli import main

if __name__ == "__main__":
    main()
