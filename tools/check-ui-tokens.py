#!/usr/bin/env python3
"""检查 4 处内联模板的 design token 是否漂移。

AgentKeyGuard 没有前端构建链，login/dashboard/setup/approve 各自带一份 CSS。
本脚本只做一件便宜的事：确认每份模板都定义了同一组核心变量，避免某次改版
只改了一处、其它页面颜色悄悄退回默认值。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "login": ROOT / "src/agentkeyguard/templates/login.html",
    "dashboard": ROOT / "src/agentkeyguard/templates/dashboard.html",
    "setup": ROOT / "src/agentkeyguard/setup_ui.py",
    "approve": ROOT / "src/agentkeyguard/dashboard.py",
}
REQUIRED = ("--text", "--line", "--ok", "--warn", "--danger", "--mono")


def main() -> int:
    bad = 0
    for name, path in SOURCES.items():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[{name}] 读不到 {path}: {exc}")
            bad += 1
            continue
        missing = [tok for tok in REQUIRED if tok not in text]
        if missing:
            print(f"[{name}] 缺 token: {', '.join(missing)}")
            bad += 1
        else:
            print(f"[{name}] OK")
    if bad:
        print(f"\n{bad} 处模板 token 不一致")
        return 1
    print("\n全部一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
