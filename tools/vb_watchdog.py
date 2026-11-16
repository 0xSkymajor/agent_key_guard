#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vb_watchdog.py —— AgentKeyGuard 存活监控

**跑在一台独立的机器上**（不要跑在 AgentKeyGuard 所在的 host-4 自己身上：
机器死机了就全完了，监控也跟着死）。设计目标是：机器挂了 → 你手机照样收到 Bark。

每次执行做一次探测，由 cron 每分钟唤醒一次（不要在脚本里自己 while sleep，
cron 更抗造：脚本崩了下一分钟自然重启，状态也不丢）。

  公网址（经 1Panel 反代 + TLS）── 通 → 一切正常
  公网址不通 + 直连通          → 反代挂了（TLS/DNS/Nginx）
  公网址不通 + 直连也不通      → AgentKeyGuard 本身挂了

防抖：连续失败 N 次（默认 3，即 3 分钟）才报警，避免网络波动误报。
恢复：重新可达后发一条恢复通知（只发一次，不会每分钟刷）。

配置（环境变量，都有默认值）：
  VB_WD_URL      公网探测地址      https://vault.home.arpa/health
  VB_WD_DIRECT   直连探测地址      http://192.0.2.4:7700/health（留空则不诊断分流）
  VB_WD_BARK     Bark 地址        https://api.day.app/<你的key>（留空则只打日志不推送）
  VB_WD_FAILS    连续失败几次报警  3
  VB_WD_STATE    状态文件          /var/tmp/vb_watchdog.state.json
  VB_WD_RESOLVE  强制解析         vault.home.arpa:443:192.0.2.4（DNS 抽风时用）
  VB_WD_TIMEOUT  单次探测超时秒   5
  VB_WD_LOG      日志文件          /var/tmp/vb_watchdog.log（留空则不写日志）

用法：
  ./vb_watchdog.py                    # 用默认值/环境变量
  ./vb_watchdog.py --once              # 等价于上面
  ./vb_watchdog.py --test-notify       # 只发一条测试推送，不探测
  crontab -e  →  * * * * * /path/vb_watchdog.py
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.erro
import urllib.request
from pathlib import Path
from urllib.parse import quote

# ── 配置 ─────────────────────────────────────────────
URL = os.environ.get("VB_WD_URL", "https://vault.home.arpa/health")
DIRECT = os.environ.get("VB_WD_DIRECT", "http://192.0.2.4:7700/health")
BARK = os.environ.get("VB_WD_BARK", "").rstrip("/")
FAILS = int(os.environ.get("VB_WD_FAILS", "3") or 3)
STATE = Path(os.environ.get("VB_WD_STATE", "/var/tmp/vb_watchdog.state.json"))
RESOLVE = os.environ.get("VB_WD_RESOLVE", "")     # host:port:ip
TIMEOUT = float(os.environ.get("VB_WD_TIMEOUT", "5") or 5)
LOG = os.environ.get("VB_WD_LOG", "/var/tmp/vb_watchdog.log")

# 自签证书（mkcert）：内网监控，-k 是正确取舍。没有中间人场景，
# 保密性由"只探 /health、不带任何凭证"来保证。
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# 显式绕过代理：urllib 默认会读 http_proxy/https_proxy 环境变量。
# 内网监控要是被塞进一个代理，所有探测都会 502/超时 → 全程误报掉线。
# （实测踩过：本机有 http_proxy 时 host-4 的 /health 返回 502。）
# 自签证书的 context 必须焊进 HTTPSHandler —— OpenerDirector.open()
# 不接受 context 关键字，只有 urlopen() 接受（实测 TypeError）。
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=CTX),
)


def log(msg: str, echo: bool = True) -> None:
    """写日志。echo=False 时只进文件不进 stdout —— 健康心跳用它，
    这样 cron 只在"出事/恢复"时才产生输出（才不会每分钟发一封邮件）。"""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    if echo:
        print(line, flush=True)
    if LOG:
        try:
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass          # 日志写不进去不影响监控本身


def probe(url: str) -> tuple[bool, str]:
    """返回 (是否可达, 诊断信息)。任何异常都算不可达，绝不往外抛。"""
    req = urllib.request.Request(url, headers={"User-Agent": "vb-watchdog/1.0"})
    try:
        with OPENER.open(req, timeout=TIMEOUT) as r:
            body = r.read(400).decode("utf-8", "replace")
            ok = r.status == 200
            return ok, f"HTTP {r.status} {body[:120]}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:                        # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def notify(title: str) -> bool:
    """推一条 Bark。失败只记日志，绝不影响探测逻辑。"""
    if not BARK:
        log(f"[通知] 未配置 VB_WD_BARK，跳过推送：{title}")
        return False
    url = f"{BARK}/{quote(title, safe='')}?group=agentkeyguard&level=timeSensitive"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vb-watchdog/1.0"})
        with OPENER.open(req, timeout=10) as r:
            raw = r.read(200).decode("utf-8", "replace")
        if '"code":200' in raw.replace(" ", ""):
            log(f"[通知] 已推送：{title}")
            return True
        log(f"[通知] Bark 返回异常：{raw[:120]}")
    except Exception as e:                        # noqa: BLE001
        log(f"[通知] Bark 推送失败：{type(e).__name__}: {e}")
    return False


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"fails": 0, "down": False}


def save_state(st: dict) -> None:
    try:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        log(f"[状态] 写不了 {STATE}：{e}（防抖计数会在重启后归零，最多多报一次）")


def check_once() -> int:
    st = load_state()
    fails, down = int(st.get("fails", 0)), bool(st.get("down", False))

    pub_ok, pub_why = probe(URL)
    if pub_ok:
        log(f"[正常] {URL} {pub_why}", echo=False)      # 心跳：只进日志文件
        if down:
            notify("✅ AgentKeyGuard 已恢复")
            log(f"[恢复] {URL} 可达（{pub_why}）")
        elif fails:
            log(f"[恢复] 连续失败 {fails} 次后又可达，未达报警线，不通知")
        save_state({"fails": 0, "down": False})
        return 0

    # ── 公网址不通：先诊断是反代还是 Broker 本身 ──
    fails += 1
    diag = ""
    if DIRECT:
        dir_ok, dir_why = probe(DIRECT)
        if dir_ok:
            diag = (f"；直连 {DIRECT} 正常（{dir_why}）→ "
                    f"**是 1Panel 反代/TLS/DNS 挂了，Broker 本身活着**")
        else:
            diag = f"；直连 {DIRECT} 也不通（{dir_why}）→ **Broker 本身或 host-4 挂了**"
    log(f"[失败] 第 {fails}/{FAILS} 次：{URL} {pub_why}{diag}")

    if fails >= FAILS and not down:
        notify(f"🚨 AgentKeyGuard 已掉线，请检查 host-4 或 1Panel 反代！"
               f"（连续 {FAILS} 次不可达：{pub_why}{diag}）")
        down = True
    save_state({"fails": fails, "down": down})
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentKeyGuard 存活监控（单次探测）")
    ap.add_argument("--once", action="store_true", help="探测一次（默认行为）")
    ap.add_argument("--test-notify", action="store_true", help="只发一条测试推送")
    ap.add_argument("--status", action="store_true", help="显示当前状态后退出")
    a = ap.parse_args()

    if a.test_notify:
        notify("🔔 AgentKeyGuard 监控测试推送（配置成功）")
        return 0
    if a.status:
        print(json.dumps(load_state(), ensure_ascii=False, indent=2))
        print(f"URL={URL}  DIRECT={DIRECT or '（未配置）'}  FAILS={FAILS}")
        return 0
    return check_once()


if __name__ == "__main__":
    sys.exit(main())
