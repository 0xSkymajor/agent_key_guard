# -*- coding: utf-8 -*-
"""命令行：子命令、交互式 setup 向导、主密码读取与 serve 装配。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。

⚠️ master_pw 的非 TTY 行为完整保留：isatty 为真走 getpass；否则读
AGENTKEYGUARD_MASTER_PASS / AGENTKEYGUARD_NEW_MASTER_PASS；都没有则明确报错。
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from .transport import HybridThreadingHTTPServer

from . import VERSION, config
from . import domains, network, server, services, setup, tls
from .crypto import derive_key
from .storage import load_vault, ensure_token, read_vault_with_key, save_vault_with_key




















def master_pw(prompt: str, env: str = "AGENTKEYGUARD_MASTER_PASS") -> str:
    """读主密码：交互终端用 getpass（不回显）；**非 TTY 改从环境变量读**。

    为什么必须封装一层：内置 getpass 在没有控制终端时会退回 sys.stdin 读一行，
    `echo pass | agentkeyguard.py serve` 这类管道用法必然错位甚至直接 EOFError。
    也就是说 serve 放进 systemd / Docker / CI（stdin 不是 TTY）根本起不来 ——
    这是个真实的健壮性缺口，不只是测试不方便。

    非 TTY 时的取值顺序：env 指定的环境变量 → 没有就明确报错并给出两种解法，
    绝不再退回读 stdin（那正是坑的来源）。

    安全权衡（说在前面）：环境变量对同一用户的其它进程可见
    （/proc/<pid>/environ），所以这是"便利性换一点点暴露面"的选项。
    家用单机可以放心用；多用户机器或生产环境请继续用交互终端，
    或改用 systemd 的 LoadCredential= 把密码喂进 stdin。
    """
    try:
        tty = sys.stdin.isatty()
    except Exception:
        tty = False                    # stdin 被替换/关闭时一律按非交互处理
    if tty:
        return getpass.getpass(prompt)
    pw = os.environ.get(env) or ""
    if pw:
        print(f"{prompt}← 来自环境变量 {env}", flush=True)
        return pw
    raise SystemExit(
        f"{prompt}需要主密码，但当前 stdin 不是交互终端。\n"
        f"  解法一：export {env}='主密码' 后重试\n"
        f"  解法二：直接在终端里运行，或用 script -c 造一个伪终端"
    )


def _disp(s: str) -> int:
    """终端显示宽度（中日韩字符算 2 列），用于把边框对齐。"""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)
















































































































def cmd_serve(args) -> None:
    args.port = int(args.port or config.PORT)
    # 先加固进程，再考虑载入任何敏感数据：
    # ① 拒绝 core dump 与 ptrace（对同用户有效，对 root 无效，见 memlock 文档）
    # ② 尽力锁定内存，失败静默降级——容器里常因 ulimit 失败，不能因此起不来
    from . import memlock
    _hard = memlock.harden_process()
    if not _hard.get("dumpable"):
        print("  [安全] PR_SET_DUMPABLE 未生效，同用户进程可能读走本进程内存", flush=True)
    # 无库时不给一句干巴巴的「解密失败」：那会让人以为是密码错了，
    # 实际是压根还没初始化。直接指路到 setup，并且不读主密码（省得白输一遍）。
    if not config.VAULT_PATH.exists():
        server.Broker.vault = {}
        server.Broker.key = b""
        server.Broker.token = ""
        server.rebuild_allowed_nets()
        srv = HybridThreadingHTTPServer(
            (args.bind, args.port), server.Broker, None)
        # 初始化模式同样要把实例交给 server：setup 完成后要靠它热启用 TLS（REQ-111）
        server.SERVER = srv
        print("╭" + "─" * 62 + "╮")
        print(f"│ AgentKeyGuard {VERSION} 初始化模式  {args.bind}:{args.port}")
        print(f"│ 打开 http://<本机IP>:{args.port}/dashboard")
        print("│ 首次打开并完成配置的人将成为管理员")
        print("╰" + "─" * 62 + "╯")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n正在退出")
        finally:
            srv.server_close()
        return
    # 不再读 master.key：vault 保持锁定，等浏览器登录时用主密码现算 KEK（REQ-306）。
    # 磁盘上不允许存在任何能直接解密的东西——这是「静态加密」成立的前提。
    # 旧版遗留的 master.key 不静默使用，只在首次成功解锁后清理。
    server.Broker.vault = {}
    server.Broker.key = None
    server.Broker.locked = True
    server.Broker.token = ""
    if (config.DATA_DIR / "master.key").exists():
        print("  [安全] 检测到旧版 master.key，已不再使用；"
              "首次登录解锁后会自动清除", flush=True)
    print("  [安全] 保险库处于锁定状态，登录一次即可解锁", flush=True)

    # [modular] 原 global 声明改为 config/server 属性
    # [modular] 原 global 声明改为 config/server 属性
    config.AUTO_YES = bool(args.yes)
    if args.bark:
        config.BARK_BASE = args.bark.rstrip("/")
    if args.public_base:
        config.PUBLIC_BASE = args.public_base.rstrip("/")
    if args.approval_timeout:
        config.APPROVAL_TIMEOUT = int(args.approval_timeout)
    if args.allow_ip:
        # --allow-ip 会**覆盖**默认白名单，但 loopback 永远保留
        server.ALLOWED_CIDRS = list(args.allow_ip) + ["127.0.0.1/32", "::1/128"]
    server.PORTAL_IP_GUARD = bool(args.lock_portal)
    server.rebuild_allowed_nets()

    tls_dir = config.DATA_DIR / "tls"
    tls.migrate_ca(tls_dir, config.CA_DIR)

    # 有 vault 却没有服务器证书：说明上次初始化在"签发证书"那步断了
    # （历史上 CA 目录不可写就会这样）。这里补签，避免 /setup 已经 410
    # 而 HTTPS 又不可用，两边都进不去（REQ-109）。
    if not (tls_dir / "server.crt").exists() or not (tls_dir / "server.key").exists() \
            or not (config.CA_DIR / "ca.crt").exists():
        try:
            ca_key, ca_cert = tls.ensure_ca(config.CA_DIR)
            srv_key, srv_cert = tls.issue_server_cert(
                ca_key, ca_cert,
                [network.local_ip(), "127.0.0.1"],
                [domains.host_domain(), "localhost"])
            tls.save_server(srv_key, srv_cert, tls_dir)
            print("  [tls] 检测到缺少服务器证书，已自动补签发", flush=True)
        except OSError as e:
            print(f"  [tls] 补签发失败：{e}", flush=True)
            print("  [tls] 请确认 CA 目录 "
                  f"{config.CA_DIR} 对服务账号可写（systemd 需 ReadWritePaths 放行）",
                  flush=True)

    cert_f = tls_dir / "server.crt"
    key_f = tls_dir / "server.key"
    ca_f = config.CA_DIR / "ca.crt"
    tls_on = cert_f.exists() and key_f.exists() and ca_f.exists()
    ssl_ctx = tls.tls_context(cert_f, key_f) if tls_on else None
    srv = HybridThreadingHTTPServer(
        (args.bind, args.port), server.Broker, ssl_ctx)
    # 交给 server 持有，setup 完成后由 reload_after_setup() 热替换 SSLContext（REQ-111）
    server.SERVER = srv

    def row(s: str) -> None:
        print("│ " + s + " " * max(0, 60 - _disp(s)) + " │")

    # 锁定态下 vault 里什么都没解出来，不能再去读 data（1.2.6 在这里踩过 NameError，
    # 服务启动即崩、端口不监听）。一律从 Broker.vault 取，锁定时它就是个空字典。
    profs = sorted((server.Broker.vault or {}).get("profiles", {}))
    print("╭" + "─" * 62 + "╮")
    row(f"agentkeyguard {VERSION}   {args.bind}:{args.port}")
    if server.Broker.locked:
        row("状态:   锁定（浏览器登录一次即可解锁）")
    row(f"profile: {', '.join(profs) if profs else ('(解锁后显示)' if server.Broker.locked else '(空)')}")
    if not server.Broker.locked:
        row(f"token:   {server.Broker.token}")
    row(f"审批:    {'Bark 已配置' if config.BARK_BASE else '⚠ 未配置 Bark'}，{config.APPROVAL_TIMEOUT}s 超时")
    row(f"控制台:  {config.PUBLIC_BASE}/dashboard")
    row(f"单条页:  {config.PUBLIC_BASE}/approve?id=...")
    row(f"白名单:  {', '.join(server.ALLOWED_CIDRS) if server.ALLOWED_CIDRS else '（空！全部拒绝）'}")
    row(f"TLS:     {'HTTP/HTTPS 同端口' if tls_on else 'off（先跑 setup）'}")
    row("登录:    管理员用户名 + 密码 + TOTP（停手 15 分钟退出，可勾选保持登录）")
    row("热加载:  POST /admin/reload（需 token）")
    row(f"审计:    {config.AUDIT_PATH}")
    if config.AUTO_YES:
        row("⚠ --yes 已开启：所有请求自动放行（仅联调）")
    print("╰" + "─" * 62 + "╯")
    if not config.BARK_BASE:
        print("⚠ 没读到 AGENTKEYGUARD_BARK（.env 或环境变量都为空）。")
        print("  推送会失败，审批将回退到本终端输入 y/N。检查 .env 文件。")
    print("等待请求…… Ctrl-C 退出\n")

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n正在退出")
    finally:
        srv.server_close()


def build_parser() -> argparse.ArgumentParser:
    from .selftest import cmd_selftest  # 延迟导入，打破 cli ↔ selftest 循环
    ap = argparse.ArgumentParser(
        prog="agentkeyguard",
        description="极简本地凭证代理：Agent 用 PG/SSH，永远看不到明文密码",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("selftest", help="自检（不碰真实数据）")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("serve", help="启动 HTTP 服务")
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=None,
                   help="监听端口（默认取 AGENTKEYGUARD_PORT，未设置则 7700）")
    p.add_argument("--bark", default=None,
                   help="Bark API Base URL（默认取 .env 的 AGENTKEYGUARD_BARK）")
    p.add_argument("--public-base", default=None,
                   help="对外可达地址（默认取 .env 的 AGENTKEYGUARD_PUBLIC_BASE）")
    p.add_argument("--approval-timeout", type=int, default=None,
                   help="等待批准的秒数（默认 300）")
    p.add_argument("--allow-ip", action="append", metavar="CIDR",
                   help="允许访问 Agent 接口的来源，支持单 IP 或网段（可重复，覆盖默认白名单）")
    p.add_argument("--lock-portal", action="store_true",
                   help="控制台也纳入 IP 白名单（手机需固定 IP，否则打不开）")
    p.add_argument("--yes", action="store_true", help="⚠ 自动放行所有请求，仅联调用")
    p.set_defaults(func=cmd_serve)

    return ap


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)
