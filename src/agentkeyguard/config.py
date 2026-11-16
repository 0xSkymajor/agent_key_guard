# -*- coding: utf-8 -*-
"""路径与全局配置常量。

拆分自原单文件 broker/agentkeyguard.py，仅做路径常量化与搬移，语义不变。

目录约定：
  配置目录 CONFIG_DIR（.env、rules.json）→ 默认 /etc/agentkeyguard
  数据目录 DATA_DIR（vault.enc、token、audit.log）→ 默认 /var/lib/agentkeyguard
均可用环境变量覆盖，供开发与自检切换到临时目录。
"""
from __future__ import annotations

import os
from pathlib import Path


# ── 目录（环境变量可覆盖）──
CONFIG_DIR = Path(os.environ.get("AGENTKEYGUARD_CONFIG_DIR", "/etc/agentkeyguard"))
DATA_DIR = Path(os.environ.get("AGENTKEYGUARD_DATA_DIR", "/var/lib/agentkeyguard"))
PORT = int(os.environ.get("AGENTKEYGUARD_PORT", "7700") or 7700)

# ── .env 载入（手写解析，不引三方依赖）──
_ENV_FILE = CONFIG_DIR / ".env"


def _parse_dotenv(path: Path) -> dict:
    """KEY=VALUE，# 注释，容忍成对引号。解析失败只跳过该行，不抛异常。"""
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k:
            out[k] = v
    return out


_DOTENV = _parse_dotenv(_ENV_FILE)


def env(key: str, default: str = "") -> str:
    """优先级：真实环境变量 > .env 文件 > 代码默认值。"""
    return os.environ.get(key) or _DOTENV.get(key) or default


# ── 数据文件路径 ──
# 注意：这些是模块级可变属性。storage 等模块必须在“调用期”读取
# config.VAULT_PATH 等，不能在 import 时把值复制到自己的模块级变量，
# 否则 selftest 把 config.VAULT_PATH 指向临时目录时不会生效。
VAULT_PATH = DATA_DIR / "vault.enc"

# 服务端密钥（可选加固层，REQ-308）：与 vault 分开放，
# 这样「拿到服务用户权限但不是 root」的攻击者读不到它。
# 经 systemd LoadCredential 以 fd 传入时优先用 $CREDENTIALS_DIRECTORY。
VAULT_SECRET_PATH = Path(env("AGENTKEYGUARD_VAULT_SECRET", "/etc/agentkeyguard/vault-secret"))
# KDF 模式侧车（明文，不含任何秘密）：{"kdf": "scrypt"} 或 {"kdf": "scrypt+secret"}
VAULT_META_PATH = DATA_DIR / "vault.meta"
TOKEN_PATH = DATA_DIR / "token"
AUDIT_PATH = DATA_DIR / "audit.log"
RULES_PATH = Path(env("AGENTKEYGUARD_RULES", str(CONFIG_DIR / "rules.json")))

# ── TLS / Web 初始化（v2）──
# 统一放 DATA_DIR：systemd ProtectSystem=strict 下 /etc 只读，/var/lib 可写。
TLS_DIR = DATA_DIR / "tls"
TLS_CA = TLS_DIR / "ca.crt"
TLS_CA_KEY = TLS_DIR / "ca.key"
TLS_SERVER_CERT = TLS_DIR / "server.crt"
TLS_SERVER_KEY = TLS_DIR / "server.key"
MASTER_KEY_PATH = DATA_DIR / "master.key"
SETUP_CODE_PATH = DATA_DIR / "setup-code"

# ── 持久 CA / 管理员状态（v4）──
# CA 独立于用户数据目录，remove/purge 不删；只有“完全重置”才删。
# ⚠ systemd 单元必须是 ProtectSystem=strict + ReadWritePaths 同时包含
#   /var/lib/agentkeyguard 与 /var/lib/agentkeyguard-ca，否则签发证书会
#   报 OSError 30 (Read-only file system)，首次初始化必挂（REQ-109）。
# portal-state 只保存 owner:true/false，用来判定“有没有管理员”，不存密钥。
CA_DIR = Path(env("AGENTKEYGUARD_CA_DIR", "/var/lib/agentkeyguard-ca"))
PORTAL_STATE_PATH = DATA_DIR / "portal-state.json"
SETUP_CODE = env("AGENTKEYGUARD_SETUP_CODE", "").strip()

# ── 凭证敏感字段白名单：/profiles 与 _pub_profile 靠它剔除密钥字段 ──
# `token` 必须在此：git 凭证的 Token 与数据库密码同级，少一个就明文出接口。
# 列表上的「查看密钥」与 reveal 接口也都以这一份为准，避免出现第三份名单。
SECRET_KEYS = {"password", "private_key", "passphrase", "totp_secret",
               "sudo_password", "token"}

# ── 来源 IP 白名单状态已迁到 server.py ──
# ALLOWED_CIDRS / IP_GUARDED_PREFIXES / PORTAL_IP_GUARD / TRUSTED_PROXIES / _ALLOWED_NETS
# 都是运行期会被 cmd_serve / selftest 改写的可变状态，按用户要求住进 server.py，
# 由 server.ip_allowed 等函数按模块全局动态读取。

# ── 面板 / 工作台 / 二次验证 ──
REVEAL_TTL = 60                  # 二次 TOTP 通过后 reveal_token 的有效期（秒）
PORTAL_MAX_FAILS = 3             # 连续失败几次锁定
PORTAL_LOCK_SECONDS = 300        # 锁定多少秒
PORTAL_TOTP_DIGITS = 6
PORTAL_TOTP_PERIOD = 30
REVEAL_MASK_SECONDS = 15         # 前端密码显示多少秒后变回星号

# ── 控制台会话（滑动空闲，无绝对过期）──
# 生物识别（WebAuthn / Face ID / Windows Hello）已整体移除：它解决的是
# 「本机免密」，而真正的防线是手机审批；代价却是 RP ID、域名绑定、证书信任
# 三层耦合，换机器或换域名都要重新绑定。登录只保留 密码 + TOTP。
#
# 计时只有一个 `idle`（滑动窗口），两档共用同一套代码，只用 span 区分：
#   SESSION_IDLE       不勾「本窗口保持登录」：停手 15 分钟退出
#   SESSION_IDLE_KEEP  勾选：窗口开着不碰也活 4 小时（防浏览器丢弃闲置标签页）
# cookie 恒为会话级（不写 Max-Age），关浏览器即被丢弃 —— 这才是「关窗即退」
# 的真正保障，与 span 取 900 还是 14400 无关。
# 兼容：老部署写的是 AGENTKEYGUARD_SESSION_TTL，仍作为 SESSION_IDLE 的兜底来源。
SESSION_IDLE = int(env("AGENTKEYGUARD_SESSION_IDLE",
                       env("AGENTKEYGUARD_SESSION_TTL", "900")) or 900)
SESSION_IDLE_KEEP = int(env("AGENTKEYGUARD_SESSION_IDLE_KEEP", "14400") or 14400)
SESSION_MAX = int(env("AGENTKEYGUARD_SESSION_MAX", "8") or 8)
# 关页即退：标签页被关时前端用 sendBeacon 打一个 /api/session/bye。服务端**不立刻**
# 删会话——刷新页面、站内跳转都会紧接着发请求，收到任何请求就撤销这个标记。
# 超过宽限仍无任何请求，才判定「窗口真的关了」并清掉会话记录。
# 宽限取 60 秒：主人要求「关掉窗口 1 分钟内就踢下线」。Chrome 对后台标签页的定时器
# 最狠节流到 1 次/分钟，理论上贴着边界，但 current() 里正在发请求的会话带 keep，
# 永远不会被自己的请求清掉；只有「另一个会话抢在它下一次心跳之前扫到」才可能误踢，
# 概率极低且重新登录即可。真被误踢就把本项调回 120。
SESSION_BYE_GRACE = int(env("AGENTKEYGUARD_SESSION_BYE_GRACE", "60") or 60)
# 在线判定：最近一次**任何**请求距今 ≤ 该秒数才算「在线」。
# 关掉的标签页不再发请求，所以超过这个数就显示「已离线（窗口可能已关闭）」，
# 不必等到 idle 到期 —— 这是「会话列表里挂着一条永远在线的僵尸」的解药。
SESSION_ONLINE = int(env("AGENTKEYGUARD_SESSION_ONLINE", "90") or 90)
HTTPS_HINT_COOKIE = "akg_https"

# ── 审批通道（运行期可变，cmd_serve / selftest 会改写）──
AUTO_YES = False
BARK_BASE = env("AGENTKEYGUARD_BARK", "").rstrip("/")
BARK_DEFAULT_SERVER = "https://api.day.app"

# 通知渠道（运行期可变，apply_vault 会从 vault.settings 同步）：
# - NOTIFY_CHANNELS 是渠道名列表，"bark" 为保留字，其余是 "preset:name"；
# - NOTIFY 是 webhook 渠道详情列表（name / preset / url / secret），Agent 不可见。
NOTIFY_CHANNELS: list[str] = ["bark"]
NOTIFY: list[dict] = []


def normalize_bark(value) -> str:
    """把 Bark 输入统一成 `{server}/{device_key}`（无尾斜杠）。

    三种写法都接受，避免「只填 Key 就测试失败」：
      · https://api.day.app/KEY  → 原样（去尾斜杠）
      · api.day.app/KEY          → 补 https://
      · KEY                      → 补 https://api.day.app/
    纯 device key 的判据是既没有 `/` 也没有 `.`：Bark 的 key 是 22 位
    无点无斜杠的字符串，而域名一定带点，两者不会混淆。
    """
    v = str(value or "").strip()
    if not v:
        return ""
    if "://" in v:
        return v.rstrip("/")
    if "/" not in v and "." not in v:
        return f"{BARK_DEFAULT_SERVER}/{v}"
    return "https://" + v.rstrip("/")
# 未配置时的哨兵值：`_public_base()` 靠它区分「没配」与「配成了回环」
DEFAULT_PUBLIC_BASE = "http://127.0.0.1:7700"
PUBLIC_BASE = env("AGENTKEYGUARD_PUBLIC_BASE", DEFAULT_PUBLIC_BASE).rstrip("/")
APPROVAL_TIMEOUT = int(env("AGENTKEYGUARD_APPROVAL_TIMEOUT", "300") or 300)
# Bark 推送失败回落到终端时的输入超时（秒）。超时一律按"拒绝"处理并落审计。
TERMINAL_TIMEOUT = int(env("AGENTKEYGUARD_TERMINAL_TIMEOUT", "60") or 60)

# ── 审批工作台 /dashboard ──
DESK_ABS_TTL = 1800           # 会话绝对过期 30 分钟，到点强制重新验证
DESK_IDLE_TTL = 300           # 5 分钟没有任何批准动作就失效
DESK_POLL_MS = 2000           # 前端轮询间隔（毫秒）
DESK_GLOBAL_FAIL_LIMIT = 20   # 全局熔断阈值：累计失败次数
DESK_GLOBAL_LOCK = 600        # 熔断锁定时长
