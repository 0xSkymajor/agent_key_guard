# -*- coding: utf-8 -*-
"""Web 初始化：bootstrap 状态机、单管理员、owner 状态、finish 落库。

v2：CLI 向导已删除，初始化全部走 Web。本模块只负责“状态 + 落库”，
HTTP 路由在 server.py 里接。
"""
from __future__ import annotations

import base64
import datetime
import hmac
import ipaddress
import json
import secrets
import shutil
import string
import threading
import time
import urllib.parse
from pathlib import Path

from . import agents, config, domains, network, tls
from .crypto import derive_key, portal_hash
from .storage import load_vault_secret, save_vault, write_meta
from .crypto import hkdf_mix

_LOCK = threading.Lock()
_DONE_LOCK = threading.Lock()
_DONE: dict[str, dict] = {}
_DOWNLOAD_LOCK = threading.Lock()
_DOWNLOADS: dict[str, dict] = {}

DRAFT: dict = {
    "username": "",
    "master": "",
    "totp_secret": "",
    "bark": "",
    "public_base": "",
    "timeout": 300,
    "profiles": {},
}


# 内部错误码 → 面向用户的中文提示（REQ-108）。
# 前端只负责展示 message；错误码仍保留在响应体的 error 字段，供日志与自动化使用。
ERRORS: dict[str, str] = {
    "weak_master": ("主密码强度不足：至少 12 位，且需同时包含小写字母、大写字母"
                    "与 ASCII 半角符号（如 ! @ # - _）"),
    "bad_username": "用户名只能包含 3-32 位字母、数字与 . _ -",
    "bad_totp_secret": "TOTP 密钥必须是至少 16 位 Base32 字符（A-Z 与 2-7）",
    "totp_required": "请先完成 TOTP 绑定：扫码后输入一次 6 位验证码",
    "already_initialized": "已完成初始化，不能重复配置；要重来请先清空数据目录",
    "loopback_public_base": ("这个地址只有本机能访问，手机打不开；"
                             "请填写局域网 IP（如 192.0.2.12）或已解析的域名"),
}


class SetupError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def message(self) -> str:
        return ERRORS.get(self.code, self.code)


def _tls_dir() -> Path:
    return config.DATA_DIR / "tls"


def host_of(public_base: str) -> str:
    """取 public_base 里的主机名（小写），解析失败返回空串。"""
    try:
        return (urllib.parse.urlsplit(public_base or "").hostname or "").strip().lower()
    except ValueError:
        return ""


def san_lists(public_base: str) -> tuple[list[str], list[str]]:
    """由「手机可访问地址」推导证书 SAN：IP 列表 + DNS 列表，均已去重。

    REQ-112：历史实现把 setup 时的**客户端来源 IP** 当成 SAN，从 Windows 经端口
    转发进来就是 127.0.0.1，签出的证书里一个局域网地址都没有，手机必不匹配。
    这里改成永远带上本机局域网 IP，并把 public_base 里的 host 也纳入（是 IP 进
    IP 列表，是域名进 DNS 列表），再补 127.0.0.1 / localhost / 本机域名。
    """
    ips: list[str] = []
    dns: list[str] = []

    def add_ip(value: str) -> None:
        value = (value or "").strip()
        if value and value not in ips:
            ips.append(value)

    def add_dns(value: str) -> None:
        value = (value or "").strip().lower().rstrip(".")
        if value and value not in dns:
            dns.append(value)

    add_ip(network.local_ip())
    add_ip("127.0.0.1")
    # 一台机器常有多个网卡（有线 / 无线 / 备用口），任一口都可能被拿来访问。
    # 只把 public_base 那一处写进 SAN，换口访问就会报 ERR_CERT_COMMON_NAME_INVALID——
    # 那是「名字对不上」，装根证书解决不了（REQ-142）。
    # 虚拟网卡（docker0 / br-* / veth）不加：只在本机可达，加进来只是让证书变胖。
    for _item in network.lan_addresses():
        if not _item.get("virtual"):
            add_ip(_item.get("ip") or "")

    host = host_of(public_base)
    if host:
        try:
            ipaddress.ip_address(host)
            add_ip(host)
        except ValueError:
            if host != "localhost":
                add_dns(host)

    add_dns("localhost")
    add_dns(domains.host_domain())
    # 上限 16 条：网卡特别多的机器上，SAN 无限膨胀会让部分客户端握手变慢
    return ips[:16], dns[:16]


def _master_key_path() -> Path:
    return config.DATA_DIR / "master.key"


# 初始化刚完成时，vault 与 KEK 已经在内存里（用户刚输过主密码）。
# 通过这个槽把它们交给 Broker，避免又去磁盘读一遍——那条路已经不存在了。
_LAST_UNLOCK: dict = {"vault": None, "kek": None}


def last_unlock() -> tuple[dict | None, object]:
    """取出最近一次初始化解出的 (vault, kek)，供 server 热生效使用。"""
    return _LAST_UNLOCK.get("vault"), _LAST_UNLOCK.get("kek")


def _drop_legacy_master_key() -> None:
    """删掉旧版遗留的 master.key（先备份成 .key.bak，可回滚）。

    这是本次安全改造的可见成果：磁盘上不再有能直接解密 vault 的文件。
    """
    p = _master_key_path()
    if not p.exists():
        return
    try:
        bak = p.with_suffix(".key.bak")
        shutil.copy2(p, bak)
        p.unlink()
        print("  [安全] 已移除旧版 master.key（备份为 master.key.bak）", flush=True)
    except OSError:
        pass


def _setup_code_path() -> Path:
    return config.DATA_DIR / "setup-code"


def _read_owner_state() -> dict:
    try:
        return json.loads(config.PORTAL_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def has_admin() -> bool:
    """是否存在管理员：以 portal-state 为准，不看 vault 文件是否存在。

    这样部分初始化/旧 vault/重装后都能回到 /setup，而不是被 410 卡死。
    """
    return bool(_read_owner_state().get("owner"))


def mark_owner(owner: bool = True) -> None:
    p = config.PORTAL_STATE_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"owner": bool(owner)}), encoding="utf-8")
    p.chmod(0o600)


def ensure_owner_state(vault: dict) -> bool:
    """旧 vault 迁移：已有完整 portal 但没有 portal-state 时补写 owner。"""
    p = vault.get("portal") or {}
    configured = bool(p.get("totp_secret") and p.get("pw_hash") and p.get("pw_salt"))
    if configured and not has_admin():
        mark_owner(True)
    return has_admin()


def initialized() -> bool:
    return has_admin()


def ensure_code() -> str:
    """生成/读取一次性初始化码，写 0600 并打到 journal。"""
    p = _setup_code_path()
    if p.exists():
        code = p.read_text(encoding="utf-8").strip()
        if code:
            return code
    code = secrets.token_urlsafe(9)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(code + "\n", encoding="utf-8")
    p.chmod(0o600)
    print(f"  [setup] 一次性初始化码: {code}", flush=True)
    print(f"  [setup] 浏览器打开 /dashboard 并输入该码", flush=True)
    return code


def check_code(code: str) -> bool:
    p = _setup_code_path()
    if not p.exists():
        return False
    return hmac.compare_digest(p.read_text(encoding="utf-8").strip(), (code or "").strip())


def _strong(pw: str) -> bool:
    return (
        len(pw) >= 12
        and any(c.islower() for c in pw)
        and any(c.isupper() for c in pw)
        and any(c in string.punctuation for c in pw)
    )


def set_username(name: str) -> None:
    """管理员用户名：保留用户输入，不做域名 slug（域名由宿主机名派生）。"""
    s = str(name or "").strip()
    if not s:
        s = "admin"
    if len(s) < 3 or len(s) > 32 or any(
            not (c.isalnum() or c in "._-") for c in s):
        raise SetupError("bad_username")
    DRAFT["username"] = s


def set_master(master: str) -> None:
    if not _strong(master):
        raise SetupError("weak_master")
    DRAFT["master"] = master


def set_totp(secret: str) -> None:
    secret = (secret or "").strip().upper()
    if len(secret) < 16 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret):
        raise SetupError("bad_totp_secret")
    DRAFT["totp_secret"] = secret


def new_totp() -> dict:
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    uri = (f"otpauth://totp/agentkeyguard:admin?secret={secret}"
           f"&issuer=agentkeyguard&algorithm=SHA1&digits=6&period=30")
    return {"secret": secret, "uri": uri}


def verify_totp(secret: str, code: str) -> bool:
    """校验 6 位 TOTP，允许 ±1 个时间窗（手机时钟漂移）。"""
    from .crypto import totp
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != 6:
        return False
    now = time.time()
    for delta in (-30, 0, 30):
        if hmac.compare_digest(totp(secret, 6, 30, now + delta), code):
            return True
    return False


def set_storage(bark: str, public_base: str, timeout: int,
                allow_loopback: bool = False, agent_name: str = "") -> None:
    base = (public_base or "").strip().rstrip("/")
    if base and not allow_loopback:
        host = host_of(base)
        if host in ("", "127.0.0.1", "localhost", "::1", "0.0.0.0"):
            # 回环地址在手机上指向手机自己，审批链接必然打不开（REQ-112）
            raise SetupError("loopback_public_base")
    # 初始化向导里同样接受「只填 key」，与设置页、测试按钮保持同一口径（P6）
    DRAFT["bark"] = config.normalize_bark(bark)
    DRAFT["public_base"] = base
    DRAFT["timeout"] = max(30, min(3600, int(timeout or 300)))
    # 首个接入密钥的会话签名：与「Agent 接入 → 添加密钥」同一套填法（REQ-139）
    DRAFT["agent_name"] = (agent_name or "").strip()[:32]


def set_profiles(profiles: dict) -> None:
    if not isinstance(profiles, dict):
        raise SetupError("bad_profiles")
    DRAFT["profiles"] = dict(profiles)


def reset() -> None:
    with _LOCK:
        DRAFT.update({"username": "", "master": "", "totp_secret": "", "bark": "",
                      "public_base": "", "timeout": 300, "profiles": {}})


def finish(ip: str, port: int = 7700) -> dict:
    """写单管理员 vault；CA 复用，只重签服务器证书。"""
    with _LOCK:
        if has_admin():
            raise SetupError("already_initialized")
        master = DRAFT["master"]
        if not _strong(master):
            raise SetupError("weak_master")
        if not DRAFT["totp_secret"]:
            raise SetupError("totp_required")

        username = DRAFT["username"] or "admin"
        # 默认用本机局域网地址，而不是"配置时的来源 IP"—— 手机要靠它访问（REQ-112）
        public_base = DRAFT["public_base"] or f"https://{network.local_ip()}:{port}"
        salt = secrets.token_bytes(16)
        psalt = secrets.token_bytes(16)
        portal = {
            "username": username,
            "totp_secret": DRAFT["totp_secret"],
            "totp_digits": 6,
            "totp_period": 30,
            "pw_salt": base64.b64encode(psalt).decode(),
            "pw_hash": base64.b64encode(portal_hash(master, psalt)).decode(),
        }
        data = {
            "version": 1,
            "profiles": dict(DRAFT["profiles"]),
            "portal": portal,
            "settings": {
                "bark": DRAFT["bark"],
                "public_base": public_base,
                "approval_timeout": DRAFT["timeout"],
            },
        }

        # 完成页直接给一条一次性接入链接（REQ-139）：与「添加密钥」完全同构——
        # 10 分钟有效、核销即焚、带会话签名。票据写进 data，随 vault 一起落盘。
        first_name = (DRAFT.get("agent_name") or "").strip()[:32] or "首次接入"
        first_ticket, first_ttl = agents.issue_ticket(data, first_name, ip)

        # ── 第 1 步：先签证书（依赖 CA 目录可写，失败时不留任何本地状态）──
        # 刻意放在落 vault 之前：systemd 若没放行 CA_DIR，ensure_ca 会抛
        # OSError 30；此时 vault 还没写，/setup 可以原样重来（REQ-109）。
        tls_dir = _tls_dir()
        ca_key, ca_cert = tls.ensure_ca(config.CA_DIR)
        san_ips, san_dns = san_lists(public_base)
        srv_key, srv_cert = tls.issue_server_cert(ca_key, ca_cert, san_ips, san_dns)
        tls.save_server(srv_key, srv_cert, tls_dir)

        # ── 第 2 步：落 vault，任一步失败整体回滚 ──
        # 没有管理员但旧 vault 存在：先备份，允许接管/修复，避免半初始化卡死。
        # master.key 已经不存在了（REQ-306 删掉），旧版遗留文件由
        # _drop_legacy_master_key 在成功后清理（备份成 .key.bak）。
        vault_bak = config.VAULT_PATH.with_suffix(".enc.bak")
        had_vault = config.VAULT_PATH.exists()
        if had_vault:
            try:
                shutil.copy2(config.VAULT_PATH, vault_bak)
                vault_bak.chmod(0o600)
            except OSError:
                pass
        try:
            # 新装默认启用服务端密钥（REQ-308）：KEK = HKDF(scrypt(密码) ‖ secret)。
            # secret 放在 /etc 下且 root-only，服务经 systemd credential 读取，
            # 这样「拿到服务用户权限但不是 root」的攻击者也算不出 KEK。
            # 拿不到 secret（比如手工部署没生成）就退回纯 scrypt，保证装得上。
            base_key = derive_key(master, salt)
            secret = load_vault_secret()
            key = hkdf_mix(base_key, secret) if secret else base_key
            from .storage import _write_vault_blob
            from .crypto import _encrypt_to_blob
            _write_vault_blob(_encrypt_to_blob(data, key, salt))
            write_meta({"kdf": "scrypt+secret" if secret else "scrypt"})
            # 不落盘 KEK：磁盘上只留密文，解密密钥由主密码在登录时现算（REQ-306）。
            # 旧版这里写 master.key，等于把钥匙插在锁孔上——拿到文件即全解。
            _drop_legacy_master_key()
        except Exception:
            # 回滚：有备份就还原，没有备份就删掉刚写出的半成品，
            # 保证「有密码没证书」这种死状态不会出现。
            for path, bak, had in ((config.VAULT_PATH, vault_bak, had_vault),):
                try:
                    if had and bak.exists():
                        shutil.copy2(bak, path)
                    else:
                        path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise

        # 只分发根证书描述文件（给 iPhone 装 CA 用），不签发客户端证书：
        # mTLS 整体不做（REQ-303），这里也不存在任何 p12 / 客户端身份。
        mc = tls.root_mobileconfig(tls.cert_der(ca_cert))

        _setup_code_path().unlink(missing_ok=True)
        mark_owner(True)
        dl_token = secrets.token_urlsafe(24)
        with _DOWNLOAD_LOCK:
            _DOWNLOADS[dl_token] = {
                "ca": tls.cert_pem(ca_cert),
                "mobileconfig": mc,
                "expires": time.time() + 600,
            }
        token = secrets.token_urlsafe(24)
        done = {
            "url": public_base,
            "username": username,
            "master": master,
            # TOTP 密钥不进完成页数据（REQ-151）：页面不再回显它，就不该让它跟着
            # /api/setup/finish 的响应一起进浏览器内存。它在 Step 2 扫码时已经给过。
            "ca_pem": tls.cert_pem(ca_cert).decode("ascii"),
            "mobileconfig_b64": base64.b64encode(mc).decode("ascii"),
            "download_token": dl_token,
            # 一次性接入链接：与「添加密钥」同格式，10 分钟、只能核销一次
            "first_link": f"{public_base}/skill?t={urllib.parse.quote(first_ticket)}",
            "first_name": first_name,
            "first_ttl": first_ttl,
        }
        with _DONE_LOCK:
            _DONE[token] = done
        # 刚解出的 vault 与 KEK 只交给当前进程，进程退出即消失（不落盘）
        _LAST_UNLOCK["vault"] = data
        _LAST_UNLOCK["kek"] = key
        return {"token": token, **done}


def take_done(token: str) -> dict | None:
    """一次性：配置页刷新后返回 None。"""
    with _DONE_LOCK:
        return _DONE.pop(token, None)


def take_download(token: str, kind: str) -> bytes | None:
    """证书下载：与页面 token 分离，10 分钟内可多次下载。"""
    with _DOWNLOAD_LOCK:
        d = _DOWNLOADS.get(token)
        if not d or d["expires"] < time.time():
            return None
        return d.get(kind)
