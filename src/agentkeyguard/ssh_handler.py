# -*- coding: utf-8 -*-
"""SSH：命令规范化、执行、主机指纹采集。

拆分自原单文件 broker/agentkeyguard.py（feature/cli-wizard 分支，7223 行版本）。
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import socket
import time

from .crypto import totp


def _ssh_fp(key) -> str:
    d = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(d).decode().rstrip("=")


def _load_pkey(spec: str, passphrase=None):
    import io
    import paramiko

    is_file = False
    if len(spec) < 4096:
        try:
            is_file = os.path.isfile(os.path.expanduser(spec))
        except (OSError, ValueError):
            is_file = False

    last = None
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            if is_file:
                return cls.from_private_key_file(os.path.expanduser(spec), password=passphrase)
            return cls.from_private_key(io.StringIO(spec), password=passphrase)
        except Exception as e:      # noqa: BLE001 - 逐个尝试密钥类型
            last = e
    raise RuntimeError(f"无法解析私钥（ed25519/ecdsa/rsa 都试过了）: {last}")


_INTERACTIVE = re.compile(
    r"(?i)^\s*(sudo\s+-[is]\b|su\b|bash\s+-i\b|sh\s+-i\b|zsh\b|vi\b|vim\b|nano\b|"
    r"top\b|htop\b|less\b|more\b|watch\b|tmux\b|screen\b|nc\b|telnet\b|ftp\b)"
)
_SUDO_PREFIX = re.compile(r"(?i)^sudo(?:\s+-(?:S|n|k|E|H)\b)*\s+(?!-)")


def _normalize_cmd(cmd: str) -> tuple[str, bool]:
    """剥掉多余的 sudo 前缀，返回 (干净命令, 是否需要提权)。

    以 sudo 开头但无法安全剥离（如 `sudo -i`、`sudo -u postgres ...`）时原样保留，
    但仍标记 needs_sudo=True——绝不把 sudo 留给远端 shell 去弹交互密码。
    """
    s = cmd.strip()
    if not re.match(r"(?i)^sudo\b", s):
        return s, False
    m = _SUDO_PREFIX.match(s)
    if m:
        rest = s[m.end():].strip()
        if rest:
            return rest, True
    return s, True


def _redact(text: str, secret: str) -> str:
    """兜底脱敏：万一密码意外出现在输出里（如 pty 回显），替换掉再返回。"""
    if secret and secret in text:
        return text.replace(secret, "***")
    return text


def ssh_exec(prof: dict, cmd: str, timeout: int = 30, use_sudo: bool = False) -> dict:
    import paramiko

    sudo_pw = ""
    send_pw = False
    if use_sudo and not prof.get("sudo_nopasswd"):
        # NOPASSWD 的机器绝不能发密码：sudo 不读 stdin，那行密码会被命令本身吃掉
        sudo_pw = prof.get("sudo_password") or prof.get("password", "")
        send_pw = bool(sudo_pw)

    def attempt(with_pty: bool):
        tr = paramiko.Transport((prof["host"], int(prof.get("port", 22))))
        tr.banner_timeout = 15
        ch = None
        try:
            tr.start_client(timeout=10)

            fp = _ssh_fp(tr.get_remote_server_key())
            want = prof.get("hostkey")
            if want and want != fp:
                raise RuntimeError(f"主机密钥不匹配（可能有中间人）：期望 {want}，实际 {fp}")
            if not want:
                print(f"  [提示] {prof['host']} 主机密钥 {fp}（未锁定；建议写入 profile 的 hostkey 字段）",
                      flush=True)

            user = prof["user"]
            if prof.get("private_key"):
                tr.auth_publickey(user, _load_pkey(prof["private_key"], prof.get("passphrase")))
            elif prof.get("totp_secret"):
                login_pw = prof.get("password", "")

                def handler(_title, _instr, prompts):
                    out = []
                    for text, _echo in prompts:
                        if re.search(r"(?i)code|otp|verif|token|passcode|动态|验证码", text):
                            out.append(totp(prof["totp_secret"]))
                        else:
                            out.append(login_pw)
                    return out

                tr.auth_interactive(user, handler)
            else:
                tr.auth_password(user, prof.get("password", ""))

            ch = tr.open_session(timeout=10)
            if with_pty:
                ch.get_pty(width=200, height=50)

            remote = cmd
            if use_sudo:
                # 关键：密码绝不进 argv。命令里只有 cmd，密码随后写进 channel 的 stdin。
                lead = "stty -echo 2>/dev/null; " if with_pty else ""
                remote = lead + "sudo -S -p '' -- bash -c " + shlex.quote(cmd)
            ch.exec_command(remote)

            if send_pw:
                buf = bytearray(sudo_pw.encode("utf-8"))
                try:
                    ch.sendall(bytes(buf) + b"\n")
                finally:
                    for i in range(len(buf)):        # 用完立刻清零
                        buf[i] = 0
            if use_sudo:
                ch.shutdown_write()                  # 立刻 EOF，避免命令读 stdin 挂住

            out, err = bytearray(), bytearray()
            deadline = time.time() + timeout
            while True:
                if ch.recv_ready():
                    out += ch.recv(65536)
                if ch.recv_stderr_ready():
                    err += ch.recv_stderr(65536)
                if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
                    break
                if time.time() > deadline:
                    raise TimeoutError(f"命令执行超过 {timeout}s")
                time.sleep(0.03)

            return ch.recv_exit_status(), bytes(out), bytes(err)
        finally:
            if ch is not None:
                try:
                    ch.close()
                except Exception:
                    pass
            try:
                tr.close()
            except Exception:
                pass

    code, raw_out, raw_err = attempt(False)

    # sudoers 若开了 requiretty，无 tty 会被直接拒绝 —— 用 pty + stty -echo 重试一次
    if use_sudo and code != 0 and re.search(rb"must have a tty|no tty present", raw_err, re.I):
        code, raw_out, raw_err = attempt(True)

    stdout = _redact(raw_out.decode("utf-8", "replace"), sudo_pw)[:200_000]
    stderr = _redact(raw_err.decode("utf-8", "replace"), sudo_pw)[:50_000]

    if use_sudo and code != 0 and re.search(
            r"(?i)sorry, try again|incorrect password|no password was provided|"
            r"is not in the sudoers|may not run sudo", stderr):
        raise RuntimeError(
            "提权失败：sudo 密码错误或无权限（已停止，不重试以免锁定账户）"
            f" | {stderr.strip()[:200]}")

    return {
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
        "host": prof["host"],
        "escalated": bool(use_sudo),
    }


# ────────────────────────────── CLI 向导：SSH 主机指纹采集 ──────────────────────────────
# 这一段的定位：example-org / 个人开发者的内网机器，不是企业级集群。
# 所以只认四种最常见的失败（没装 paramiko、超时、端口拒绝、域名解析失败），
# 其余异常一律折成一句「连接失败，请检查网络或参数」——
# 不为穷尽异常写长篇映射表，也不做 Mock 注入测试。

_HOSTKEY_TIMEOUT = 10.0          # 计划 §4.5：首次握手给 10 秒，慢机器也够


def probe_hostkey(host: str, port: int, timeout: float = _HOSTKEY_TIMEOUT) -> tuple:
    """连上去读主机密钥指纹。返回 (指纹, "") 或 ("", 中文原因)。**绝不抛异常**。

    指纹口径直接复用 `_ssh_fp` —— 必须与 ssh_exec 里比对 hostkey 的算法
    100% 一致，否则「向导锁定的指纹」和「运行时校验的指纹」会对不上，
    表现为每次连接都报「主机密钥不匹配（可能有中间人）」。这种不一致
    比不锁定更糟，所以宁可调现成函数，也绝不在这里重算一遍。
    """
    try:
        import paramiko
    except ImportError:
        return "", "未安装 paramiko（pip install paramiko 后再试）"

    tr = None
    try:
        tr = paramiko.Transport((host, int(port)))
        tr.banner_timeout = timeout          # 有些机器 banner 发得慢
        tr.start_client(timeout=timeout)
        return _ssh_fp(tr.get_remote_server_key()), ""
    except (TimeoutError, socket.timeout):
        return "", f"连接超时（{timeout:.0f} 秒）"
    except ConnectionRefusedError:
        return "", f"端口 {port} 拒绝连接（sshd 没开？）"
    except socket.gaierror:
        return "", f"域名解析失败：{host}"
    except Exception as e:                   # noqa: BLE001
        # paramiko 会把底层 socket 错误包成 SSHException，类型分不出来，
        # 只能看消息。注意消息随**系统语言**变：中文 Windows 上是
        # 「由于目标计算机积极拒绝」，英文才是 "Connection refused"；
        # 所以中英关键词 + POSIX/Linux 两种 errno 文案一起判。
        msg = str(e).lower()
        if ("refused" in msg or "10061" in msg or "拒绝" in msg
                or "econnrefused" in msg):
            return "", f"端口 {port} 拒绝连接（sshd 没开？）"
        if ("timed out" in msg or "timeout" in msg or "超时" in msg
                or "10060" in msg):
            return "", f"连接超时（{timeout:.0f} 秒）"
        if ("name or service not known" in msg or "getaddrinfo" in msg
                or "11001" in msg or "解析" in msg):
            return "", f"域名解析失败：{host}"
        return "", "连接失败，请检查网络或参数"
    finally:
        if tr is not None:
            try:
                tr.close()
            except Exception:                # noqa: BLE001 - 关不上就算了
                pass
