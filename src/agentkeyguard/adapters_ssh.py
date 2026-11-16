# -*- coding: utf-8 -*-
"""SSH 适配器：profile 构造、连通性测试、命令执行（REQ-106 从 server.py 搬出）。

行为与 v1.1.2 一致，包括两处容易踩的顺序约束：
1. 原始命令先匹配一次规则，`_normalize_cmd` 剥掉 sudo 后再匹配一次，取更严重的结论；
2. `blocked` 命中直接 403，连审批都不弹。
"""
from __future__ import annotations

import time

from . import adapters
from .rules import _RULE_SEV, desc_of, match_rule, needs_reflection
from .ssh_handler import _normalize_cmd
from .storage import audit


class SshAdapter:
    name = "ssh"
    executes = True

    # ---- profile ----
    def build_profile(self, req: dict) -> dict | None:
        try:
            prof = {
                "type": "ssh",
                "host": str(req.get("host") or ""),
                "port": int(req.get("port") or 22),
                "user": str(req.get("user") or ""),
                "password": str(req.get("password") or ""),
                "private_key": str(req.get("private_key") or ""),
                "passphrase": str(req.get("passphrase") or ""),
                "hostkey": str(req.get("hostkey") or ""),
                "sudo": str(req.get("sudo") or "none"),
                "sudo_password": str(req.get("sudo_password") or ""),
                "totp_secret": str(req.get("totp_secret") or ""),
            }
            # 旧数据里可能手工写了 sudo_nopasswd，重建 profile 时不能丢
            if req.get("sudo_nopasswd"):
                prof["sudo_nopasswd"] = bool(req.get("sudo_nopasswd"))
        except Exception:  # noqa: BLE001
            return None
        if not prof.get("host") or not prof.get("user"):
            return None
        return prof

    # ---- 连通性测试 ----
    def test(self, profile: dict) -> None:
        import io

        import paramiko

        pkey = None
        raw = profile.get("private_key") or ""
        if raw:
            classes = [getattr(paramiko, n, None) for n in
                       ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey")]
            for cls in [c for c in classes if c is not None]:
                try:
                    pkey = cls.from_private_key(
                        io.StringIO(raw), password=profile.get("passphrase") or None)
                    break
                except Exception:  # noqa: BLE001
                    continue
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cli.connect(profile["host"], port=int(profile.get("port") or 22),
                    username=profile["user"],
                    password=profile.get("password") or None,
                    pkey=pkey, timeout=5, allow_agent=False,
                    look_for_keys=False)
        cli.close()

    # ---- 执行 ----
    def execute(self, srv, req: dict, src: str) -> None:
        name = (req.get("profile") or "").strip()
        raw_cmd = req.get("cmd") or ""
        if not name or not raw_cmd.strip():
            return srv._send(400, {"error": "需要 profile 与 cmd"})

        prof = srv.vault.get("profiles", {}).get(name)
        if not prof or prof.get("type") != "ssh":
            return srv._send(404, {"error": f"没有 ssh profile: {name}"})

        # ── 分级拦截（rules.json 每次请求热读取） ──
        # blocked 命中后连审批都不弹：不可逆的破坏只能由人手动执行。
        # 主人在「敏感权限自动屏蔽」里关掉的规则传进来，匹配时跳过；
        # 自保护规则在 rules.is_locked_rule 里硬挡，不受这个列表影响（REQ-307）
        _off = set((getattr(srv, "vault", {}).get("settings") or {}).get("rules_off") or [])
        layer, label = match_rule(raw_cmd, "shell", off=_off)
        if layer == "blocked":
            audit({"event": "deny", "kind": "ssh.exec", "profile": name,
                   "reason": "system_blocked", "rule": label,
                   "cmd": raw_cmd[:2000], "src": src})
            print(f"  [拦截] {name} 命中绝对禁区 [{label}]：{raw_cmd[:120]}", flush=True)
            return srv._send(403, {"error": "系统拦截", "reason": label,
                                   "explain": desc_of(label),
                                   "type": "system_blocked"})

        cmd, had_sudo = _normalize_cmd(raw_cmd)
        if not cmd:
            return srv._send(400, {"error": "cmd 为空"})

        # sudo 前缀剥掉后再匹配一次，取更严重的结论：`sudo rm -rf /` 原始串以
        # sudo 开头，规范化之后才看清真正要执行的东西。
        l2, n2 = match_rule(cmd, "shell", off=_off)
        if _RULE_SEV[l2] > _RULE_SEV[layer]:
            layer, label = l2, n2
        if layer == "blocked":
            audit({"event": "deny", "kind": "ssh.exec", "profile": name,
                   "reason": "system_blocked", "rule": label,
                   "cmd": raw_cmd[:2000], "src": src})
            print(f"  [拦截] {name} 命中绝对禁区 [{label}]：{raw_cmd[:120]}", flush=True)
            return srv._send(403, {"error": "系统拦截", "reason": label,
                                   "explain": desc_of(label),
                                   "type": "system_blocked"})
        if layer == "interactive":
            audit({"event": "deny", "kind": "ssh.exec", "profile": name,
                   "reason": "interactive_blocked", "rule": label,
                   "cmd": raw_cmd[:2000], "src": src})
            return srv._send(400, {
                "error": "拒绝执行交互式命令（会挂起到超时）。请用单条非交互命令，"
                         "需要 root 请用 sudo:true 而不是 sudo -i",
                "reason": label,
                "type": "interactive_blocked",
            })

        # dangerous：先 428 逼 Agent 自我反思，反思非空才推手机审批。
        # 主人在「灵魂三问」块关掉自审的规则跳过 428，但**照样推审批**：
        # 省的是一次往返，不是那道闸门（见 rules.needs_reflection）。
        dangerous = layer == "dangerous"
        self_reflection = ""
        reflection_off = False
        if dangerous:
            _ref_off = set((getattr(srv, "vault", {}).get("settings") or {})
                           .get("reflection_off") or [])
            reflection_off = not needs_reflection(label, _ref_off)
            self_reflection = str(req.get("self_reflection") or "").strip()[:1000]
            if not self_reflection and not reflection_off:
                audit({"event": "deny", "kind": "ssh.exec", "profile": name,
                       "reason": "self_reflection_required", "rule": label,
                       "cmd": raw_cmd[:2000], "src": src})
                print(f"  [拦截] {name} 高危操作 [{label}] 缺 self_reflection，回 428",
                      flush=True)
                return srv._send(428, {
                    "error": "高危操作需自我反思",
                    "instruction": "请先思考并回答：1. 我是谁？2. 我在哪儿？3. 我打算干什么？"
                                   "想清楚还要不要继续。如果确认继续，请在下次请求的 "
                                   "'self_reflection' 字段中带上你的思考结果。",
                    "rule": label,
                })

        sudo_mode = prof.get("sudo", "none")
        want_sudo = bool(req.get("sudo")) or had_sudo or sudo_mode == "required"

        if want_sudo and sudo_mode == "none":
            audit({"event": "deny", "kind": "ssh.exec", "profile": name,
                   "reason": "sudo_not_allowed", "cmd": cmd, "src": src})
            return srv._send(403, {
                "error": f"profile {name} 不允许提权（sudo=none）。该机器请直接用 root 账号，"
                         "或重新 add-ssh 时加 --sudo auto",
            })

        if want_sudo and not (prof.get("sudo_nopasswd")
                              or prof.get("sudo_password") or prof.get("password")):
            return srv._send(400, {
                "error": "该 profile 既没有 sudo 密码也没标记 NOPASSWD，无法提权",
            })

        target = f"{prof.get('user')}@{prof.get('host')}:{prof.get('port', 22)}"
        detail = f"命令:\n{cmd[:1500]}"
        if want_sudo:
            detail = "【提权 root】\n" + detail

        # 延迟导入：自检照旧 patch server.ask_approval / server.ssh_exec
        from . import server as server_mod

        # force=True：SSH 永远要人工批准，--yes 在这里无效
        res: dict = {}
        if not server_mod.ask_approval("ssh.exec", name, target, detail, src,
                                       force=True, title=(req.get("title") or ""),
                                       dangerous=dangerous, self_reflection=self_reflection,
                                       reflection_off=reflection_off, out=res):
            audit({"event": "denied", "kind": "ssh.exec", "profile": name,
                   "cmd": cmd, "sudo": want_sudo, "src": src,
                   "reason": res.get("reason", "")})
            return srv._send(403, {"error": "用户拒绝",
                                   "reason": res.get("reason") or "",
                                   "type": "user_denied"})

        if res.get("duplicate"):
            # 客户端把同一条命令发了两遍：上一条已批准并执行过，这里不再执行第二遍
            return srv._send(200, {"ok": True, "duplicate": True,
                                   "note": "同一操作已由前一条相同请求处理，本次未重复执行"})

        t0 = time.time()
        try:
            out = server_mod.ssh_exec(prof, cmd, int(req.get("timeout") or 30),
                                      use_sudo=want_sudo)
        except Exception as e:              # noqa: BLE001
            audit({"event": "error", "kind": "ssh.exec", "profile": name,
                   "error": f"{type(e).__name__}: {e}", "src": src})
            return srv._send(502, {"error": f"SSH 错误: {type(e).__name__}: {e}"})

        out["elapsed_ms"] = int((time.time() - t0) * 1000)
        audit({"event": "ok", "kind": "ssh.exec", "profile": name,
               "cmd": cmd[:2000], "sudo": want_sudo, "src": src,
               "exit": out.get("exit_code"), "ms": out["elapsed_ms"]})
        return srv._send(200, out)


adapters.register(SshAdapter())
