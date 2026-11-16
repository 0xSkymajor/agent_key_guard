# -*- coding: utf-8 -*-
"""登录 / 锁定 / 证书换发路由：由 server.Broker 调度。

生物识别（WebAuthn）已整体移除。本模块现在只处理四件事：

- `POST /api/unlock/password`  密码 + TOTP 登录（可选「本窗口保持登录」）
- `POST /api/logout`           退出登录（`/api/lock` 保留为旧别名）
- `POST /api/session/touch`    用户真实操作触发的滑动续期
- `POST /api/session/bye`      页面正在关闭（sendBeacon 打的标记，宽限后生效）
- `POST /api/sessions/revoke`  按 sid 踢掉一条在线会话
- `POST /api/sessions/prune`   一次清掉全部已离线会话记录
- `POST /api/network/verify`   校验域名解析（换证书前确认域名指向本机）
- `POST /api/tls/reissue`      换发服务器证书并热生效（REQ-122）

注意：HTTPS / CA / 证书换发全部保留 —— 内网链路加密是必要的，
被砍掉的只是「用生物识别代替口令」这一层。
"""
from __future__ import annotations

from . import auth, config, domains, network, setup, storage, tls
from .storage import audit, save_vault_with_key


def _try_unlock(master: str):
    """用主密码试着解库。成功返回 (数据, KEK, "")；失败返回 (None, None, 原因)。

    这里不比对 pw_hash：AES-GCM 认证失败本身就说明密码不对，
    多存一份密码校验值只会多一个可被离线爆破的靶子。
    """
    secret = b""
    if storage.vault_kdf_mode() == "scrypt+secret":
        secret = storage.load_vault_secret()
        if not secret:
            # 库是用「密码 + 服务端密钥」加密的，secret 丢了就是永久打不开。
            # 必须单独报出来，不能混成「密码错」，否则用户会一直试密码。
            return None, None, "missing_vault_secret"
    try:
        data, kek = storage.unlock_vault(master, secret)
    except ValueError:
        return None, None, "bad_password"
    except Exception:  # noqa: BLE001
        return None, None, "bad_password"
    return data, kek, ""


def _discard(kek) -> None:
    """把已解出的密钥在内存里覆写掉（bytearray 才能原地清零）。"""
    try:
        if isinstance(kek, bytearray):
            kek[:] = b"\x00" * len(kek)
    except Exception:  # noqa: BLE001
        pass


def handle_get(broker, path: str) -> bool:
    """WebAuthn 的状态查询已随模块移除，这里没有 GET 需要接管。"""
    return False


def handle_post(broker, path: str, req: dict) -> bool:
    ip = broker._ip()
    ua = broker.headers.get("User-Agent", "")

    if path == "/api/unlock/password":
        if not auth.origin_ok(broker):
            broker._send(403, {"error": "csrf"})
            return True
        if not auth.login_allowed(ip):
            broker._send(429, {"error": "尝试过多，请稍后再试"})
            return True
        username = str(req.get("username") or "admin")
        master = str(req.get("master") or "")
        totp = str(req.get("totp") or "")

        # 锁定态（服务刚重启）：解密这一步本身就是密码校验
        kek = None
        if getattr(broker, "locked", False):
            data, kek, why = _try_unlock(master)
            if data is None:
                auth.note_login_fail(ip)
                audit({"event": "login_fail", "reason": why, "src": ip})
                broker._send(403, {"error": "主密码或 TOTP 错误", "reason": why})
                return True
        else:
            data = broker.vault

        ok, why = auth.login(data, username, master, totp)
        if not ok:
            # 密码对但动态码错：刚解出的库与密钥必须立即丢弃。
            # 不丢就等于「密码对了就解锁」，TOTP 形同虚设。
            _discard(kek)
            auth.note_login_fail(ip)
            audit({"event": "login_fail", "reason": why, "src": ip})
            broker._send(403, {"error": "主密码或 TOTP 错误", "reason": why})
            return True

        # 两道都过才真正解锁：把 vault 挂到进程上，并清理旧版遗留的 master.key
        if kek is not None:
            from . import server as server_mod
            server_mod.apply_vault(data, kek)
            try:
                from . import setup as setup_mod
                setup_mod._drop_legacy_master_key()
            except Exception:  # noqa: BLE001
                pass
            audit({"event": "vault_unlock", "src": ip})

        auth.clear_login_fail(ip)
        # 勾选「本窗口保持登录」→ remember=True：该会话的任何请求都续期。
        remember = bool(req.get("remember"))
        _tok, sess = auth.create(broker, ip, ua, remember=remember)
        audit({"event": "login_ok", "sid": sess["sid"], "device": sess["device"],
               "ip": ip, "src": ip, "remember": remember})
        broker._send(200, {"ok": True, "csrf": sess["csrf"],
                           "sid": sess["sid"], "remember": remember,
                           "idle_in": auth.idle_in(sess)})
        return True

    if path in ("/api/lock", "/api/logout"):
        # 语义就是登出：删会话 + 清 cookie。不碰 Broker.key —— 保险库仍解密着。
        s = auth.require(broker)
        if not s:
            return True
        auth.destroy(broker)
        audit({"event": "logout", "sid": s["sid"], "device": s["device"],
               "ip": ip, "src": ip})
        broker._send(200, {"ok": True})
        return True

    if path == "/api/session/touch":
        # 用户真实操作（点/键/滚）触发。touch=True 是**唯一**让不勾选档续期的入口：
        # 其余请求都不续，否则面板自己的轮询会让 15 分钟超时名存实亡。
        s = auth.current(broker, touch=True)
        if not s:
            broker._send(401, {"error": "login_required"})
            return True
        if not auth.csrf_ok(broker, s):
            broker._send(403, {"error": "csrf"})
            return True
        broker._send(200, {"ok": True, "idle_in": auth.idle_in(s)})
        return True

    if path == "/api/session/bye":
        # 由 navigator.sendBeacon 在页面 pagehide 时触发：只打一个「本窗口要关了」
        # 的标记，服务端 60 秒内没收到任何请求才真的清掉会话。sendBeacon 发不出
        # 自定义头，所以这里不能要求 CSRF；它只作用于自己那条会话，伪造它最多把
        # 自己标成待关闭，拿不到任何别的东西。
        auth.bye(broker)
        broker._send(200, {"ok": True})
        return True

    if path == "/api/sessions/prune":
        s = auth.require(broker)
        if not s:
            return True
        cleared = auth.prune_offline(broker)
        broker._send(200, {"ok": True, "cleared": cleared})
        return True

    if path == "/api/sessions/revoke":
        s = auth.require(broker)
        if not s:
            return True
        sid = str(req.get("sid") or "")
        if not sid:
            broker._send(400, {"error": "bad_sid"})
            return True
        hit, is_self = auth.revoke(broker, sid)
        if not hit:
            broker._send(404, {"error": "session_not_found"})
            return True
        broker._send(200, {"ok": True, "self": is_self})
        return True

    if path in ("/api/network/verify", "/api/tls/reissue"):
        if not auth.require(broker):
            return True

    if path == "/api/network/verify":
        # 域名默认取本机派生域名，不再依赖已移除的 WA_RP_ID
        domain = str(req.get("domain") or domains.host_domain())
        expected = str(req.get("expected_ip") or "") or None
        broker._send(200, network.verify_dns(domain, expected))
        return True

    if path == "/api/tls/reissue":
        try:
            domain = domains.validate_domain(str(req.get("domain") or ""))
        except ValueError:
            broker._send(400, {"error": "bad_domain"})
            return True
        port = broker.server.server_address[1]
        # SAN 走和初始化同一套推导（setup.san_lists）：全部物理网卡 IP + 本机域名，
        # 再把这次要用的域名塞到最前面。旧实现只写 local_ip + 127.0.0.1，换一块网卡
        # 或换域名访问就报 ERR_CERT_COMMON_NAME_INVALID —— 那是「名字对不上」，装根
        # 证书解决不了（REQ-142）。
        try:
            san_ips, san_dns = setup.san_lists(broker._public_base())
            if domain and domain not in san_dns:
                san_dns.insert(0, domain)
            tls.reissue_server_cert(
                config.CA_DIR,
                config.DATA_DIR / "tls",
                san_ips,
                san_dns,
            )
        except Exception as e:  # noqa: BLE001
            broker._send(500, {"error": f"换发失败：{type(e).__name__}: {e}"})
            return True
        origin = domains.origin(domain, port)
        save_vault_with_key(broker.key, broker.vault)
        audit({"event": "tls_reissue", "domain": domain, "src": ip})
        # 证书已落盘，但当前连接的 SSLContext 还是旧的；REQ-122 要求「立即生效」，
        # 这里复用 setup 的热加载：重建 SSLContext 并热替换，不重启进程。
        # 函数内导入避免与 server 模块的顶层循环依赖。
        from . import server as server_mod
        hot = False
        try:
            hot = bool(server_mod.reload_after_setup())
        except Exception as e:  # noqa: BLE001
            print(f"  [tls_reissue] 热加载失败：{type(e).__name__}: {e}", flush=True)
        broker._send(200, {
            "ok": True, "origin": origin, "restart_required": not hot,
        })
        return True

    return False
