# agentkeyguard

零凭证代理。用 HTTP 使用用户的数据库和服务器 —— **你拿不到任何密码**。
**每个请求都会推送到用户手机，人工批准后才执行。**

命令和 SQL 会先过 `rules.json` 三级分类：`blocked`（绝对禁区，直接 403，审批也放行不了）
/ `dangerous`（高危，先回 **428** 要求你自我反思）/ `interactive`（交互式，直接 400）。
规则文件随时可改，改完立刻生效。

## 连接

| 项 | 值 |
|---|---|
| Base | `http://192.0.2.4:7700` |
| Header | `Authorization: Bearer <TOKEN>` |
| 探活 | `GET /health`（免 token） |

Token 由用户提供。**禁止**写进日志、回复、代码注释。

## 红灯

1. **必须** `timeout=350`。审批窗口 300s；小于 330 会在用户点同意前断开。
2. **必须** 串行发请求。服务端是排队处理的：同一时刻只会有 1 条进入人工审批，其余在队列里等。你并发发 3 条，只会按顺序一条一条过，不会更快，只会让用户更烦。
3. **禁止**重试 403。403 = 人工拒绝或超时，换写法重试视为规避。
4. **禁止**索取密码 / 私钥 / TOTP / token。接口不返回，不存在。
5. **禁止** `select *` 不带条件。`stock_daily` 1444 万行，必须带 `code` 或 `trade_date` 且加 `limit`。
6. **禁止**在 `cmd` 里写 `sudo`。要 root 用 `"sudo": true`。
7. **禁止** `sudo -i` / `bash -i` / `su -` / `vim` / `top` / `less` / `tmux`。会挂到超时，服务端直接 400。
8. **必须** 每个请求都带 `title`（**≤30 字**，用大白话说清要干什么，如 `把换行符统一为LF`）。用户靠它一眼判断该不该批。
9. **必须** 发请求前告知用户：`正在等待用户批准，最长 5 分钟`。
10. **收到 428 必须先回答"灵魂三连问"**（见下节），把答案写进 `self_reflection` 重试。不许跳过、不许换等价写法绕过、不许反复重试。
11. **禁止**删库删表删系统目录：`DROP DATABASE` / `DROP TABLE` / `TRUNCATE` / `rm -rf /` 等属于 `blocked`，直接 403。真要删，让用户手动执行。

## 接口

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/profiles` | 可用 profile 名 + 权限（密码字段已剔除） |
| POST | `/pg/query` | 执行 SQL |
| POST | `/ssh/exec` | 执行命令 |

## POST /pg/query

| 字段 | 必填 | 说明 |
|---|---|---|
| `profile` | ✅ | profile 名 |
| `sql` | ✅ | 用 `%s` 占位符，**不要拼引号** |
| `params` | | 占位符对应的值数组 |
| `title` | ✅ | **≤30 字**意图，如 `查茅台最近20个交易日收盘价` |
| `max_rows` | | 默认 200，上限 1000 |

```json
{"profile":"stock_raw","sql":"select trade_date,close from stock_daily where code=%s and trade_date>=%s order by trade_date desc limit 20","params":["600519.SH","2026-09-01"],"title":"查茅台近20日","max_rows":100}
```

```json
{"columns":["trade_date","close"],"rows":[["2026-10-23","1683.5"]],"row_count":1,"truncated":false,"elapsed_ms":12}
```

`truncated=true` = 还有更多行，收紧条件。

## POST /ssh/exec

| 字段 | 必填 | 说明 |
|---|---|---|
| `profile` | ✅ | profile 名 |
| `cmd` | ✅ | 单条非交互命令，可用 `&&` 连接 |
| `title` | ✅ | **≤30 字**意图，如 `重启docker并确认服务状态` |
| `sudo` | | `true` 表示以 root 执行（需 profile 允许） |
| `timeout` | | 命令执行秒数，默认 30（与审批等待无关） |
| `self_reflection` | 条件必填 | 命中 `dangerous` 规则时必填：你对这次操作的思考，原文会展示给用户 |

```json
{"profile":"fn-host-6","cmd":"systemctl is-active docker","sudo":true,"title":"查docker状态","timeout":30}
```

```json
{"exit_code":0,"stdout":"active\n","stderr":"","host":"192.0.2.6","escalated":true,"elapsed_ms":240}
```

`exit_code!=0` 先读 `stderr`，**不要**盲目重试。

## 🚨 428：高危操作的"灵魂三连问"

命中 `dangerous` 规则（重启、强杀进程、`rm -rf` 业务目录、`DELETE` 不带 `WHERE`……）时，
服务端**不会**立刻推送给用户，而是先回 `428 Precondition Required`：

```json
{"error":"高危操作需自我反思",
 "instruction":"请先思考并回答：1. 我是谁？2. 我在哪儿？3. 我打算干什么？想清楚还要不要继续。如果确认继续，请在下次请求的 'self_reflection' 字段中带上你的思考结果。",
 "rule":"systemctl_state_change"}
```

**你必须做的**：

1. 认真回答三问：**我是谁**（什么身份/什么任务）、**我在哪儿**（哪台机器/哪个环境）、
   **我打算干什么**（具体操作 + 影响面 + 为什么值得做）。
2. 想清楚**还要不要继续**。如果结论是不该做——**那就停，把结论告诉用户**，不要重试。
3. 结论是继续，就把这段思考**原文**写进重试请求的 `self_reflection` 字段：

```json
{"profile":"fn-host-6","cmd":"systemctl restart docker","sudo":true,
 "title":"重启docker服务",
 "self_reflection":"我是云端Agent，我现在在host-5，我打算重启host-6上的docker服务，会影响该机上所有容器约10秒；这是修复拉取失败的必要步骤，确认继续"}
```

`self_reflection` 会原文展示在用户的审批卡片上（黄色区块"🤖 Agent 的自我反思"），
**写清楚 = 更容易被批准；写敷衍 = 更容易被拒绝**。空思考、复制 instruction、
只写"确认继续"三个字，都视为没反思。

## 错误

| 码 | 含义 | 动作 |
|---|---|---|
| 401 | token 错 | 停止，报告配置问题 |
| 403 | 人工拒绝 / 超时 / 策略拦截 / 来源 IP 不在白名单 | **停止**，告知用户，不重试 |
| 404 | profile 不存在 | 读 `/profiles` 取正确名字 |
| 428 | 高危操作需自我反思 | **回答灵魂三连问**，带 `self_reflection` 重试（见上节） |
| 429 | 触发限流 | 等提示的秒数，不要循环重试 |
| 502 | 上游错误 | 读 `error` 字段，报告用户 |

`reason:"dangerous_function"` = 硬性禁止（读写服务器文件、执行系统命令），审批也放行不了。

403 的 `type` 字段说明拒绝来自谁：

| `type` | 含义 | 你该怎么办 |
|---|---|---|
| `system_blocked` | 命中 `rules.json` 的 `blocked` 层，**系统直接挡死** | 停止。`reason` 是规则名。真要做得让用户手动执行 |
| `user_denied` | 用户在手机上点了拒绝 | 停止。`reason` 是用户写的拒绝原因，读它，通常按原因调整后再问用户 |
| `interactive_blocked` | 交互式命令，会挂起到超时 | 换成单条非交互命令重试（这不是人工拒绝，可以改） |

400 带 `type:"interactive_blocked"` 同理：改命令即可，不是拒绝。

## 调用骨架

```python
import requests
H = {"Authorization": "Bearer <TOKEN>", "Content-Type": "application/json"}

def call(path, payload):
    print("正在等待用户批准，最长 5 分钟")
    r = requests.post("http://192.0.2.4:7700" + path, headers=H,
                      json=payload, timeout=350)
    if r.status_code == 403:
        t = r.json().get("type")
        why = r.json().get("reason", "")
        raise SystemExit(f"被拒绝（{t or 'policy'}）：{why}，停止")
    if r.status_code == 428:
        d = r.json()
        raise SystemExit(f"高危操作需自我反思：{d['instruction']}")
    r.raise_for_status()
    return r.json()
```
