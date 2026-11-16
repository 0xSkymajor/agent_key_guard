# agentkeyguard · 架构与运维（当前实现）

> 基线：**v1.4.0**（2026-11-02；1.4.1-rc 系列的界面微调不改变本文的结构描述）
> 读者：要改这份代码的人。这里只写**现在真实跑着的东西**，不写历史。
> 相关文档：设计意图与取舍见 [`design/AgentKeyGuard-需求文档.md`](design/AgentKeyGuard-需求文档.md)；

---

## 代码规模（v1.4.1，2026-11-02 实测）

| 类别 | 文件 | 行数 | 占比 |
| --- | --- | --- | --- |
| 核心后端（`src/agentkeyguard/*.py`：服务、审批、保险库、适配器、CLI、自检） | 34 | 10,669 | 67.3% |
| 视觉 / 前端（`templates/*.html`，含内联 CSS 与 JS） | 3 | 3,660 | 23.1% |
| 工程脚本（`tools/`） | 6 | 692 | 4.4% |
| 打包与运维（`debian/`） | 14 | 825 | 5.2% |
| **代码合计** | **57** | **15,846** | **100%** |

- 视觉的 3,660 行里：HTML 结构约 708 行、内联 CSS 881 行、内联 JS 2,071 行。
- 规则文件 `broker/rules.json` 另有 99 行（配置，不计入代码）。
- 文档（`docs/**/*.md` + README/SKILL）共 13,195 行，不计入代码。
- 历史遗留：`broker/agentkeyguard.py` 是 1.x 的单文件实现（7,222 行），打包不包含，开源前删除（git 历史保留）。

---

## 1. 一句话

一个跑在家庭内网 7700 端口的常驻服务，站在 **AI Agent** 和 **真实凭证** 之间：
Agent 只能发「意图」（查这个库、在这台机器跑这条命令），凭证由服务端解密后代为使用，
高危动作必须由主人在手机上点同意。**AI 拿不到任何密码、私钥或 token。**

---

## 2. 威胁模型：只防一件事

防**「被 AI 顺手拿走凭证，或借 AI 的手把机器搞坏」**。这里「AI」不假设是善意的，也不假设运行它的环境没被攻破——包括云端模型供应商、中转站和不明来源的 API。不防：

| 不防 | 原因 |
| --- | --- |
| root | root 能读进程内存、能改二进制。`vault-secret` 那层只挡「拿到服务用户权限但不是 root」 |
| 物理接触 | 拆盘拿走 `vault.enc` 也解不开，但能直接改代码 |
| 主人的手机被拿走 | 审批是最后一道闸，闸门在手机上 |
| 内网嗅探 | 已全量 HTTPS；HTTP 侧只有证书落地页，业务接口一律 `403 https_required` |
| 上下文数据本身 | 代码、文档、对话内容会经过模型方/中转站，AKG 只保证凭证不进入这条链路 |

**前提假设（写清楚，避免误读）**：

- 云端模型供应商可能恶意，也可能已被攻破；中转站会看到全部上下文；
- Agent 会被提示注入或上下文漂移影响；
- 本机磁盘（`.env`、私钥、token 文件）对 Agent 进程可读。

结论只有一句：**凭证与高危动作必须离开「Agent + 模型」这条链路。**

对应的三条硬不变量：

1. **磁盘上没有任何能解密的东西**。盐在密文头部，KEK 由主密码登录时现算，进程退出即消失。
2. **凭证明文只在使用的那一瞬间存在于内存**，用完立刻清零（`bytearray` 覆写），绝不进日志、不进出口、不进 argv。
3. **危险动作没有「AI 自己决定」这条路径**。403 直接拒绝不给审批选项，428 先自审再审批。

---

## 3. 部署形态

单个 Debian 包（`dpkg-buildpackage` 打，Gitea Packages 分发），装完即 systemd 服务。

```
[AI Agent] --HTTPS:7700--> [agentkeyguard 服务 root→降权 agentkeyguard]
                                  ├── 解密 vault.enc（主密码在登录时现算 KEK）
                                  ├── 按凭证类型代连目标（pg/mysql/redis/ssh/git）
                                  └── 高危动作 → 推送手机 → 等批准
[主人浏览器] --HTTPS:7700--> [控制台 / 审批台 / 初始化向导]
```

| 项 | 值 |
| --- | --- |
| 单元 | `agentkeyguard.service`，`Type=simple`，`User=agentkeyguard` |
| 启动命令 | `/usr/bin/agentkeyguard serve`（launcher → `/usr/lib/agentkeyguard/venv/bin/python -m agentkeyguard`） |
| 环境文件 | `/etc/agentkeyguard/agentkeyguard.env`（`EnvironmentFile`） |
| 端口 | `7700`，HTTP 与 HTTPS **同端口**（先握手判断，非 TLS 走 HTTP 分支） |
| 日志 | `journalctl -u agentkeyguard -f`，`SyslogIdentifier=agentkeyguard` |

### 3.1 目录与权限

| 路径 | 内容 | 权限要点 |
| --- | --- | --- |
| `/etc/agentkeyguard/rules.json` | 内置三层规则（dpkg conffile） | `0644 root:agentkeyguard`，**面板永不写它** |
| `/etc/agentkeyguard/agentkeyguard.env` | 服务环境变量 | `0600 root:root` |
| `/etc/agentkeyguard/vault-secret` | 服务端密钥（可选加固层） | `0640 root:agentkeyguard`，**与 vault 分开** |
| `/var/lib/agentkeyguard/vault.enc` | 加密后的全部数据 | `0600 agentkeyguard` |
| `/var/lib/agentkeyguard/vault.meta` | KDF 模式侧车（不含秘密） | 明文，`{"kdf":"scrypt"}` 或 `"scrypt+secret"` |
| `/var/lib/agentkeyguard/audit.log` | JSONL 审计 | 追加写，不轮转（读尾部固定块） |
| `/var/lib/agentkeyguard/tls/` | 运行期证书（`server.crt/key`） | 每次启动按 CA 复用或重签 |
| `/var/lib/agentkeyguard/portal-state.json` | `owner:true/false`，判定「有没有管理员」 | 不存密钥 |
| `/var/lib/agentkeyguard-ca/` | **持久 CA**（`ca.crt` `ca.key`） | `0700`，`ca.key` `0600`，`remove/purge 不删` |

> CA 单独放 `/var/lib/agentkeyguard-ca` 的原因：重装数据目录不该让全家的根证书作废；
> 反之「彻底重置」必须明确删掉它。注意 systemd 的 `ReadWritePaths` 必须同时放行这两个目录，
> 否则首次签发服务器证书会 `OSError 30`（REQ-109 踩过）。

### 3.2 systemd 加固（现行值）

```
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/agentkeyguard /var/lib/agentkeyguard-ca
ProtectKernelTunables/Modules/ControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
LimitCORE=0            # 崩溃不把解锁态的明文堆写进 core
MemorySwapMax=0        # 密钥页不落 swap
ProtectProc=invisible  # 看不到别人的 /proc
ProcSubset=pid
```

**不要改回 `LoadCredential=vault_secret:...`**：源文件缺失时 systemd 会直接拒绝启动，
而 AKG 自己是唯一管理入口，等于把人锁在门外（1.2.5 的真实事故）。现在服务自己读文件，
最坏情况只是这一层不生效。

---

## 4. 模块地图

`src/agentkeyguard/`（31 个模块）。无 Web 框架（`http.server` + 内联模板）；
运行时依赖只有五个：`cryptography` `pg8000` `pymysql` `redis` `paramiko`：

| 层 | 模块 | 职责 |
| --- | --- | --- |
| 入口 | `cli.py` `__main__.py` | `serve` / `selftest` / 认证等子命令 |
| 服务 | `server.py` | `ThreadingHTTPServer`，全部路由分发、`/api/*` 装配、来源 IP 门禁 |
| 会话 | `auth.py` `unlock.py` `unlock_api.py` | 登录/解锁、会话表、TOTP、证书换发、会话管理接口 |
| 加密 | `crypto.py` `memlock.py` | scrypt/HKDF、AES-GCM blob、内存锁定与清零 |
| 存储 | `storage.py` | vault 读写、审计追加、`read_audit_tail` 尾部倒读 |
| 权限 | `rules.py` `approval.py` | 三层规则引擎、428 自审、审批队列与推送 |
| 凭证 | `adapters*.py`（pg/mysql/redis/ssh/git）`agents.py` `services.py` | 五类凭证的建/测/执行；Agent 密钥与服务 token |
| 通道 | `pg_handler.py` `ssh_handler.py` `git_handler.py` | 三个执行器的请求解析与结果整形 |
| 表现 | `dashboard.py` `setup_ui.py` `templates/` | 单文件 HTML（内联 CSS/JS），无构建 |
| 其他 | `tls.py` `network.py` `domains.py` `notify.py` `skill.py` `setup.py` `transport.py` | 证书、网卡探测、域名、推送渠道、`/skill` 渲染 |

**改动的边界约定**：新增一种凭证类型 = 新增一个 `adapters_xxx.py` + 在 `adapters.load_builtin()`
加一行；`server.py` 不需要改（REQ-106 的核心约束）。新增页面级接口才动 `server.py`。

---

## 5. 加密与密钥派生

`vault.enc` 是**单个二进制 blob**，不是 JSON：

```
MAGIC(8B "VBRKv1\0\0") | salt(16B) | nonce(12B) | AESGCM(明文JSON)
AAD = b"vaultbroker-vault-v1"     ← 改了老库永远解不开，改名时绝不改动
```

派生链：

```
KEK0 = scrypt(主密码, salt, n=2^15, r=8, p=1, dklen=32)      # 约 100ms / 32MiB
KEK  = hkdf_mix(KEK0, /etc/agentkeyguard/vault-secret)        # 有该文件时；HKDF-SHA256
明文 = AESGCM(KEK).decrypt(blob, AAD)
```

- **没有 `master.key`**：以前把 KEK 明文写在 vault 旁边，等于把钥匙插在锁孔上（REQ-306 删掉）。
- **密码对不对不需要单独校验值**：AES-GCM 认证失败就是密码错。
- **`vault-secret` 丢了就解不开**，必须备份；老库升级不会自动启用这一层。
- 解锁后的 `Broker.key`（KEK）常驻内存直到进程退出；`/api/logout` **不碰它**——
  退出登录只是丢 cookie，Agent 请求与审批队列完全不受影响。

---

## 6. 会话与登录

| 项 | 现状 |
| --- | --- |
| 登录要素 | 用户名 + 主密码 + 6 位 TOTP（`30s` / 6 位 / 含重放防护） |
| cookie | `akg_session`，**会话级**（不写 `Max-Age`），`Secure` `HttpOnly` `SameSite=Strict` `Path=/` |
| 计时 | 只有一个滑动 `idle`，两档：不勾「本窗口保持登录」`900s`；勾选 `14400s`。**没有绝对过期** |
| 续期 | 勾选档任何请求都续；不勾档只认 `POST /api/session/touch`（真实操作，60 秒节流） |
| 上限 | `SESSION_MAX=8`，超限淘汰 `seen` 最早的一条并落 `session_evict` |
| 关页 | `pagehide` → `sendBeacon('/api/session/bye')` 打标记，`60s`（`SESSION_BYE_GRACE`）内无任何请求才清 |
| 在线 | `now - seen <= 90s`（`SESSION_ONLINE`）才算在线；列表里其余标「已离线」 |
| 退出 | `POST /api/logout`（`/api/lock` 是别名）：删会话 + 清 cookie + 审计 `logout` |
| 限流 | 同一 IP `8 次 / 60 秒`；连续失败 3 次锁 300 秒（`PORTAL_*`） |

**`423 vault_locked` 与登录态无关**：它是「保险库还没解锁」（服务重启后），
给 Agent 看的含义是「等着，别重新申请密钥」。两者语义不要混。

---

## 7. 请求链路：从 Agent 到目标

```
POST /ssh/exec  (Authorization: Bearer <agent_token>)
  1. 校验 token 哈希 → 得到 agent 签名（Claude-桌面版）
  2. 来源 IP / HTTPS 门禁
  3. 规则引擎分类（blocked → 403 ｜ dangerous → 先 428 ｜ interactive → 400）
  4. 进审批队列：rid = uuid4()[:10]，推手机，`APPROVAL_TIMEOUT=300s` 等事件
  5. 批准 → adapters_ssh.execute()：解密凭证 → 代连 → 执行 → 结果脱敏
  6. 拒绝/超时 → 403 + explain；审计落 deny
```

关键实现点：

- **审批是阻塞等待 + 事件唤醒**，不是轮询；同一时刻只有一条进工作台，其余在队列（并发请求真的并行挂起，各请求各自的 `ev.wait`）。
- **凭证注入不进 argv**：ssh 走 **paramiko 内存认证**（密码/私钥都在 Python 对象里，不落临时文件、不起 `ssh` 子进程）；
  git 用 `GIT_ASKPASS` 小脚本 + 环境变量（URL 里永不出现 token）；数据库密码只走连接参数。
- **数据库只读**：`SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY` + 回滚兜底。
- **`title` 原样显示在审批卡片上**，所以 Skill 明确要求「中文大白话 ≤30 字」，未传时按 `_KIND_CN` 兜底成「执行命令 · 8.7」这类。

---

## 8. 三级规则与审批

规则文件 `/etc/agentkeyguard/rules.json` 三层，**面板只读不写**；用户的开关与自定义规则存在 vault 里（覆盖层），
解锁成功与每次保存后注入引擎并强制重编译（`set_overrides(force=True)`）。

| 层 | 命中后 | 用户能怎么改 |
| --- | --- | --- |
| `blocked` | 直接 403，**不弹审批、不给「同意」选项** | 可关闭（= 不拦截）、可降到 428；自保护类不可关 |
| `dangerous` | 先回 428 要 Agent 回答「我是谁/在哪/要干什么」，答完才推手机 | 可关闭自审（**审批照弹**）、可升到 403 |
| `interactive` | 400，直接拒绝（会挂住的命令） | 不出现在 UI，固定 |

- 放宽（关闭 blocked、降级、删自定义规则）要**主密码 + 动态码双因子**；收紧免认证。
- 搬层是「改覆盖层」，不是改 conffile，所以 `dpkg` 升级不会和用户配置打架。
- 审批按「同一签名 + 同一类型 + 同一凭证」折叠成一组，可一次批完（REQ-138）。

---

## 9. 凭证适配器

五类，统一四条约定：`build_profile` / `test` / `execute` / `executes`。

| kind | 执行路由 | 说明 |
| --- | --- | --- |
| `pg` | `/pg/databases` `/pg/query` | 一个账号一条凭证，库名由请求带（REQ-147） |
| `mysql` | `/mysql/databases` `/mysql/query` | 同上，`%s` 占位符 |
| `redis` | `/redis/cmd` | 读命令直放，写命令审批，`FLUSHALL/CONFIG/EVAL/KEYS` 拒绝 |
| `ssh` | `/ssh/exec` | 单条非交互命令；root 用 `"sudo": true`，不写进命令 |
| `git` | `/git/exec` | 凭证只登记「站点 + 用户名 + Token」，仓库 url 由请求带并做同源校验（REQ-107） |

**「账号 / HTTP」类型已删除**：只有连通性测试、没有执行通道，说不清指向哪个系统。

---

## 10. 控制台（表现层）

v1.4 起所有页面共用一套深色 token；设计稿与可预览版本在 `design/` 分支（`tokens.css`、`*-preview.html`），架构图见 `docs/diagrams/`。

| 入口 | 生成方式 | 说明 |
| --- | --- | --- |
| `/login` | `templates/login.html` + `dashboard.login_page()` | 独立登录页：品牌区 + 用户名/密码/六格动态码；逻辑仍走 `/api/unlock/password`，`__LOCKED_NOTE__` 承载锁定态提示 |
| `/setup`、`/setup/done` | `setup_ui.py` | 三步向导（主密码 / TOTP / 存储与推送）+ 一次性完成页；二维码用本地 `qrcode.min.js` |
| `/dashboard` | `templates/dashboard.html` | 单页五 tab：审批工作台 / 凭证 / 服务 / Agent 接入 / 设置；所有数据由 `/api/*` 注入 |
| `/approve` 系列 | `dashboard.py` 的 `_page_pending` / `_page_decided` / `_page_gone` | 手机审批页三种状态；表单字段 `id` / `decision` / `reason` 不变 |
| `/service-spec`、`/skill` | `server.py` 直接读 `templates/SERVICE_DEV_SPEC.md.tmpl` / `skill.render()` | 两份公开 Markdown：服务开发规范（模板里的 `<网关地址>` 会替换成真实地址，`?download=1` 才是附件）与 Agent 接入说明；都「打开即读」，方便直接丢给 AI |
| `/favicon.svg`、`/favicon.ico` | `server.py` 读取 `templates/favicon.svg` | 浏览器标签页图标；bootstrap 与正常模式都可达 |

改界面的硬规矩：

- **只动表现层**，不碰接口与状态机；`dashboard.html` 的 `<script>` 一次只做 CSS/结构级替换，改完必须跑 selftest；
- 品牌 Logo 以 `templates/logo.svg` 为准（setup 页读取该文件；登录页/控制台内联）；
- selftest 含界面断言（登录页六格、tab 文案、审批页转义、favicon 路由等），当前 **85 项**必须全绿。

## 11. 审计

`/var/lib/agentkeyguard/audit.log`，一行一条 JSON，只追加不轮转。常见事件：

`login_ok` `login_fail` `logout` `session_expired` `session_revoke` `session_bye` `session_prune` `session_evict`
`approve` `deny` `reflect`（428 自审） `ssh.exec` `pg.query` `git.exec`
`skill_ticket_issue` `skill_ticket_ok` `skill_ticket_fail` `rule_change` `reveal` `bark_test`

- 近期记录页用 `storage.read_audit_tail(limit, events)`：`seek(0,2)` 按 64KB 块倒读，**禁止整文件读入**。
- 审计**不含**凭证明文、token、主密码；只写 `sid` / `device` / `ip` / `request_id` / 动作摘要。

---

## 12. 运维手册

```bash
# 状态与版本
systemctl status agentkeyguard
curl -sk https://192.0.2.10:7700/health          # {"ok":true,"version":"v1.4.0","initialized":true,"locked":false,"profiles":[...]}

# 升级（禁止 -r/-P，数据目录要留）
dpkg -i agentkeyguard_1.3.6_amd64.deb
# ⚠ 装完服务重启 → 保险库回到锁定态，业务接口 423，需要用浏览器登录一次解锁

# 日志
journalctl -u agentkeyguard -n 200 --no-pager
journalctl -u agentkeyguard -f

# 看审计尾部（不要 cat 整个文件）
tail -n 50 /var/lib/agentkeyguard/audit.log

# 自检（85 项；需源码目录 + PYTHONPATH）
cd /home/dev/agent_key_guard
PYTHONPATH=src python3 -c "import sys;sys.argv=['akg','selftest'];from agentkeyguard.cli import main;main()"

# 彻底重置（连根证书一起清，两步都要，postrm 不会删 CA）
systemctl stop agentkeyguard
rm -rf /var/lib/agentkeyguard /var/lib/agentkeyguard-ca /etc/agentkeyguard
```

上传 Gitea `PUT /api/packages/HomeLab/generic/agentkeyguard/<ver>/<file>`（basic auth `agent_bot:<token>`）。
`.deb` 永远不要进源码树。

---

## 13. 已知限制（诚实清单）

1. **root 挡不住**：能读进程内存就能拿到解锁态的 KEK 与凭证（`memlock` 只提高门槛）。
2. **SQL 分类是正则不是解析器**：宁可误判为写（多弹一次窗），兜底靠只读会话 + 回滚。
3. **关窗即退是尽力而为**：`pagehide` + `sendBeacon` 在崩溃、断电、强杀时发不出来，靠所在档位 idle 兜底。
   Chrome「继续上次会话」会恢复会话 cookie，也必须承认。
4. **`/skill` 是公开可读的**：带任何 Bearer 都返回 200，**不能用来判 token 有效性**；验 token 必须用执行类接口。
5. **一次性接入链接只有一次**：核销即焚，丢了只能让主人重新生成。
6. **TOTP 密钥只在初始化第 2 步出现一次**，完成页不回显（REQ-151）；设置页没有重绑入口，换手机目前只能清库重装。
7. **会话在内存**：服务重启即全部失效（这也避免了 token 落盘）。

---

## 14. 自检

`selftest.py` 85 项，覆盖：加解密往返、KDF 模式、TOTP、会话两档续期与关页宽限、规则三层与覆盖层、
审批折叠与批量、五类适配器建模、证书 SAN、路由与鉴权、以及**启动冒烟**（真起一个子进程请求 `/health`）。

> 教训：79 项断言曾经全是纯函数，没有一条真的启动过服务，于是 `cmd_serve` 引用已删变量这种
> 启动即崩的问题能一路全绿（1.2.7）。加断言时优先问「这条能不能在真实进程里跑」。

---

## 附录 A：`stock_raw` 库事实（演示 profile 用）

`stock_daily`：`code` `trade_date`（主键）`open` `high` `low` `close` `volume` `pre_close` `change` `pct_chg` `amount`，
约 **1444 万行**。索引：主键 `(code, trade_date)` 为主力；`idx_stockdaily_code` 冗余（主键前缀列）；
`idx_stockdaily_tradedate` 供单日全市场扫描。

```sql
-- ✅ 走主键
select trade_date, close from stock_daily
where code = %s and trade_date between %s and %s order by trade_date limit 250;

-- ✅ 走日期索引（单日全市场）
select code, close, pct_chg from stock_daily where trade_date = %s limit 5000;
```

**规矩**：除聚合统计外，查询必须带 `code` 或 `trade_date` 并带 `limit`。
