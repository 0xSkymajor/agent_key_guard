# -*- coding: utf-8 -*-
"""Web 初始化页面：分步向导 + TOTP 二维码 + 一次性配置页。"""
from __future__ import annotations

import base64
from pathlib import Path
import html

from . import network

_LOGO = (Path(__file__).with_name("templates") / "logo.svg").read_text(encoding="utf-8")

_CSS = """
/* AgentKeyGuard 1.4 · 初始化向导 / 完成页 */
:root{--text:#EBF2FF;--t2:#A8B8D8;--t3:#6C7C9F;--t4:#6C7C9F;
  --line:rgba(143,208,255,.14);--line2:rgba(143,208,255,.30);
  --ok:#3BE0A8;--warn:#FFC24B;--danger:#FF7A93;--brand:#8FD0FF;
  --mono:ui-monospace,"JetBrains Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;padding:26px 18px 60px;color:var(--text);font-size:13.5px;line-height:1.6;
  font-family:"PingFang SC","HarmonyOS Sans SC","Microsoft YaHei",system-ui,-apple-system,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
  background:
    radial-gradient(900px 520px at 8% -8%,rgba(77,107,254,.20),transparent 60%),
    radial-gradient(760px 520px at 104% 26%,rgba(108,77,254,.12),transparent 62%),
    linear-gradient(158deg,#060A24,#03050F 72%) fixed}
.wrap{max-width:560px;margin:0 auto}
.logo{width:64px;height:64px;margin:0 0 14px;display:block}
.logo svg{width:100%;height:100%;display:block;
  filter:brightness(1.5) saturate(1.05) drop-shadow(0 6px 20px rgba(77,107,254,.55))}
h1{font-size:24px;font-weight:700;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;font-weight:600;margin:0 0 6px}
p{margin:0 0 14px;color:var(--t3);font-size:13px;line-height:1.65}
p.sub{color:var(--t2);font-size:13px;margin-bottom:16px}

.pills{display:flex;gap:8px;margin:18px 0 16px}
.pill{flex:1;text-align:center;padding:8px 6px;border-radius:10px;font-size:12px;color:var(--t3);
  border:1px solid var(--line);background:rgba(255,255,255,.02);white-space:nowrap}
.pill.active{color:#061029;border-color:transparent;font-weight:700;
  background:linear-gradient(96deg,#8FD0FF,#5B8DFF)}

.card{background:linear-gradient(180deg,rgba(14,20,52,.62),rgba(8,11,32,.55));
  border:1px solid var(--line);border-radius:14px;padding:18px;margin:0 0 16px}
.card.hide,.hide{display:none!important}
/* 完成页两张卡包在一列里：桌面端不能各自 grid-row:1/span 6（会重叠） */
.cardcol{display:flex;flex-direction:column;gap:16px}
.cardcol > .card{margin:0}
/* 短状态页（失效 / 已关闭）：竖向居中，桌面端也不走双栏 rail */
body.short{display:flex;flex-direction:column;justify-content:center;min-height:100vh;min-height:100dvh}
body.short .wrap{display:block;max-width:520px;width:100%;margin:0 auto}

label{display:block;font-size:12px;color:var(--t2);margin:12px 0 6px;letter-spacing:.03em}
input,select{width:100%;padding:10px 12px;font-size:13.5px;border-radius:9px;border:1px solid var(--line);
  background:rgba(255,255,255,.035);color:var(--text);font-family:inherit;outline:none}
input:focus,select:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(77,107,254,.18)}
input[readonly]{font-family:var(--mono);font-size:11.5px;color:var(--t2)}
button{font-family:inherit;cursor:pointer;border:0;border-radius:10px;height:46px;padding:0 18px;
  font-size:14px;font-weight:600;color:#04152E;background:linear-gradient(96deg,#8FD0FF,#5B8DFF);
  box-shadow:0 8px 22px rgba(77,107,254,.28);margin-top:14px;width:100%}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--t2);box-shadow:none;height:38px;font-size:12.5px}
button:disabled{opacity:.55;cursor:not-allowed}
#gen{margin-top:6px}
#qr{margin:14px 0 0;display:flex;justify-content:center}
#qr table,#qr img,#qr canvas{background:#fff;padding:10px;border-radius:12px}

.hint{font-size:12px;color:var(--t3);line-height:1.6;margin:8px 0 0}
.err{color:var(--danger);font-size:12px;min-height:18px;margin:10px 0 0}
.warn{display:flex;gap:8px;align-items:flex-start;background:rgba(255,194,75,.07);
  border:1px solid rgba(255,194,75,.28);border-radius:10px;padding:10px 12px;margin:0 0 16px;
  color:#FFE9C7;font-size:12px}
.hash{color:var(--warn);font-weight:700}
.tag{display:inline-block;font-family:var(--mono);font-size:10px;padding:1px 7px;border-radius:999px;
  color:var(--brand);background:rgba(143,208,255,.08);border:1px solid rgba(143,208,255,.24);
  margin-left:6px;vertical-align:1px}
.secretset{margin:14px 0 0;padding:12px;border-radius:12px;background:rgba(255,255,255,.03);
  border:1px solid rgba(143,208,255,.10)}
.secretset b{display:block;font-size:11px;color:var(--t3);margin-bottom:4px;font-weight:500}
.secret{font-family:var(--mono);font-size:12.5px;color:#DCEAFF;word-break:break-all;line-height:1.7}
.secret.hide{display:none}
.secretset button{width:auto;height:32px;margin:8px 8px 0 0;padding:0 14px;font-size:12px;
  background:transparent;border:1px solid var(--line);color:var(--t2);box-shadow:none}
.secretset button:hover{border-color:var(--line2);color:var(--text)}
.card h2:not(:first-child){margin-top:18px}
.mini{font-size:11px;color:var(--t4);margin-top:6px}
dl{border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:0 0 16px;background:rgba(255,255,255,.02)}
dt{font-size:11px;color:var(--t3);padding:9px 12px 0}
dd{margin:2px 12px 9px;font-size:12.5px;color:#DCEAFF;word-break:break-all}
dd code{font-family:var(--mono);font-size:11px;color:#C4E7FF}
.dl-btn{display:block;text-align:center;padding:12px;border-radius:10px;border:1px solid var(--line);
  color:var(--text);text-decoration:none;background:rgba(255,255,255,.03);margin:10px 0 0;font-size:13px}
.dl-btn:hover{border-color:var(--line2)}
.trust{margin:14px 0 0;padding:12px;border-radius:12px;background:rgba(255,255,255,.02);
  border:1px dashed rgba(143,208,255,.22);font-size:11.5px;color:var(--t3);line-height:1.7}
.trust b{color:var(--t2)}
@media (max-width:520px){
  body{padding:20px 14px 48px}
  h1{font-size:21px}
  .pills{gap:6px}
  .pill{font-size:11.5px;padding:7px 4px}
}

/* setup rail：桌面左侧步骤栏，移动折回顶部 pills */
@media (min-width:901px){
  body{display:flex;flex-direction:column;min-height:100dvh;padding:40px 24px}
  .wrap{margin:auto;max-width:820px;display:grid;grid-template-columns:236px minmax(0,1fr);column-gap:26px;align-items:start}
  .logo{grid-column:1;grid-row:1;width:52px;height:52px;margin:0 0 8px}
  h1{grid-column:1;grid-row:2;font-size:21px;margin:0 0 2px}
  .sub{grid-column:1;grid-row:3;font-size:11.5px;margin:0 0 18px}
  .pills{grid-column:1;grid-row:4;flex-direction:column;gap:6px;margin:0}
  .pill{text-align:left;padding:9px 12px}
  .card{grid-column:2;grid-row:1 / span 6;margin:0}
  .cardcol{grid-column:2;grid-row:1 / span 6}
  .cardcol > .card{grid-column:auto;grid-row:auto}
  #err{grid-column:2}
}
"""

_SETUP = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#05081C">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<title>AgentKeyGuard 初始化</title><style>__CSS__</style></head><body>
<div class="wrap">
  <div class="logo">__LOGO__</div>
  <h1>AgentKeyGuard</h1>
  <p class="sub">Web 初始化 · 守护云端 AI 的安全网关</p>
  <div class="pills">
    <span class="pill active" id="pill1">1 · 主密码</span>
    <span class="pill" id="pill2">2 · TOTP</span>
    <span class="pill" id="pill3">3 · 存储</span>
  </div>

  <section class="card" id="step1">
    <h2>创建管理员</h2>
    <p>这是第一次打开，首次完成配置的人将成为管理员。用户名、密码和 TOTP 用于登录 Dashboard。</p>
    <label>管理员用户名</label><input id="username" value="admin" autocomplete="username" placeholder="admin">
    <label>主密码（至少 12 位，含大小写与符号）</label><input id="master" type="password">
    <label>确认主密码</label><input id="master2" type="password">
    <button onclick="step1()">下一步</button>
  </section>

  <section class="card hide" id="step2">
    <h2>绑定 TOTP</h2>
    <p>用认证器扫码，或手动输入密钥；输入 6 位码完成绑定。</p>
    <button id="gen" onclick="genTotp()">生成 TOTP 密钥</button>
    <div id="qr" class="hide"></div>
    <div id="totpBox" class="hide">
      <label>密钥（手动输入用）</label><input id="secret" readonly>
      <label>otpauth</label><input id="otpauth" readonly>
      <label>6 位验证码</label><input id="otp" inputmode="numeric" maxlength="6" placeholder="000000">
      <button onclick="step2()">验证并继续</button>
    </div>
  </section>

  <section class="card hide" id="step3">
    <h2>存储与推送</h2>
    <p>Bark 可留空；Public Base 用于生成审批链接。</p>
    <label>Bark Key / 完整 URL（可留空）</label><input id="bark" placeholder="https://api.day.app/xxxx">
    <label>Public Base（手机可访问地址，局域网 IP 或已解析域名）</label><input id="base" placeholder="https://__LANIP__:7700">
    <label>首个接入密钥的名字（可留空）</label><input id="agentName" placeholder="如 Claude-桌面版 / 终端B" maxlength="32">
    <p class="hint">完成页会给一条一次性接入链接，10 分钟有效、只能打开一次；名字会显示在审批卡片上。</p>
    <label>审批超时（秒）</label><input id="timeout" type="number" value="300" min="30" max="3600">
    <button onclick="step3()">完成初始化</button>
  </section>

  <div id="err" class="err"></div>
</div>
<script src="/setup/qrcode.min.js"></script>
<script>
const S = {username:'admin', secret:''};
const $ = (id) => document.getElementById(id);
function show(n) {
  [1,2,3].forEach(i => {
    $('step'+i).classList.toggle('hide', i !== n);
    $('pill'+i).classList.toggle('active', i === n);
  });
}
function err(m) { $('err').textContent = m || ''; }
const MSG = {
  weak_master: '主密码强度不足：至少 12 位，且需同时包含小写字母、大写字母与 ASCII 半角符号（如 ! @ # - _）',
  bad_username: '用户名只能包含 3-32 位字母、数字与 . _ -',
  bad_totp_secret: 'TOTP 密钥必须是至少 16 位 Base32 字符（A-Z 与 2-7）',
  totp_required: '请先完成 TOTP 绑定：扫码后输入一次 6 位验证码',
  already_initialized: '已完成初始化，不能重复配置；要重来请先清空数据目录',
  loopback_public_base: '这个地址只有本机能访问，手机打不开；请填写局域网 IP 或已解析的域名'
};
async function post(p, b) {
  const r = await fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(b)});
  const j = await r.json().catch(() => ({error:'bad json'}));
  // 优先用后端的中文 message；后端没给就查本地映射，绝不把内部错误码直接甩给用户
  if (!r.ok) throw new Error(j.message || MSG[j.error] || j.error || ('HTTP ' + r.status));
  return j;
}
async function step1() {
  err('');
  try {
    S.username = $('username').value.trim() || 'admin';
    const m = $('master').value, m2 = $('master2').value;
    if (m !== m2) throw new Error('两次主密码不一致');
    await post('/api/setup/username', {username:S.username});
    await post('/api/setup/master', {master:m});
    show(2);
  } catch (e) { err(e.message); }
}
async function genTotp() {
  err('');
  try {
    const j = await post('/api/setup/totp/new', {});
    S.secret = j.secret;
    $('secret').value = j.secret;
    $('otpauth').value = j.uri;
    $('qr').innerHTML = '';
    new QRCode($('qr'), {text:j.uri, width:220, height:220, correctLevel:QRCode.CorrectLevel.M});
    $('qr').classList.remove('hide');
    $('totpBox').classList.remove('hide');
    $('gen').classList.add('hide');
  } catch (e) { err(e.message); }
}
async function step2() {
  err('');
  try {
    const c = $('otp').value.replace(/\\D/g, '');
    if (c.length !== 6) throw new Error('请输入 6 位验证码');
    await post('/api/setup/totp', {secret:S.secret});
    await post('/api/setup/totp/verify', {secret:S.secret, totp:c});
    show(3);
  } catch (e) { err(e.message); }
}
async function step3() {
  err('');
  try {
    const bark = $('bark').value.trim();
    const base = $('base').value.trim();
    const name = ($('agentName') ? $('agentName').value.trim() : '');
    const t = parseInt($('timeout').value || '300', 10);
    await post('/api/setup/storage', {bark:bark, public_base:base,
      agent_name:name, timeout:t});
    const d = await post('/api/setup/finish', {});
    location.href = '/setup/done?token=' + encodeURIComponent(d.token);
  } catch (e) { err(e.message); }
}
show(1);
// 默认填服务器算出的局域网地址：location.hostname 在配置者从本机访问时是 127.0.0.1，
// 手机拿这个地址必然连不上（REQ-112）
$('base').value = 'https://__LANIP__:' + (location.port || '7700');
</script></body></html>"""

_DONE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentKeyGuard 配置完成</title><style>__CSS__</style></head><body>
<div class="wrap">
  <div class="logo">__LOGO__</div>
  <h1>配置完成</h1>
  <p class="sub">AgentKeyGuard 已初始化，以下信息只显示这一次</p>
  <div class="warn"><span class="hash">#</span>请立刻保存，刷新页面之后再也无法查看</div>

  <div class="cardcol">
  <section class="card">
    <h2>主密码<span class="tag">= 面板登录密码</span></h2>
    <div class="secretset">
      <code class="secret" id="masterBox" data-raw="__MASTER__" data-masked="1">••••••••••••</code>
      <button class="mini" type="button" id="eyeMaster" aria-label="显示主密码" aria-pressed="false">显示</button>
      <button class="mini" type="button" data-copy="__MASTER__">复制</button>
    </div>

    <p class="hint">动态码密钥已在第 2 步扫码时给出，本页不再重复显示——它长得像密钥，
      留在这里只会和下面的接入链接混淆。</p>

    <h2>访问地址</h2>
    <div class="secretset">
      <code class="secret">__URL__</code>
      <button class="mini" type="button" data-copy="__URL__">复制</button>
    </div>

    <h2>首个接入链接<span class="tag">给 AI 用，一次性</span></h2>
    <p>把这条链接发给 AI：它打开后同时拿到 Skill 文档与一条密钥（署名「__FIRST_NAME__」）。
       __FIRST_TTL__ 秒内有效、<b>只能打开一次</b>，打开即作废。</p>
    <div class="secretset">
      <code class="secret">__FIRST_LINK__</code>
      <button class="mini" type="button" data-copy="__FIRST_LINK__">复制</button>
    </div>

  </section>

  <section class="card">
    <h2>安装根证书<span class="tag">推荐</span></h2>
    <p>只用于让浏览器信任本机服务，不含客户端身份。手机要用 HTTPS 必须先装。</p>
    <div class="dl">
      <a class="dl-btn" href="/ca.crt">下载 ca.crt</a>
      <a class="dl-btn" href="/ca.mobileconfig">iPhone 描述文件</a>
    </div>
    <details class="trust"><summary>各系统安装步骤</summary>
      <p>iOS：设置 → 通用 → VPN 与设备管理 → 安装；再到 通用 → 关于本机 → 证书信任设置 → 开启完全信任。</p>
      <p>Android：设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书 → 选 ca.crt。</p>
      <p>Windows / macOS：双击 ca.crt 装到「受信任的根证书颁发机构」；macOS 设为始终信任。</p>
    </details>
    <a class="dl-btn" href="/dashboard?https=1">我已安装，切换到 HTTPS</a>
    <p class="hint">点上面按钮即刻生效，<b>不需要重启服务</b>。</p>
  </section>
  </div>
</div>
<script>
(function(){
  function flash(btn, text){
    var old = btn.getAttribute('data-label') || btn.textContent;
    btn.setAttribute('data-label', old);
    btn.textContent = text;
    setTimeout(function(){ btn.textContent = old; }, 1300);
  }
  function copy(text){
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
    return Promise.resolve();
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function(btn){
    btn.addEventListener('click', function(){
      copy(btn.getAttribute('data-copy')).then(function(){ flash(btn, '已复制'); })
        .catch(function(){ flash(btn, '复制失败'); });
    });
  });
  var box = document.getElementById('masterBox');
  var eye = document.getElementById('eyeMaster');
  var timer = null;
  function mask(){
    box.textContent = '••••••••••••';
    box.setAttribute('data-masked', '1');
    eye.textContent = '显示';
    eye.setAttribute('aria-label', '显示主密码');
    eye.setAttribute('aria-pressed', 'false');
  }
  if (box && eye) {
    eye.addEventListener('click', function(){
      if (box.getAttribute('data-masked') === '1') {
        box.textContent = box.getAttribute('data-raw');
        box.setAttribute('data-masked', '0');
        eye.textContent = '隐藏';
        eye.setAttribute('aria-label', '隐藏主密码');
        eye.setAttribute('aria-pressed', 'true');
        clearTimeout(timer);
        timer = setTimeout(mask, 30000);   // 30 秒无操作自动收回
      } else {
        clearTimeout(timer);
        mask();
      }
    });
  }
})();
</script>
</body></html>"""

_LANDING = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentKeyGuard · 安装根证书</title><style>__CSS__</style></head><body>
<div class="wrap">
  <div class="logo">__LOGO__</div>
  <h1>已配置，建议安装根证书</h1>
  <p class="sub">当前是 HTTP；安装根证书后使用 HTTPS</p>
  <section class="card">
    <h2>HTTPS 地址</h2><pre class="secret">__URL__</pre>
    <h2>根证书（仅一次）</h2>
    <p>根证书只用于让浏览器信任 HTTPS，不包含客户端身份。安装并信任后点“切换到 HTTPS”。</p>
    <div class="dl">
      <a class="dl-btn" href="/ca.crt">下载 ca.crt</a>
      <a class="dl-btn" href="/ca.mobileconfig">iPhone 根证书描述文件</a>
    </div>
    <details><summary>iOS 信任步骤</summary><p>设置 → 通用 → VPN 与设备管理 → 安装；设置 → 通用 → 关于本机 → 证书信任设置 → 对 AgentKeyGuard Root CA 开启完全信任。</p></details>
    <details><summary>Android 信任步骤</summary><p>设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书 → 选择 ca.crt。</p></details>
    <details><summary>Windows / macOS</summary><p>双击 ca.crt，安装到“受信任的根证书颁发机构”；macOS 在“钥匙串访问”里设为始终信任。</p></details>
    <a class="dl-btn" href="/dashboard?https=1">我已安装，切换到 HTTPS</a>
    <a class="dl-btn" href="/dashboard?http=1">暂时继续用 HTTP</a>
  </section>
</div></body></html>"""

_GONE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>配置页已失效</title><style>__CSS__</style></head><body class="short">
<div class="wrap">
  <div class="logo">__LOGO__</div>
  <h1>配置页已失效</h1>
  <div class="warn"><span class="hash">#</span>该配置只显示一次，刷新后无法再查看</div>
  <p class="sub">如果还没保存证书，请在服务器上重新运行初始化。</p>
</div></body></html>"""


# 已初始化后又访问 /setup：这不是「凭证页过期」，而是「配置向导已关闭」。
# 跟 _GONE 分开是因为语义不同 —— 后者是「一次性内容你看不到了」，前者是
# 「你什么都没错过，去控制台登录」。混用会把「刷新后无法再查看」糊到已完成的
# 用户脸上，看起来像 HTML 残留。
_CLOSED = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>配置页已失效</title><style>__CSS__</style></head><body class="short">
<div class="wrap">
  <div class="logo">__LOGO__</div>
  <h1>配置页已失效</h1>
  <div class="warn"><span class="hash">#</span>本机已完成初始化，配置向导不再开放。</div>
  <p class="sub">请登录控制台继续操作；如确实需要重新初始化，先在服务器上清空数据目录。</p>
  <section class="card"><a class="dl-btn" href="/dashboard">前往 /dashboard 登录</a></section>
</div></body></html>"""


def _fill(text: str) -> str:
    return text.replace("__CSS__", _CSS).replace("__LOGO__", _LOGO)


def setup_page() -> str:
    # __LANIP__ 用服务端探测到的局域网地址，避免默认值变成 127.0.0.1（REQ-112）
    return _fill(_SETUP).replace("__LANIP__", network.local_ip())


def gone_page() -> str:
    return _fill(_GONE)


def setup_closed_page() -> str:
    return _fill(_CLOSED)


def done_page(d: dict) -> str:
    # 本页只留「主密码 / 访问地址 / 首个接入链接 / 根证书」四块。
    # TOTP 密钥刻意不在这里回显（REQ-151）：Step 2 刚扫码给过一次，它是手机上
    # 已经在用的东西，再以明文出现只会被误当成「又一条要发给 AI 的密钥」。
    return (
        _fill(_DONE)
        .replace("__URL__", html.escape(d.get("url", "")))
        .replace("__MASTER__", html.escape(d.get("master", "")))
        # 首个接入链接：与「添加密钥」同格式（REQ-139）
        .replace("__FIRST_LINK__", html.escape(d.get("first_link", "") or "（未生成）"))
        .replace("__FIRST_NAME__", html.escape(d.get("first_name", "") or "首次接入"))
        .replace("__FIRST_TTL__", str(int(d.get("first_ttl") or 600)))
    )


def https_landing_page(url: str = "") -> str:
    """HTTP 落地页：只做根证书安装与切 HTTPS，不显示登录表单。"""
    return _fill(_LANDING).replace("__URL__", html.escape(url))
