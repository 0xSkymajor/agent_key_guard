# -*- coding: utf-8 -*-
"""通知渠道的 Webhook 发送（REQ-148）。

Bark 的推送逻辑仍在 `approval.push_bark`（历史原因：selftest 大量 monkeypatch 它），
本模块只负责「把审批消息按 preset 包装后发到某个 Webhook 渠道」。

渠道 Agent 不可见、不可调用——它只是系统的通知出口，不是凭证。
依赖边界：只依赖标准库，不 import approval（避免循环导入）。
"""
from __future__ import annotations

import json
import urllib.request

# 支持的预设：决定审批消息（标题 / 正文 / 跳转链接）如何包装
PRESETS = ("custom", "dingtalk", "feishu", "wecom", "slack", "telegram", "ntfy", "gotify")


def _send(url: str, data: bytes, headers: dict) -> bool:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception as e:  # noqa: BLE001
        print(f"  [通知] {url[:60]} 发送失败: {type(e).__name__}: {e}", flush=True)
        return False


def push_webhook(channel: dict, title: str, body: str, link: str) -> bool:
    """把一条审批消息发到指定 Webhook 渠道。成功返回 True，失败不抛异常。"""
    url = (channel.get("url") or "").strip()
    if not url:
        return False
    preset = (channel.get("preset") or "custom").lower()
    secret = (channel.get("secret") or "").strip()

    # 审批消息 = 标题 + 正文 + 跳转链接（链接统一指向常驻工作台）
    content = title if title else body
    if body and body != title:
        content = f"{title}\n{body}"
    if link:
        content += f"\n{link}"

    headers: dict = {}
    data: bytes
    if preset == "custom":
        # 原样发纯文本；secret 放进一个通用头，服务端可自行读取
        data = content.encode("utf-8")
        headers["Content-Type"] = "text/plain; charset=utf-8"
        if secret:
            headers["X-AKG-Secret"] = secret
    elif preset == "dingtalk":
        data = json.dumps({"msgtype": "text", "text": {"content": content}},
                          ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif preset == "feishu":
        data = json.dumps({"msg_type": "text", "content": {"text": content}},
                          ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif preset == "wecom":
        data = json.dumps({"msgtype": "text", "text": {"content": content}},
                          ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif preset == "slack":
        data = json.dumps({"text": content}, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif preset == "telegram":
        # chat_id 藏在 url 的 query 里（用户配渠道时填完整地址），body 只发文本
        data = json.dumps({"text": content}, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif preset == "ntfy":
        # ntfy 是纯文本：标题进 Title 头、链接进 Click 头、正文是消息体
        data = body.encode("utf-8")
        headers["Title"] = title
        if link:
            headers["Click"] = link
        if secret:
            headers["Authorization"] = "Bearer " + secret
    elif preset == "gotify":
        data = json.dumps({"title": title, "message": body, "priority": 5},
                          ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        if secret:
            headers["X-Gotify-Key"] = secret
    else:
        return False

    return _send(url, data, headers)
