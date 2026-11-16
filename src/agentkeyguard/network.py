# -*- coding: utf-8 -*-
"""网络辅助：DNS 解析检测（只检测，不修改任何 DNS 配置）。"""
from __future__ import annotations

import socket


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def verify_dns(domain: str, expected_ip: str | None = None) -> dict:
    domain = (domain or "").strip()
    if not domain:
        return {"ok": False, "domain": domain, "error": "no_domain", "resolved": []}
    try:
        infos = socket.getaddrinfo(domain, None)
        resolved = sorted({i[4][0] for i in infos})
    except OSError as e:
        return {"ok": False, "domain": domain, "error": str(e), "resolved": []}
    ok = bool(resolved) and (not expected_ip or expected_ip in resolved)
    return {"ok": ok, "domain": domain, "resolved": resolved, "expected": expected_ip}


# ── 部署形态与地址清单（REQ-125）──────────────────────────────
_VIRTUAL_IFACE_PREFIX = ("docker", "br-", "veth", "virbr", "vmnet", "tun", "tap", "lo")
# WSL 镜像模式会把这个地址挂在 lo 上，它是 DNS 代理不是入口，列出来只会误导
_WSL_MIRRORED_DNS = "10.255.255.254"


def is_wsl() -> bool:
    """内核版本里带 microsoft 就是 WSL。"""
    try:
        with open("/proc/version", encoding="utf-8") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def lan_addresses() -> list:
    """列出本机 IPv4 地址：[{ip, iface, virtual}]。虚拟网卡单独标记。"""
    import subprocess

    out = []
    try:
        cp = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True,
                            text=True, timeout=3, shell=False)
        for line in cp.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != "inet":
                continue
            iface = parts[1].rstrip(":")
            ip = parts[3].split("/")[0]
            if ip.startswith("127.") or ip == _WSL_MIRRORED_DNS:
                continue
            out.append({"ip": ip, "iface": iface,
                        "virtual": iface.startswith(_VIRTUAL_IFACE_PREFIX)})
    except Exception:  # noqa: BLE001
        ip = local_ip()
        if ip and not ip.startswith("127."):
            out.append({"ip": ip, "iface": "?", "virtual": False})
    out.sort(key=lambda x: (x["virtual"], x["ip"]))
    return out


def net_mode() -> str:
    """粗略判断 WSL 的网络模式：mirrored 下 /etc/resolv.conf 指向 10.255.255.254。"""
    if not is_wsl():
        return "host"
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("nameserver") and "10.255.255.254" in line:
                    return "mirrored"
    except OSError:
        pass
    return "nat"
