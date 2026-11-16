# -*- coding: utf-8 -*-
"""进程内存加固：禁止 core dump、拒绝被 ptrace、尽力锁定内存页。

实测结论（WSL2 / kernel 6.18 / yama ptrace_scope=1）：

| 攻击者 | 读 /proc/pid/mem | 读 /proc/pid/environ |
| --- | --- | --- |
| root | 成功 | 成功 |
| 非 root 跨用户 | EPERM | EPERM |
| 非 root 同用户兄弟进程 | EPERM（yama 挡） | **原本可读** |
| 同用户 + PR_SET_DUMPABLE=0 | EPERM | **EPERM** |

所以这一层对「同用户但不是 root」的进程有实际意义——`environ` 尤其要紧，
一旦把主密码或 KEK 放进环境变量，同 uid 一条 `cat /proc/<pid>/environ` 就拿走。
对 root 无效，文档必须如实写。

所有失败都静默降级：容器里 `mlockall` 常因 `ulimit memlock` 失败，
不能因为加固失败就让服务起不来。
"""
from __future__ import annotations

import ctypes
import ctypes.util

PR_SET_DUMPABLE = 4
PR_SET_PTRACER = 0x59616D61
MCL_CURRENT = 1
MCL_FUTURE = 2


def _libc():
    try:
        name = ctypes.util.find_library("c") or "libc.so.6"
        return ctypes.CDLL(name, use_errno=True)
    except Exception:  # noqa: BLE001
        return None


def harden_process(lock_memory: bool = True) -> dict:
    """尽力加固当前进程，返回每项是否成功（供日志与自检查看，不抛异常）。"""
    out = {"dumpable": False, "ptracer": False, "mlock": False}
    libc = _libc()
    if libc is None:
        return out
    for key, which in (("dumpable", PR_SET_DUMPABLE), ("ptracer", PR_SET_PTRACER)):
        try:
            if libc.prctl(which, 0, 0, 0, 0) == 0:
                out[key] = True
        except Exception:  # noqa: BLE001
            pass
    if lock_memory:
        try:
            if libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0:
                out["mlock"] = True
        except Exception:  # noqa: BLE001
            pass
    return out


def wipe(buf) -> None:
    """原地覆写一段可变缓冲区。

    只对 bytearray 有效——bytes / str 不可变，Python 层面无法覆写，
    只能丢掉引用等 GC。所以 KEK 一律用 bytearray 持有。
    """
    try:
        if isinstance(buf, bytearray):
            buf[:] = b"\x00" * len(buf)
    except Exception:  # noqa: BLE001
        pass
