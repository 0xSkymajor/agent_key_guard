# -*- coding: utf-8 -*-
"""单端口 HTTP/HTTPS 传输层：TLS 首字节探测，避免首次访问被证书卡住。"""
from __future__ import annotations

import socket
import ssl
from http.server import ThreadingHTTPServer


class HybridThreadingHTTPServer(ThreadingHTTPServer):
    """同一端口同时接受 HTTP 与 HTTPS。

    - 有 ssl_ctx 时，首字节 0x16（TLS handshake）走 TLS，其余按普通 HTTP 处理；
    - 无 ssl_ctx（首次初始化）时只接受 HTTP，不生成临时自签证书。
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, ssl_ctx=None):
        self.ssl_ctx = ssl_ctx
        super().__init__(server_address, RequestHandlerClass)

    def set_ssl_ctx(self, ssl_ctx) -> None:
        """运行期热替换 TLS 上下文（setup 完成后调用，无需重启进程）。

        get_request() 是在 accept 之后才读 self.ssl_ctx 的，所以这里只做一次
        属性赋值即可：已建立/正在握手的连接仍持有旧对象，替换只影响之后的新连接，
        不需要加锁，也不会打断进行中的请求。
        """
        self.ssl_ctx = ssl_ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            sock.settimeout(5.0)
            first = sock.recv(1, socket.MSG_PEEK)
            if self.ssl_ctx is not None and first == b"\x16":
                sock = self.ssl_ctx.wrap_socket(sock, server_side=True)
            sock.settimeout(None)
            return sock, addr
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise


def is_https(connection) -> bool:
    return isinstance(connection, ssl.SSLSocket)
