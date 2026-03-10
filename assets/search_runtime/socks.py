# VERSION: 1.00

"""Minimal PySocks-compatible shim for rustorrent's bundled search runtime.

The upstream qBittorrent search helpers import `socks`, but rustorrent does not
bundle the full PySocks module yet. Normal direct socket connections work
without this shim. If a user sets qBittorrent-style SOCKS proxy environment
variables for search plugins, connection attempts will fail with a clear error
instead of silently bypassing the proxy.
"""

import socket

PROXY_TYPE_SOCKS4 = SOCKS4 = 1
PROXY_TYPE_SOCKS5 = SOCKS5 = 2

_default_proxy = None


def set_default_proxy(proxy_type=None, addr=None, port=None, rdns=True, username=None, password=None):
    global _default_proxy
    _default_proxy = (proxy_type, addr, port, rdns, username, password)


def setdefaultproxy(*args, **kwargs):
    return set_default_proxy(*args, **kwargs)


class socksocket(socket.socket):
    default_proxy = None

    def connect(self, address):
        if _default_proxy is not None:
            raise OSError("SOCKS proxy support is not bundled in rustorrent search yet")
        return super().connect(address)
