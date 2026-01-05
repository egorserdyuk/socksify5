"""
Socksify5 - A Python library for creating SOCKS5 proxy servers.

This library provides a straightforward API for creating proxy servers that handle
TCP connections with various authentication methods including no authentication,
username/password authentication (BASIC), and GSSAPI/Negotiate (Kerberos).

It exposes a rich set of events that allow developers to monitor and control
proxy behavior at every stage of the connection lifecycle.

The server handles IPv4, IPv6, and domain name address types, supports connection
filtering for access control, and provides configurable idle timeouts for both
client and destination sockets.

Author: Egor Serdiuk
"""

from .server import Socks5Server
from .auth import NoAuthProvider, UsernamePasswordProvider, GSSAPIProvider, AuthProvider
from .events import EventEmitter

__version__ = "0.1.0"
__author__ = "Egor Serdiuk"
__all__ = [
    "Socks5Server",
    "NoAuthProvider",
    "UsernamePasswordProvider",
    "GSSAPIProvider",
    "AuthProvider",
    "EventEmitter",
]
