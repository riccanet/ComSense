"""PROXY protocol (v1 and v2) support for the agent port.

Normally firewalls connect to the agent port directly (a port forward), and
none of this is used. When they reach it through a TCP/TLS pass-through proxy
or load balancer instead (HAProxy, nginx stream, Traefik TCP, a cloud load
balancer, an overlay network's TCP proxy...), the proxy can prepend a standard
PROXY protocol header carrying the real client address. A small front listener on the
agent port reads that header, then relays the untouched TLS stream to the app's
TLS listener on a loopback socket. The real address is remembered by the
loopback connection's source port and put back into the request by
ClientAddressMiddleware, so per-address rate limits and "checks in from" show
the firewall's own address.

Headers are honoured only from trusted proxy networks (Settings page). A header
from anyone else closes the connection, so the address cannot be spoofed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
import time
from collections.abc import Callable, Iterable

log = logging.getLogger("comsense.proxyproto")

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
V1_PREFIX = b"PROXY "
V1_MAX = 107
HEADER_TIMEOUT = 10.0

# Loopback source port of a relayed connection -> real client address.
CLIENT_BY_PORT: dict[int, str] = {}


class ProxyHeaderError(ValueError):
    pass


def looks_like_header(data: bytes) -> bool:
    """True if data starts like a PROXY header (TLS records start with 0x16, so they never match)."""
    head = data[:12]
    return bool(head) and (V2_SIGNATURE.startswith(head) or V1_PREFIX.startswith(head[:6]))


def parse_header(data: bytes) -> tuple[int, str | None] | None:
    """Parse a PROXY header at the start of data.

    Returns (bytes consumed, client address or None for LOCAL/UNKNOWN), or None
    if more data is needed. Raises ProxyHeaderError if it is malformed.
    """
    if data[:1] == b"\r":
        if len(data) < 16:
            return None
        if data[:12] != V2_SIGNATURE:
            raise ProxyHeaderError("bad v2 signature")
        ver_cmd, fam, length = data[12], data[13], struct.unpack("!H", data[14:16])[0]
        if ver_cmd >> 4 != 2:
            raise ProxyHeaderError("unsupported PROXY protocol version")
        total = 16 + length
        if len(data) < total:
            return None
        cmd, family = ver_cmd & 0x0F, fam >> 4
        if cmd == 0:  # LOCAL: health check from the proxy itself
            return total, None
        if cmd != 1:
            raise ProxyHeaderError("unknown v2 command")
        body = data[16:total]
        if family == 1 and len(body) >= 12:
            return total, str(ipaddress.IPv4Address(body[:4]))
        if family == 2 and len(body) >= 36:
            return total, str(ipaddress.IPv6Address(body[:16]))
        return total, None
    if data[:1] == b"P":
        if len(data) >= 6 and not data.startswith(V1_PREFIX):
            raise ProxyHeaderError("not a PROXY header")
        end = data.find(b"\r\n")
        if end == -1:
            if len(data) >= V1_MAX:
                raise ProxyHeaderError("v1 header too long")
            return None
        parts = data[:end].decode("ascii", "replace").split(" ")
        if len(parts) >= 2 and parts[1] == "UNKNOWN":
            return end + 2, None
        if len(parts) != 6 or parts[1] not in ("TCP4", "TCP6"):
            raise ProxyHeaderError("malformed v1 header")
        return end + 2, str(ipaddress.ip_address(parts[2]))
    raise ProxyHeaderError("not a PROXY header")


def _peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername") or ("", 0)
    ip = ipaddress.ip_address(peer[0]) if peer[0] else None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip) if ip else ""


def is_trusted(ip: str, networks: Iterable[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class TrustedNetworks:
    """Cached view of the trusted-proxy setting, refreshed every few seconds."""

    def __init__(self, loader: Callable[[], list[str]], ttl: float = 15.0):
        self._loader = loader
        self._ttl = ttl
        self._value: list[ipaddress._BaseNetwork] = []
        self._loaded = 0.0

    async def get(self) -> list[ipaddress._BaseNetwork]:
        if time.monotonic() - self._loaded > self._ttl:
            try:
                raw = await asyncio.to_thread(self._loader)
                self._value = [ipaddress.ip_network(c, strict=False) for c in raw]
            except Exception:  # keep the previous value if the database hiccups
                log.exception("Could not load trusted proxy networks")
            self._loaded = time.monotonic()
        return self._value


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def make_front_handler(inner_host: str, inner_port: int, trusted: TrustedNetworks):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = _peer_ip(writer)
        client = peer
        try:
            buffered = await asyncio.wait_for(reader.read(4096), HEADER_TIMEOUT)
            if not buffered:
                writer.close()
                return
            if looks_like_header(buffered[:12]):
                if not is_trusted(peer, await trusted.get()):
                    log.warning("Dropped connection from %s: PROXY header from an untrusted address", peer)
                    writer.close()
                    return
                while (parsed := parse_header(buffered)) is None:
                    more = await asyncio.wait_for(reader.read(4096), HEADER_TIMEOUT)
                    if not more:
                        writer.close()
                        return
                    buffered += more
                consumed, real = parsed
                client = real or peer
                buffered = buffered[consumed:]
        except (asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        except ProxyHeaderError as exc:
            log.warning("Dropped connection from %s: %s", peer, exc)
            writer.close()
            return

        try:
            inner_reader, inner_writer = await asyncio.open_connection(inner_host, inner_port)
        except OSError:
            writer.close()
            return
        local_port = inner_writer.get_extra_info("sockname")[1]
        CLIENT_BY_PORT[local_port] = client
        try:
            if buffered:
                inner_writer.write(buffered)
                await inner_writer.drain()
            await asyncio.gather(_pipe(reader, inner_writer), _pipe(inner_reader, writer))
        finally:
            CLIENT_BY_PORT.pop(local_port, None)

    return handle


class ClientAddressMiddleware:
    """Restore the real client address for connections relayed by the front listener."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            client = scope.get("client")
            if client and client[0] in ("127.0.0.1", "::1"):
                real = CLIENT_BY_PORT.get(client[1])
                if real:
                    scope = dict(scope, client=(real, client[1]))
        await self.app(scope, receive, send)
