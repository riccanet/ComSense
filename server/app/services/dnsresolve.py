"""Look up a host name through specific DNS servers (Settings > Email (SMTP) > DNS servers).

For hosts whose containers cannot use the system resolver (e.g. Docker relaying to a host DNS that
does not answer). Only A records are needed: the SMTP connection goes to the address while TLS is
still verified against the host name. Standard library only; plain DNS over UDP port 53.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct

TIMEOUT = 3.0
DNS_PORT = 53  # tests point this at an unprivileged port


class DnsError(OSError):
    pass


def _query(name: str) -> tuple[int, bytes]:
    qid = secrets.randbelow(0x10000)
    labels = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split("."))
    # Header: id, flags (recursion desired), 1 question; then QNAME, QTYPE=A, QCLASS=IN.
    return qid, struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def _skip_name(data: bytes, i: int) -> int:
    while True:
        length = data[i]
        if length & 0xC0 == 0xC0:  # compression pointer ends the name
            return i + 2
        if length == 0:
            return i + 1
        i += length + 1


def _parse_a(data: bytes, qid: int) -> list[str]:
    rid, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if rid != qid or not flags & 0x8000:
        raise DnsError("unexpected DNS response")
    rcode = flags & 0x0F
    if rcode == 3:
        raise DnsError("host name not found (NXDOMAIN)")
    if rcode:
        raise DnsError(f"DNS server error (rcode {rcode})")
    i = 12
    for _ in range(qdcount):
        i = _skip_name(data, i) + 4
    addresses = []
    for _ in range(ancount):
        i = _skip_name(data, i)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:  # A; CNAMEs in between are simply skipped
            addresses.append(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    return addresses


def resolve_a(name: str, servers: list[str]) -> str:
    """First IPv4 address for name, asking the servers in order. Raises DnsError."""
    try:
        return str(ipaddress.ip_address(name))  # already an address
    except ValueError:
        pass
    errors = []
    for server in servers:
        qid, packet = _query(name)
        try:
            with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.sendto(packet, (server, DNS_PORT))
                data, _ = sock.recvfrom(4096)
            addresses = _parse_a(data, qid)
            if addresses:
                return addresses[0]
            errors.append(f"{server}: no address for {name}")
        except (OSError, struct.error, IndexError) as exc:
            errors.append(f"{server}: {exc}")
    raise DnsError("; ".join(errors) or "no DNS servers given")
