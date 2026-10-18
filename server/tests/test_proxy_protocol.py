from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.proxyproto import (
    CLIENT_BY_PORT,
    ProxyHeaderError,
    TrustedNetworks,
    looks_like_header,
    make_front_handler,
    parse_header,
)

V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"


def v2_header(src: str, dst: str = "10.0.0.1", sport: int = 40000, dport: int = 10443) -> bytes:
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 4:
        body = s.packed + d.packed + struct.pack("!HH", sport, dport)
        fam = 0x11
    else:
        body = s.packed + d.packed + struct.pack("!HH", sport, dport)
        fam = 0x21
    return V2_SIG + bytes([0x21, fam]) + struct.pack("!H", len(body)) + body


def test_parse_v2_ipv4_ipv6_and_local():
    hdr = v2_header("203.0.113.7")
    assert parse_header(hdr + b"\x16\x03\x01") == (len(hdr), "203.0.113.7")
    hdr6 = v2_header("2001:db8::7", "2001:db8::1")
    assert parse_header(hdr6) == (len(hdr6), "2001:db8::7")
    local = V2_SIG + bytes([0x20, 0x00]) + b"\x00\x00"
    assert parse_header(local) == (16, None)
    assert parse_header(hdr[:10]) is None  # incomplete
    assert parse_header(hdr[:20]) is None
    with pytest.raises(ProxyHeaderError):
        parse_header(V2_SIG + bytes([0x11, 0x11]) + b"\x00\x00")


def test_parse_v1():
    line = b"PROXY TCP4 198.51.100.9 10.0.0.1 51000 10443\r\n"
    assert parse_header(line + b"rest") == (len(line), "198.51.100.9")
    assert parse_header(b"PROXY UNKNOWN\r\n") == (15, None)
    assert parse_header(b"PROXY TCP4 198.51") is None
    for bad in (b"PROXY TCP4 nonsense\r\n", b"PROXX TCP4 1 2 3 4\r\n"):
        with pytest.raises((ProxyHeaderError, ValueError)):
            parse_header(bad)


def test_tls_is_not_mistaken_for_a_header():
    assert not looks_like_header(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")
    assert looks_like_header(V2_SIG[:5]) and looks_like_header(b"PROXY TCP4")


async def _run_front(trusted: list[str], payload: bytes) -> tuple[bytes, str | None]:
    """Start the front listener in front of a capture server; return (bytes received, recorded client)."""
    got: dict[str, object] = {}

    async def inner(reader, writer):
        # Like uvicorn, only look up the client once request bytes have arrived.
        port = writer.get_extra_info("peername")[1]
        got["data"] = await reader.read(65536)
        got["client"] = CLIENT_BY_PORT.get(port)
        writer.close()

    inner_server = await asyncio.start_server(inner, "127.0.0.1", 0)
    inner_port = inner_server.sockets[0].getsockname()[1]
    front = await asyncio.start_server(
        make_front_handler("127.0.0.1", inner_port, TrustedNetworks(lambda: trusted)), "127.0.0.1", 0
    )
    port = front.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    writer.write_eof()
    await asyncio.sleep(0.3)
    writer.close()
    front.close()
    inner_server.close()
    return got.get("data", b""), got.get("client")


def test_front_strips_trusted_header_and_records_client():
    data, client = asyncio.run(_run_front(["127.0.0.0/8"], v2_header("203.0.113.7") + b"TLSDATA"))
    assert data == b"TLSDATA" and client == "203.0.113.7"


def test_front_passes_plain_connections_through():
    data, client = asyncio.run(_run_front([], b"\x16\x03\x01TLSDATA"))
    assert data == b"\x16\x03\x01TLSDATA" and client == "127.0.0.1"


def test_front_drops_headers_from_untrusted_addresses():
    data, client = asyncio.run(_run_front(["10.0.0.0/8"], v2_header("203.0.113.7") + b"TLSDATA"))
    assert data == b"" and client is None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_full_stack_real_client_address_through_proxy_header(tmp_path):
    """Production entry point: PROXY v2 header, then TLS, then an enrollment request."""
    server_dir = Path(__file__).resolve().parents[1]
    db_url = f"sqlite:///{tmp_path / 'pp.db'}"
    env = {
        **os.environ,
        "CSFM_DATABASE_URL": db_url,
        "CSFM_SECRET_KEY": "p" * 48,
        "CSFM_BACKUP_ENCRYPTION_KEY": __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode(),
        "CSFM_DATA_DIR": str(tmp_path / "data"),
        "CSFM_RUN_SCHEDULER": "false",
        "CSFM_PUBLIC_URL": "https://localhost",
        "CSFM_WEB_HOST": "127.0.0.1",
        "CSFM_WEB_PORT": str(_free_port()),
        "CSFM_AGENT_HOST": "127.0.0.1",
        "CSFM_AGENT_PORT": str(agent_port := _free_port()),
    }
    # Prepare the database with a key and the trusted proxy setting before the server starts.
    prep = (
        "from app.config import Settings; from app.main import init_backend; from app.db import session_factory;"
        "from app.models import EnrollmentKey; from app.security import hash_secret;"
        "from app.services.appsettings import AgentNetworkSettings, save_agent_network_settings;"
        "init_backend(Settings());"
        "db=session_factory()();"
        "db.add(EnrollmentKey(name='pp', prefix='p', key_hash=hash_secret('csfm_enr_pp')));"
        "save_agent_network_settings(db, AgentNetworkSettings(trusted_proxies=['127.0.0.1/32']), 't');"
        "db.commit()"
    )
    subprocess.run([sys.executable, "-c", prep], cwd=server_dir, env=env, check=True, capture_output=True)
    proc = subprocess.Popen([sys.executable, "-m", "app.serve"], cwd=server_dir, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(150):
            try:
                socket.create_connection(("127.0.0.1", agent_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the real agent pins the key; this test only checks addressing

        def request(header: bytes, body: dict) -> dict:
            raw = socket.create_connection(("127.0.0.1", agent_port), timeout=5)
            raw.sendall(header)
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                payload = json.dumps(body).encode()
                tls.sendall(
                    b"POST /api/agent/v1/enroll HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload
                )
                resp = b""
                while chunk := tls.recv(65536):
                    resp += chunk
            return json.loads(resp.split(b"\r\n\r\n", 1)[1])

        enrolled = request(v2_header("203.0.113.77"), {"enrollment_key": "csfm_enr_pp", "system": {"unique_id": "u1"}})
        direct = request(b"", {"enrollment_key": "csfm_enr_pp", "system": {"unique_id": "u2"}})

        check = (
            "from app.db import init_engine, session_factory; from app.models import Device;"
            f"init_engine('{db_url}'); db=session_factory()();"
            "print({d.unique_id: d.last_seen_ip for d in db.query(Device)})"
        )
        out = subprocess.run([sys.executable, "-c", check], cwd=server_dir, env=env, check=True,
                             capture_output=True, text=True).stdout
        seen = eval(out)  # noqa: S307 - our own subprocess output
        assert enrolled["device_id"] and direct["device_id"]
        assert seen == {"u1": "203.0.113.77", "u2": "127.0.0.1"}
    finally:
        proc.terminate()
        proc.wait(timeout=10)
