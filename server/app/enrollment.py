"""Enrollment codes: everything a firewall needs to join, in one pasteable string.

    csfm1.<base64url(JSON {"url": agent URL, "key": enrollment key, "pin": SPKI pin})>

"pin" is present only when the agent listener uses a self-issued certificate;
the agent then trusts exactly that public key instead of a certificate authority.
"""
from __future__ import annotations

import base64
import json

CODE_PREFIX = "csfm1."


def make_code(agent_url: str, key: str, pin: str | None) -> str:
    doc: dict[str, str] = {"url": agent_url, "key": key}
    if pin:
        doc["pin"] = pin
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return CODE_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_code(code: str) -> dict[str, str]:
    if not code.startswith(CODE_PREFIX):
        raise ValueError("not an enrollment code")
    body = code[len(CODE_PREFIX):]
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    if not isinstance(data, dict) or "url" not in data or "key" not in data:
        raise ValueError("incomplete enrollment code")
    return data
