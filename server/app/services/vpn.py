"""VPN tunnels as the firewalls report them (agent 0.2.49+, report key "vpn"), and the connect / disconnect /
reconnect task payloads. The agent re-checks every target against its own configuration; this module only
refuses what the firewall did not report, so the console shows sensible errors early."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Device

KINDS = ("ipsec", "openvpn", "wireguard")
KIND_NAMES = {"ipsec": "IPsec", "openvpn": "OpenVPN", "wireguard": "WireGuard"}
ACTIONS = ("connect", "disconnect", "reconnect", "kick")
ACTION_NAMES = {"connect": "Connect", "disconnect": "Disconnect", "reconnect": "Reconnect", "kick": "Disconnect user"}


class VpnError(ValueError):
    pass


@dataclass
class Tunnel:
    kind: str
    id: str
    name: str
    status: str
    remote: str = ""
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def kind_name(self) -> str:
        return KIND_NAMES[self.kind]

    @property
    def problem(self) -> bool:
        """Down or partly up, and the kind of tunnel that alerts when it is (vpn_conditions)."""
        r = self.raw
        if self.status not in ("down", "partial"):
            return False
        if self.kind == "ipsec":
            return not (r.get("mobile") or r.get("responder"))
        if self.kind == "openvpn":
            return r.get("mode") == "client" or bool(r.get("p2p"))
        return True


def report(device: Device) -> dict[str, Any]:
    vpn = (device.inventory or {}).get("vpn")
    return vpn if isinstance(vpn, dict) else {}


def reported(device: Device) -> bool:
    """Whether the firewall's agent reports VPN status at all (0.2.49+)."""
    return "vpn" in (device.inventory or {})


def tunnels(device: Device) -> list[Tunnel]:
    out: list[Tunnel] = []
    vpn = report(device)
    for kind in KINDS:
        for t in vpn.get(kind) or []:
            if not isinstance(t, dict) or not str(t.get("id", "")):
                continue
            status = str(t.get("status") or "unknown")
            remote = str(t.get("remote") or "")
            detail = str(t.get("detail") or "")
            if kind == "wireguard":
                peers = [p for p in t.get("peers") or [] if isinstance(p, dict)]
                if any(p.get("status") == "down" for p in peers) and status == "up":
                    status = "partial"
                if not peers:
                    detail = "no peers"
                if status == "down" and t.get("interface_up") is False:
                    detail = f"interface {t.get('interface')} is down"
            out.append(Tunnel(kind, str(t["id"]), str(t.get("name") or t["id"]), status, remote, detail, t))
    return out


def counts(device: Device) -> dict[str, int]:
    ts = tunnels(device)
    return {"total": len(ts), "problems": sum(1 for t in ts if t.problem), "up": sum(1 for t in ts if t.status == "up")}


def find(device: Device, kind: str, tunnel_id: str) -> Tunnel:
    for t in tunnels(device):
        if t.kind == kind and t.id == tunnel_id:
            return t
    raise VpnError("That tunnel is not in the firewall's last report. Refresh and try again.")


def control_payload(device: Device, kind: str, tunnel_id: str, action: str, peer: str = "",
                    client: str = "") -> dict[str, Any]:
    """The vpn_control task payload, checked against the firewall's last report."""
    if kind not in KINDS:
        raise VpnError("Unknown VPN type.")
    if action not in ACTIONS:
        raise VpnError("Unknown VPN action.")
    tunnel = find(device, kind, tunnel_id)
    payload: dict[str, Any] = {"kind": kind, "id": tunnel.id, "action": action, "name": tunnel.name}
    raw = tunnel.raw
    if kind == "ipsec" and raw.get("mobile"):
        raise VpnError("Mobile client connections are started by the clients, not the firewall.")
    if action == "kick":
        if kind != "openvpn" or raw.get("mode") != "server" or raw.get("p2p"):
            raise VpnError("Only users connected to an OpenVPN remote access server can be disconnected one by one.")
        conn = next((c for c in raw.get("connections") or []
                     if isinstance(c, dict) and client and client in (c.get("client_id"), c.get("remote"))), None)
        if conn is None:
            raise VpnError("That user is no longer connected.")
        payload["client"] = str(conn.get("client_id") or conn.get("remote"))
        payload["user"] = str(conn.get("user") or conn.get("remote") or "")
    if peer:
        if kind != "wireguard" or action != "reconnect":
            raise VpnError("Only a WireGuard peer can be reconnected on its own.")
        match = next((p for p in raw.get("peers") or [] if isinstance(p, dict) and p.get("id") == peer), None)
        if match is None:
            raise VpnError("That peer is not in the firewall's last report.")
        if not match.get("endpoint"):
            raise VpnError("This peer connects to the firewall (it has no endpoint), so the firewall cannot "
                           "reconnect it.")
        payload["peer"] = peer
        payload["name"] = f"{match.get('name')} on {tunnel.name}"
    return payload


def human_bytes(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def human_seconds(value: Any) -> str:
    try:
        s = int(value)
    except (TypeError, ValueError):
        return ""
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    if s < 172800:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"
