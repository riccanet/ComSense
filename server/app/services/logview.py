"""Firewall logs fetched on demand (the read_logs task): which logs there are and how lines are shown."""
from __future__ import annotations

import re
from typing import Any

# name (as the agent knows it) -> label, as on pfSense's Status > System Logs.
LOGS = {
    "system": "System",
    "firewall": "Firewall",
    "dhcp": "DHCP",
    "resolver": "DNS resolver",
    "gateways": "Gateways",
    "openvpn": "OpenVPN",
    "ipsec": "IPsec",
    "auth": "Authentication",
    "ntp": "NTP",
    "routing": "Routing",
}
LINE_CHOICES = (100, 250, 500, 1000, 2000)

# "<134>1 2026-10-21T03:05:09.123456+00:00 host prog 123 - - msg" (RFC 5424, pfSense's default)
_RFC5424 = re.compile(r"^(?:<\d+>)?1 (?P<time>\S+) \S+ (?P<prog>\S+) (?P<pid>\S+) \S+ \S+ ?(?P<msg>.*)$")
# "Oct 21 03:05:09 host prog[123]: msg" (BSD, RFC 3164)
_RFC3164 = re.compile(r"^(?:<\d+>)?(?P<time>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) \S+ (?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")


def parse_line(line: str) -> dict[str, str]:
    """{time, program, message} of a syslog line; the whole line as the message when it does not parse."""
    m = _RFC5424.match(line) or _RFC3164.match(line)
    if not m:
        return {"time": "", "program": "", "message": line}
    time = m.group("time")
    if "T" in time:  # 2026-10-21T03:05:09.123456+00:00 -> 2026-10-21 03:05:09
        time = time.replace("T", " ")[:19]
    return {"time": time, "program": m.group("prog"), "message": m.group("msg")}


def parse_filter_line(line: str) -> dict[str, Any]:
    """A firewall (filterlog) line as pfSense's firewall log shows it: action, interface, protocol, source,
    destination. Its CSV fields: rule, sub, anchor, tracker, interface, reason, action, direction,
    ip version, then per IP version."""
    base = parse_line(line)
    out: dict[str, Any] = {"time": base["time"], "raw": line, "action": "", "interface": "", "direction": "",
                           "protocol": "", "source": "", "destination": "", "rule": ""}
    if base["program"] != "filterlog":
        out["message"] = base["message"]
        return out
    f = base["message"].split(",")
    try:
        out.update(rule=f[3], interface=f[4], action=f[6], direction=f[7])
        if f[8] == "4":
            proto, src, dst, ports = f[16], f[18], f[19], f[20:22]
        elif f[8] == "6":
            proto, src, dst, ports = f[12], f[15], f[16], f[17:19]
        else:
            raise IndexError
    except IndexError:
        out["message"] = base["message"]
        return out
    out["protocol"] = proto
    if proto in ("tcp", "udp") and len(ports) == 2 and all(p.isdigit() for p in ports):
        def with_port(addr: str, port: str) -> str:
            return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"

        src, dst = with_port(src, ports[0]), with_port(dst, ports[1])
    out["source"], out["destination"] = src, dst
    return out
