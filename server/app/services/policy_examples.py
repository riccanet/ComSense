"""Starter documents shown in the policy editor for each policy type."""
from ..models import PolicyType

EXAMPLES = {
    PolicyType.aliases: {
        "remove_unlisted": True,
        "aliases": [
            {
                "name": "CSFM_Mgmt_Hosts",
                "type": "host",
                "address": ["203.0.113.10", "203.0.113.11"],
                "detail": ["NOC primary", "NOC secondary"],
                "descr": "Management hosts allowed to reach the firewall",
            },
            {
                "name": "CSFM_Blocked_Nets",
                "type": "network",
                "address": ["198.51.100.0/24"],
                "descr": "Networks blocked on every site",
            },
        ],
    },
    PolicyType.firewall_rules: {
        "position": "top",
        "rules": [
            {
                "interface": "wan",
                "type": "block",
                "ipprotocol": "inet",
                "protocol": "any",
                "source": {"address": "CSFM_Blocked_Nets"},
                "destination": {"any": True},
                "descr": "Block known-bad networks",
                "log": True,
            },
            {
                "interface": "wan",
                "type": "pass",
                "ipprotocol": "inet",
                "protocol": "tcp",
                "source": {"address": "CSFM_Mgmt_Hosts"},
                "destination": {"network": "wanip", "port": "443"},
                "descr": "Allow NOC to WebGUI",
            },
        ],
    },
    PolicyType.system: {
        "timezone": "America/New_York",
        "timeservers": "0.pool.ntp.org 1.pool.ntp.org",
        "dnsservers": ["1.1.1.1", "9.9.9.9"],
        "dnsallowoverride": False,
    },
    PolicyType.packages: {
        "install": ["pfSense-pkg-Status_Traffic_Totals"],
        "remove": [],
    },
    PolicyType.config_set: {
        "items": [
            {"path": "system/webgui/loginautocomplete", "delete": True},
            {"path": "system/maximumstates", "value": "400000"},
        ],
        "reload": ["filter"],
    },
}
