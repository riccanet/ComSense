"""pfBlocker GeoIP configurations: on every assigned firewall, pfBlockerNG permits one region's countries as an
alias (pfB_NAmerica_v4 / _v6 for North America) and every other GeoIP region is off. The alias is then used as the
source of port forwards (services/opennat.py), so only those countries reach them.

Only pfBlockerNG's GeoIP sections are managed; its IP feed lists (PRI1...) and DNSBL are left as they are.
"Alias Permit" builds an alias and no rules, so nothing depends on each firewall's interfaces.

The MaxMind license key (GeoIP needs a free MaxMind account) is a secret: stored encrypted with the server's
secret key, shown hidden, decrypted only when the configuration is sent to a firewall.
"""
from __future__ import annotations

import copy
import re
from typing import Any

from ..config import Settings
from ..models import Backup
from .appsettings import decrypt_secret, encrypt_secret
from .backups import load_backup
from .configview import _parse

# pfBlockerNG's GeoIP sections (installedpackages/pfblockerng<section>) -> the alias name it builds for them.
REGIONS = {
    "africa": ("Africa", "Africa"),
    "antarctica": ("Antarctica", "Antarctica"),
    "asia": ("Asia", "Asia"),
    "europe": ("Europe", "Europe"),
    "northamerica": ("North America", "NAmerica"),
    "oceania": ("Oceania", "Oceania"),
    "southamerica": ("South America", "SAmerica"),
}
# Also GeoIP sections, never permitted here; turned off with the other regions.
OTHER_SECTIONS = ("proxyandsatellite", "topspammers")
ENCRYPTED = "enc:"
_COUNTRY = re.compile(r"^[A-Z0-9]{2}(_rep)?$|^[0-9]{5,8}(_rep)?$")


def alias_name(region: str, version: int = 4) -> str:
    return f"pfB_{REGIONS[region][1]}_v{version}"


def _error(message: str):
    from .policies import PolicyError  # noqa: PLC0415 - policies imports this module

    return PolicyError(message)


def validate(content: dict[str, Any]) -> None:
    if not isinstance(content, dict):
        raise _error("A pfBlocker GeoIP configuration is an object")
    if content.get("permit") not in REGIONS:
        raise _error(f"permit must be one of: {', '.join(REGIONS)}")
    for field in ("countries4", "countries6"):
        values = content.get(field)
        if not isinstance(values, list) or not all(isinstance(v, str) and _COUNTRY.match(v) for v in values):
            raise _error(f"{field} must be a list of country codes such as US or US_rep")
    if not content.get("countries4"):
        raise _error("Permit at least one country (IPv4)")
    account = str(content.get("maxmind_account") or "")
    if not re.fullmatch(r"[0-9]{1,12}", account):
        raise _error("Enter the MaxMind account ID (a number): GeoIP needs a MaxMind account")
    key = str(content.get("maxmind_key") or "")
    if not key.startswith(ENCRYPTED) or len(key) <= len(ENCRYPTED):
        raise _error("Enter the MaxMind license key")


def protect_key(content: dict[str, Any], previous: dict[str, Any] | None, secret_key: str) -> dict[str, Any]:
    """The license key as stored: a new one encrypted; left empty (or "[hidden]") to keep the saved one."""
    content = dict(content)
    key = str(content.get("maxmind_key") or "").strip()
    if not key or key == "[hidden]" or key.startswith(ENCRYPTED):
        kept = str((previous or {}).get("maxmind_key") or "")
        content["maxmind_key"] = key if key.startswith(ENCRYPTED) else kept
    else:
        if not re.fullmatch(r"[A-Za-z0-9_]{6,64}", key):
            raise _error("That does not look like a MaxMind license key")
        content["maxmind_key"] = ENCRYPTED + encrypt_secret(secret_key, key)
    return content


def for_firewall(content: dict[str, Any], secret_key: str) -> dict[str, Any]:
    """The content as sent to the agent, with the license key in clear."""
    out = copy.deepcopy(content)
    key = str(out.get("maxmind_key") or "")
    out["maxmind_key"] = decrypt_secret(secret_key, key[len(ENCRYPTED):]) if key.startswith(ENCRYPTED) else ""
    return out


def for_display(content: dict[str, Any]) -> dict[str, Any]:
    out = dict(content)
    if out.get("maxmind_key"):
        out["maxmind_key"] = "[hidden]"
    return out


def capture(settings: Settings, backup: Backup) -> dict[str, Any]:
    """A GeoIP configuration copied from a firewall's pfBlockerNG settings (its newest backup): the region it
    permits, its countries, and its MaxMind account and key. Raises PolicyError when it permits no region."""
    root = _parse(load_backup(settings, backup))
    pkgs = root.find("installedpackages")
    if pkgs is None:
        raise _error("This firewall has no pfBlockerNG settings")

    def section(name: str) -> dict[str, str]:
        el = pkgs.find(f"pfblockerng{name}/config")
        return {c.tag: (c.text or "").strip() for c in el} if el is not None else {}

    permitted = [r for r in REGIONS if section(r).get("action") == "Alias_Permit"]
    if len(permitted) != 1:
        raise _error("This firewall's pfBlockerNG permits " + ("no region" if not permitted else "several regions")
                     + " as an alias (IP > GeoIP > Alias Permit); one is needed")
    region = section(permitted[0])
    ip = section("ipsettings")
    split = lambda value: [c for c in (value or "").split(",") if c]  # noqa: E731
    key = ip.get("maxmind_key", "")
    return {
        "permit": permitted[0],
        "countries4": split(region.get("countries4")),
        "countries6": split(region.get("countries6")),
        "maxmind_account": ip.get("maxmind_account", ""),
        "maxmind_key": ENCRYPTED + encrypt_secret(settings.secret_key, key) if key else "",
    }


def summary(content: dict[str, Any]) -> str:
    region = content.get("permit")
    if region not in REGIONS:
        return ""
    countries = ", ".join(c for c in content.get("countries4") or [] if not c.endswith("_rep"))
    return f"Permit {countries or 'nothing'} as {alias_name(region)}; every other region off"
