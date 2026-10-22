"""The agent package's definition as pfSense reads it."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

PKG_XML = Path(__file__).resolve().parents[2] / "agent/pfSense-pkg-ComSense/files/usr/local/pkg/comsense.xml"


def test_the_service_names_an_executable():
    # pfSense Plus 25.x/26.x stops package services before a reboot with is_process_running($executable);
    # without one it throws a TypeError and the reboot is aborted.
    service = ET.parse(PKG_XML).getroot().find("service")
    assert service is not None and service.findtext("name") == "comsense"
    assert service.findtext("executable") == "comsense-agentd"
    assert service.findtext("custom_php_service_status_command")
