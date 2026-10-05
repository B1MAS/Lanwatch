"""Create privacy-safe, shareable support diagnostics."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from . import __version__


def diagnostic_report(adapter: str, detected: bool) -> dict[str, Any]:
    # Deliberately use a small allowlist. Never serialize router responses,
    # credentials, addresses, identifiers, device data, or local paths.
    return {
        "schema": "lanwatch-support-v1",
        "lanwatch_version": __version__,
        "python_version": platform.python_version(),
        "platform": platform.system().lower(),
        "adapter": adapter if detected else "unknown",
        "adapter_status": "detected" if detected else "not_detected",
        "capabilities": {
            "device_presence": adapter in {"miwifi", "openwrt"} and detected,
            "wan_status": adapter in {"miwifi", "openwrt"} and detected,
            "dns_monitoring": adapter in {"miwifi", "openwrt"} and detected,
            "wifi_association_details": adapter == "miwifi" and detected,
            "router_cpu_memory_metrics": adapter == "miwifi" and detected,
        },
        "privacy": "No router IP, MAC, device name, credentials, token, or router response included.",
    }


def write_report(report: dict[str, Any], destination: str) -> Path:
    path = Path(destination)
    # Exclusive create avoids silently overwriting a user's existing report.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return path
