from __future__ import annotations

from typing import Any


def _number(value: Any, default: float = 0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    status = raw.get("status", {})
    wan = raw.get("wan", {}).get("info", {})
    hardware = status.get("hardware", {})
    devices: dict[str, dict[str, Any]] = {}

    for item in raw.get("devices", {}).get("list", []):
        mac = str(item.get("mac", "")).upper()
        if not mac:
            continue
        ips = [entry.get("ip") for entry in item.get("ip", []) if entry.get("ip")]
        stats = item.get("statistics", {})
        devices[mac] = {
            "mac": mac,
            "name": item.get("oname") or item.get("name") or "Unknown device",
            "online": bool(item.get("online")),
            "wan_access": bool(item.get("authority", {}).get("wan", 1)),
            "ips": ips,
            "up_bps": _number(stats.get("upspeed")),
            "down_bps": _number(stats.get("downspeed")),
            "online_seconds": _number(stats.get("online")),
        }

    dns = [str(v) for v in (wan.get("dnsAddrs"), wan.get("dnsAddrs1")) if v]
    wifi = raw.get("wifi_security")
    wifi_config: dict[str, Any] = {"available": False, "radios": [], "guest_enabled": None, "guest_encryption": None}
    if isinstance(wifi, dict) and wifi.get("code") == 0:
        info = wifi.get("info", [])
        radios = []
        if isinstance(info, list):
            for item in info:
                if not isinstance(item, dict):
                    continue
                encryption = item.get("encryption")
                radio_status = item.get("status")
                radios.append({
                    "band": str(item.get("band") or "radio"),
                    "encryption": str(encryption).lower() if encryption is not None else None,
                    "enabled": str(radio_status).lower() in {"1", "true", "on"} if radio_status is not None else None,
                })
        wifi_config = {
            "available": True,
            "radios": radios,
            "guest_enabled": _optional_bool(wifi.get("on3")),
            "guest_encryption": str(wifi.get("encryption3")).lower() if wifi.get("encryption3") is not None else None,
        }
    return {
        "captured_at": raw.get("captured_at"),
        "router": {
            "model": hardware.get("platform") or raw.get("init_info", {}).get("hardware"),
            "firmware": hardware.get("version") or raw.get("init_info", {}).get("romversion"),
            "uptime": _number(status.get("upTime")),
            "memory_usage": _number(status.get("mem", {}).get("usage")),
            "cpu_load": _number(status.get("cpu", {}).get("load")),
        },
        "wan": {
            "online": bool(wan.get("link", wan.get("status", 0))) and bool(wan.get("status", 0)),
            "dns": sorted(set(dns)),
            "type": wan.get("details", {}).get("wanType"),
        },
        "devices": devices,
        "wifi_security": wifi_config,
    }


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if str(value).lower() in {"1", "true", "on", "yes"}:
        return True
    if str(value).lower() in {"0", "false", "off", "no"}:
        return False
    return None


def make_baseline(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "created_at": snapshot.get("captured_at"),
        "router_model": snapshot.get("router", {}).get("model"),
        "firmware": snapshot.get("router", {}).get("firmware"),
        "expected_dns": snapshot.get("wan", {}).get("dns", []),
        "known_devices": {
            mac: {"name": device.get("name", "Unknown device")}
            for mac, device in snapshot.get("devices", {}).items()
            if "router_api" in device.get("sources", ["router_api"])
        },
    }
