"""Local, passive neighbor-cache enrichment and offline IEEE vendor lookup."""

from __future__ import annotations

import csv
import ipaddress
import io
import os
import platform
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__
from .client import NoRedirectHandler, RouterError


MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
IP_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
IEEE_OUI_CSV = "https://standards-oui.ieee.org/oui/oui.csv"
MAX_OUI_BYTES = 20_000_000


def read_neighbor_cache() -> dict[str, list[str]] | None:
    """Read the host's existing ARP cache; never probes or scans the subnet."""
    neighbors: dict[str, set[str]] = {}
    system = platform.system().lower()
    try:
        if system == "linux":
            rows = Path("/proc/net/arp").read_text(encoding="ascii", errors="ignore").splitlines()[1:]
            for row in rows:
                fields = row.split()
                if len(fields) < 6:
                    continue
                ip, flags, mac = fields[0], fields[2], fields[3]
                try:
                    if int(flags, 16) & 0x2 == 0:
                        continue
                except ValueError:
                    continue
                _add_neighbor(neighbors, ip, mac)
        elif system in {"windows", "darwin", "freebsd", "openbsd", "netbsd"}:
            command = ["arp", "-a"] if system == "windows" else ["arp", "-an"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False, shell=False)
            if result.returncode != 0:
                return None
            output = result.stdout[:1_000_000]
            for line in output.splitlines():
                mac_match = MAC_PATTERN.search(line)
                ip_match = IP_PATTERN.search(line)
                if mac_match and ip_match:
                    _add_neighbor(neighbors, ip_match.group(0), mac_match.group(0))
        else:
            return None
    except (OSError, subprocess.SubprocessError):
        return None
    return {mac: sorted(ips) for mac, ips in neighbors.items()}


def _add_neighbor(target: dict[str, set[str]], ip_value: str, mac_value: str) -> None:
    raw_mac = re.sub(r"[:-]", "", mac_value).upper()
    mac = ":".join(raw_mac[index:index + 2] for index in range(0, len(raw_mac), 2))
    if not MAC_PATTERN.fullmatch(mac) or int(mac[:2], 16) & 1:
        return
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return
    if not address.is_private and not address.is_link_local:
        return
    target.setdefault(mac, set()).add(str(address))


class OUIDatabase:
    def __init__(self, path: Path) -> None:
        self.records: dict[str, str] = {}
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                for row in csv.DictReader(stream):
                    prefix = re.sub(r"[^0-9A-Fa-f]", "", str(row.get("Assignment") or ""))[:6].upper()
                    organization = str(row.get("Organization Name") or "").strip()[:160]
                    if len(prefix) == 6 and re.fullmatch(r"[0-9A-F]{6}", prefix) and organization:
                        self.records[prefix] = organization
        except (OSError, csv.Error):
            pass

    def vendor(self, mac: str) -> str | None:
        normalized = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(normalized) != 12 or not re.fullmatch(r"[0-9A-F]{12}", normalized):
            return None
        if int(normalized[:2], 16) & 0x02:
            return "Локально назначенный MAC (вендор не определяется)"
        return self.records.get(normalized[:6])


def update_oui_database(directory: Path) -> tuple[int, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(IEEE_OUI_CSV, headers={"User-Agent": f"LANwatch/{__version__}"})
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_OUI_BYTES + 1)
    except (urllib.error.URLError, TimeoutError):
        raise RouterError("Не удалось получить OUI справочник IEEE; существующая локальная база не изменена") from None
    if len(body) > MAX_OUI_BYTES:
        raise RouterError("Файл IEEE OUI превысил допустимый размер")
    try:
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
    except (UnicodeDecodeError, csv.Error):
        raise RouterError("IEEE вернул файл неизвестного формата; локальная база не изменена") from None
    if not rows or not {"Assignment", "Organization Name"}.issubset(rows[0]):
        raise RouterError("Структура IEEE OUI файла изменилась; локальная база не изменена")
    valid = sum(1 for row in rows if re.fullmatch(r"[0-9A-Fa-f]{6}", re.sub(r"[^0-9A-Fa-f]", "", str(row.get("Assignment") or ""))[:6]) and str(row.get("Organization Name") or "").strip())
    if valid < 1000:
        raise RouterError("Слишком мало OUI записей; загрузка отклонена")
    path = directory / "oui.csv"
    temp = path.with_suffix(".tmp")
    temp.write_bytes(body)
    if os.name != "nt":
        temp.chmod(0o600)
    temp.replace(path)
    return valid, path


def merge_neighbor_cache(snapshot: dict[str, Any], neighbors: dict[str, list[str]] | None, oui_path: Path) -> dict[str, Any]:
    """Merge cache rows without treating cache entries as confirmed online."""
    devices = snapshot.setdefault("devices", {})
    api_macs = sorted(devices)
    arp_map = neighbors or {}
    lookup = OUIDatabase(oui_path)
    for mac, ips in arp_map.items():
        vendor = lookup.vendor(mac)
        if mac in devices:
            item = devices[mac]
            item["ips"] = sorted(set(item.get("ips", [])) | set(ips))
            item["sources"] = ["router_api", "arp_cache"]
            item["vendor"] = vendor
        else:
            devices[mac] = {
                "mac": mac,
                "name": "Обнаружено в ARP-кэше",
                "online": None,
                "wan_access": None,
                "ips": ips,
                "up_bps": 0,
                "down_bps": 0,
                "online_seconds": 0,
                "sources": ["arp_cache"],
                "vendor": vendor,
            }
    for mac, item in devices.items():
        item.setdefault("sources", ["router_api"])
        if "vendor" not in item:
            item["vendor"] = lookup.vendor(mac)
    arp_macs = sorted(arp_map)
    snapshot["source_comparison"] = {
        "router_api_available": True,
        "arp_cache_available": neighbors is not None,
        "router_api_only": sorted(set(api_macs) - set(arp_macs)),
        "arp_cache_only": sorted(set(arp_macs) - set(api_macs)),
        "both": sorted(set(api_macs) & set(arp_macs)),
        "arp_cache_count": len(arp_macs),
    }
    return snapshot


def collect_snapshot(client: Any, credentials: tuple[str, ...], directory: Path, include_arp: bool = True) -> dict[str, Any]:
    snapshot = client.snapshot(*credentials)
    if include_arp:
        return merge_neighbor_cache(snapshot, read_neighbor_cache(), directory / "oui.csv")
    merge_neighbor_cache(snapshot, {}, directory / "oui.csv")
    snapshot["source_comparison"]["arp_cache_available"] = False
    snapshot["source_comparison"]["arp_cache_disabled"] = True
    return snapshot
