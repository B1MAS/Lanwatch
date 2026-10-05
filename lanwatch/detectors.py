from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Event:
    severity: str
    kind: str
    title: str
    details: str

    @property
    def fingerprint(self) -> str:
        return f"{self.kind}:{self.title}:{self.details}"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def detect(
    baseline: dict[str, Any],
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    upload_threshold_bps: float = 5_000_000,
) -> list[Event]:
    events: list[Event] = []
    known = baseline.get("known_devices", {})
    current_devices = current.get("devices", {})

    if not current.get("wan", {}).get("online", False):
        events.append(Event("CRITICAL", "wan_down", "WAN недоступен", "Роутер сообщает об отсутствии интернет-соединения"))

    expected_dns = sorted(baseline.get("expected_dns", []))
    actual_dns = sorted(current.get("wan", {}).get("dns", []))
    if expected_dns and actual_dns != expected_dns:
        events.append(Event("HIGH", "dns_changed", "Изменены DNS-серверы", f"Было: {', '.join(expected_dns)}; стало: {', '.join(actual_dns) or 'нет данных'}"))

    for mac, device in current_devices.items():
        if device.get("online") and mac not in known:
            events.append(Event("HIGH", "unknown_device", "Новое устройство", f"{device.get('name')} ({mac}), IP: {', '.join(device.get('ips', [])) or 'неизвестен'}"))
        if device.get("online") and not device.get("wan_access", True):
            events.append(Event("MEDIUM", "wan_blocked", "Устройству закрыт интернет", f"{device.get('name')} ({mac})"))
        if device.get("online") and device.get("up_bps", 0) >= upload_threshold_bps:
            mbps = device["up_bps"] * 8 / 1_000_000
            events.append(Event("MEDIUM", "high_upload", "Высокая исходящая скорость", f"{device.get('name')} ({mac}): {mbps:.1f} Мбит/с"))

    if previous:
        old_wifi = previous.get("wifi_security", {})
        new_wifi = current.get("wifi_security", {})
        if old_wifi.get("available") and new_wifi.get("available") and old_wifi != new_wifi:
            events.append(Event("MEDIUM", "wifi_config_changed", "Изменились настройки Wi-Fi", "Проверьте, не ослабло ли шифрование и ожидаемо ли изменение гостевой сети."))
        old_uptime = previous.get("router", {}).get("uptime", 0)
        new_uptime = current.get("router", {}).get("uptime", 0)
        if new_uptime + 30 < old_uptime:
            events.append(Event("MEDIUM", "router_reboot", "Роутер перезагрузился", f"Uptime изменился с {old_uptime:.0f} до {new_uptime:.0f} секунд"))

        old_fw = previous.get("router", {}).get("firmware")
        new_fw = current.get("router", {}).get("firmware")
        if old_fw and new_fw and old_fw != new_fw:
            events.append(Event("INFO", "firmware_changed", "Изменилась прошивка", f"{old_fw} -> {new_fw}"))

        old_devices = previous.get("devices", {})
        for mac in sorted(set(old_devices) | set(current_devices)):
            if mac not in known:
                continue
            was = bool(old_devices.get(mac, {}).get("online"))
            now = bool(current_devices.get(mac, {}).get("online"))
            if was != now:
                name = current_devices.get(mac, old_devices.get(mac, {})).get("name", mac)
                state = "подключилось" if now else "отключилось"
                events.append(Event("INFO", "device_state", f"Изменился статус устройства", f"{name} ({mac}) {state}"))

    return events
