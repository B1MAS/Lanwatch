"""Conservative, read-only checks for router security settings."""

from __future__ import annotations

from typing import Any


UNSUPPORTED = (
    ("wps", "WPS", "Текущий адаптер не предоставляет подтверждённое read-only поле WPS."),
    ("upnp", "UPnP", "Текущий адаптер не предоставляет подтверждённое read-only поле UPnP."),
    ("port_forwarding", "Проброс портов", "Правила проброса портов этим адаптером не проверяются."),
    ("remote_admin", "Удалённое управление", "Настройка удалённого управления этим адаптером не проверяется."),
    ("dhcp", "DHCP", "Параметры DHCP этим адаптером не проверяются."),
    ("admin_accounts", "Администраторы", "Список административных учётных записей недоступен."),
)


def _encryption_finding(scope: str, value: Any) -> dict[str, str]:
    label = "Гостевая Wi-Fi сеть" if scope == "guest" else f"Wi-Fi {scope}"
    encryption = str(value or "").lower()
    if encryption in {"none", "open", ""} and value is not None:
        status, severity, summary, advice = "risk", "CRITICAL", "Сеть не использует шифрование.", "Включите WPA2-AES или WPA3 и задайте новый пароль."
    elif encryption == "wep":
        status, severity, summary, advice = "risk", "HIGH", "Обнаружено устаревшее шифрование WEP.", "Переключите сеть на WPA2-AES или WPA3."
    elif encryption in {"psk", "psk-mixed"}:
        status, severity, summary, advice = "review", "HIGH", "Режим совместимости может допускать устаревшее шифрование.", "Проверьте настройки роутера; предпочтителен WPA2-AES или WPA3."
    elif encryption in {"psk2", "wpa2", "wpa2-psk"}:
        status, severity, summary, advice = "review", "MEDIUM", "Похоже на WPA2; WPA3 может быть предпочтительнее, если поддерживается.", "Проверьте, что используется WPA2-AES (не TKIP), и рассмотрите WPA3."
    elif encryption in {"psk3", "sae", "wpa3", "wpa3-sae"}:
        status, severity, summary, advice = "ok", "INFO", "Адаптер сообщает режим WPA3/SAE.", "Убедитесь, что все клиенты поддерживают выбранный режим."
    elif encryption in {"psk2+ccmp", "wpa2-aes"}:
        status, severity, summary, advice = "ok", "INFO", "Адаптер сообщает WPA2 с AES/CCMP.", "Для более новых устройств можно рассмотреть WPA3."
    else:
        status, severity, summary, advice = "unknown", "INFO", "Формат шифрования неизвестен адаптеру.", "Проверьте режим защиты вручную в панели роутера."
    return {"id": f"wifi_encryption_{scope}", "label": label, "status": status, "severity": severity, "summary": summary, "recommendation": advice}


def audit_snapshot(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    """Return findings without secrets; unavailable checks are explicitly unknown."""
    wifi = snapshot.get("wifi_security") or {}
    findings: list[dict[str, str]] = []
    if wifi.get("available"):
        radios = wifi.get("radios", [])
        if radios:
            for index, radio in enumerate(radios, start=1):
                band = str(radio.get("band") or index)
                # Limit API-controlled label size; never include SSID/password.
                band = band[:24]
                if radio.get("enabled") is False:
                    continue
                findings.append(_encryption_finding(band, radio.get("encryption")))
        else:
            findings.append({"id": "wifi_encryption", "label": "Основная Wi-Fi сеть", "status": "unknown", "severity": "INFO", "summary": "API не вернул сведения о Wi-Fi диапазонах.", "recommendation": "Проверьте защиту Wi-Fi вручную."})
        guest_enabled = wifi.get("guest_enabled")
        if guest_enabled is True:
            findings.append({"id": "guest_wifi", "label": "Гостевая Wi-Fi сеть", "status": "review", "severity": "MEDIUM", "summary": "Гостевая сеть включена.", "recommendation": "Убедитесь, что включена изоляция клиентов и доступ только к интернету."})
            findings.append(_encryption_finding("guest", wifi.get("guest_encryption")))
        elif guest_enabled is False:
            findings.append({"id": "guest_wifi", "label": "Гостевая Wi-Fi сеть", "status": "ok", "severity": "INFO", "summary": "Гостевая сеть выключена.", "recommendation": "Если включите её, проверьте изоляцию от основной сети."})
        else:
            findings.append({"id": "guest_wifi", "label": "Гостевая Wi-Fi сеть", "status": "unknown", "severity": "INFO", "summary": "Состояние гостевой сети не сообщается API.", "recommendation": "Проверьте её состояние вручную."})
    else:
        findings.append({"id": "wifi_api", "label": "Настройки Wi-Fi", "status": "unknown", "severity": "INFO", "summary": "Текущий API не предоставил настройки Wi-Fi.", "recommendation": "Проверьте настройки защиты вручную или приложите безопасный probe-отчёт для улучшения поддержки."})
    for check_id, label, summary in UNSUPPORTED:
        findings.append({"id": check_id, "label": label, "status": "unknown", "severity": "INFO", "summary": summary, "recommendation": "Проверьте настройку вручную в административной панели роутера."})
    return findings
