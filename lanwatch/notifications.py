"""Explicit opt-in, privacy-minimized webhook notifications."""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import __version__
from .client import NoRedirectHandler


def send_webhook(url: str | None, events: list[Any]) -> None:
    if not url or not events:
        return
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or parts.fragment or not parts.hostname:
        raise ValueError("Webhook должен быть URL без логина/пароля и фрагмента")
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http":
        try:
            address = ipaddress.ip_address(parts.hostname)
        except ValueError:
            raise ValueError("HTTP webhook разрешён только на loopback IP; для внешних адресов используйте HTTPS") from None
        if not address.is_loopback:
            raise ValueError("HTTP webhook разрешён только на loopback IP; для внешних адресов используйте HTTPS")
    else:
        raise ValueError("Webhook должен использовать HTTPS (или HTTP только для loopback)")
    payload = {
        "source": "LANwatch",
        "events": [{"severity": e.severity, "kind": e.kind, "title": e.title} for e in events],
    }
    request = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=True).encode(), headers={"Content-Type": "application/json", "User-Agent": f"LANwatch/{__version__}"}, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=5) as response:
            if response.status < 200 or response.status >= 300:
                raise ValueError("Webhook вернул неуспешный статус")
    except (urllib.error.URLError, TimeoutError):
        raise ValueError("Не удалось доставить webhook; проверьте URL и доступность сервера") from None


def send_telegram(enabled: bool, events: list[Any]) -> None:
    if not enabled or not events:
        return
    token = os.environ.get("LANWATCH_TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("LANWATCH_TELEGRAM_CHAT_ID", "")
    if not token or not chat_id or "/" in token:
        raise ValueError("Для Telegram задайте LANWATCH_TELEGRAM_BOT_TOKEN и LANWATCH_TELEGRAM_CHAT_ID")
    message = "LANwatch: " + "\n".join(f"[{e.severity}] {e.title}" for e in events)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode()
    request = urllib.request.Request(url, data=body, headers={"User-Agent": f"LANwatch/{__version__}"}, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=5) as response:
            if response.status < 200 or response.status >= 300:
                raise ValueError("Telegram вернул неуспешный статус")
    except (urllib.error.URLError, TimeoutError):
        raise ValueError("Не удалось доставить Telegram уведомление; проверьте переменные окружения") from None
