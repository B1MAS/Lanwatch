"""Xiaomi MiWiFi adapter over the local vendor API."""

from __future__ import annotations

from typing import Any

from ..client import MiWiFiClient
from ..models import normalize


class MiWiFiAdapter:
    name = "miwifi"
    experimental = False

    def __init__(self, router: str, timeout: int = 10) -> None:
        self.client = MiWiFiClient(router, timeout=timeout)

    def probe(self) -> bool:
        return bool(self.client.init_info())

    def snapshot(self, password: str) -> dict[str, Any]:
        return normalize(self.client.snapshot(password))
