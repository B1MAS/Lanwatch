"""Copy this file when implementing a read-only router adapter."""

from __future__ import annotations

from typing import Any


class ExampleAdapter:
    name = "example"
    experimental = True

    def __init__(self, router: str, timeout: int = 10) -> None:
        self.router = router
        self.timeout = timeout

    def probe(self) -> bool:
        # Return true only after identifying a documented/reproducible API.
        return False

    def snapshot(self, *credentials: str) -> dict[str, Any]:
        # Fetch data only. Never call config setters, reboot, scan other hosts,
        # or persist API tokens/passwords/SSID values in the returned snapshot.
        return {
            "captured_at": 0,
            "router": {"model": None, "firmware": None},
            "wan": {"online": None, "dns": []},
            "devices": {},
            "wifi_security": {"available": False, "radios": []},
        }
