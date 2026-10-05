"""Shared contract for router integrations."""

from __future__ import annotations

from typing import Any, Protocol


class RouterAdapter(Protocol):
    name: str
    experimental: bool

    def probe(self) -> bool: ...

    def snapshot(self, *credentials: str) -> dict[str, Any]: ...
