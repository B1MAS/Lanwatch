"""Router adapter selection and safe local platform detection."""

from __future__ import annotations

from .miwifi import MiWiFiAdapter
from .openwrt import OpenWrtAdapter
from ..client import RouterError


def detect_adapter(router: str, timeout: int = 3) -> str:
    """Identify supported local router APIs without sending credentials."""
    try:
        if MiWiFiAdapter(router, timeout=timeout).probe():
            return "miwifi"
    except RouterError:
        pass
    try:
        if OpenWrtAdapter(router, timeout=timeout, allow_insecure_http=True).probe():
            return "openwrt"
    except RouterError:
        pass
    raise RouterError("Не удалось определить API роутера. Укажите --adapter miwifi или --adapter openwrt")


def adapter_name(adapter: str, router: str) -> str:
    return detect_adapter(router) if adapter == "auto" else adapter


def create_adapter(router: str, adapter: str, allow_insecure_http: bool = False):
    if adapter == "openwrt":
        return OpenWrtAdapter(router, allow_insecure_http=allow_insecure_http)
    if adapter == "miwifi":
        return MiWiFiAdapter(router)
    raise RouterError("Неизвестный адаптер роутера")


def capture_snapshot(router: str, adapter: str, credentials: tuple[str, ...], allow_insecure_http: bool = False):
    return create_adapter(router, adapter, allow_insecure_http).snapshot(*credentials)
