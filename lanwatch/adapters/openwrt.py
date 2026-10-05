"""Experimental, read-only OpenWrt ubus-over-HTTP adapter."""

from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from ..client import NoRedirectHandler, RouterError


class OpenWrtClient:
    # The application intentionally has no general-purpose RPC method. Keeping
    # this allowlist local makes accidental configuration/write calls harder.
    READ_CALLS = {
        ("system", "board"),
        ("system", "info"),
        ("network.interface.wan", "status"),
        ("dhcp", "ipv4leases"),
    }

    def __init__(self, base_url: str, timeout: int = 8, *, allow_insecure_http: bool = False) -> None:
        try:
            parts = urlsplit(base_url)
            address = ipaddress.ip_address(parts.hostname or "")
            port = parts.port
        except (ValueError, TypeError):
            raise RouterError("Адрес роутера должен быть локальным IP, например http://192.168.1.1") from None
        if (
            parts.scheme not in {"http", "https"}
            or not (address.is_private or address.is_loopback or address.is_link_local)
            or address.is_unspecified or address.is_multicast or address.is_reserved
            or (port is not None and not 1 <= port <= 65535)
            or parts.username is not None or parts.password is not None
            or parts.path not in {"", "/"} or parts.query or parts.fragment
        ):
            raise RouterError("Разрешён только HTTP(S)-адрес роутера в локальной сети")
        if parts.scheme != "https" and not allow_insecure_http:
            raise RouterError("Для OpenWrt нужен HTTPS. HTTP передаёт пароль по сети открытым текстом; для доверенной изолированной LAN можно явно добавить --allow-insecure-http")
        self.base_url = f"{parts.scheme}://{parts.netloc}"
        self.timeout = timeout
        self.session = "00000000000000000000000000000000"
        self.authenticated = False
        self.opener = urllib.request.build_opener(NoRedirectHandler())
        self._request_id = 0

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/ubus", data=body,
            headers={"Content-Type": "application/json", "User-Agent": "LANwatch/0.3"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1_000_001)
                if len(raw) > 1_000_000:
                    raise RouterError("Ответ OpenWrt превысил допустимый размер")
        except urllib.error.URLError:
            raise RouterError("Ошибка подключения к OpenWrt. Проверьте локальный адрес и доступность API.") from None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RouterError("OpenWrt вернул некорректный JSON-RPC ответ") from None
        if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
            raise RouterError("Ответ не похож на OpenWrt ubus JSON-RPC")
        return parsed

    def _call(self, obj: str, method: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        if (obj, method) not in self.READ_CALLS:
            raise RouterError("Адаптер заблокировал неизвестный или изменяющий RPC-вызов")
        self._request_id += 1
        response = self._post({
            "jsonrpc": "2.0", "id": self._request_id, "method": "call",
            "params": [self.session, obj, method, args or {}],
        })
        result = response.get("result")
        if not isinstance(result, list) or not result:
            raise RouterError("OpenWrt вернул ошибку ubus")
        if result[0] != 0:
            raise RouterError("Нет прав на чтение данных OpenWrt. Проверьте read-only ACL для LANwatch.")
        data = result[1] if len(result) > 1 else {}
        return data if isinstance(data, dict) else {}

    def probe(self) -> bool:
        # Unauthenticated and read-only: system.board only; no password/token.
        try:
            self._call("system", "board")
            return True
        except RouterError as exc:
            # A denial still confirms ubus JSON-RPC and the known object/method;
            # malformed endpoints and transport failures do not.
            return "Нет прав на чтение" in str(exc)

    def login(self, username: str, password: str) -> None:
        if not username or not password:
            raise RouterError("Для OpenWrt нужны непустые имя пользователя и пароль")
        self._request_id += 1
        result = self._post({
            "jsonrpc": "2.0", "id": self._request_id, "method": "call",
            "params": [self.session, "session", "login", {
                "username": username, "password": password, "timeout": 300,
            }],
        }).get("result")
        if not isinstance(result, list) or not result or result[0] != 0:
            raise RouterError("Ошибка входа в OpenWrt RPC. Проверьте учётную запись и ACL.")
        value = result[1] if len(result) > 1 and isinstance(result[1], dict) else {}
        session = value.get("ubus_rpc_session")
        if not isinstance(session, str) or not session:
            raise RouterError("OpenWrt не вернул сессию RPC")
        self.session = session
        self.authenticated = True

    def snapshot(self, username: str, password: str) -> dict[str, Any]:
        if not self.authenticated:
            self.login(username, password)
        for attempt in range(2):
            try:
                board = self._call("system", "board")
                info = self._call("system", "info")
                wan = self._call("network.interface.wan", "status")
                leases = self._call("dhcp", "ipv4leases")
                return {"captured_at": time.time(), "board": board, "info": info, "wan": wan, "leases": leases}
            except RouterError as exc:
                if attempt or "Нет прав на чтение" not in str(exc):
                    raise
                # ubus sessions expire after inactivity; re-login once using
                # the in-memory credentials supplied by the caller.
                self.session = "00000000000000000000000000000000"
                self.authenticated = False
                self.login(username, password)
        raise RouterError("Не удалось получить снимок OpenWrt")


def normalize_openwrt(raw: dict[str, Any]) -> dict[str, Any]:
    board = raw.get("board", {})
    board = board if isinstance(board, dict) else {}
    release = board.get("release", {}) if isinstance(board.get("release"), dict) else {}
    wan = raw.get("wan", {})
    wan = wan if isinstance(wan, dict) else {}
    info = raw.get("info", {})
    info = info if isinstance(info, dict) else {}
    devices: dict[str, dict[str, Any]] = {}
    lease_data = raw.get("leases", {})
    if isinstance(lease_data, dict) and "leases" in lease_data:
        groups = [lease_data]
    elif isinstance(lease_data, dict):
        groups = list(lease_data.values())
    elif isinstance(lease_data, list):
        groups = lease_data if any(isinstance(item, dict) and "leases" in item for item in lease_data) else [{"leases": lease_data}]
    else:
        groups = []
    for group in groups:
        leases = group.get("leases", []) if isinstance(group, dict) else []
        for item in leases if isinstance(leases, list) else []:
            if not isinstance(item, dict):
                continue
            mac = str(item.get("macaddr", "")).upper()
            if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
                continue
            devices[mac] = {
                "mac": mac, "name": str(item.get("hostname") or "Unknown device"),
                "online": True, "wan_access": True,
                "ips": [str(item["ipaddr"])] if item.get("ipaddr") else [],
                "up_bps": 0.0, "down_bps": 0.0, "online_seconds": 0.0,
            }
    dns = wan.get("dns-server", [])
    dns = [str(item) for item in dns if isinstance(item, (str, int))] if isinstance(dns, list) else []
    return {
        "captured_at": int(raw.get("captured_at", 0)),
        "router": {
            "model": board.get("model") or board.get("board_name"),
            "firmware": release.get("version"),
            "uptime": _number(info.get("uptime", 0)),
            "memory_usage": 0, "cpu_load": 0,
        },
        "wan": {"online": bool(wan.get("up")), "dns": sorted(set(dns)), "type": None},
        "devices": devices,
    }


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class OpenWrtAdapter:
    name = "openwrt"
    experimental = True

    def __init__(self, router: str, timeout: int = 8, *, allow_insecure_http: bool = False) -> None:
        self.client = OpenWrtClient(router, timeout=timeout, allow_insecure_http=allow_insecure_http)

    def probe(self) -> bool:
        return self.client.probe()

    def snapshot(self, username: str, password: str) -> dict[str, Any]:
        return normalize_openwrt(self.client.snapshot(username, password))
