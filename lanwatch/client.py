from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from . import __version__


class RouterError(RuntimeError):
    """Router connection or API error."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class MiWiFiClient:
    """Minimal read-only client for the Xiaomi MiWiFi local API."""

    def __init__(self, base_url: str, timeout: int = 10) -> None:
        try:
            parts = urlsplit(base_url)
            address = ipaddress.ip_address(parts.hostname or "")
            port = parts.port
        except (ValueError, TypeError):
            raise RouterError("Адрес роутера должен быть локальным IP, например http://192.168.31.1") from None
        if (
            parts.scheme not in {"http", "https"}
            or not (address.is_private or address.is_loopback or address.is_link_local)
            or address.is_unspecified
            or address.is_multicast
            or address.is_reserved
            or (port is not None and not 1 <= port <= 65535)
            or parts.username is not None
            or parts.password is not None
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            raise RouterError("Разрешён только HTTP(S)-адрес роутера в локальной сети без логина в URL")
        self.base_url = f"{parts.scheme}://{parts.netloc}"
        self.timeout = timeout
        self.token = ""
        self.opener = urllib.request.build_opener(NoRedirectHandler(), urllib.request.HTTPCookieProcessor())

    def _request(self, path: str, data: dict[str, str] | None = None) -> Any:
        encoded = urllib.parse.urlencode(data).encode() if data else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=encoded,
            headers={"User-Agent": f"LANwatch/{__version__}"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw_body = response.read(4_000_001)
                if len(raw_body) > 4_000_000:
                    raise RouterError("Ответ роутера превысил допустимый размер")
                body = raw_body.decode("utf-8", errors="replace")
        except urllib.error.URLError:
            # Do not include the exception text: it can contain a URL with a stok token.
            raise RouterError("Ошибка подключения к роутеру. Проверьте адрес и доступность устройства.") from None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    def init_info(self) -> dict[str, Any]:
        result = self._request("/cgi-bin/luci/api/xqsystem/init_info")
        if not isinstance(result, dict) or result.get("code") != 0:
            raise RouterError("Не удалось получить init_info")
        return result

    def login(self, password: str) -> dict[str, Any]:
        info = self.init_info()
        page = self._request("/cgi-bin/luci/web")
        if not isinstance(page, str):
            raise RouterError("Не удалось получить страницу авторизации")
        key = re.search(r"key\s*:\s*['\"]([^'\"]+)", page)
        device = re.search(r"deviceId\s*=\s*['\"]([^'\"]+)", page)
        if not key or not device:
            raise RouterError("Прошивка использует неизвестный формат входа")

        nonce = f"0_{device.group(1)}_{int(time.time())}_{random.randint(1000, 9999)}"
        digest = hashlib.sha256 if str(info.get("newEncryptMode", "0")) == "1" else hashlib.sha1
        inner = digest((password + key.group(1)).encode()).hexdigest()
        password_hash = digest((nonce + inner).encode()).hexdigest()
        result = self._request(
            "/cgi-bin/luci/api/xqsystem/login",
            {"username": "admin", "password": password_hash, "logtype": "2", "nonce": nonce},
        )
        if not isinstance(result, dict) or result.get("code") != 0:
            code = result.get("code") if isinstance(result, dict) else "unknown"
            raise RouterError(f"Ошибка авторизации, код: {code}")
        self.token = str(result.get("token", ""))
        if not self.token:
            match = re.search(r";stok=([^/]+)/", str(result.get("url", "")))
            self.token = match.group(1) if match else ""
        if not self.token:
            raise RouterError("Роутер не вернул токен")
        return info

    def get(self, endpoint: str) -> dict[str, Any]:
        result = self._request(
            f"/cgi-bin/luci/;stok={self.token}/api/{endpoint.strip('/')}"
        )
        if not isinstance(result, dict) or result.get("code") != 0:
            raise RouterError(f"API {endpoint} вернул ошибку")
        return result

    def snapshot(self, password: str) -> dict[str, Any]:
        info = self.login(password)
        # This endpoint is read-only. Some firmware variants do not expose it;
        # missing data must remain unknown, not be treated as safe.
        try:
            wifi_security = self.get("xqnetwork/wifi_detail_all")
        except RouterError:
            wifi_security = None
        return {
            "captured_at": int(time.time()),
            "init_info": info,
            "status": self.get("misystem/status"),
            "devices": self.get("misystem/devicelist"),
            "wan": self.get("xqnetwork/wan_info"),
            "new_status": self.get("misystem/newstatus"),
            "wifi_security": wifi_security,
        }
