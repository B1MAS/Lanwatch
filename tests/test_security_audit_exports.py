import unittest
from unittest.mock import patch

from lanwatch.exports import render_events
from lanwatch.models import normalize
from lanwatch.notifications import send_webhook
from lanwatch.security_audit import audit_snapshot
from lanwatch.local_discovery import OUIDatabase, merge_neighbor_cache


class SecurityAuditTests(unittest.TestCase):
    def test_normalizer_never_keeps_ssid_or_wifi_password(self):
        snapshot = normalize({"wifi_security": {"code": 0, "info": [
            {"band": "2.4G", "ssid": "private-network", "password": "secret", "encryption": "psk2", "status": "1"},
        ], "on3": "1", "encryption3": "none"}})
        rendered = repr(snapshot)
        self.assertNotIn("private-network", rendered)
        self.assertNotIn("secret", rendered)
        findings = audit_snapshot(snapshot)
        self.assertIn("CRITICAL", {finding["severity"] for finding in findings})
        self.assertTrue(all(finding["status"] == "unknown" for finding in findings if finding["id"] in {"wps", "upnp", "port_forwarding", "remote_admin", "dhcp", "admin_accounts"}))

    def test_unavailable_api_never_reports_unknown_checks_as_ok(self):
        findings = audit_snapshot({"wifi_security": {"available": False}})
        self.assertTrue(all(item["status"] == "unknown" for item in findings))

    def test_export_formats_escape_newlines_and_cef_delimiters(self):
        event = {"captured_at": 1, "severity": "HIGH", "kind": "test", "title": "bad|title\nforged", "details": "x=y\r\n<4>spoof"}
        syslog = render_events([event], "syslog")
        self.assertEqual(len(syslog.splitlines()), 1)
        cef = render_events([event], "cef")
        self.assertEqual(len(cef.splitlines()), 1)
        self.assertIn("bad\\|title forged", cef)
        self.assertIn("x\\=y", cef)

    def test_webhook_is_opt_in_and_sends_minimal_payload(self):
        send_webhook(None, [])
        event = type("E", (), {"severity": "HIGH", "kind": "x", "title": "notice", "details": "secret IP/MAC"})()
        with patch("lanwatch.notifications.urllib.request.OpenerDirector.open") as request:
            # Exercise request construction by intercepting the opener factory.
            class FakeOpener:
                def open(self, req, timeout):
                    self.request = req
                    self.timeout = timeout
                    return type("Response", (), {"status": 204, "__enter__": lambda s: s, "__exit__": lambda *a: None})()
            fake = FakeOpener()
            with patch("lanwatch.notifications.urllib.request.build_opener", return_value=fake):
                send_webhook("https://example.invalid/hook", [event])
            body = fake.request.data.decode()
            self.assertNotIn("secret IP/MAC", body)
            self.assertIn('"title": "notice"', body)
        with self.assertRaises(ValueError):
            send_webhook("http://192.168.1.2/hook", [event])

    def test_arp_source_is_separate_and_not_treated_as_confirmed_online(self):
        import tempfile
        from pathlib import Path
        api_mac = "00:11:22:33:44:55"
        cache_mac = "00:11:22:33:44:66"
        snapshot = {"devices": {api_mac: {"mac": api_mac, "name": "AP device", "online": True, "ips": []}}}
        with tempfile.TemporaryDirectory() as temp:
            merged = merge_neighbor_cache(snapshot, {api_mac: ["192.168.1.2"], cache_mac: ["192.168.1.3"]}, Path(temp) / "oui.csv")
        self.assertEqual(merged["devices"][api_mac]["sources"], ["router_api", "arp_cache"])
        self.assertIsNone(merged["devices"][cache_mac]["online"])
        self.assertEqual(merged["source_comparison"]["arp_cache_only"], [cache_mac])

    def test_oui_database_matches_globally_assigned_prefix_and_flags_randomized(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "oui.csv"
            path.write_text('Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,Example Devices,Address\n', encoding="utf-8")
            lookup = OUIDatabase(path)
        self.assertEqual(lookup.vendor("00:11:22:aa:bb:cc"), "Example Devices")
        self.assertIn("Локально назначенный", lookup.vendor("02:11:22:aa:bb:cc"))


if __name__ == "__main__":
    unittest.main()
