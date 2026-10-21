import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
import status_checker


class StatusCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp_dir.name) / "monitor.sqlite3"
        )
        self.db_patch.start()
        database.init_db()
        self.lock_patch = patch.object(status_checker, "refresh_lock")
        self.lock_patch.start()
        status_checker.refresh_lock.acquire.return_value = True

    def tearDown(self):
        self.lock_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def configure_device(self, networks, arp_command="ip neigh", device_type="ssh"):
        path = Path(self.temp_dir.name) / "devices.json"
        device = {
            "name": "test-router",
            "type": device_type,
            "host": "192.0.2.1",
            "username": "monitor",
            "password_env": "TEST_ROUTER_PASSWORD",
            "arp_command": arp_command,
            "networks": networks,
        }
        if device_type == "none":
            device.pop("username", None)
            device.pop("password_env", None)
            device.pop("arp_command", None)
        path.write_text(json.dumps([device]), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        self.env_patch = patch.dict(os.environ, {"TEST_ROUTER_PASSWORD": "test-password"})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        return patch.object(status_checker, "DEVICES_PATH", path)

    def test_none_type_is_skipped(self):
        database.add_client("A", "192.168.1.10")
        network_patch = self.configure_device(["192.168.1.0/24"], device_type="none")
        with network_patch:
            self.assertTrue(status_checker.refresh_all_statuses())
        self.assertEqual(database.get_all_clients()[0]["status"], "ok")

    def test_configured_arp_command_is_used_for_router(self):
        network_patch = self.configure_device(["192.168.1.0/24"], "show arp")
        with network_patch:
            device = status_checker.load_devices()[0]
        with patch.object(
            status_checker.huawei, "get_arp_table", return_value={"192.168.1.1"}
        ) as get_arp_table:
            self.assertEqual(
                status_checker.get_arp_with_retry(device), {"192.168.1.1"}
            )
        self.assertEqual(get_arp_table.call_args.kwargs["command"], "show arp")

    def test_missing_device_config_aborts_refresh(self):
        missing_path = Path(self.temp_dir.name) / "missing.json"
        with patch.object(status_checker, "DEVICES_PATH", missing_path):
            self.assertFalse(status_checker.refresh_all_statuses())

    def test_complete_snapshot_updates_database_atomically(self):
        database.add_client("UP", "192.168.1.10")
        database.add_client("DOWN", "192.168.1.11")
        network_patch = self.configure_device(["192.168.1.0/24"])
        with network_patch:
            with patch.object(
                status_checker, "get_arp_with_retry",
                return_value={"192.168.1.10", "192.168.1.1"}
            ):
                self.assertTrue(status_checker.refresh_all_statuses())
        clients = {item["client_id"]: item for item in database.get_all_clients()}
        self.assertEqual(clients["UP"]["status"], "ok")
        self.assertEqual(clients["DOWN"]["status"], "error")

    def test_uncovered_network_marks_clients_offline(self):
        database.add_client("UP", "192.168.1.10")
        network_patch = self.configure_device(["192.168.1.0/24"])
        with network_patch:
            with patch.object(
                status_checker, "get_arp_with_retry",
                return_value={"10.0.0.5"}
            ):
                self.assertTrue(status_checker.refresh_all_statuses())
        client = database.get_all_clients()[0]
        self.assertEqual(client["status"], "error")

    def test_empty_arp_does_not_change_status(self):
        database.add_client("A", "192.168.1.10")
        network_patch = self.configure_device(["192.168.1.0/24"])
        with network_patch:
            with patch.object(status_checker, "get_arp_with_retry", return_value=set()):
                self.assertFalse(status_checker.refresh_all_statuses())
        self.assertEqual(database.get_all_clients()[0]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
