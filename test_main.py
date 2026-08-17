import asyncio
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


WAR_MAIN = Path(__file__).with_name("main.py")


def _load_app(data_root: str):
    os.environ["DATA_ROOT"] = data_root
    os.environ.pop("XRAY_BRIDGE_WS_PATH", None)
    spec = importlib.util.spec_from_file_location(f"war_main_test_{id(data_root)}", WAR_MAIN)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WarsawConfigTests(unittest.TestCase):
    def test_fresh_data_preserves_all_migrated_uuids_and_routes_direct(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            app._ensure_layout()

            panel = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            self.assertEqual(17, len(panel["users"]))
            self.assertFalse(panel["settings"]["include_base_user"])
            self.assertEqual(set(app.MIGRATED_CLIENT_UUIDS), {user["uuid"] for user in panel["users"]})

            store = app.PanelStore(app.PANEL_DB_PATH)
            manager = app.XrayManager(store)
            config_path = asyncio.run(manager._build_runtime_config())
            config = json.loads(config_path.read_text(encoding="utf-8"))

            clients = config["inbounds"][0]["settings"]["clients"]
            self.assertEqual(set(app.MIGRATED_CLIENT_UUIDS), {client["id"] for client in clients})
            self.assertEqual("/api/e6f5774ee4c658e2", config["inbounds"][0]["streamSettings"]["wsSettings"]["path"])
            self.assertNotIn("routing", config)
            self.assertEqual([{"protocol": "freedom", "tag": "DIRECT"}], config["outbounds"])

    def test_seed_runs_once_and_does_not_restore_deleted_users(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            app._ensure_layout()
            panel = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            removed_uuid = panel["users"].pop()["uuid"]
            app.PANEL_DB_PATH.write_text(json.dumps(panel), encoding="utf-8")

            app._ensure_layout()
            reloaded = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            self.assertNotIn(removed_uuid, {user["uuid"] for user in reloaded["users"]})


if __name__ == "__main__":
    unittest.main()
