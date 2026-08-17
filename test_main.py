import asyncio
import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


WAR_MAIN = Path(__file__).with_name("main.py")


def _load_app(data_root: str, migrated_uuids: list[str] | None = None):
    os.environ["DATA_ROOT"] = data_root
    os.environ.pop("XRAY_BRIDGE_WS_PATH", None)
    if migrated_uuids is None:
        os.environ.pop("XRAY_MIGRATED_CLIENT_UUIDS", None)
    else:
        os.environ["XRAY_MIGRATED_CLIENT_UUIDS"] = ",".join(migrated_uuids)
    spec = importlib.util.spec_from_file_location(f"war_main_test_{id(data_root)}", WAR_MAIN)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WarsawConfigTests(unittest.TestCase):
    def test_fresh_data_preserves_all_migrated_uuids_and_routes_direct(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            migrated_uuids = [str(uuid.uuid5(uuid.NAMESPACE_URL, f"vpn-test-user-{index}")) for index in range(17)]
            app = _load_app(temp_dir, migrated_uuids)
            app._ensure_layout()

            panel = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            self.assertEqual(17, len(panel["users"]))
            self.assertFalse(panel["settings"]["include_base_user"])
            self.assertEqual(set(migrated_uuids), {user["uuid"] for user in panel["users"]})

            store = app.PanelStore(app.PANEL_DB_PATH)
            manager = app.XrayManager(store)
            config_path = asyncio.run(manager._build_runtime_config())
            config = json.loads(config_path.read_text(encoding="utf-8"))

            clients = config["inbounds"][0]["settings"]["clients"]
            self.assertEqual(set(migrated_uuids), {client["id"] for client in clients})
            self.assertEqual("/api/e6f5774ee4c658e2", config["inbounds"][0]["streamSettings"]["wsSettings"]["path"])
            self.assertNotIn("routing", config)
            self.assertEqual([{"protocol": "freedom", "tag": "DIRECT"}], config["outbounds"])

    def test_seed_runs_once_and_does_not_restore_deleted_users(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            migrated_uuids = [str(uuid.uuid5(uuid.NAMESPACE_URL, f"vpn-deleted-user-{index}")) for index in range(2)]
            app = _load_app(temp_dir, migrated_uuids)
            app._ensure_layout()
            panel = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            removed_uuid = panel["users"].pop()["uuid"]
            app.PANEL_DB_PATH.write_text(json.dumps(panel), encoding="utf-8")

            app._ensure_layout()
            reloaded = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            self.assertNotIn(removed_uuid, {user["uuid"] for user in reloaded["users"]})

    def test_fresh_install_without_import_enables_generated_base_user(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            app._ensure_layout()

            panel = json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8"))
            self.assertEqual([], panel["users"])
            self.assertTrue(panel["settings"]["include_base_user"])

            store = app.PanelStore(app.PANEL_DB_PATH)
            manager = app.XrayManager(store)
            config_path = asyncio.run(manager._build_runtime_config())
            config = json.loads(config_path.read_text(encoding="utf-8"))
            clients = config["inbounds"][0]["settings"]["clients"]
            self.assertEqual(1, len(clients))

    def test_existing_panel_is_untouched_without_migration_env(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            existing_user_uuid = str(uuid.uuid4())
            existing_panel = {
                "users": [{"id": "existing", "uuid": existing_user_uuid, "enabled": True}],
                "settings": {"include_base_user": False},
                "migration": {"uuid_seed_version": app.UUID_SEED_VERSION},
            }
            app.PANEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            app.PANEL_DB_PATH.write_text(json.dumps(existing_panel), encoding="utf-8")

            app._ensure_layout()

            self.assertEqual(existing_panel, json.loads(app.PANEL_DB_PATH.read_text(encoding="utf-8")))

    def test_client_url_omits_redundant_host_but_keeps_custom_host(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            client_uuid = str(uuid.uuid4())
            common_env = {
                "XRAY_PUBLIC_HOST": "vpn.example.com",
                "XRAY_PUBLIC_PORT": "443",
                "XRAY_PUBLIC_SNI": "vpn.example.com",
            }

            with patch.dict(
                os.environ,
                {**common_env, "XRAY_PUBLIC_HOST_HEADER": "vpn.example.com"},
                clear=False,
            ):
                params = parse_qs(urlsplit(app._build_client_url_for_uuid(client_uuid)).query)
                self.assertNotIn("host", params)
                self.assertEqual(["ws"], params["type"])

            with patch.dict(
                os.environ,
                {**common_env, "XRAY_PUBLIC_HOST_HEADER": "edge.example.com"},
                clear=False,
            ):
                params = parse_qs(urlsplit(app._build_client_url_for_uuid(client_uuid)).query)
                self.assertEqual(["edge.example.com"], params["host"])

    def test_upstream_ws_retries_and_restarts_after_handshake_failures(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)
            connected_ws = object()

            class StubSession:
                def __init__(self):
                    self.calls = 0
                    self.timeouts = []

                async def ws_connect(self, _upstream, **kwargs):
                    self.calls += 1
                    self.timeouts.append(kwargs["timeout"])
                    if self.calls < 3:
                        raise OSError("transient handshake failure")
                    return connected_ws

            class StubManager:
                def __init__(self):
                    self.restarts = 0

                async def restart(self):
                    self.restarts += 1

            async def no_sleep(_delay):
                return None

            session = StubSession()
            manager = StubManager()
            with patch.object(app.asyncio, "sleep", new=no_sleep):
                ws, error = asyncio.run(
                    app._connect_xray_upstream(session, "ws://127.0.0.1:10080/path", manager)
                )

            self.assertIs(connected_ws, ws)
            self.assertIsNone(error)
            self.assertEqual(3, session.calls)
            self.assertEqual(1, manager.restarts)
            self.assertTrue(all(timeout.ws_receive is None for timeout in session.timeouts))

    def test_upstream_ws_handshake_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app = _load_app(temp_dir)

            class HangingSession:
                def __init__(self):
                    self.calls = 0

                async def ws_connect(self, _upstream, **_kwargs):
                    self.calls += 1
                    await asyncio.Event().wait()

            class StubManager:
                def __init__(self):
                    self.restarts = 0

                async def restart(self):
                    self.restarts += 1

            async def no_sleep(_delay):
                return None

            session = HangingSession()
            manager = StubManager()
            with (
                patch.object(app, "XRAY_WS_HANDSHAKE_TIMEOUT_SEC", 0.01),
                patch.object(app.asyncio, "sleep", new=no_sleep),
            ):
                ws, error = asyncio.run(
                    app._connect_xray_upstream(session, "ws://127.0.0.1:10080/path", manager)
                )

            self.assertIsNone(ws)
            self.assertIsInstance(error, asyncio.TimeoutError)
            self.assertEqual(3, session.calls)
            self.assertEqual(1, manager.restarts)


if __name__ == "__main__":
    unittest.main()
