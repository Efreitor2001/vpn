import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path
from urllib.parse import quote

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from aiohttp.client_exceptions import ClientConnectionResetError, ClientConnectorError


DATA_ROOT = Path(os.getenv("DATA_ROOT", "/data")).resolve()
RUNTIME_DIR = DATA_ROOT / "service"
WAR_DIR = Path(__file__).resolve().parent
XRAY_DIR = DATA_ROOT / "xray"
XRAY_RUNTIME_DIR = XRAY_DIR / "runtime"
MASK_LOG_DIR = DATA_ROOT / "mask-site" / "logs"
XRAY_BINARY = XRAY_DIR / "xray"
XRAY_LOG_FILE = XRAY_RUNTIME_DIR / "xray.log"
SESSION_KEY_PATH = RUNTIME_DIR / "session.key"
PANEL_DB_PATH = RUNTIME_DIR / "panel-db.json"
DEVICE_DB_PATH = RUNTIME_DIR / "device-stats.json"

WEB_PORT = int(os.getenv("WEB_PORT", "80"))
XRAY_UPSTREAM_PORT = int(os.getenv("XRAY_BRIDGE_UPSTREAM_PORT", "10080"))
HEALTHCHECK_SEC = max(5, int(os.getenv("AMVERA_HEALTHCHECK_SEC", "15")))
ADMIN_USER = (os.getenv("ADMIN_USER") or "admin").strip()
ADMIN_PASSWORD = (os.getenv("ADMIN_PASSWORD") or "change-me-now").strip()
AUTH_COOKIE = "xadmin"
AUTH_TTL_SEC = max(300, int(os.getenv("ADMIN_SESSION_TTL_SEC", "86400")))

LOG = logging.getLogger("amvera-bootstrap")
_EGRESS_PROBE_CACHE: dict[str, object] = {"host": "", "ts": 0.0, "data": {}}

DEFAULT_WS_PATH = "/api/e6f5774ee4c658e2"
DEFAULT_PUBLIC_HOST = "123-efreitor2001.waw0.amvera.tech"
UUID_SEED_VERSION = "warsaw-single-server-v1"
MIGRATED_CLIENT_UUIDS = [
    "fc306288-cc29-4775-b267-b750c910795c",
    "bb34e402-9ea0-4e77-96f5-de873cd25efd",
    "003aa409-abc9-4c8d-b305-b3f54b21c718",
    "cb819037-3461-4851-b0fd-af29989e0804",
    "331d59ac-9e85-4718-b491-e1649058d154",
    "d60071bc-10d1-4a8c-9d0b-4da8a7e09ca4",
    "d49636c2-6996-49d9-9c6b-7d865a270e63",
    "d23dd234-4e00-403a-9223-bd30ced424a6",
    "2ed846f6-12de-4049-a1ae-d3ce1326afe9",
    "002d3e0a-38de-4aa1-8775-a74e48d0de34",
    "4669f506-707f-4b7f-bf58-f49f8277a098",
    "e64ddca6-c467-4b63-883c-4bf2056f2e14",
    "802d157e-44e6-4183-aed6-12e63884f9f3",
    "33fc6ede-29d7-4d26-80a6-c1d04a983d34",
    "0ff2eaaf-2d0b-48e2-bfcb-2bb815f4d4fa",
    "3fbff13b-1351-4a8c-bfea-4a3d08c1c3aa",
    "9dd9c1ea-f4e9-4e8d-9605-ca3cd9b014a9",
]


def _log(message: str):
    print(f"[amvera-bootstrap] {message}", flush=True)


def _tail_text(path: Path, max_lines: int = 30) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    if not lines:
        return ""
    return "\n".join(lines[-max(1, int(max_lines)):])


def _now_ts() -> int:
    return int(time.time())


def _extract_client_ip(request: web.Request) -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").strip()
    if forwarded:
        return _normalize_ip(forwarded.split(",")[0].strip())
    return _normalize_ip(str(request.remote or ""))


def _normalize_ip(raw: str) -> str:
    value = (raw or "").strip().strip('"')
    if not value:
        return ""
    # Common proxy form for IPv6 with port: [2001:db8::1]:443
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    # Common form for IPv4 with port: 1.2.3.4:54321
    elif value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0].strip()
    # IPv6 zone suffix (rare): fe80::1%eth0
    if "%" in value:
        value = value.split("%", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _normalize_user_agent(raw: str) -> str:
    value = " ".join((raw or "").split())
    if not value:
        return "unknown-agent"
    return value[:220]


def _build_fingerprint(ip: str, user_agent: str) -> str:
    clean_ip = _normalize_ip(ip)
    clean_ua = _normalize_user_agent(user_agent)
    return f"{clean_ip or 'no-ip'}|{clean_ua}"


def _try_parse_vless_uuid(payload: bytes) -> str:
    # VLESS request starts with version(1 byte) + user UUID(16 bytes).
    if not payload or len(payload) < 17:
        return ""
    try:
        return str(uuid.UUID(bytes=payload[1:17]))
    except Exception:
        return ""


def _bool_env(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _split_csv_env(raw: str) -> list[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        clean = str(value or "").strip()
        key = clean.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(clean)
    return out


def _write_if_missing(path: Path, content: str):
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _seed_migrated_users():
    now = _now_ts()
    if PANEL_DB_PATH.exists():
        try:
            payload = json.loads(PANEL_DB_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"existing panel DB is invalid; refusing to overwrite {PANEL_DB_PATH}: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"existing panel DB must contain a JSON object: {PANEL_DB_PATH}")
    else:
        payload = {"users": [], "created_at": now}

    migration = payload.setdefault("migration", {})
    if migration.get("uuid_seed_version") == UUID_SEED_VERSION:
        return

    users = payload.setdefault("users", [])
    existing = {
        str(user.get("uuid") or "").strip().lower()
        for user in users
        if isinstance(user, dict)
    }
    added = 0
    for index, client_uuid in enumerate(MIGRATED_CLIENT_UUIDS, start=1):
        if client_uuid.lower() in existing:
            continue
        users.append(
            {
                "id": f"migrated-{index:02d}",
                "uuid": client_uuid,
                "remark": f"migrated-{index:02d}",
                "signature": "",
                "enabled": True,
                "created_at": now,
                "expires_at": 0,
                "traffic_limit_gb": 0,
                "traffic_used_gb": 0,
            }
        )
        existing.add(client_uuid.lower())
        added += 1

    # Every UUID from the old active runtime is represented as a panel user.
    # The newly generated fallback/base UUID therefore stays disabled.
    payload.setdefault("settings", {})["include_base_user"] = False
    migration["uuid_seed_version"] = UUID_SEED_VERSION
    migration["seeded_at"] = now
    PANEL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    PANEL_DB_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _log(f"UUID migration seed applied: added={added}, total_preserved={len(MIGRATED_CLIENT_UUIDS)}")


def _ensure_layout():
    MASK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    XRAY_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    (RUNTIME_DIR / "mask-site").mkdir(parents=True, exist_ok=True)
    shutil.copy2(WAR_DIR / "mask-site" / "index.html", RUNTIME_DIR / "mask-site" / "index.html")
    _write_if_missing(SESSION_KEY_PATH, secrets.token_hex(32) + "\n")
    _seed_migrated_users()
    _write_if_missing(
        DEVICE_DB_PATH,
        json.dumps({"by_uuid": {}, "created_at": _now_ts()}, ensure_ascii=False, indent=2) + "\n",
    )

def _download_xray():
    if XRAY_BINARY.exists():
        XRAY_BINARY.chmod(XRAY_BINARY.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return

    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = XRAY_DIR / "xray.zip"
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    _log(f"download xray: {url}")
    urllib.request.urlretrieve(url, archive_path)
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(XRAY_DIR)
    archive_path.unlink(missing_ok=True)
    XRAY_BINARY.chmod(XRAY_BINARY.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _load_or_create_direct_secrets() -> dict[str, str]:
    secrets_path = XRAY_RUNTIME_DIR / "bridge.secrets.json"
    payload: dict[str, str] = {}
    if secrets_path.exists():
        try:
            loaded = json.loads(secrets_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = {str(key): str(value) for key, value in loaded.items()}
        except Exception:
            payload = {}

    env_base_uuid = (os.getenv("XRAY_BRIDGE_CLIENT_UUID") or "").strip()
    if env_base_uuid:
        payload["client_uuid"] = str(uuid.UUID(env_base_uuid))
    elif not payload.get("client_uuid"):
        payload["client_uuid"] = str(uuid.uuid4())

    ws_path = (os.getenv("XRAY_BRIDGE_WS_PATH") or payload.get("ws_path") or DEFAULT_WS_PATH).strip()
    if not ws_path.startswith("/"):
        ws_path = "/" + ws_path
    payload["ws_path"] = ws_path

    secrets_path.parent.mkdir(parents=True, exist_ok=True)
    secrets_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def _build_client_url_for_uuid(client_uuid: str) -> str:
    safe_uuid = str(uuid.UUID(str(client_uuid or "").strip()))
    host = (os.getenv("XRAY_PUBLIC_HOST") or DEFAULT_PUBLIC_HOST).strip()
    public_port = int(os.getenv("XRAY_PUBLIC_PORT", "443"))
    ws_path = _load_or_create_direct_secrets()["ws_path"]
    host_header = (os.getenv("XRAY_PUBLIC_HOST_HEADER") or host).strip()
    sni = (os.getenv("XRAY_PUBLIC_SNI") or host).strip()
    fingerprint = (os.getenv("XRAY_CLIENT_FINGERPRINT") or "chrome").strip()
    params = (
        "encryption=none&security=tls&type=ws"
        f"&host={quote(host_header, safe='')}"
        f"&path={quote(ws_path, safe='/')}"
        f"&sni={quote(sni, safe='')}"
        f"&fp={quote(fingerprint, safe='')}"
    )
    return f"vless://{safe_uuid}@{host}:{public_port}?{params}#{quote('Lucifer_VPN', safe='')}"


class PanelStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = asyncio.Lock()

    async def load(self) -> dict:
        async with self.lock:
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                payload = {"users": []}
            payload.setdefault("users", [])
            payload.setdefault("settings", {})
            payload["settings"].setdefault("include_base_user", True)
            return payload

    async def save(self, payload: dict):
        async with self.lock:
            payload.setdefault("users", [])
            payload.setdefault("settings", {})
            payload["settings"].setdefault("include_base_user", True)
            payload["updated_at"] = _now_ts()
            self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    async def add_user(self, remark: str, signature: str, duration_days: int, traffic_limit_gb: int):
        db = await self.load()
        now = _now_ts()
        expires_at = now + duration_days * 86400 if duration_days > 0 else 0
        db.setdefault("users", []).append(
            {
                "id": secrets.token_hex(8),
                "uuid": str(uuid.uuid4()),
                "remark": remark.strip() or "client",
                "signature": signature.strip(),
                "enabled": True,
                "created_at": now,
                "expires_at": expires_at,
                "traffic_limit_gb": max(0, traffic_limit_gb),
                "traffic_used_gb": 0,
            }
        )
        await self.save(db)

    async def toggle_user(self, user_id: str):
        db = await self.load()
        for user in db.get("users", []):
            if user.get("id") == user_id:
                user["enabled"] = not bool(user.get("enabled", True))
                break
        await self.save(db)

    async def delete_user(self, user_id: str):
        db = await self.load()
        db["users"] = [u for u in db.get("users", []) if u.get("id") != user_id]
        await self.save(db)

    async def update_signature(self, user_id: str, signature: str):
        db = await self.load()
        for user in db.get("users", []):
            if user.get("id") == user_id:
                user["signature"] = signature.strip()
                break
        await self.save(db)

    async def active_uuids(self) -> list[str]:
        db = await self.load()
        now = _now_ts()
        out: list[str] = []
        for user in db.get("users", []):
            if not user.get("enabled", True):
                continue
            expires_at = int(user.get("expires_at") or 0)
            if expires_at and expires_at <= now:
                continue
            out.append(str(user.get("uuid") or "").strip())
        return [u for u in out if u]

    async def stats(self) -> dict:
        db = await self.load()
        now = _now_ts()
        users = db.get("users", [])
        total = len(users)
        enabled = sum(1 for u in users if bool(u.get("enabled", True)))
        disabled = total - enabled
        expired = sum(1 for u in users if int(u.get("expires_at") or 0) and int(u.get("expires_at") or 0) <= now)
        active = sum(
            1
            for u in users
            if bool(u.get("enabled", True))
            and not (int(u.get("expires_at") or 0) and int(u.get("expires_at") or 0) <= now)
        )
        return {
            "total_users": total,
            "enabled_users": enabled,
            "disabled_users": disabled,
            "expired_users": expired,
            "active_users": active,
            "traffic_note": "Traffic limit field is saved; realtime traffic accounting is not available in this mode.",
        }

    async def include_base_user(self) -> bool:
        db = await self.load()
        return bool((db.get("settings") or {}).get("include_base_user", True))

    async def toggle_include_base_user(self):
        db = await self.load()
        settings = db.setdefault("settings", {})
        settings["include_base_user"] = not bool(settings.get("include_base_user", True))
        await self.save(db)


class DeviceTracker:
    def __init__(self, path: Path):
        self.path = path
        self.lock = asyncio.Lock()
        self.active_connections_by_uuid: dict[str, int] = {}
        self.active_fingerprint_connections_by_uuid: dict[str, dict[str, int]] = {}
        self.fingerprint_last_seen_by_uuid: dict[str, dict[str, int]] = {}
        self.ip_last_seen_by_uuid: dict[str, dict[str, int]] = {}
        self.all_time_ips_by_uuid: dict[str, dict[str, int]] = {}
        self.all_time_fingerprints_by_uuid: dict[str, dict[str, int]] = {}
        self.violations_by_uuid: dict[str, list[int]] = {}
        self.violation_events: list[dict[str, object]] = []
        self.violation_cooldown_by_key: dict[str, int] = {}
        self._dirty = False
        self._writer_task: asyncio.Task | None = None
        self._writer_stop = asyncio.Event()
        self._events_queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=2048)
        self._load_all_time()

    def _load_all_time(self):
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            changed = False
            by_uuid_ips_raw = payload.get("by_uuid_ips")
            by_uuid_fps_raw = payload.get("by_uuid_fingerprints")
            legacy_by_uuid = payload.get("by_uuid")

            if isinstance(by_uuid_ips_raw, dict):
                for raw_uuid, raw_ips in by_uuid_ips_raw.items():
                    uuid_key = str(raw_uuid)
                    bucket: dict[str, int] = {}
                    for raw_ip, raw_ts in dict(raw_ips or {}).items():
                        clean_ip = _normalize_ip(str(raw_ip or ""))
                        if not clean_ip:
                            changed = True
                            continue
                        ts = int(raw_ts or 0)
                        prev_ts = bucket.get(clean_ip)
                        if prev_ts is None or (ts and ts < prev_ts):
                            bucket[clean_ip] = ts
                        if clean_ip != str(raw_ip):
                            changed = True
                    self.all_time_ips_by_uuid[uuid_key] = bucket

            if isinstance(by_uuid_fps_raw, dict):
                for raw_uuid, raw_fps in by_uuid_fps_raw.items():
                    uuid_key = str(raw_uuid)
                    bucket: dict[str, int] = {}
                    for raw_fp, raw_ts in dict(raw_fps or {}).items():
                        fp = str(raw_fp or "").strip()
                        if not fp:
                            changed = True
                            continue
                        ts = int(raw_ts or 0)
                        prev_ts = bucket.get(fp)
                        if prev_ts is None or (ts and ts < prev_ts):
                            bucket[fp] = ts
                    self.all_time_fingerprints_by_uuid[uuid_key] = bucket

            if isinstance(legacy_by_uuid, dict):
                changed = True
                for raw_uuid, raw_ips in legacy_by_uuid.items():
                    uuid_key = str(raw_uuid)
                    ip_bucket = self.all_time_ips_by_uuid.setdefault(uuid_key, {})
                    fp_bucket = self.all_time_fingerprints_by_uuid.setdefault(uuid_key, {})
                    for raw_ip, raw_ts in dict(raw_ips or {}).items():
                        clean_ip = _normalize_ip(str(raw_ip or ""))
                        if not clean_ip:
                            continue
                        ts = int(raw_ts or 0)
                        prev_ip_ts = ip_bucket.get(clean_ip)
                        if prev_ip_ts is None or (ts and ts < prev_ip_ts):
                            ip_bucket[clean_ip] = ts
                        legacy_fp = _build_fingerprint(clean_ip, "legacy-ip-only")
                        prev_fp_ts = fp_bucket.get(legacy_fp)
                        if prev_fp_ts is None or (ts and ts < prev_fp_ts):
                            fp_bucket[legacy_fp] = ts

            violations_raw = payload.get("violations_by_uuid") or {}
            if isinstance(violations_raw, dict):
                for raw_uuid, raw_list in violations_raw.items():
                    uuid_key = str(raw_uuid)
                    parsed = [int(ts or 0) for ts in list(raw_list or []) if int(ts or 0) > 0]
                    if parsed:
                        self.violations_by_uuid[uuid_key] = parsed[-200:]
            events_raw = payload.get("violation_events") or []
            if isinstance(events_raw, list):
                parsed_events: list[dict[str, object]] = []
                for item in events_raw:
                    if not isinstance(item, dict):
                        continue
                    ts = int(item.get("ts") or 0)
                    client_uuid = str(item.get("uuid") or "").strip()
                    if not ts or not client_uuid:
                        continue
                    parsed_events.append(
                        {
                            "ts": ts,
                            "uuid": client_uuid,
                            "active_fingerprints": int(item.get("active_fingerprints") or 0),
                            "limit": int(item.get("limit") or 0),
                            "ip": str(item.get("ip") or "").strip(),
                            "user_agent": str(item.get("user_agent") or "").strip(),
                        }
                    )
                if parsed_events:
                    self.violation_events = parsed_events[-500:]

            if changed:
                self._save_all_time()
        except Exception:
            pass

    def _save_all_time(self):
        payload = {
            "updated_at": _now_ts(),
            "by_uuid_ips": self.all_time_ips_by_uuid,
            "by_uuid_fingerprints": self.all_time_fingerprints_by_uuid,
            "violations_by_uuid": self.violations_by_uuid,
            "violation_events": self.violation_events[-500:],
        }
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    async def start(self):
        if self._writer_task and not self._writer_task.done():
            return
        self._writer_stop.clear()
        self._writer_task = asyncio.create_task(self._writer_loop())

    async def stop(self):
        self._writer_stop.set()
        if self._writer_task:
            await self._writer_task
            self._writer_task = None

    async def _writer_loop(self):
        flush_interval_sec = 5
        next_flush_ts = time.monotonic() + flush_interval_sec
        while True:
            if self._writer_stop.is_set() and self._events_queue.empty():
                break
            timeout_sec = max(0.1, next_flush_ts - time.monotonic())
            try:
                event = await asyncio.wait_for(self._events_queue.get(), timeout=timeout_sec)
                await self._apply_event(event)
            except asyncio.TimeoutError:
                pass
            if time.monotonic() >= next_flush_ts:
                await self._flush_if_dirty()
                next_flush_ts = time.monotonic() + flush_interval_sec
        await self._flush_if_dirty(force=True)

    async def _apply_event(self, event: dict[str, object]):
        if str(event.get("type") or "") != "violation":
            return
        now = _now_ts()
        client_uuid = str(event.get("uuid") or "").strip()
        if not client_uuid:
            return
        active_fingerprints = int(event.get("active_fingerprints") or 0)
        limit = int(event.get("limit") or 0)
        clean_ip = _normalize_ip(str(event.get("ip") or ""))
        clean_ua = _normalize_user_agent(str(event.get("user_agent") or ""))
        dedupe_key = f"{client_uuid}|{clean_ip}|{clean_ua}"
        async with self.lock:
            last_seen = int(self.violation_cooldown_by_key.get(dedupe_key) or 0)
            if last_seen and (now - last_seen) < 60:
                return
            self.violation_cooldown_by_key[dedupe_key] = now
            bucket = self.violations_by_uuid.setdefault(client_uuid, [])
            bucket.append(now)
            if len(bucket) > 200:
                del bucket[:-200]
            self.violation_events.append(
                {
                    "ts": now,
                    "uuid": client_uuid,
                    "active_fingerprints": active_fingerprints,
                    "limit": limit,
                    "ip": clean_ip,
                    "user_agent": clean_ua,
                }
            )
            if len(self.violation_events) > 500:
                del self.violation_events[:-500]
            self._dirty = True

    async def _flush_if_dirty(self, force: bool = False):
        async with self.lock:
            if not force and not self._dirty:
                return
            payload = {
                "updated_at": _now_ts(),
                "by_uuid_ips": self.all_time_ips_by_uuid,
                "by_uuid_fingerprints": self.all_time_fingerprints_by_uuid,
                "violations_by_uuid": self.violations_by_uuid,
                "violation_events": self.violation_events[-500:],
            }
            self._dirty = False
        await asyncio.to_thread(
            self.path.write_text,
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    async def on_connect(self, client_uuid: str, ip: str, user_agent: str) -> dict:
        if not client_uuid:
            return {"active_connections": 0, "active_fingerprints": 0}
        async with self.lock:
            now = _now_ts()
            fp = _build_fingerprint(ip, user_agent)
            clean_ip = _normalize_ip(ip)
            self.active_connections_by_uuid[client_uuid] = self.active_connections_by_uuid.get(client_uuid, 0) + 1

            active_fp_bucket = self.active_fingerprint_connections_by_uuid.setdefault(client_uuid, {})
            active_fp_bucket[fp] = active_fp_bucket.get(fp, 0) + 1

            fp_bucket = self.fingerprint_last_seen_by_uuid.setdefault(client_uuid, {})
            fp_bucket[fp] = now

            changed = False
            all_fp_bucket = self.all_time_fingerprints_by_uuid.setdefault(client_uuid, {})
            if fp not in all_fp_bucket:
                all_fp_bucket[fp] = now
                changed = True

            if clean_ip:
                ip_bucket = self.ip_last_seen_by_uuid.setdefault(client_uuid, {})
                ip_bucket[clean_ip] = now
                all_ip_bucket = self.all_time_ips_by_uuid.setdefault(client_uuid, {})
                if clean_ip not in all_ip_bucket:
                    all_ip_bucket[clean_ip] = now
                    changed = True

            if changed:
                self._dirty = True

            return {
                "active_connections": self.active_connections_by_uuid.get(client_uuid, 0),
                "active_fingerprints": len(self.active_fingerprint_connections_by_uuid.get(client_uuid, {})),
            }

    async def on_disconnect(self, client_uuid: str, fingerprint: str = ""):
        if not client_uuid:
            return
        async with self.lock:
            current = self.active_connections_by_uuid.get(client_uuid, 0)
            if current <= 1:
                self.active_connections_by_uuid.pop(client_uuid, None)
            else:
                self.active_connections_by_uuid[client_uuid] = current - 1
            fp_bucket = self.active_fingerprint_connections_by_uuid.get(client_uuid, {})
            if fingerprint:
                fp_count = fp_bucket.get(fingerprint, 0)
                if fp_count <= 1:
                    fp_bucket.pop(fingerprint, None)
                else:
                    fp_bucket[fingerprint] = fp_count - 1
            if not fp_bucket:
                self.active_fingerprint_connections_by_uuid.pop(client_uuid, None)

    def queue_violation(
        self,
        client_uuid: str,
        *,
        active_fingerprints: int,
        limit: int,
        ip: str,
        user_agent: str,
    ) -> bool:
        if not client_uuid:
            return False
        event = {
            "type": "violation",
            "uuid": client_uuid,
            "active_fingerprints": int(active_fingerprints),
            "limit": int(limit),
            "ip": ip,
            "user_agent": user_agent,
        }
        try:
            self._events_queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            return False

    async def recent_violation_events(self, limit: int = 60) -> list[dict[str, object]]:
        async with self.lock:
            out = list(self.violation_events[-max(1, int(limit)):])
            out.reverse()
            return out

    async def stats_for(self, client_uuid: str) -> dict:
        now = _now_ts()
        cutoff = now - 86400
        async with self.lock:
            active_connections = self.active_connections_by_uuid.get(client_uuid, 0)
            fp_active = self.active_fingerprint_connections_by_uuid.get(client_uuid, {})

            fp_bucket = self.fingerprint_last_seen_by_uuid.get(client_uuid, {})
            fresh_fps = {fp: ts for fp, ts in fp_bucket.items() if ts >= cutoff}
            if fresh_fps:
                self.fingerprint_last_seen_by_uuid[client_uuid] = fresh_fps
            elif client_uuid in self.fingerprint_last_seen_by_uuid:
                self.fingerprint_last_seen_by_uuid.pop(client_uuid, None)

            ip_bucket = self.ip_last_seen_by_uuid.get(client_uuid, {})
            fresh_ips = {ip: ts for ip, ts in ip_bucket.items() if ts >= cutoff}
            if fresh_ips:
                self.ip_last_seen_by_uuid[client_uuid] = fresh_ips
            elif client_uuid in self.ip_last_seen_by_uuid:
                self.ip_last_seen_by_uuid.pop(client_uuid, None)

            violations = [ts for ts in self.violations_by_uuid.get(client_uuid, []) if ts >= cutoff]
            if violations:
                self.violations_by_uuid[client_uuid] = violations[-200:]
            elif client_uuid in self.violations_by_uuid:
                self.violations_by_uuid.pop(client_uuid, None)

            return {
                "active_connections": active_connections,
                "active_fingerprints": len(fp_active),
                "unique_24h_fingerprints": len(fresh_fps),
                "unique_all_time_fingerprints": len(self.all_time_fingerprints_by_uuid.get(client_uuid, {})),
                "unique_24h_ips": len(fresh_ips),
                "unique_all_time_ips": len(self.all_time_ips_by_uuid.get(client_uuid, {})),
                "violations_24h": len(violations),
                "violations_all_time": len(self.violations_by_uuid.get(client_uuid, [])),
            }


def _strip_host_port(raw_host: str) -> str:
    text = str(raw_host or "").strip()
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    if text.count(":") == 1 and "." in text:
        return text.rsplit(":", 1)[0].strip()
    return text


async def _probe_egress_identity(ingress_host: str) -> dict[str, str]:
    clean_host = _strip_host_port(ingress_host)
    now = time.time()
    cached_host = str(_EGRESS_PROBE_CACHE.get("host") or "")
    cached_ts = float(_EGRESS_PROBE_CACHE.get("ts") or 0.0)
    cached_data = _EGRESS_PROBE_CACHE.get("data") or {}
    if clean_host == cached_host and (now - cached_ts) < 60 and isinstance(cached_data, dict):
        return dict(cached_data)

    ingress_ip = ""
    ingress_error = ""
    if clean_host:
        try:
            infos = socket.getaddrinfo(clean_host, None, type=socket.SOCK_STREAM)
            for info in infos:
                addr = str((info[4] or [""])[0]).strip()
                if addr:
                    ingress_ip = addr
                    break
        except OSError as exc:
            ingress_error = str(exc)

    egress_ip = ""
    egress_source = ""
    egress_error = ""
    endpoints = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("icanhazip", "https://ipv4.icanhazip.com"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
    ]
    timeout = ClientTimeout(total=4)
    for source_name, url in endpoints:
        try:
            async with ClientSession(timeout=timeout) as session:
                async with session.get(url) as resp:
                    body = (await resp.text()).strip()
            if not body:
                continue
            if source_name == "ipify":
                try:
                    payload = json.loads(body)
                    body = str(payload.get("ip") or "").strip()
                except Exception:
                    body = ""
            if body:
                egress_ip = body
                egress_source = source_name
                break
        except Exception as exc:
            egress_error = str(exc)

    result = {
        "ingress_host": clean_host,
        "ingress_ip": ingress_ip,
        "ingress_error": ingress_error,
        "egress_ip": egress_ip,
        "egress_source": egress_source,
        "egress_error": egress_error,
        "checked_at": _format_ts(int(now)),
    }
    _EGRESS_PROBE_CACHE["host"] = clean_host
    _EGRESS_PROBE_CACHE["ts"] = now
    _EGRESS_PROBE_CACHE["data"] = dict(result)
    return result


class XrayManager:
    def __init__(self, store: PanelStore):
        self.proc: subprocess.Popen | None = None
        self.proc_lock = asyncio.Lock()
        self.config_path: Path | None = None
        self.ws_path = DEFAULT_WS_PATH
        self.last_start_ts = 0.0
        self.store = store

    async def _build_runtime_config(self) -> Path:
        runtime_secrets = _load_or_create_direct_secrets()
        self.ws_path = runtime_secrets["ws_path"]

        client_uuids = await self.store.active_uuids()
        if await self.store.include_base_user():
            client_uuids.append(runtime_secrets["client_uuid"])

        normalized_uuids: list[str] = []
        seen: set[str] = set()
        for value in client_uuids:
            try:
                normalized = str(uuid.UUID(str(value or "").strip()))
            except ValueError:
                _log(f"skip invalid client UUID: {value!r}")
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            normalized_uuids.append(normalized)

        payload = {
            "log": {"loglevel": (os.getenv("XRAY_LOGLEVEL") or "warning").strip()},
            "inbounds": [
                {
                    "tag": "inbound-client",
                    "listen": "127.0.0.1",
                    "port": XRAY_UPSTREAM_PORT,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": client_uuid} for client_uuid in normalized_uuids],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "none",
                        "wsSettings": {"path": self.ws_path},
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True,
                    },
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "tag": "DIRECT",
                }
            ],
        }
        config_path = XRAY_RUNTIME_DIR / "config.direct.json"
        config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _log(
            f"built single-server Warsaw config: clients={len(normalized_uuids)} "
            f"ws_path={self.ws_path} outbound=DIRECT"
        )
        return config_path

    async def start(self):
        async with self.proc_lock:
            await self._start_unlocked()

    async def _start_unlocked(self):
        cfg_path = await self._build_runtime_config()
        self.config_path = cfg_path
        with XRAY_LOG_FILE.open("ab") as log_fd:
            self.proc = subprocess.Popen(
                [str(XRAY_BINARY), "run", "-c", str(cfg_path)],
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                cwd=str(XRAY_DIR),
                start_new_session=True,
            )
        await asyncio.sleep(0.35)
        self.last_start_ts = time.time()
        if self.proc.poll() is not None:
            tail = _tail_text(XRAY_LOG_FILE, max_lines=20)
            raise RuntimeError(
                f"xray exited right after start code={self.proc.returncode} config={cfg_path}\n"
                f"last log lines:\n{tail}"
            )
        _log(f"xray started pid={self.proc.pid} config={cfg_path} ws_path={self.ws_path}")

    async def stop(self):
        async with self.proc_lock:
            await self._stop_unlocked()

    async def _stop_unlocked(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2)
        _log("xray stopped")

    async def restart(self):
        async with self.proc_lock:
            await self._stop_unlocked()
            await self._start_unlocked()

    async def ensure_running(self):
        async with self.proc_lock:
            if self.proc is None or self.proc.poll() is not None:
                code = None if self.proc is None else self.proc.returncode
                _log(f"xray not running (code={code}), restarting")
                await self._start_unlocked()

    def status(self) -> dict:
        running = self.proc is not None and self.proc.poll() is None
        return {
            "running": running,
            "pid": self.proc.pid if self.proc else None,
            "uptime_sec": int(time.time() - self.last_start_ts) if running else 0,
            "config": str(self.config_path) if self.config_path else "",
            "ws_path": self.ws_path,
            "upstream_port": XRAY_UPSTREAM_PORT,
            "topology": "single-server-war-direct",
        }

    def build_link(self, client_uuid: str) -> str:
        try:
            return _build_client_url_for_uuid(client_uuid)
        except Exception:
            return ""

    def base_client_uuid(self) -> str:
        try:
            return _load_or_create_direct_secrets()["client_uuid"]
        except Exception:
            return ""


def _session_secret() -> bytes:
    return SESSION_KEY_PATH.read_text(encoding="utf-8").strip().encode("utf-8")


def _sign(payload: str) -> str:
    mac = hmac.new(_session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{mac}"


def _verify(token: str) -> bool:
    parts = (token or "").split(".")
    if len(parts) != 3:
        return False
    user, ts, sig = parts
    payload = f"{user}.{ts}"
    expected = hmac.new(_session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False
    try:
        issued = int(ts)
    except ValueError:
        return False
    return (time.time() - issued) <= AUTH_TTL_SEC


def _is_admin(request: web.Request) -> bool:
    token = request.cookies.get(AUTH_COOKIE, "")
    return _verify(token)


def _admin_required(handler):
    async def wrapped(request: web.Request):
        if not _is_admin(request):
            raise web.HTTPFound("/admin/login")
        return await handler(request)

    return wrapped


def _mask_html() -> str:
    return (RUNTIME_DIR / "mask-site" / "index.html").read_text(encoding="utf-8")


def _admin_login_html(error: str = "") -> str:
    err = f"<p style='color:#b91c1c'>{error}</p>" if error else ""
    return (
        "<!doctype html><html><body style='font-family:Arial;padding:24px'>"
        "<h2>Admin Login</h2>"
        f"{err}"
        "<form method='post' action='/admin/login'>"
        "<input name='user' placeholder='User' /><br/><br/>"
        "<input name='password' type='password' placeholder='Password' /><br/><br/>"
        "<button type='submit'>Sign in</button>"
        "</form></body></html>"
    )


def _format_ts(ts: int) -> str:
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _admin_dashboard_html(
    status: dict,
    panel_stats: dict,
    users: list[dict],
    links: dict[str, str],
    base_uuid: str,
    base_link: str,
    include_base_user: bool,
    per_uuid_devices: dict[str, dict[str, int]],
    violation_events: list[dict[str, object]],
    total_active_connections: int,
    total_active_fingerprints: int,
    total_violations_24h: int,
    network_probe: dict[str, str],
) -> str:
    realtime_limit = max(1, int(os.getenv("REALTIME_DEVICE_LIMIT_PER_LINK", "1")))
    max_fingerprint_limit = max(1, int(os.getenv("MAX_ACTIVE_FINGERPRINTS_PER_UUID", "2")))
    now_ts = _now_ts()
    rows: list[str] = []
    for u in users:
        expires_at = int(u.get("expires_at") or 0)
        is_expired = bool(expires_at and expires_at <= now_ts)
        is_enabled = bool(u.get("enabled", True))
        effective_status = "expired" if is_expired else ("on" if is_enabled else "off")
        traffic_limit_gb = int(u.get("traffic_limit_gb") or 0)
        traffic_limit_label = "unlimited" if traffic_limit_gb <= 0 else f"{traffic_limit_gb} GB"
        link = links.get(str(u.get("uuid") or ""), "")
        device_stats = per_uuid_devices.get(
            str(u.get("uuid") or ""),
            {
                "active_connections": 0,
                "active_fingerprints": 0,
                "unique_24h_fingerprints": 0,
                "unique_all_time_fingerprints": 0,
                "unique_24h_ips": 0,
                "unique_all_time_ips": 0,
                "violations_24h": 0,
                "violations_all_time": 0,
            },
        )
        suspicious_rt = int(device_stats.get("active_fingerprints") or 0) > max_fingerprint_limit
        suspicious_badge = '<b style="color:#b91c1c">SUSPICIOUS</b>' if suspicious_rt else ""
        rows.append(
            "<tr>"
            f"<td>{u.get('remark','')}</td>"
            f"<td>{u.get('signature','')}</td>"
            f"<td><code>{u.get('uuid','')}</code></td>"
            f"<td>{effective_status}</td>"
            f"<td>{_format_ts(expires_at)}</td>"
            f"<td>{traffic_limit_label}</td>"
            f"<td>{device_stats['active_connections']} conn-now / {device_stats['active_fingerprints']} fp-now / {device_stats['unique_24h_fingerprints']} fp-24h / {device_stats['unique_all_time_fingerprints']} fp-all / {device_stats['unique_24h_ips']} ip-24h / viol24h={device_stats['violations_24h']} {suspicious_badge}</td>"
            f"<td><textarea rows='2' cols='50' readonly>{link}</textarea></td>"
            "<td>"
            f"<form style='display:inline' method='post' action='/admin/users/signature'><input type='hidden' name='id' value='{u.get('id','')}' /><input name='signature' value='{u.get('signature','')}' placeholder='Signature' /><button type='submit'>Save</button></form> "
            f"<form style='display:inline' method='post' action='/admin/users/toggle'><input type='hidden' name='id' value='{u.get('id','')}' /><button type='submit'>Toggle</button></form> "
            f"<form style='display:inline' method='post' action='/admin/users/delete'><input type='hidden' name='id' value='{u.get('id','')}' /><button type='submit'>Delete</button></form>"
            "</td>"
            "</tr>"
        )
    rows_html = "".join(rows) or "<tr><td colspan='9'>No users</td></tr>"
    base_devices = (
        per_uuid_devices.get(
            base_uuid,
            {
                "active_connections": 0,
                "active_fingerprints": 0,
                "unique_24h_fingerprints": 0,
                "unique_all_time_fingerprints": 0,
                "unique_24h_ips": 0,
                "unique_all_time_ips": 0,
                "violations_24h": 0,
                "violations_all_time": 0,
            },
        )
        if base_uuid
        else {
            "active_connections": 0,
            "active_fingerprints": 0,
            "unique_24h_fingerprints": 0,
            "unique_all_time_fingerprints": 0,
            "unique_24h_ips": 0,
            "unique_all_time_ips": 0,
            "violations_24h": 0,
            "violations_all_time": 0,
        }
    )
    base_section = (
        "<h3>Base startup user</h3>"
        f"<p><b>Included in runtime:</b> {'yes' if include_base_user else 'no'}</p>"
        f"<p><b>UUID:</b> <code>{base_uuid or '-'}</code></p>"
        f"<p><b>Usage:</b> {base_devices['active_connections']} conn-now / {base_devices['active_fingerprints']} fp-now / {base_devices['unique_24h_fingerprints']} fp-24h / {base_devices['unique_all_time_fingerprints']} fp-all</p>"
        f"<p><b>Link:</b> <textarea rows='2' cols='80' readonly>{base_link}</textarea></p>"
        "<form method='post' action='/admin/base/toggle'>"
        f"<button type='submit'>{'Disable' if include_base_user else 'Enable'} base user</button>"
        "</form>"
    )
    abuse_threshold_active = max(2, int(os.getenv("ABUSE_ACTIVE_THRESHOLD", str(max_fingerprint_limit + 1))))
    abuse_threshold_all_time = max(5, int(os.getenv("ABUSE_ALL_TIME_THRESHOLD", "8")))
    abusive_rows: list[str] = []
    for u in users:
        uid = str(u.get("uuid") or "")
        stat = per_uuid_devices.get(
            uid,
            {
                "active_connections": 0,
                "active_fingerprints": 0,
                "unique_24h_fingerprints": 0,
                "unique_all_time_fingerprints": 0,
                "unique_24h_ips": 0,
                "unique_all_time_ips": 0,
                "violations_24h": 0,
                "violations_all_time": 0,
            },
        )
        suspicious = (
            int(stat.get("active_fingerprints") or 0) > max_fingerprint_limit
            or int(stat.get("active_fingerprints") or 0) >= abuse_threshold_active
            or int(stat.get("unique_all_time_fingerprints") or 0) >= abuse_threshold_all_time
            or int(stat.get("violations_24h") or 0) > 0
        )
        if not suspicious:
            continue
        suspicious_mark = "YES" if suspicious else "NO"
        abusive_rows.append(
            "<tr>"
            f"<td>{u.get('remark','')}</td>"
            f"<td>{u.get('signature','')}</td>"
            f"<td><code>{uid}</code></td>"
            f"<td>{stat.get('active_fingerprints', 0)}</td>"
            f"<td>{stat.get('unique_24h_fingerprints', 0)}</td>"
            f"<td>{stat.get('unique_all_time_fingerprints', 0)}</td>"
            f"<td><b>{suspicious_mark}</b></td>"
            "<td>"
            f"<form style='display:inline' method='post' action='/admin/users/toggle'><input type='hidden' name='id' value='{u.get('id','')}' /><button type='submit'>Disable</button></form> "
            f"<form style='display:inline' method='post' action='/admin/users/delete'><input type='hidden' name='id' value='{u.get('id','')}' /><button type='submit'>Delete</button></form>"
            "</td>"
            "</tr>"
        )
    abusive_html = "".join(abusive_rows) or "<tr><td colspan='8'>No suspicious links</td></tr>"
    violation_rows: list[str] = []
    for event in violation_events:
        ts = int(event.get("ts") or 0)
        uid = str(event.get("uuid") or "")
        event_user = per_uuid_devices.get(uid, {})
        violation_rows.append(
            "<tr>"
            f"<td>{_format_ts(ts)}</td>"
            f"<td>{str(event.get('remark') or '')}</td>"
            f"<td>{str(event.get('signature') or '')}</td>"
            f"<td><code>{uid}</code></td>"
            f"<td>{int(event.get('active_fingerprints') or 0)}</td>"
            f"<td>{int(event.get('limit') or 0)}</td>"
            f"<td><code>{str(event.get('ip') or '-')}</code></td>"
            f"<td>{str(event.get('user_agent') or '-')}</td>"
            f"<td>{int(event_user.get('active_fingerprints') or 0)}</td>"
            "</tr>"
        )
    violations_html = "".join(violation_rows) or "<tr><td colspan='9'>No warnings yet</td></tr>"
    ingress_host = str(network_probe.get("ingress_host") or "-")
    ingress_ip = str(network_probe.get("ingress_ip") or "-")
    ingress_error = str(network_probe.get("ingress_error") or "")
    egress_ip = str(network_probe.get("egress_ip") or "-")
    egress_source = str(network_probe.get("egress_source") or "")
    egress_error = str(network_probe.get("egress_error") or "")
    checked_at = str(network_probe.get("checked_at") or "-")
    network_section = (
        "<h3>Network Identity</h3>"
        f"<p><b>Ingress host:</b> <code>{ingress_host}</code> -> <code>{ingress_ip}</code></p>"
        f"<p><b>Container egress IP:</b> <code>{egress_ip}</code>"
        f"{' via ' + egress_source if egress_source else ''} | <b>Checked:</b> {checked_at}</p>"
        f"{f'<p><b>Ingress DNS note:</b> <code>{ingress_error}</code></p>' if ingress_error else ''}"
        f"{f'<p><b>Egress probe note:</b> <code>{egress_error}</code></p>' if egress_error and not egress_ip else ''}"
        "<p><i>Single-server mode: VPN traffic exits directly from the Warsaw server.</i></p>"
    )
    return (
        "<!doctype html><html><body style='font-family:Arial;padding:24px'>"
        "<h2>Warsaw VPN Panel</h2>"
        f"<p><b>Xray running:</b> {status['running']} | <b>PID:</b> {status['pid']} | <b>Uptime:</b> {status['uptime_sec']}s</p>"
        f"<p><b>WS path:</b> <code>{status['ws_path']}</code> | <b>Upstream:</b> 127.0.0.1:{status['upstream_port']}</p>"
        f"<p><b>Users:</b> total={panel_stats['total_users']}, enabled={panel_stats['enabled_users']}, disabled={panel_stats.get('disabled_users', 0)}, active={panel_stats['active_users']}, expired={panel_stats['expired_users']}</p>"
        f"<p><b>Realtime now:</b> {total_active_connections} ws-connections / {total_active_fingerprints} active fingerprints</p>"
        f"<p><b>Violations (24h):</b> {total_violations_24h}</p>"
        f"<p><b>Limits:</b> active-conn threshold={realtime_limit}; active-fingerprint threshold={max_fingerprint_limit}</p>"
        f"<p><i>{panel_stats['traffic_note']}</i></p>"
        f"{network_section}"
        f"{base_section}"
        "<h3>Add user</h3>"
        "<form method='post' action='/admin/users/add'>"
        "<input name='remark' placeholder='Remark' /> "
        "<input name='signature' placeholder='Signature (owner/comment)' /> "
        "<input name='days' type='number' min='0' value='30' placeholder='Days' /> "
        "<input name='traffic_gb' type='number' min='0' value='0' placeholder='Traffic GB (0=unlimited)' /> "
        "<button type='submit'>Add</button>"
        "</form>"
        "<h3>Users</h3>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>Remark</th><th>Signature</th><th>UUID</th><th>Enabled</th><th>Expires</th><th>Limit</th><th>Devices</th><th>Link</th><th>Actions</th></tr>"
        f"{rows_html}"
        "</table>"
        "<h3>Anti-sharing watchlist</h3>"
        f"<p><i>Suspicious if fp-active>{max_fingerprint_limit} (hard rule), or fp-active>={abuse_threshold_active}, or fp-all-time>={abuse_threshold_all_time}, or any violations in 24h.</i></p>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>Remark</th><th>Signature</th><th>UUID</th><th>FP Active</th><th>FP 24h</th><th>FP All-time</th><th>Suspicious</th><th>Ban actions</th></tr>"
        f"{abusive_html}"
        "</table>"
        "<h3>Warning log (fingerprints over limit)</h3>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>Time</th><th>Remark</th><th>Signature</th><th>UUID</th><th>FP Active</th><th>Limit</th><th>IP</th><th>User-Agent</th><th>Current FP Active</th></tr>"
        f"{violations_html}"
        "</table>"
        "<br/>"
        "<form method='post' action='/admin/restart'><button type='submit'>Restart Xray</button></form>"
        "<form method='post' action='/admin/logout' style='margin-top:10px'><button type='submit'>Logout</button></form>"
        "</body></html>"
    )


async def _health_loop(manager: XrayManager):
    while True:
        await asyncio.sleep(HEALTHCHECK_SEC)
        await manager.ensure_running()


async def _proxy_ws(request: web.Request):
    manager: XrayManager = request.app["manager"]
    tracker: DeviceTracker = request.app["tracker"]
    max_active_fingerprints = max(1, int(os.getenv("MAX_ACTIVE_FINGERPRINTS_PER_UUID", "2")))
    if request.path != manager.ws_path:
        if request.method == "GET":
            return web.Response(text=_mask_html(), content_type="text/html")
        raise web.HTTPNotFound()

    if request.headers.get("Upgrade", "").strip().lower() != "websocket":
        return web.Response(status=426, text="websocket upgrade required")

    # Client may disconnect before websocket handshake reaches app code.
    transport = request.transport
    if transport is None or transport.is_closing():
        return web.Response(status=204)

    upstream = f"ws://127.0.0.1:{XRAY_UPSTREAM_PORT}{request.rel_url}"
    # Keep WS tunnel long-lived; total timeout can break active VPN sessions.
    timeout = None

    try:
        await manager.ensure_running()
    except Exception as exc:
        _log(f"xray ensure_running failed before ws proxy: {exc}")

    async with ClientSession() as session:
        ws_upstream = None
        last_connect_error: Exception | None = None
        for attempt in range(3):
            try:
                ws_upstream = await session.ws_connect(
                    upstream,
                    autoping=False,
                    timeout=timeout,
                    heartbeat=30,
                    max_msg_size=0,
                )
                last_connect_error = None
                break
            except (ClientConnectorError, OSError) as exc:
                last_connect_error = exc
                if attempt == 0:
                    # Freshly restarted xray may need a short warmup window.
                    await asyncio.sleep(0.25)
                    continue
                if attempt == 1:
                    _log(f"upstream ws connect failed: {exc}; restarting xray and retrying")
                    try:
                        await manager.restart()
                    except Exception as restart_exc:
                        _log(f"xray restart failed during ws retry: {restart_exc}")
                    await asyncio.sleep(0.35)
                    continue

        if ws_upstream is None:
            _log(f"upstream ws unavailable after retry: {last_connect_error}")
            return web.Response(status=503, text="upstream unavailable")

        try:
            ws_client = web.WebSocketResponse(autoping=False)
            try:
                transport = request.transport
                if transport is None or transport.is_closing():
                    return web.Response(status=204)
                await ws_client.prepare(request)
            except (AssertionError, ConnectionResetError, ClientConnectionResetError, RuntimeError):
                return web.Response(status=204)

            client_ip = _extract_client_ip(request)
            client_ua = _normalize_user_agent(request.headers.get("User-Agent", ""))
            stream_state = {"uuid": "", "fingerprint": ""}

            async def safe_close(ws):
                try:
                    await ws.close()
                except Exception:
                    pass

            async def relay(src, dst):
                try:
                    async for msg in src:
                        if msg.type == WSMsgType.TEXT:
                            await dst.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            if src is ws_client and not stream_state["uuid"]:
                                parsed_uuid = _try_parse_vless_uuid(msg.data)
                                if parsed_uuid:
                                    try:
                                        stream_state["uuid"] = parsed_uuid
                                        stream_state["fingerprint"] = _build_fingerprint(client_ip, client_ua)
                                        connect_stat = await tracker.on_connect(parsed_uuid, client_ip, client_ua)
                                        if int(connect_stat.get("active_fingerprints") or 0) > max_active_fingerprints:
                                            tracker.queue_violation(
                                                parsed_uuid,
                                                active_fingerprints=int(connect_stat.get("active_fingerprints") or 0),
                                                limit=max_active_fingerprints,
                                                ip=client_ip,
                                                user_agent=client_ua,
                                            )
                                    except Exception:
                                        # Monitoring must never break VPN traffic forwarding.
                                        pass
                            await dst.send_bytes(msg.data)
                        elif msg.type == WSMsgType.PING:
                            await dst.ping()
                        elif msg.type == WSMsgType.PONG:
                            await dst.pong()
                        elif msg.type in {WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR}:
                            break
                except (ConnectionResetError, BrokenPipeError, RuntimeError, ClientConnectionResetError):
                    # Normal for unstable mobile networks / abrupt client disconnects.
                    pass
                finally:
                    await safe_close(dst)

            t1 = asyncio.create_task(relay(ws_client, ws_upstream))
            t2 = asyncio.create_task(relay(ws_upstream, ws_client))
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(*done, return_exceptions=True)
            if stream_state["uuid"]:
                await tracker.on_disconnect(stream_state["uuid"], stream_state["fingerprint"])
        finally:
            try:
                await ws_upstream.close()
            except Exception:
                pass

    return ws_client


async def _mask_handler(_request: web.Request):
    return web.Response(text=_mask_html(), content_type="text/html")


async def _admin_login_get(_request: web.Request):
    return web.Response(text=_admin_login_html(), content_type="text/html")


async def _admin_login_post(request: web.Request):
    data = await request.post()
    user = str(data.get("user") or "").strip()
    password = str(data.get("password") or "").strip()
    if user != ADMIN_USER or password != ADMIN_PASSWORD:
        return web.Response(text=_admin_login_html("Invalid credentials"), content_type="text/html")
    payload = f"{user}.{int(time.time())}"
    token = _sign(payload)
    response = web.HTTPFound("/admin")
    response.set_cookie(AUTH_COOKIE, token, httponly=True, samesite="Lax", max_age=AUTH_TTL_SEC)
    return response


@_admin_required
async def _admin_dashboard(request: web.Request):
    manager: XrayManager = request.app["manager"]
    store: PanelStore = request.app["store"]
    tracker: DeviceTracker = request.app["tracker"]
    network_probe = await _probe_egress_identity(request.host)
    db = await store.load()
    users = db.get("users", [])
    user_by_uuid = {str(u.get("uuid") or ""): u for u in users}
    links = {str(u.get("uuid") or ""): manager.build_link(str(u.get("uuid") or "")) for u in users}
    base_uuid = manager.base_client_uuid()
    base_link = manager.build_link(base_uuid) if base_uuid else ""
    include_base_user = await store.include_base_user()
    per_uuid_devices: dict[str, dict[str, int]] = {}
    total_active_connections = 0
    total_active_fingerprints = 0
    total_violations_24h = 0
    uuids = [str(u.get("uuid") or "") for u in users if str(u.get("uuid") or "")]
    if base_uuid:
        uuids.append(base_uuid)
    for cid in uuids:
        stat = await tracker.stats_for(cid)
        per_uuid_devices[cid] = stat
        total_active_connections += int(stat.get("active_connections") or 0)
        total_active_fingerprints += int(stat.get("active_fingerprints") or 0)
        total_violations_24h += int(stat.get("violations_24h") or 0)
    raw_events = await tracker.recent_violation_events(limit=80)
    violation_events: list[dict[str, object]] = []
    for event in raw_events:
        uid = str(event.get("uuid") or "")
        user = user_by_uuid.get(uid, {})
        merged = dict(event)
        merged["remark"] = str(user.get("remark") or "")
        merged["signature"] = str(user.get("signature") or "")
        violation_events.append(merged)
    html = _admin_dashboard_html(
        manager.status(),
        await store.stats(),
        users,
        links,
        base_uuid,
        base_link,
        include_base_user,
        per_uuid_devices,
        violation_events,
        total_active_connections,
        total_active_fingerprints,
        total_violations_24h,
        network_probe,
    )
    return web.Response(text=html, content_type="text/html")


@_admin_required
async def _admin_restart(request: web.Request):
    manager: XrayManager = request.app["manager"]
    await manager.restart()
    raise web.HTTPFound("/admin")


@_admin_required
async def _admin_user_add(request: web.Request):
    store: PanelStore = request.app["store"]
    manager: XrayManager = request.app["manager"]
    data = await request.post()
    remark = str(data.get("remark") or "").strip() or "client"
    signature = str(data.get("signature") or "").strip()
    days = max(0, int(str(data.get("days") or "0")))
    traffic_gb = max(0, int(str(data.get("traffic_gb") or "0")))
    await store.add_user(remark, signature, days, traffic_gb)
    await manager.restart()
    raise web.HTTPFound("/admin")


@_admin_required
async def _admin_user_toggle(request: web.Request):
    store: PanelStore = request.app["store"]
    manager: XrayManager = request.app["manager"]
    data = await request.post()
    user_id = str(data.get("id") or "")
    await store.toggle_user(user_id)
    await manager.restart()
    raise web.HTTPFound("/admin")


@_admin_required
async def _admin_user_delete(request: web.Request):
    store: PanelStore = request.app["store"]
    manager: XrayManager = request.app["manager"]
    data = await request.post()
    user_id = str(data.get("id") or "")
    await store.delete_user(user_id)
    await manager.restart()
    raise web.HTTPFound("/admin")


@_admin_required
async def _admin_user_signature(request: web.Request):
    store: PanelStore = request.app["store"]
    data = await request.post()
    user_id = str(data.get("id") or "")
    signature = str(data.get("signature") or "")
    await store.update_signature(user_id, signature)
    raise web.HTTPFound("/admin")


@_admin_required
async def _admin_base_toggle(request: web.Request):
    store: PanelStore = request.app["store"]
    manager: XrayManager = request.app["manager"]
    await store.toggle_include_base_user()
    await manager.restart()
    raise web.HTTPFound("/admin")


async def _admin_logout(_request: web.Request):
    response = web.HTTPFound("/admin/login")
    response.del_cookie(AUTH_COOKIE)
    return response


def _app(manager: XrayManager, store: PanelStore, tracker: DeviceTracker) -> web.Application:
    app = web.Application()
    app["manager"] = manager
    app["store"] = store
    app["tracker"] = tracker

    app.router.add_get("/admin/login", _admin_login_get)
    app.router.add_post("/admin/login", _admin_login_post)
    app.router.add_get("/admin", _admin_dashboard)
    app.router.add_post("/admin/restart", _admin_restart)
    app.router.add_post("/admin/users/add", _admin_user_add)
    app.router.add_post("/admin/users/signature", _admin_user_signature)
    app.router.add_post("/admin/users/toggle", _admin_user_toggle)
    app.router.add_post("/admin/users/delete", _admin_user_delete)
    app.router.add_post("/admin/base/toggle", _admin_base_toggle)
    app.router.add_post("/admin/logout", _admin_logout)
    app.router.add_get("/healthz", lambda _r: web.Response(text="ok"))
    app.router.add_get("/", _mask_handler)
    app.router.add_route("*", "/{tail:.*}", _proxy_ws)
    return app


async def _run():
    _log("prepare persistent layout in /data")
    _ensure_layout()
    _download_xray()
    store = PanelStore(PANEL_DB_PATH)
    tracker = DeviceTracker(DEVICE_DB_PATH)
    await tracker.start()
    manager = XrayManager(store)
    await manager.start()

    app = _app(manager, store, tracker)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", WEB_PORT)
    await site.start()
    _log(f"web ui started on :{WEB_PORT} (admin: /admin)")
    _log(f"vpn ws path: {manager.ws_path} -> 127.0.0.1:{XRAY_UPSTREAM_PORT}")

    health_task = asyncio.create_task(_health_loop(manager))
    stop_event = asyncio.Event()

    def _on_signal():
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    await stop_event.wait()
    health_task.cancel()
    await asyncio.gather(health_task, return_exceptions=True)
    await manager.stop()
    await tracker.stop()
    await runner.cleanup()


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.server").setLevel(logging.WARNING)
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        _log(f"fatal: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
