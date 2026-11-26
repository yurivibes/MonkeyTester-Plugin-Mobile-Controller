#!/usr/bin/env python3
"""
macOS device controller for MonkeyTester iOS + Android runs.

The Mac's ONLY job is device control: this service owns the devices
(iOS via Appium + XCUITest + devicectl; Android via adb / UiAutomator2)
and exposes a small HTTP API. The viewer and test runner live on Linux
and talk to this service over the LAN.

    viewer + runner (Linux) ──HTTP──► device_controller.py (Mac, :8090)
                                          ├── Appium (:4723) ──► iPhone (XCUITest)
                                          ├── adb ────────────► Android (input/screencap)
                                          └── xcrun devicectl ─► iPhone (install)

iOS notes: this XCUITest driver removed the legacy `/wda/*` HTTP routes, so
iOS actions go through `execute/sync` mobile commands and W3C pointer
actions. WDA works in POINTS, not device pixels — actions accept pixel
coordinates (like Android) and this controller converts them to points
(scale from `mobile: deviceScreenInfo`). Screen recording uses the driver's
XCTest recorder (`mobile: startXCTestScreenRecording`): no ffmpeg, no
devicectl (devicectl screen-record is not supported on iPhone SE). It is an
insecure driver feature, so the Appium the controller spawns is started
with `--allow-insecure xcuitest:xctest_screen_record`; if APPIUM_URL points
at an Appium you manage yourself, start it with that flag or /record fails.

Android notes: coordinate actions (tap/swipe/text/keys) go straight through
`adb shell input` — fast, no first-session server build. The
`uiautomator2` driver is installed on Appium for element-based automation
when needed. Android device ids are ADB serials (USB `R58N123` or wireless
`IP:PORT`); iOS ids are UDIDs. Platform is auto-detected per request
(an explicit `"platform"` in the action body overrides).

Stdlib only (no aiohttp needed on the Mac): http.server + urllib.

Endpoints: see API.md, which is the contract.

Environment:
  CONTROLLER_PORT      — HTTP port (default 8090)
  CONTROLLER_BIND      — bind address (default 0.0.0.0, every interface)
  CONTROLLER_TOKEN     — shared token clients send as X-Controller-Token
                         (every route except /health). REQUIRED unless
                         CONTROLLER_BIND is loopback (127.0.0.1, ::1,
                         localhost): without it the service refuses to start.
                         See SECURITY.md.
  CONTROLLER_MAX_UPLOAD_MB — largest app upload accepted (default 2048);
                         bigger uploads get 413
  APPIUM_URL           — Appium base URL (default http://127.0.0.1:4723). The
                         controller only spawns Appium itself when this host is
                         loopback, because Appium has no authentication
  APPIUM_ORG_ID        — Xcode team/org ID for WDA signing (real devices)
  APPIUM_SIGNING_ID    — signing identity (default "Apple Development")
  APPIUM_WDA_BUNDLE_ID — updatedWDABundleId when WDA was renamed by Xcode
  APPIUM_CAPS_JSON     — extra Appium caps merged into alwaysMatch (JSON)
  APPIUM_ALLOW_INSECURE — driver insecure features to allow when the
                         controller spawns Appium (default
                         "xcuitest:xctest_screen_record" — required for iOS
                         screen recording); set "" to omit the flag
  DEVICECTL            — devicectl command (default "xcrun devicectl")
  ANDROID_HOME         — Android SDK (default ~/Library/Android/sdk)
  ADB_BIN              — adb binary (default $ANDROID_HOME/platform-tools/adb)
  JAVA_HOME            — JDK for Appium's UiAutomator2 driver (auto-detected)
  ADB_CONNECT          — comma list of wireless IP:PORT to keep adb-connected
                         (retried by a background thread every 30s, alongside
                         wireless devices found through adb mDNS)
"""
import base64
import hmac
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import urllib.error
import uuid
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import android_stream

# Bumped when the HTTP contract in API.md changes incompatibly.
API_VERSION = 2
SERVICE_NAME = "monkeytester-mobile-controller"

MAX_JSON_BYTES = 1024 * 1024


def _upload_cap_bytes(raw):
    """CONTROLLER_MAX_UPLOAD_MB as bytes; a bad value falls back to 2048 MiB."""
    try:
        mb = int(raw)
    except (TypeError, ValueError):
        mb = 0
    return (mb if mb > 0 else 2048) * 1024 * 1024


MAX_APP_BYTES = _upload_cap_bytes(os.environ.get("CONTROLLER_MAX_UPLOAD_MB", "2048"))
# An archive may unpack to more than it weighs; past this it's treated as a zip bomb.
MAX_UNPACKED_FACTOR = 4
VIDEO_RETENTION_SECS = 24 * 60 * 60
DEVICE_SNAPSHOT_TTL_SECS = 1.0
ANDROID_SERIALS_TTL_SECS = 3.0

# Device ids go into argv (`adb -s <id>`, `devicectl --device <id>`). They
# start with a letter or digit, so they can never be read as an option. `_` is
# kept because adb's mDNS serials contain it (`adb-X._adb-tls-connect._tcp`).
DEVICE_ID = r"([0-9A-Za-z][0-9A-Za-z:._-]{3,127})"
DEVICE_ID_RE = re.compile(DEVICE_ID)
# iOS bundle ids (letters, digits, `.`, `-`) and Android package names
# (letters, digits, `.`, `_`). adb joins its arguments into a device shell
# command line, so nothing else may get through.
BUNDLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
RECORDING_TOKEN = re.compile(r"[0-9a-f]{12}")
# `pkg/activity` as printed by `cmd package resolve-activity --brief`.
LAUNCH_COMPONENT = re.compile(r"[A-Za-z0-9._]+/[A-Za-z0-9._$]+")
UDID_SHAPE = re.compile(r"[0-9A-Fa-f]{8,}(-[0-9A-Fa-f]+)*")
LOOPBACK_NAMES = ("localhost",)


class ApiError(Exception):
    """A failure with a stable machine-readable code. See "Errors" in API.md."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code

PORT = int(os.environ.get("CONTROLLER_PORT", "8090"))
# Every interface by default: the viewer reaches this service over the LAN.
# That is why a token is then mandatory (see check_bind_token).
BIND = os.environ.get("CONTROLLER_BIND", "0.0.0.0").strip()  # nosec B104
TOKEN = os.environ.get("CONTROLLER_TOKEN", "").strip()
APPIUM_URL = os.environ.get("APPIUM_URL", "http://127.0.0.1:4723").rstrip("/")
DEVICECTL = shlex.split(os.environ.get("DEVICECTL", "xcrun devicectl"))
APPIUM_ALLOW_INSECURE = os.environ.get(
    "APPIUM_ALLOW_INSECURE", "xcuitest:xctest_screen_record").strip()

# ── Android (adb) ──

ANDROID_HOME = os.environ.get("ANDROID_HOME", "").strip() or \
    os.path.expanduser("~/Library/Android/sdk")
ADB_BIN = os.environ.get("ADB_BIN", "").strip() or \
    os.path.join(ANDROID_HOME, "platform-tools", "adb")
JAVA_HOME = os.environ.get("JAVA_HOME", "").strip()
if not JAVA_HOME and os.path.exists("/usr/libexec/java_home"):
    try:
        r = subprocess.run(["/usr/libexec/java_home"], capture_output=True,
                           text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            JAVA_HOME = r.stdout.strip()
    except Exception:
        pass
# Make the SDK + JDK visible to Appium's UiAutomator2 driver (it shells out
# to adb and java). Set before Appium is spawned.
os.environ.setdefault("ANDROID_HOME", ANDROID_HOME)
os.environ.setdefault("ANDROID_SDK_ROOT", ANDROID_HOME)
if JAVA_HOME:
    os.environ.setdefault("JAVA_HOME", JAVA_HOME)
DEVICE_EVENTS_POLL_SECS = 2.0
DEVICE_EVENTS_KEEPALIVE_SECS = 15.0
ADB_CONNECT = [p.strip() for p in
               os.environ.get("ADB_CONNECT", "").split(",") if p.strip()]

APP_DIR = Path(tempfile.gettempdir()) / "mt_ios_apps"
VIDEO_DIR = Path(tempfile.gettempdir()) / "mt_ios_video"
APP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
VIDEO_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

APPIUM_LOG = str(Path(tempfile.gettempdir()) / "mt_controller_appium.log")

_appium_proc = None
_appium_lock = threading.Lock()


def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Startup checks ──

def is_loopback(host):
    """True for 127.0.0.0/8, ::1 and `localhost`; False for anything else,
    including 0.0.0.0, :: and names that only might resolve to loopback."""
    host = (host or "").strip().strip("[]").lower()
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind_token(bind, token):
    """None when this bind/token pair may start, else the reason it may not.

    Listening beyond loopback without a token would hand every phone (install,
    tap, screenshots) to anyone on the network, so that is refused.
    """
    if token.upper().startswith("REPLACE"):
        return ("refusing to start: CONTROLLER_TOKEN is still the plist placeholder. "
                "Generate a real one: python3 -c 'import secrets; "
                "print(secrets.token_urlsafe(32))'")
    if token or is_loopback(bind):
        return None
    return (
        f"refusing to start: CONTROLLER_BIND={bind or '(empty)'} listens beyond this "
        "Mac, and CONTROLLER_TOKEN is not set.\n"
        "  Generate a token:  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'\n"
        "  Then set CONTROLLER_TOKEN=<token> in the environment (for launchd: the "
        "EnvironmentVariables dict of the plist) and enter the same token in the "
        "MonkeyTester viewer's Settings.\n"
        "  Or bind to loopback only: CONTROLLER_BIND=127.0.0.1 (token optional there).\n"
        "  See SECURITY.md.")


def check_appium_url(url):
    """None when APPIUM_URL is usable, else why not. Only http(s) is opened,
    so urlopen can never be pointed at file:// or a custom scheme."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return f"refusing to start: APPIUM_URL must be an http(s) URL, got {url!r}"
    return None


def safe_path_under(root, path):
    """`path` resolved, if it stays under `root` (also resolved); else None.

    Symlinks are followed before comparing, so a link out of root is refused.
    """
    if not path or "\x00" in str(path):
        return None
    root_real = os.path.realpath(root)
    real = os.path.realpath(path)
    try:
        if os.path.commonpath([root_real, real]) != root_real:
            return None
    except ValueError:  # different drives / mix of absolute and relative
        return None
    return real


def validate_device_id(dev):
    if not isinstance(dev, str) or not DEVICE_ID_RE.fullmatch(dev):
        raise ApiError(400, "invalid_request", "invalid device id")
    return dev


def validate_recording_token(token):
    if not isinstance(token, str) or not RECORDING_TOKEN.fullmatch(token):
        raise ApiError(400, "invalid_request", "invalid recording token")
    return token


def optional_int(body, name, default=None, low=None, high=None):
    """An integer body field, or 400. Missing/null gives the default."""
    value = body.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        raise ApiError(400, "invalid_request", f"{name} must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, "invalid_request", f"{name} must be an integer") from None
    if (low is not None and value < low) or (high is not None and value > high):
        raise ApiError(400, "invalid_request", f"{name} must be between {low} and {high}")
    return value


def parse_device_xml(xml_text):
    """Parse XML from Appium or uiautomator. A DOCTYPE/ENTITY is refused, so
    entity-expansion tricks from a hostile app under test can't apply; neither
    tool ever emits one."""
    head = xml_text if isinstance(xml_text, str) else bytes(xml_text).decode("utf-8", "replace")
    if "<!DOCTYPE" in head or "<!ENTITY" in head:
        raise RuntimeError("device XML contains a DOCTYPE/ENTITY; refused")
    return ET.fromstring(xml_text)  # nosec B314 - DOCTYPE/ENTITY rejected above


# ── Appium ──

def appium_ready():
    try:
        req = urllib.request.Request(f"{APPIUM_URL}/status")
        # APPIUM_URL is checked to be http(s) at startup (check_appium_url).
        with urllib.request.urlopen(req, timeout=5) as r:  # nosec B310
            body = json.loads(r.read().decode() or "{}")
            return bool((body.get("value") or {}).get("ready"))
    except Exception:
        return False


def ensure_appium():
    """Make sure Appium is up; start it if not (this process's child)."""
    with _appium_lock:
        return _ensure_appium_locked()


def _ensure_appium_locked():
    global _appium_proc
    if appium_ready():
        return True
    log(f"Appium not responding at {APPIUM_URL} — starting it...")
    appium_bin = shutil.which("appium")
    if not appium_bin:
        # node local install layout
        cand = os.path.expanduser("~/.local/node/bin/appium")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            appium_bin = cand
    if not appium_bin:
        return False
    port = urlsplit(APPIUM_URL).port or 4723
    # Listen only where APPIUM_URL points (127.0.0.1 by default). Appium's own
    # default is every interface, which exposes an unauthenticated server to
    # the network and makes macOS ask to accept incoming connections. Appium
    # has no authentication, so it is never spawned on a non-loopback address.
    address = urlsplit(APPIUM_URL).hostname or "127.0.0.1"
    if not is_loopback(address):
        log(f"APPIUM_URL host {address} is not loopback; not spawning an "
            "unauthenticated Appium there. Start that Appium yourself.")
        return False
    cmd = [appium_bin, "--address", address, "--port", str(port),
           "--log", APPIUM_LOG]
    if APPIUM_ALLOW_INSECURE:
        cmd += ["--allow-insecure", APPIUM_ALLOW_INSECURE]
    try:
        _appium_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log(f"failed to start appium: {e}")
        return False
    for _ in range(30):
        if appium_ready():
            log("Appium is up")
            return True
        time.sleep(1)
    log("Appium did not come up within 30s")
    return False


def http_json(method, url, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method=method)
    # Only ever APPIUM_URL + a path; its scheme is checked at startup.
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return json.loads(resp.read().decode() or "{}")


# ── Session management (one Appium session per UDID) ──

_sessions = {}  # udid -> {"sid": str, "created": float}
_session_locks = {}  # udid -> Lock; creating a session can take minutes (WDA build)
_session_locks_guard = threading.Lock()
_screen_scales = {}  # udid -> points-to-pixels factor


def build_caps(udid):
    caps = {
        "platformName": "iOS",
        "appium:automationName": "XCUITest",
        "appium:udid": udid,
        "appium:bundleId": "com.apple.springboard",
        "appium:newCommandTimeout": 3600,
    }
    org = os.environ.get("APPIUM_ORG_ID", "").strip()
    if org:
        caps["appium:xcodeOrgId"] = org
    signing = os.environ.get("APPIUM_SIGNING_ID", "Apple Development").strip()
    if signing:
        caps["appium:xcodeSigningId"] = signing
    wda_bundle = os.environ.get("APPIUM_WDA_BUNDLE_ID", "").strip()
    if wda_bundle:
        caps["appium:updatedWDABundleId"] = wda_bundle
    extra = os.environ.get("APPIUM_CAPS_JSON", "").strip()
    if extra:
        try:
            merged = json.loads(extra)
            if isinstance(merged, dict):
                caps.update(merged)
        except Exception as e:
            log(f"APPIUM_CAPS_JSON invalid, ignored: {e}")
    return caps


def session_alive(sid):
    try:
        http_json("GET", f"{APPIUM_URL}/session/{sid}", timeout=10)
        return True
    except Exception:
        return False


def get_session(udid):
    """Return a live Appium session id for the UDID, creating it if needed."""
    with _session_locks_guard:
        lock = _session_locks.setdefault(udid, threading.Lock())
    with lock:
        s = _sessions.get(udid)
        if s and session_alive(s["sid"]):
            return s["sid"]
        if s:
            log(f"session for {udid[:8]} stale, recreating")
            _sessions.pop(udid, None)
        if not ensure_appium():
            raise RuntimeError("Appium is not available on the controller Mac")
        log(f"creating Appium session for {udid} (first use may build WDA — slow)")
        body = http_json("POST", f"{APPIUM_URL}/session",
                         {"capabilities": {"alwaysMatch": build_caps(udid)}},
                         timeout=300)
        value = body.get("value") or {}
        sid = value.get("sessionId")
        if not sid:
            raise RuntimeError(f"Appium session creation failed: "
                               f"{json.dumps(body)[:300]}")
        _sessions[udid] = {"sid": sid, "created": time.time()}
        log(f"Appium session for {udid[:8]}: {sid}")
        return sid


def mobile(udid, script, args=None, timeout=60):
    """Run an `execute/sync` mobile command against the udid's session."""
    sid = get_session(udid)
    body = http_json("POST", f"{APPIUM_URL}/session/{sid}/execute/sync",
                     {"script": script, "args": args if args is not None else {}},
                     timeout=timeout)
    return body.get("value")


def w3c_tap(udid, x, y, timeout=30):
    sid = get_session(udid)
    actions = {"actions": [{"type": "pointer", "id": "mt",
                            "duration": 100, "button": 0,
                            "pointerType": "touch",
                            "actions": [
                                {"type": "pointerMove", "duration": 0,
                                 "x": int(x), "y": int(y), "origin": "viewport"},
                                {"type": "pointerDown", "button": 0},
                                {"type": "pointerUp", "button": 0}]}]}
    http_json("POST", f"{APPIUM_URL}/session/{sid}/actions", actions,
              timeout=timeout)
    return {"ok": True}


def w3c_swipe(udid, x1, y1, x2, y2, ms=300, timeout=60):
    sid = get_session(udid)
    ms = int(max(50, min(60000, ms)))
    actions = {"actions": [{"type": "pointer", "id": "mt",
                            "duration": ms, "button": 0,
                            "pointerType": "touch",
                            "actions": [
                                {"type": "pointerMove", "duration": 0,
                                 "x": int(x1), "y": int(y1), "origin": "viewport"},
                                {"type": "pointerDown", "button": 0},
                                {"type": "pointerMove", "duration": ms,
                                 "x": int(x2), "y": int(y2), "origin": "viewport"},
                                {"type": "pointerUp", "button": 0}]}]}
    http_json("POST", f"{APPIUM_URL}/session/{sid}/actions", actions,
              timeout=timeout)
    return {"ok": True}


# ── devicectl ──

def devicectl(*args, timeout=120):
    cmd = DEVICECTL + list(args)
    log(f"[DEVICECTL] {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except Exception as e:
        return 1, "", str(e)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def parse_devicectl_devices(output):
    """UDIDs of usable iPhones in `devicectl list devices` output.

    A row reads `Name  Host  00008030-... (UDID)  available (paired)  Model  physical`.
    The state can be `available` or `connected`; only `unavailable` means unusable.
    """
    udids = []
    for line in (output or "").splitlines():
        parts = line.split()
        if "(UDID)" not in parts:
            continue
        idx = parts.index("(UDID)")
        state = parts[idx + 1].lower() if idx + 1 < len(parts) else ""
        if idx > 0 and state in ("available", "connected") and parts[idx - 1] not in udids:
            udids.append(parts[idx - 1])
    return udids


def list_devices():
    rc, out, err = devicectl("list", "devices", timeout=20)
    if rc != 0:
        return [], f"devicectl list failed: {err[:200]}"
    return parse_devicectl_devices(out), None


def png_size(data):
    """(width, height) from a PNG's IHDR chunk."""
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) < 24:
        raise RuntimeError("device returned a screenshot that is not a PNG")
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def screen_size(udid):
    """Device-pixel screen size, read from a screenshot so it always matches one.

    `mobile: deviceScreenInfo` reports only the scale and status bar, so asking it
    for a size gives nothing, and guessing a size sends taps to the wrong place.
    """
    return png_size(screenshot_png(udid))


def screen_scale(udid):
    """Points-to-pixels factor. Cached: it never changes and a tap needs it each time."""
    if udid not in _screen_scales:
        v = mobile(udid, "mobile: deviceScreenInfo", {}, timeout=30)
        scale = float(v.get("scale") or 0) if isinstance(v, dict) else 0
        if scale <= 0:
            raise RuntimeError(f"device reported no screen scale: {str(v)[:200]}")
        _screen_scales[udid] = scale
    return _screen_scales[udid]


def px_to_pt(udid, x, y):
    """/action pixel coords -> WDA points. WDA works in points."""
    scale = screen_scale(udid)
    return int(round(int(x) / scale)), int(round(int(y) / scale))


def parse_xcuitest_elements(xml_text, scale):
    """Visible, named elements in an XCUITest page source, in device pixels.

    `name` is the accessibility identifier when one is set (a Compose testTag
    on iOS). The source gives points; multiplying by scale gives pixels.
    """
    root = parse_device_xml(xml_text)
    elements = []
    for node in root.iter():
        name = (node.get("name") or "").strip()
        if not name or node.get("visible") != "true":
            continue
        try:
            x, y, w, h = (float(node.get(k) or "") for k in ("x", "y", "width", "height"))
        except ValueError:
            continue
        el = {"id": name, "x": int(round(x * scale)), "y": int(round(y * scale)),
              "w": int(round(w * scale)), "h": int(round(h * scale))}
        if node.get("label"):
            el["label"] = node.get("label")
        elements.append(el)
    return elements


def page_source(udid):
    sid = get_session(udid)
    body = http_json("GET", f"{APPIUM_URL}/session/{sid}/source", timeout=120)
    xml_text = (body or {}).get("value")
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise RuntimeError("Appium page source returned no data")
    return xml_text


def ios_elements(udid):
    scale = screen_scale(udid)
    w, h = screen_size(udid)
    return {"width": w, "height": h, "scale": scale,
            "elements": parse_xcuitest_elements(page_source(udid), scale)}


def screenshot_png(udid):
    """One PNG of the device screen (device pixels)."""
    sid = get_session(udid)
    try:
        body = http_json("GET", f"{APPIUM_URL}/session/{sid}/screenshot",
                         timeout=60)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Appium screenshot failed: HTTP {e.code}")
    b64 = (body or {}).get("value")
    if not isinstance(b64, str):
        raise RuntimeError("Appium screenshot returned no data")
    return base64.b64decode(b64)


# ── Recordings ──

_recordings = {}  # token -> {"path", "udid", "done", "finished", ...}
_recordings_lock = threading.Lock()


def _reserve_recording(udid):
    """Claim the device for a new recording, atomically. Returns (token, entry).

    One recording per device. A start on a device that still has an unfinished
    recording takes it over: the old one is stopped first (its video stays
    downloadable). Runs on a device are serialized by the runner, so an
    unfinished recording here belongs to a run that died without stopping it,
    and refusing would leave the device unable to record until a restart.
    """
    with _recordings_lock:
        stale = [(t, r) for t, r in _recordings.items()
                 if r["udid"] == udid and not r["done"]]
        token = uuid.uuid4().hex[:12]
        entry = {"path": str(VIDEO_DIR / f"{token}.mp4"), "udid": udid,
                 "done": False, "finished": None, "replaced": [t for t, _ in stale]}
        _recordings[token] = entry
    for old, _ in stale:
        log(f"recording {old} on {udid} was never stopped; stopping it for {token}")
        try:
            record_stop(old)
        except Exception as e:  # a failed stop still ends it (see record_stop)
            log(f"stopping stale recording {old} failed: {e}")
    return token, entry


def record_start(udid, fps=30, codec=0):
    """Start the driver's XCTest screen recorder (no ffmpeg/devicectl).

    Requires the Appium backing the session to allow the
    `xcuitest:xctest_screen_record` insecure feature — the Appium spawned
    by this controller is started with it (see APPIUM_ALLOW_INSECURE).
    """
    token, entry = _reserve_recording(udid)
    try:
        v = mobile(udid, "mobile: startXCTestScreenRecording",
                   {"fps": int(fps), "codec": int(codec)}, timeout=120)
        if not isinstance(v, dict) or "uuid" not in v:
            raise RuntimeError(
                "startXCTestScreenRecording failed — is the Appium backing the "
                "session started with --allow-insecure "
                f"xcuitest:xctest_screen_record? {str(v)[:200]}")
    except Exception:
        with _recordings_lock:
            _recordings.pop(token, None)
        raise
    entry["uuid"] = v["uuid"]
    return token


def android_record_start(serial, time_limit=None):
    token, entry = _reserve_recording(serial)
    try:
        entry["recorder"] = android_stream.AndroidRecording(
            ADB_BIN, serial, entry["path"], time_limit, log=log)
    except Exception:
        with _recordings_lock:
            _recordings.pop(token, None)
        raise
    return token


def record_stop(token):
    """Finish a recording. Stopping one already finished is a no-op.

    A failed stop still ends the recording, so the device can record again.
    """
    with _recordings_lock:
        rec = _recordings.get(token)
        if not rec:
            raise ApiError(404, "recording_not_found", f"unknown recording token {token}")
        if rec["done"]:
            return
        rec["done"] = True
    rec["finished"] = time.time()
    if rec.get("recorder"):
        rec["recorder"].stop()
        return
    v = mobile(rec["udid"], "mobile: stopXCTestScreenRecording", {}, timeout=300)
    payload = v.get("payload") if isinstance(v, dict) else None
    if not isinstance(payload, str) or not payload:
        raise RuntimeError(f"stopXCTestScreenRecording returned no "
                           f"video payload: {str(v)[:200]}")
    with open(rec["path"], "wb") as f:
        f.write(base64.b64decode(payload))


def prune_recordings(max_age=VIDEO_RETENTION_SECS, now=None):
    """Delete finished recordings older than max_age, so videos don't fill the disk."""
    cutoff = (time.time() if now is None else now) - max_age
    with _recordings_lock:
        expired = [t for t, r in _recordings.items()
                   if r["done"] and r["finished"] is not None and r["finished"] < cutoff]
        paths = [_recordings.pop(t)["path"] for t in expired]
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass
    return expired


# ── Android (adb) ──

def adb_global(*args, timeout=60):
    """Run an adb command with no target serial (e.g. `devices`)."""
    cmd = [ADB_BIN] + list(args)
    log(f"[ADB] adb {' '.join(args)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found at {ADB_BIN} "
                           f"(set ANDROID_HOME/ADB_BIN)")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"adb timed out: {' '.join(args)}")
    if result.returncode != 0:
        raise RuntimeError("adb %s failed: %s" % (" ".join(args),
                                (result.stderr or result.stdout).strip()[:200]))
    return result.stdout.strip()


def adb(serial, *args, timeout=60):
    """Run an adb command against a specific device serial (text output)."""
    cmd = [ADB_BIN, "-s", serial] + list(args)
    log(f"[ADB] {serial}: adb {' '.join(args)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found at {ADB_BIN} "
                           f"(set ANDROID_HOME/ADB_BIN)")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"adb timed out: {' '.join(args)}")
    if result.returncode != 0:
        raise RuntimeError("adb %s failed: %s" % (" ".join(args),
                                (result.stderr or result.stdout).strip()[:200]))
    return result.stdout.strip()


def adb_bytes(serial, *args, timeout=60):
    """Run an adb command returning raw stdout bytes (binary-safe)."""
    cmd = [ADB_BIN, "-s", serial] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found at {ADB_BIN}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"adb timed out: {' '.join(args)}")
    if result.returncode != 0:
        err = (result.stderr or b"").decode(errors="replace").strip()[:200]
        raise RuntimeError("adb %s failed: %s" % (" ".join(args), err))
    return result.stdout


def adb_connected(serials=None):
    """Serials currently attached (online).

    A wireless phone can be registered twice, as IP:PORT and under its mDNS
    name. Only the IP:PORT form is reported, so one phone is one device.
    """
    out = adb_global("devices")
    serials = set(serials) if serials else None
    online = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and parts[0]:
            if serials is None or parts[0] in serials:
                online.append(parts[0])
    return [s for s in online if _mdns_aliases.get(s) not in online]


def parse_adb_mdns_connect_services(output):
    """Connectable wireless services in `adb mdns services` output, as
    [{"serial": <mDNS adb serial>, "target": "IP:PORT"}], without duplicates."""
    services = []
    seen = set()
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[1].startswith("_adb-tls-connect._tcp"):
            continue
        name, service, target = parts[0], parts[1].rstrip("."), parts[2]
        if target not in seen:
            seen.add(target)
            services.append({"serial": f"{name}.{service}", "target": target})
    return services


def parse_adb_mdns_connect_targets(output):
    return [s["target"] for s in parse_adb_mdns_connect_services(output)]


_mdns_aliases = {}  # mDNS adb serial -> IP:PORT


def adb_discover_targets():
    """Wireless IP:PORT targets advertised over mDNS right now."""
    result = subprocess.run([ADB_BIN, "mdns", "services"], capture_output=True,
                            text=True, timeout=5)
    services = parse_adb_mdns_connect_services(result.stdout)
    _mdns_aliases.update({s["serial"]: s["target"] for s in services})
    return [s["target"] for s in services]


_android_models = {}  # serial -> model


def android_model(serial):
    """ro.product.model, cached once read. None when it can't be read."""
    if serial not in _android_models:
        try:
            model = adb(serial, "shell", "getprop", "ro.product.model", timeout=10)
        except Exception:
            return None
        if model:
            _android_models[serial] = model
    return _android_models.get(serial)


def device_list(udids, android):
    return ([{"id": u, "platform": "ios", "model": None} for u in udids]
            + [{"id": s, "platform": "android", "model": android_model(s)}
               for s in android])


_snapshot_cache = {"at": 0.0, "body": None}
_snapshot_lock = threading.Lock()


def device_snapshot():
    """The body of GET /devices and of each device event.

    One platform failing never hides the other: a Mac without Xcode still lists
    its Android phones, with the problem in `errors`. Shared briefly, so several
    subscribers don't each run devicectl and adb every poll.
    """
    with _snapshot_lock:
        now = time.monotonic()
        if _snapshot_cache["body"] is not None and now - _snapshot_cache["at"] < DEVICE_SNAPSHOT_TTL_SECS:
            return _snapshot_cache["body"]
        errors = {}
        udids, ios_error = list_devices()
        if ios_error:
            errors["ios"] = ios_error
        try:
            android = adb_connected()
        except Exception as e:
            android = []
            errors["android"] = str(e)
        body = {"devices": device_list(udids, android), "errors": errors}
        _snapshot_cache.update(at=time.monotonic(), body=body)
        return body


def adb_screen_size(serial):
    out = adb(serial, "shell", "wm", "size")
    m = re.search(r"(\d+)x(\d+)", out)
    if m:
        return int(m.group(1)), int(m.group(2))
    raise RuntimeError(f"could not parse screen size from: {out[:100]}")


def parse_wm_density(output):
    """dpi from `wm density` output; an `Override density` line wins."""
    found = dict(re.findall(r"(Physical|Override) density:\s*(\d+)", output or ""))
    dpi = found.get("Override") or found.get("Physical")
    if not dpi:
        raise RuntimeError(f"could not parse screen density from: {(output or '')[:100]}")
    return int(dpi)


def adb_screen_scale(serial):
    """Pixels per dp: the density in use / 160."""
    return parse_wm_density(adb(serial, "shell", "wm", "density")) / 160.0


_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


def parse_uiautomator_elements(xml_text):
    """Elements with a resource-id in a `uiautomator dump`, in device pixels.

    The id drops any `<pkg>:id/` prefix, so a Compose testTag exposed with
    testTagsAsResourceId reads the same as on iOS. The dump holds only nodes
    shown on screen; nodes with no area are dropped too.
    """
    root = parse_device_xml(xml_text)
    elements = []
    for node in root.iter("node"):
        rid = (node.get("resource-id") or "").strip()
        m = _BOUNDS.fullmatch(node.get("bounds") or "")
        if not rid or not m:
            continue
        x1, y1, x2, y2 = (int(v) for v in m.groups())
        if x2 <= x1 or y2 <= y1:
            continue
        el = {"id": rid.split(":id/", 1)[-1], "x": x1, "y": y1, "w": x2 - x1, "h": y2 - y1}
        label = node.get("text") or node.get("content-desc")
        if label:
            el["label"] = label
        elements.append(el)
    return elements


def adb_ui_dump(serial):
    """The window hierarchy XML from `uiautomator dump`."""
    remote = f"/sdcard/mt_window_{uuid.uuid4().hex[:8]}.xml"
    try:
        out = adb(serial, "shell", "uiautomator", "dump", remote, timeout=60)
        if "dumped to" not in out:
            raise RuntimeError(f"uiautomator dump failed: {out[:200]}")
        return adb_bytes(serial, "exec-out", "cat", remote, timeout=60)
    finally:
        try:
            adb(serial, "shell", "rm", "-f", remote, timeout=10)
        except Exception:
            pass


def android_elements(serial):
    w, h = adb_screen_size(serial)
    return {"width": w, "height": h, "scale": adb_screen_scale(serial),
            "elements": parse_uiautomator_elements(adb_ui_dump(serial))}


def adb_screenshot_png(serial):
    remote = f"/sdcard/mt_ctrl_shot_{uuid.uuid4().hex[:8]}.png"
    adb(serial, "shell", "screencap", "-p", remote)
    data = adb_bytes(serial, "exec-out", "cat", remote, timeout=60)
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise RuntimeError("screencap returned non-PNG data "
                           f"({len(data)} bytes)")
    try:
        adb(serial, "shell", "rm", "-f", remote, timeout=10)
    except Exception:
        pass
    return data


def adb_install_apk(serial, local_path):
    """Install an .apk over the wire (adb install -r)."""
    cmd = [ADB_BIN, "-s", serial, "install", "-r", "-t", local_path]
    log(f"[ADB] {serial}: adb install -r -t {local_path}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        raise RuntimeError(f"adb not found at {ADB_BIN}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("adb install timed out")
    if r.returncode != 0 or "Success" not in (r.stdout or ""):
        raise RuntimeError("adb install failed: %s"
                           % ((r.stderr or r.stdout).strip()[:300]))


def parse_launch_component(resolve_activity_output, package_name):
    """Pick pkg/activity from `cmd package resolve-activity --brief` output.

    Falls back to pkg/.MainActivity. Asking the device matters because an app's
    activity class need not live under its applicationId.
    """
    prefix = f"{package_name}/"
    for line in reversed((resolve_activity_output or "").splitlines()):
        line = line.strip()
        # The line goes back into a device shell command: only a plain
        # pkg/activity name is used, anything else falls back.
        if line.startswith(prefix) and LAUNCH_COMPONENT.fullmatch(line):
            return line
    return f"{package_name}/.MainActivity"


def android_action(serial, action, params):
    if action == "tap":
        adb(serial, "shell", "input", "tap",
            str(int(params["x"])), str(int(params["y"])))
        return {"ok": True}
    if action == "swipe":
        ms = max(50, min(10000, int(params.get("duration_ms", 300))))
        adb(serial, "shell", "input", "swipe",
            str(int(params["x1"])), str(int(params["y1"])),
            str(int(params["x2"])), str(int(params["y2"])), str(ms),
            timeout=60)
        return {"ok": True}
    if action == "text":
        # `input text` only takes basic ASCII. adb joins its arguments into a
        # device shell command, so quote to keep metacharacters literal.
        text = params.get("text", "").replace(" ", "%s")
        adb(serial, "shell", "input", "text", shlex.quote(text))
        return {"ok": True}
    if action == "delete":
        for _ in range(max(1, int(params.get("count", 1)))):
            adb(serial, "shell", "input", "keyevent", "67")  # KEYCODE_DEL
        return {"ok": True}
    if action == "dismiss-keyboard":
        adb(serial, "shell", "input", "keyevent", "4")  # KEYCODE_BACK
        return {"ok": True}
    if action == "keyevent":
        code = str(int(params.get("code", "")))
        adb(serial, "shell", "input", "keyevent", code)
        return {"ok": True}
    if action == "launch":
        pid = params["bundle_id"]
        resolved = adb(serial, "shell", "cmd", "package", "resolve-activity",
                       "--brief", "-a", "android.intent.action.MAIN",
                       "-c", "android.intent.category.LAUNCHER", pid)
        component = parse_launch_component(resolved, pid)
        adb(serial, "shell", "am", "start", "-n", shlex.quote(component), "-W",
            "-f", "0x10000000", timeout=120)
        return {"ok": True, "component": component}
    if action == "clear-data":
        adb(serial, "shell", "pm", "clear", params["bundle_id"])
        return {"ok": True}
    if action == "terminate":
        adb(serial, "shell", "am", "force-stop", params["bundle_id"])
        return {"ok": True}
    if action == "unlock":
        adb(serial, "shell", "input", "keyevent", "82")  # KEYCODE_MENU wakes
        adb(serial, "shell", "wm", "dismiss-keyguard")
        time.sleep(1)
        out = adb(serial, "shell", "dumpsys", "window")
        locked = "mDreamingLockscreen=true" in out or \
            "isStatusBarKeyguard" in out
        return {"ok": True, "locked": locked}
    raise RuntimeError(f"unknown android action: {action}")


def adb_connect_wireless_once():
    """Connect configured and mDNS-advertised wireless devices not yet online."""
    targets = list(ADB_CONNECT)
    try:
        targets += [t for t in adb_discover_targets() if t not in targets]
        connected = set(adb_connected())
    except Exception as e:
        log(f"adb wireless discovery failed: {e}")
        return
    for target in targets:
        if target in connected:
            continue
        try:
            subprocess.run([ADB_BIN, "connect", target],
                           capture_output=True, text=True, timeout=10)
            log(f"adb connect {target} attempted")
        except Exception as e:
            log(f"adb connect {target} failed: {e}")


def adb_keepalive():
    """Background thread: keep wireless adb devices connected."""
    while True:
        adb_connect_wireless_once()
        prune_recordings()
        time.sleep(30)


# ── Actions ──

_android_serials = {"at": 0.0, "serials": frozenset()}


def known_android_serials():
    """Serials adb can see now, cached briefly because this runs on every request."""
    now = time.monotonic()
    if now - _android_serials["at"] >= ANDROID_SERIALS_TTL_SECS:
        try:
            serials = frozenset(adb_connected())
        except Exception:
            serials = frozenset()
        _android_serials.update(at=now, serials=serials)
    return _android_serials["serials"]


def detect_platform(dev_id, hint=""):
    """'ios' or 'android'. An explicit hint wins, and ':' means a wireless adb
    serial. adb is asked before looking at the id's shape, because many USB
    Android serials are plain hex and look just like a UDID."""
    hint = (hint or "").strip().lower()
    if hint in ("ios", "android"):
        return hint
    if ":" in dev_id or dev_id in known_android_serials():
        return "android"
    return "ios"


# Required parameters of each action; API.md lists the optional ones.
ACTION_PARAMS = {
    "tap": ("x", "y"),
    "swipe": ("x1", "y1", "x2", "y2"),
    "text": ("text",),
    "delete": (),
    "dismiss-keyboard": (),
    "keyevent": ("code",),
    "launch": ("bundle_id",),
    "terminate": ("bundle_id",),
    "clear-data": ("bundle_id",),
    "unlock": (),
}
_INTEGER_PARAMS = ("x", "y", "x1", "y1", "x2", "y2", "code", "count", "duration_ms")


def validate_action(action, params):
    """Reject a malformed action with a 400 before anything reaches a device."""
    if action not in ACTION_PARAMS:
        raise ApiError(400, "unknown_action", f"unknown action: {action!r}")
    missing = [name for name in ACTION_PARAMS[action] if name not in params]
    if missing:
        raise ApiError(400, "invalid_request",
                       f"{action} needs {', '.join(missing)}")
    for name in _INTEGER_PARAMS:
        if name in params:
            try:
                int(params[name])
            except (TypeError, ValueError):
                raise ApiError(400, "invalid_request",
                               f"{name} must be an integer") from None
    if "bundle_id" in params:
        validate_bundle_id(params["bundle_id"])


def validate_bundle_id(bundle_id):
    """adb joins its arguments into a device shell command, so only let real ids through."""
    if not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id):
        raise ApiError(400, "invalid_request", "invalid bundle_id")


def do_action(udid, action, params):
    validate_action(action, params)
    if detect_platform(udid, params.get("platform")) == "android":
        return android_action(udid, action, params)
    # iOS: /action coordinates are device pixels (vision-model space); WDA
    # works in points, so convert before sending (see px_to_pt).
    if action == "tap":
        x, y = px_to_pt(udid, params["x"], params["y"])
        return w3c_tap(udid, x, y)
    if action == "swipe":
        x1, y1 = px_to_pt(udid, params["x1"], params["y1"])
        x2, y2 = px_to_pt(udid, params["x2"], params["y2"])
        return w3c_swipe(udid, x1, y1, x2, y2,
                         ms=params.get("duration_ms", 300))
    if action == "text":
        text = params.get("text", "")
        return mobile(udid, "mobile: keys", {"keys": list(text)}, timeout=90)
    if action == "delete":
        count = max(1, int(params.get("count", 1)))
        return mobile(udid, "mobile: keys", {"keys": ["\b"] * count}, timeout=90)
    if action == "clear-data":
        return {"skipped": "iOS cannot clear app data; uninstall the app instead"}
    if action == "dismiss-keyboard":
        return mobile(udid, "mobile: hideKeyboard", {}, timeout=15)
    if action == "keyevent":
        code = str(params.get("code", ""))
        if code == "3":
            return mobile(udid, "mobile: pressButton",
                          {"name": "home"}, timeout=15)
        if code == "4":
            return mobile(udid, "mobile: hideKeyboard", {}, timeout=15)
        if code == "66":
            return mobile(udid, "mobile: keys", {"keys": ["\n"]}, timeout=15)
        return {"skipped": f"keyevent {code} not mapped"}
    if action == "launch":
        return mobile(udid, "mobile: launchApp",
                      {"bundleId": params["bundle_id"]}, timeout=180)
    if action == "terminate":
        return mobile(udid, "mobile: terminateApp",
                      {"bundleId": params["bundle_id"]}, timeout=30)
    if action == "unlock":
        v = mobile(udid, "mobile: isLocked", {}, timeout=15)
        if isinstance(v, dict) and v.get("isLocked"):
            mobile(udid, "mobile: unlock", {}, timeout=30)
            time.sleep(2)
            v2 = mobile(udid, "mobile: isLocked", {}, timeout=15)
            if isinstance(v2, dict) and v2.get("isLocked"):
                raise ApiError(409, "device_locked",
                               "device is locked and cannot be unlocked "
                               "automatically (passcode/Face ID required)")
        return {"ok": True}
    raise RuntimeError(f"unknown action: {action}")


# ── HTTP server ──

_streams = android_stream.StreamManager(ADB_BIN, log=log)


def check_archive_members(archive, max_unpacked):
    """Refuse a zip whose member names escape the extraction dir (absolute,
    `..`, NUL, drive letters) or that unpacks to more than max_unpacked bytes.
    Checked before ditto runs, since ditto doesn't promise either."""
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
    except zipfile.BadZipFile:
        raise ApiError(400, "invalid_app", "upload is not a valid zip archive") from None
    total = 0
    for info in infos:
        name = info.filename.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or "\x00" in name or ".." in parts \
                or (len(parts[0]) >= 2 and parts[0][1] == ":"):
            raise ApiError(400, "invalid_app", f"unsafe path in archive: {info.filename[:100]!r}")
        total += info.file_size
        if total > max_unpacked:
            raise ApiError(413, "body_too_large",
                           f"archive unpacks to more than {max_unpacked} bytes")
    return infos


def extract_app_archive(archive, dest):
    """Unpack an app archive into dest. ditto keeps the symlinks and exec bits
    the code signature covers; zipfile (which loses them) is only for non-Macs."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    check_archive_members(archive, MAX_APP_BYTES * MAX_UNPACKED_FACTOR)
    ditto = "/usr/bin/ditto"
    if os.path.exists(ditto):
        result = subprocess.run([ditto, "-x", "-k", str(archive), str(dest)],
                                capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "ditto failed")
        return
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)


def find_app_bundle(root):
    """Return the shallowest *.app directory under root, or None."""
    level = [Path(root)]
    while level:
        dirs = sorted(c for parent in level for c in parent.iterdir()
                      if c.is_dir() and not c.is_symlink())
        apps = [d for d in dirs if d.suffix == ".app"]
        if apps:
            return apps[0]
        level = dirs
    return None


_INSTALL_HINTS = (
    (("provision", "0xe8008012", "not included"),
     "the signing profile may not include this device; register its UDID with "
     "the team and rebuild the IPA."),
    (("signature", "not signed", "0xe8008015", "0xe8008016", "0xe8008018", "0xe8008019", "0xe800801c"),
     "the app may not be validly signed for this device; a simulator or unsigned "
     "build cannot be installed."),
    (("developer mode",), "enable Developer Mode on the iPhone."),
    (("passcode", "device is locked"), "unlock the iPhone."),
    (("not paired", "pairing", "trust"), "trust this Mac on the iPhone."),
)


def describe_install_failure(out, err):
    """Short devicectl failure text, with a next step when the cause is known."""
    detail = "\n".join(part.strip() for part in (err or "", out or "") if part and part.strip())
    lowered = detail.lower()
    for needles, hint in _INSTALL_HINTS:
        if any(needle in lowered for needle in needles):
            return f"install failed: {hint} devicectl said: {detail[:400]}"
    return f"install failed: {detail[:400]}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 900  # a client that stalls mid-request shouldn't hold a thread forever

    def log_message(self, format, *args):  # noqa: A002
        log(f"{self.address_string()} {format % args}")

    def _auth_ok(self):
        if not TOKEN:
            return True
        supplied = self.headers.get("X-Controller-Token") or ""
        return hmac.compare_digest(supplied.encode(), TOKEN.encode())

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status, code, message):
        self._send_json(status, {"error": {"code": code, "message": message}})

    def _send_bytes(self, code, data, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path, ctype):
        """Stream a file, so a long recording isn't held in memory."""
        with open(path, "rb") as f:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(os.fstat(f.fileno()).st_size))
            self.end_headers()
            shutil.copyfileobj(f, self.wfile, 1024 * 1024)

    def _content_length(self, limit, required=False):
        """The request's Content-Length, checked against limit (413).

        Chunked bodies aren't decoded by http.server, so they are refused
        rather than misread.
        """
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise ApiError(411, "length_required",
                           "chunked bodies are not accepted; send Content-Length")
        raw = self.headers.get("Content-Length")
        if raw is None:
            if required:
                self.close_connection = True
                raise ApiError(411, "length_required", "Content-Length is required")
            return 0
        try:
            n = int(raw)
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "invalid_request", "bad Content-Length") from None
        if n < 0:
            self.close_connection = True
            raise ApiError(400, "invalid_request", "bad Content-Length")
        if n > limit:
            self.close_connection = True  # the unread body would poison keep-alive
            raise ApiError(413, "body_too_large", f"body exceeds {limit} bytes")
        return n

    def _read_body(self, limit):
        n = self._content_length(limit)
        data = self.rfile.read(n) if n else b""
        if len(data) != n:
            self.close_connection = True
            raise ApiError(400, "invalid_request", "body shorter than Content-Length")
        return data

    def _receive_upload(self, dest_dir):
        """Stream an upload into a new private file under dest_dir; returns its
        path. Never holds the whole app in memory. The caller deletes it."""
        n = self._content_length(MAX_APP_BYTES, required=True)
        if n == 0:
            raise ApiError(400, "invalid_app", "empty upload")
        fd, path = tempfile.mkstemp(prefix="upload_", suffix=".bin", dir=dest_dir)
        try:
            with os.fdopen(fd, "wb") as f:
                left = n
                while left:
                    chunk = self.rfile.read(min(left, 1024 * 1024))
                    if not chunk:
                        self.close_connection = True
                        raise ApiError(400, "invalid_request", "upload shorter than Content-Length")
                    f.write(chunk)
                    left -= len(chunk)
        except BaseException:
            Path(path).unlink(missing_ok=True)
            raise
        return path

    def _read_json(self):
        raw = self._read_body(MAX_JSON_BYTES)
        try:
            body = json.loads(raw.decode() or "{}")
        except (ValueError, RecursionError):
            raise ApiError(400, "invalid_request", "body is not valid JSON") from None
        if not isinstance(body, dict):
            raise ApiError(400, "invalid_request", "body must be a JSON object")
        return body

    def _dispatch(self, route):
        """Authenticate, run the route, and turn every failure into the same error body."""
        self._response_started = False
        path = self.path.split("?")[0].rstrip("/")
        try:
            if path != "/health" and not self._auth_ok():
                self.close_connection = True
                raise ApiError(401, "unauthorized", "missing or wrong X-Controller-Token")
            if route(path) is False:
                raise ApiError(404, "not_found", f"no route for {self.command} {path}")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True  # client went away
        except ApiError as e:
            self._finish_error(e.status, e.code, str(e))
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            # Device/tool failures: their messages are written for people.
            self._finish_error(502, "device_error", str(e))
        except Exception as e:
            # A bug: the traceback goes to the log only, never to the client.
            log(f"{self.command} {path} crashed: {type(e).__name__}\n{traceback.format_exc()}")
            self._finish_error(502, "device_error", "internal error; see the controller log")

    def _finish_error(self, status, code, message):
        if self._response_started:
            log(f"{self.command} {self.path} failed mid-stream: {message}")
            self.close_connection = True
        else:
            self._send_error_json(status, code, message)

    def do_GET(self):
        self._dispatch(self._route_get)

    def do_POST(self):
        self._dispatch(self._route_post)

    def do_DELETE(self):
        self._dispatch(self._route_delete)

    def _route_get(self, path):
        if path == "/health":
            with _recordings_lock:
                active = sum(1 for r in _recordings.values() if not r["done"])
            return self._send_json(200, {
                "ok": True,
                "service": SERVICE_NAME,
                "api_version": API_VERSION,
                "appium": appium_ready(),
                "adb": os.path.exists(ADB_BIN),
                "recordings": active,
            })
        if path == "/devices":
            return self._send_json(200, device_snapshot())
        if path == "/devices/events":
            return self._stream_device_events()
        m = re.fullmatch(rf"/devices/{DEVICE_ID}/(frame|screen|elements|stream)", path)
        if m:
            dev, what = m.groups()
            android = detect_platform(dev) == "android"
            if what == "frame":
                png = adb_screenshot_png(dev) if android else screenshot_png(dev)
                return self._send_bytes(200, png, "image/png")
            if what == "screen":
                if android:
                    (w, h), scale = adb_screen_size(dev), adb_screen_scale(dev)
                else:
                    (w, h), scale = screen_size(dev), screen_scale(dev)
                return self._send_json(200, {"width": w, "height": h, "scale": scale})
            if what == "elements":
                return self._send_json(200, android_elements(dev) if android
                                       else ios_elements(dev))
            return self._stream_device(dev)
        m = re.fullmatch(r"/recordings/([^/]+)/video", path)
        if m:
            rec = _recordings.get(validate_recording_token(m.group(1)))
            real = safe_path_under(VIDEO_DIR, rec["path"]) if rec else None
            if not rec or not rec["done"] or not real or not os.path.isfile(real):
                raise ApiError(404, "recording_not_found", "video not found")
            return self._send_file(real, "video/mp4")
        return False

    def _route_post(self, path):
        m = re.fullmatch(rf"/devices/{DEVICE_ID}/actions", path)
        if m:
            body = self._read_json()
            action = str(body.pop("action", "")).strip()
            result = do_action(m.group(1), action, body)
            return self._send_json(200, {
                "ok": True,
                "value": result if isinstance(result, (dict, list)) else None})
        m = re.fullmatch(rf"/devices/{DEVICE_ID}/apps", path)
        if m:
            return self._handle_app_install(m.group(1))
        m = re.fullmatch(rf"/devices/{DEVICE_ID}/recordings", path)
        if m:
            body = self._read_json()
            dev = m.group(1)
            if detect_platform(dev) == "android":
                token = android_record_start(
                    dev, optional_int(body, "time_limit", None, 0, 24 * 3600))
            else:
                token = record_start(dev, fps=optional_int(body, "fps", 30, 1, 120),
                                     codec=optional_int(body, "codec", 0, 0, 10))
            with _recordings_lock:
                replaced = list(_recordings.get(token, {}).get("replaced", []))
            return self._send_json(200, {"ok": True, "token": token, "replaced": replaced})
        m = re.fullmatch(r"/recordings/([^/]+)/stop", path)
        if m:
            record_stop(validate_recording_token(m.group(1)))
            return self._send_json(200, {"ok": True})
        return False

    def _route_delete(self, path):
        m = re.fullmatch(rf"/devices/{DEVICE_ID}/apps/([^/]+)", path)
        if not m:
            return False
        dev, bundle_id = m.groups()
        validate_bundle_id(bundle_id)
        if detect_platform(dev) == "android":
            out = adb(dev, "shell", "pm", "uninstall", "--user", "0", bundle_id, timeout=300)
            ok, detail = "Success" in out, out
        else:
            rc, out, err = devicectl("device", "uninstall", "app", "--device", dev, bundle_id, timeout=300)
            ok, detail = rc == 0, (out or err)
        if not ok:
            raise ApiError(502, "uninstall_failed", detail[:300])
        return self._send_json(200, {"ok": True})

    def _start_stream(self, content_type):
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self._response_started = True

    def _stream_device_events(self):
        """Server-sent events: the device list now, then again on every change."""
        self._start_stream("text/event-stream")
        last = None
        idle = 0.0
        while True:
            body = json.dumps(device_snapshot())
            if body != last:
                self.wfile.write(f"event: devices\ndata: {body}\n\n".encode())
                last = body
                idle = 0.0
            elif idle >= DEVICE_EVENTS_KEEPALIVE_SECS:
                self.wfile.write(b": keepalive\n\n")
                idle = 0.0
            self.wfile.flush()
            time.sleep(DEVICE_EVENTS_POLL_SECS)
            idle += DEVICE_EVENTS_POLL_SECS

    def _stream_device(self, dev):
        if detect_platform(dev) != "android":
            raise ApiError(404, "stream_unsupported",
                           f"iOS has no live stream; poll /devices/{dev}/frame instead")
        self._start_stream("multipart/x-mixed-replace; boundary=frame")
        for frame in _streams.frames(dev):
            self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\n"
                             b"Content-Length: %d\r\n\r\n" % len(frame))
            self.wfile.write(frame + b"\r\n")

    def _handle_apk_install(self, upload, work_dir, udid):
        """Install an .apk on an Android device.

        The payload is either a raw .apk or a .zip containing one. A raw .apk is
        itself a zip, told apart by the AndroidManifest.xml at its root.
        """
        try:
            with zipfile.ZipFile(upload) as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" in names:
                    # adb install refuses a file not named *.apk, and the
                    # streamed upload is upload_*.bin: give it a fixed .apk
                    # name inside our private work dir.
                    apk_path = str(Path(work_dir) / "app.apk")
                    shutil.move(str(upload), apk_path)
                else:
                    apks = [i for i in zf.infolist() if i.filename.lower().endswith(".apk")]
                    if not apks:
                        raise ApiError(400, "invalid_app", "no .apk in zip")
                    if apks[0].file_size > MAX_APP_BYTES:
                        raise ApiError(413, "body_too_large",
                                       f"apk in zip exceeds {MAX_APP_BYTES} bytes")
                    # A fixed name inside our private work dir: the member's
                    # own name is never used as a path.
                    apk_path = str(Path(work_dir) / "app.apk")
                    with zf.open(apks[0]) as src, open(apk_path, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
        except zipfile.BadZipFile:
            raise ApiError(400, "invalid_app", "upload is not a valid .apk") from None
        try:
            adb_install_apk(udid, apk_path)
        except RuntimeError as e:
            raise ApiError(502, "install_failed", str(e)) from None
        return {"ok": True, "platform": "android"}

    def _handle_app_install(self, udid):
        """Install an .apk (Android), or an .ipa / .zip holding a .app (iOS,
        with devicectl). Everything uploaded or unpacked lives in one private
        work dir under APP_DIR, removed when the request ends."""
        android = detect_platform(udid) == "android"
        APP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        work_dir = Path(tempfile.mkdtemp(prefix="install_", dir=APP_DIR))
        try:
            upload = self._receive_upload(work_dir)
            if android:
                result = self._handle_apk_install(upload, work_dir, udid)
            else:
                result = self._install_ios(upload, work_dir, udid)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
        return self._send_json(200, result)

    def _install_ios(self, upload, work_dir, udid):
        try:
            extract_app_archive(upload, work_dir / "unpacked")
        except (OSError, RuntimeError, zipfile.BadZipFile) as e:
            raise ApiError(400, "invalid_app", f"bad app archive: {e}") from None
        app_dir = find_app_bundle(work_dir / "unpacked")
        if not app_dir or not safe_path_under(work_dir, app_dir):
            raise ApiError(400, "invalid_app", "no .app bundle in archive")
        rc, out, err = devicectl("device", "install", "app",
                                 "--device", udid, str(app_dir), timeout=600)
        if rc != 0:
            raise ApiError(502, "install_failed", describe_install_failure(out, err))
        return {"ok": True, "platform": "ios"}


def clean_app_dir(app_dir=None):
    """Remove uploads left by a previous run (e.g. killed mid-install).
    Called at startup, before any request can be using APP_DIR."""
    app_dir = Path(app_dir or APP_DIR)
    if not app_dir.is_dir():
        return []
    removed = []
    for child in app_dir.iterdir():
        if not child.name.startswith(("install_", "upload_")):
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)
        removed.append(child.name)
    return removed


class ControllerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        # IPv6 binds (`::1`, `::`) need an AF_INET6 socket.
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)


def stop_appium():
    """Stop the Appium this process started; an external one is left alone."""
    global _appium_proc
    proc, _appium_proc = _appium_proc, None
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main():
    for problem in (check_bind_token(BIND, TOKEN), check_appium_url(APPIUM_URL)):
        if problem:
            print(f"device_controller: {problem}", file=sys.stderr, flush=True)
            sys.exit(2)
    removed = clean_app_dir()
    if removed:
        log(f"removed {len(removed)} leftover upload(s) from {APP_DIR}")
    log(f"device controller starting on {BIND}:{PORT} "
        f"(appium={APPIUM_URL}, adb={ADB_BIN}, "
        f"adb_present={os.path.exists(ADB_BIN)}, "
        f"java_home={JAVA_HOME or 'not set'}, token={'set' if TOKEN else 'off'})")
    threading.Thread(target=adb_keepalive, daemon=True,
                     name="adb-keepalive").start()
    server = ControllerServer((BIND, PORT), Handler)

    def shutdown(_signum, _frame):
        # serve_forever must be stopped from another thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        stop_appium()


if __name__ == "__main__":
    main()
