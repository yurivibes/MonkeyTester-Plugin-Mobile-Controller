import io
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import android_stream
import device_controller as controller

FAKE_ADB = str(ROOT / "tests" / "fake_adb.py")
SERIAL = "10.0.0.9:5555"


class ArchiveTests(unittest.TestCase):
    def test_finds_top_level_bundle_in_ipa_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested = Path(tmp) / "Payload" / "My.app" / "Watch" / "W.app"
            nested.mkdir(parents=True)
            self.assertEqual(controller.find_app_bundle(tmp).name, "My.app")

    def test_no_bundle_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Payload").mkdir()
            self.assertIsNone(controller.find_app_bundle(tmp))

    def test_failure_text_explains_known_causes_and_keeps_detail(self):
        message = controller.describe_install_failure("", "Failed to verify code signature (0xe8008015)")
        self.assertIn("signed", message)
        self.assertIn("0xe8008015", message)
        self.assertEqual(controller.describe_install_failure("boom", ""), "install failed: boom")


class LaunchComponentTests(unittest.TestCase):
    def test_uses_activity_reported_by_device(self):
        output = "priority=0 preferredOrder=0\ncom.blackbox.tempsensor/com.application.tempsensor.MainActivity\n"
        self.assertEqual(
            controller.parse_launch_component(output, "com.blackbox.tempsensor"),
            "com.blackbox.tempsensor/com.application.tempsensor.MainActivity")

    def test_falls_back_when_not_resolved(self):
        self.assertEqual(controller.parse_launch_component("No activity found", "a.b"), "a.b/.MainActivity")


class AdbMdnsDiscoveryTests(unittest.TestCase):
    def test_extracts_connect_services_only(self):
        output = """
List of discovered mdns services
adb-ABC123 _adb-tls-connect._tcp. 192.168.1.100:37123
adb-ABC123 _adb-tls-pairing._tcp. 192.168.1.100:42017
adb-DEF456 _adb-tls-connect._tcp. 192.168.1.101:38123
"""
        self.assertEqual(controller.parse_adb_mdns_connect_targets(output),
                         ["192.168.1.100:37123", "192.168.1.101:38123"])

    def test_deduplicates_connect_targets(self):
        output = "adb-A _adb-tls-connect._tcp. 1.1.1.1:37\nadb-A _adb-tls-connect._tcp. 1.1.1.1:37\n"
        self.assertEqual(controller.parse_adb_mdns_connect_targets(output), ["1.1.1.1:37"])

    def test_maps_mdns_serial_to_endpoint(self):
        self.assertEqual(
            controller.parse_adb_mdns_connect_services("adb-ABC123 _adb-tls-connect._tcp. 192.168.1.100:37123"),
            [{"serial": "adb-ABC123._adb-tls-connect._tcp", "target": "192.168.1.100:37123"}])

    def test_phone_registered_twice_is_one_device(self):
        alias = "adb-X._adb-tls-connect._tcp"
        with patch.object(controller, "adb_global",
                          return_value=f"List\n{alias}\tdevice\n{SERIAL}\tdevice"), \
                patch.dict(controller._mdns_aliases, {alias: SERIAL}):
            self.assertEqual(controller.adb_connected(), [SERIAL])


class FrameParsingTests(unittest.TestCase):
    def test_keeps_partial_frame_for_next_read(self):
        frames, rest = android_stream.extract_frames(b"x\xff\xd8a\xff\xd9\xff\xd8b")
        self.assertEqual(frames, [b"\xff\xd8a\xff\xd9"])
        self.assertEqual(rest, b"\xff\xd8b")

    def test_stuffed_bytes_do_not_end_a_frame(self):
        frames, rest = android_stream.extract_frames(b"\xff\xd8\xff\x00\xff\xd9")
        self.assertEqual(frames, [b"\xff\xd8\xff\x00\xff\xd9"])
        self.assertEqual(rest, b"")


class CaptureLatencyTests(unittest.TestCase):
    """screenrecord sends frames only while the screen changes. A short burst
    (a tap that switches screens) must reach viewers and recordings while the
    stream is still open, not when the next change comes along."""

    def test_short_burst_is_published_without_waiting_for_more_input(self):
        os.chmod(FAKE_ADB, os.stat(FAKE_ADB).st_mode | stat.S_IEXEC)
        manager = android_stream.StreamManager(FAKE_ADB, log=lambda *_: None)
        env = patch.dict(os.environ, {"FAKE_ADB_SCREENRECORD": "burst"})
        env.start()  # until the end: the capture thread starts adb when it gets to it
        self.addCleanup(env.stop)
        capture = manager.acquire(SERIAL)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and capture.seq < 30:
                time.sleep(0.05)
            # 29 pictures come out of ffmpeg; the parser holds the 30th until
            # the next one starts, so a screenshot stands in for it.
            self.assertEqual(capture.seq, 30)
            self.assertEqual(capture._pictures_in, 30)
            self.assertEqual(capture._pictures_out, 29)
            self.assertEqual(capture._skip_through, 30)
        finally:
            manager.release(SERIAL)

    def test_held_picture_is_dropped_after_the_screenshot(self):
        capture = android_stream._Capture(FAKE_ADB, SERIAL, log=lambda *_: None)
        capture._pictures_in = 3
        for name in (b"1", b"2"):
            capture._on_decoded(name)
        with patch.object(capture, "_screenshot_jpeg", return_value=b"shot"):
            capture._fill_idle()
        capture._on_decoded(b"3")  # the held picture, older than the shot
        self.assertEqual((capture.frame, capture.seq), (b"shot", 3))
        capture._pictures_in = 4
        capture._on_decoded(b"4")
        self.assertEqual((capture.frame, capture.seq), (b"4", 4))

    def test_no_screenshot_when_nothing_is_held(self):
        capture = android_stream._Capture(FAKE_ADB, SERIAL, log=lambda *_: None)
        capture._pictures_in = 1
        capture._on_decoded(b"1")
        with patch.object(capture, "_screenshot_jpeg", return_value=b"shot"):
            capture._fill_idle()
        self.assertEqual((capture.frame, capture.seq), (b"1", 1))

    def test_pictures_are_counted_across_reads(self):
        idr = b"\x00\x00\x00\x01\x67\x42" + b"\x00\x00\x00\x01\x68\xce" + b"\x00\x00\x01\x65\x88\x84"
        second_slice = b"\x00\x00\x01\x41\x20\x11"   # first_mb_in_slice != 0
        p = b"\x00\x00\x01\x41\x9a\x02"
        stream = idr + second_slice + p + p
        for cut in range(1, len(stream)):
            total, carry = android_stream.count_pictures(stream[:cut])
            more, carry = android_stream.count_pictures(carry + stream[cut:] + b"\x00\x00\x00\x00")
            self.assertEqual(total + more, 3, cut)


class AndroidRecordingTests(unittest.TestCase):
    """Recordings are made by screenrecord on the (fake) phone."""

    def setUp(self):
        os.chmod(FAKE_ADB, os.stat(FAKE_ADB).st_mode | stat.S_IEXEC)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {"FAKE_ADB_SDCARD": self.tmp.name + "/sdcard"})
        env.start()
        self.addCleanup(env.stop)

    def record(self, secs):
        path = os.path.join(self.tmp.name, "abc123.mp4")
        rec = android_stream.AndroidRecording(FAKE_ADB, SERIAL, path, log=lambda *_: None)
        time.sleep(secs)
        return rec.stop()

    def duration(self, path):
        return float(subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
            capture_output=True, text=True).stdout)

    def test_video_lasts_as_long_as_the_recording(self):
        path = self.record(3)
        self.assertAlmostEqual(self.duration(path), 4, delta=1.2)  # +1 s start check
        self.assertEqual(os.listdir(self.tmp.name + "/sdcard"), [], "file left on the phone")

    def test_falls_back_to_180_s_where_0_is_refused(self):
        with patch.dict(os.environ, {"FAKE_ADB_NO_UNLIMITED": "1"}):
            path = self.record(2)
        self.assertGreater(self.duration(path), 1)


class ServiceTests(unittest.TestCase):
    """The real HTTP service, with only the adb binary faked."""

    @classmethod
    def setUpClass(cls):
        os.chmod(FAKE_ADB, os.stat(FAKE_ADB).st_mode | stat.S_IEXEC)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.adb_log = Path(cls.tmp.name) / "adb.log"
        os.environ["FAKE_ADB_LOG"] = str(cls.adb_log)
        cls.patches = [
            patch.object(controller, "ADB_BIN", FAKE_ADB),
            patch.object(controller, "_streams", android_stream.StreamManager(FAKE_ADB)),
            patch.object(controller, "list_devices", return_value=(["00008030-ABCDEF"], None)),
            patch.object(controller, "appium_ready", return_value=False),
            patch.object(controller, "TOKEN", ""),
        ]
        for p in cls.patches:
            p.start()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), controller.Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        for p in cls.patches:
            p.stop()
        cls.tmp.cleanup()

    def setUp(self):
        self.adb_log.write_text("")
        controller._snapshot_cache.update(at=0.0, body=None)
        controller._android_serials.update(at=0.0, serials=frozenset())

    def get(self, path):
        with urllib.request.urlopen(self.url + path, timeout=20) as r:
            return r.read()

    def post(self, path, payload):
        req = urllib.request.Request(self.url + path, json.dumps(payload).encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def action(self, name, **params):
        return self.post(f"/devices/{SERIAL}/actions", {"action": name, **params})

    def error_of(self, method, path, payload=None, headers=None):
        """Status and error body of a request that should fail."""
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data, headers or {}, method=method)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=20)
        return caught.exception.code, json.loads(caught.exception.read())["error"]

    def test_health_reports_api_version(self):
        body = json.loads(self.get("/health"))
        self.assertEqual(body["api_version"], controller.API_VERSION)
        self.assertEqual(body["service"], "monkeytester-mobile-controller")

    def test_devices_lists_both_platforms(self):
        body = json.loads(self.get("/devices"))
        self.assertEqual(body["devices"], [
            {"id": "00008030-ABCDEF", "platform": "ios", "model": None},
            {"id": SERIAL, "platform": "android", "model": "Fake-Model"},
        ])

    def test_device_events_send_the_list_then_each_change(self):
        with patch.object(controller, "DEVICE_EVENTS_POLL_SECS", 0.01), \
                patch.object(controller, "DEVICE_SNAPSHOT_TTL_SECS", 0):
            with urllib.request.urlopen(f"{self.url}/devices/events", timeout=20) as r:
                self.assertEqual(r.headers["Content-Type"], "text/event-stream")
                self.assertEqual(self.next_device_event(r)["devices"][0]["id"], "00008030-ABCDEF")
                with patch.object(controller, "list_devices", return_value=([], "devicectl down")):
                    changed = self.next_device_event(r)
        self.assertEqual(changed["errors"], {"ios": "devicectl down"})
        self.assertEqual(changed["devices"], [
            {"id": SERIAL, "platform": "android", "model": "Fake-Model"},
        ])

    def test_device_events_require_the_token(self):
        with patch.object(controller, "TOKEN", "secret"):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.get("/devices/events")
        self.assertEqual(caught.exception.code, 401)

    @staticmethod
    def next_device_event(response):
        for line in response:
            if line.startswith(b"data: "):
                return json.loads(line[len(b"data: "):])
        raise AssertionError("stream ended without an event")

    def test_frame_is_png(self):
        self.assertEqual(self.get(f"/devices/{SERIAL}/frame")[:4], b"\x89PNG")

    def test_screen_size(self):
        self.assertEqual(json.loads(self.get(f"/devices/{SERIAL}/screen")),
                         {"width": 1080, "height": 2400, "scale": 3.0})

    def test_ios_screen_has_scale(self):
        with patch.object(controller, "screen_size", return_value=(750, 1334)), \
                patch.object(controller, "screen_scale", return_value=2.0):
            self.assertEqual(json.loads(self.get("/devices/00008030-ABCDEF/screen")),
                             {"width": 750, "height": 1334, "scale": 2.0})

    def test_android_elements_come_from_uiautomator(self):
        body = json.loads(self.get(f"/devices/{SERIAL}/elements"))
        self.assertEqual(body, {"width": 1080, "height": 2400, "scale": 3.0, "elements": [
            {"id": "content", "x": 0, "y": 0, "w": 1080, "h": 2400},
            {"id": "title", "x": 100, "y": 200, "w": 880, "h": 100, "label": "Welcome"},
            {"id": "accept_button", "x": 340, "y": 2000, "w": 400, "h": 140, "label": "Accept"},
        ]})
        log = self.adb_log.read_text()
        self.assertIn("shell uiautomator dump /sdcard/vt_window_", log)
        self.assertIn("shell rm -f /sdcard/vt_window_", log, "dump left on the phone")

    def test_ios_elements_are_in_pixels(self):
        with patch.object(controller, "screen_size", return_value=(750, 1334)), \
                patch.object(controller, "screen_scale", return_value=2.0), \
                patch.object(controller, "page_source", return_value=XCUITEST_SOURCE):
            body = json.loads(self.get("/devices/00008030-ABCDEF/elements"))
        self.assertEqual((body["width"], body["height"], body["scale"]), (750, 1334, 2.0))
        self.assertEqual([e["id"] for e in body["elements"]],
                         ["TempSensor", "eula_title", "accept_button"])

    def test_stream_sends_jpeg_frames(self):
        with urllib.request.urlopen(f"{self.url}/devices/{SERIAL}/stream", timeout=20) as r:
            self.assertIn("multipart/x-mixed-replace", r.headers["Content-Type"])
            data = b""
            while data.count(b"\xff\xd9") < 2:
                data += r.read1(65536)
        self.assertIn(b"--frame", data)
        self.assertIn(b"\xff\xd8", data)

    def test_ios_stream_points_to_frame(self):
        status, error = self.error_of("GET", "/devices/00008030-ABCDEF/stream")
        self.assertEqual((status, error["code"]), (404, "stream_unsupported"))
        self.assertIn("/devices/00008030-ABCDEF/frame", error["message"])

    def test_recording_downloads_an_mp4(self):
        started = self.post(f"/devices/{SERIAL}/recordings", {})
        self.assertEqual(started["replaced"], [])
        time.sleep(2)
        token = started["token"]
        self.assertTrue(self.post(f"/recordings/{token}/stop", {})["ok"])
        self.assertTrue(self.post(f"/recordings/{token}/stop", {})["ok"], "stop is idempotent")
        self.assertIn(b"ftyp", self.get(f"/recordings/{token}/video")[:32])

    def test_new_recording_takes_over_one_that_was_never_stopped(self):
        """A run that died mid-recording must not block the device: the next
        start stops the orphan, and the orphan's video is still served."""
        orphan = self.post(f"/devices/{SERIAL}/recordings", {})["token"]
        time.sleep(2)
        started = self.post(f"/devices/{SERIAL}/recordings", {})
        self.assertEqual(started["replaced"], [orphan])
        self.assertNotEqual(started["token"], orphan)
        self.assertIn(b"ftyp", self.get(f"/recordings/{orphan}/video")[:32])
        self.assertTrue(self.post(f"/recordings/{orphan}/stop", {})["ok"],
                        "stopping the replaced recording again is a no-op")
        time.sleep(2)
        token = started["token"]
        self.assertTrue(self.post(f"/recordings/{token}/stop", {})["ok"])
        self.assertIn(b"ftyp", self.get(f"/recordings/{token}/video")[:32])

    def test_video_is_not_served_until_the_recording_stops(self):
        started = self.post(f"/devices/{SERIAL}/recordings", {})
        try:
            status, error = self.error_of("GET", f"/recordings/{started['token']}/video")
            self.assertEqual((status, error["code"]), (404, "recording_not_found"))
        finally:
            self.post(f"/recordings/{started['token']}/stop", {})

    def test_unknown_recording_is_404(self):
        status, error = self.error_of("POST", "/recordings/0123456789ab/stop", {})
        self.assertEqual((status, error["code"]), (404, "recording_not_found"))

    def test_restart_actions_use_the_devices_activity(self):
        self.action("terminate", bundle_id="com.example.app")
        self.action("clear-data", bundle_id="com.example.app")
        result = self.action("launch", bundle_id="com.example.app")
        self.assertEqual(result["value"]["component"], "com.example.app/com.other.MainActivity")
        log = self.adb_log.read_text()
        self.assertIn("am force-stop com.example.app", log)
        self.assertIn("pm clear com.example.app", log)
        self.assertIn("am start -n com.example.app/com.other.MainActivity", log)

    def install(self, payload):
        req = urllib.request.Request(self.url + f"/devices/{SERIAL}/apps", payload, {
            "Content-Type": "application/zip"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    @staticmethod
    def zip_of(entries):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        return buf.getvalue()

    def test_raw_apk_installs(self):
        self.assertTrue(self.install(self.zip_of({"AndroidManifest.xml": b"x"}))["ok"])
        self.assertIn("install -r -t", self.adb_log.read_text())

    def test_raw_apk_is_handed_to_adb_with_an_apk_name(self):
        # Real adb refuses "filename doesn't end .apk"; the streamed upload is
        # upload_*.bin, so the controller must rename it before installing.
        self.install(self.zip_of({"AndroidManifest.xml": b"x"}))
        line = [l for l in self.adb_log.read_text().splitlines() if "install -r -t" in l][-1]
        self.assertTrue(line.rstrip().endswith(".apk"), line)

    def test_zip_holding_an_apk_installs(self):
        apk = self.zip_of({"AndroidManifest.xml": b"x"})
        self.assertTrue(self.install(self.zip_of({"build/app.apk": apk}))["ok"])
        line = [l for l in self.adb_log.read_text().splitlines() if "install -r -t" in l][-1]
        self.assertTrue(line.rstrip().endswith(".apk"), line)

    def test_zip_without_an_apk_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.install(self.zip_of({"readme.txt": b"x"}))
        self.assertEqual(caught.exception.code, 400)

    def test_text_is_quoted_for_the_device_shell(self):
        self.action("text", text="a b;$(x)")
        self.assertIn("input text 'a%sb;$(x)'", self.adb_log.read_text())

    def test_delete_sends_one_backspace_per_count(self):
        self.action("delete", count=3)
        self.assertEqual(self.adb_log.read_text().count("input keyevent 67"), 3)

    def test_keyevent_rejects_non_numeric_codes(self):
        status, error = self.error_of("POST", f"/devices/{SERIAL}/actions",
                                      {"action": "keyevent", "code": "3; reboot"})
        self.assertEqual((status, error["code"]), (400, "invalid_request"))
        self.assertNotIn("reboot", self.adb_log.read_text())

    def test_uninstall_uses_delete(self):
        req = urllib.request.Request(f"{self.url}/devices/{SERIAL}/apps/com.example.app", method="DELETE")
        with urllib.request.urlopen(req, timeout=20) as r:
            self.assertTrue(json.loads(r.read())["ok"])
        self.assertIn("pm uninstall --user 0 com.example.app", self.adb_log.read_text())

    def test_ios_uninstall_uses_the_app_subcommand(self):
        # devicectl's syntax is `device uninstall app --device <udid> <bundle>`;
        # without `app` it fails with "Unknown option '--device'".
        calls = []

        def fake_devicectl(*args, **kwargs):
            calls.append(args)
            return 0, "App uninstalled.", ""

        udid = "00008030-000C50D42EE3802E"
        with patch.object(controller, "devicectl", side_effect=fake_devicectl):
            req = urllib.request.Request(f"{self.url}/devices/{udid}/apps/com.example.app", method="DELETE")
            with urllib.request.urlopen(req, timeout=20) as r:
                self.assertTrue(json.loads(r.read())["ok"])
        self.assertEqual(calls, [("device", "uninstall", "app", "--device", udid, "com.example.app")])

    def test_bundle_ids_cannot_reach_the_device_shell(self):
        for action in ("launch", "terminate", "clear-data"):
            status, error = self.error_of("POST", f"/devices/{SERIAL}/actions",
                                          {"action": action, "bundle_id": "x;reboot"})
            self.assertEqual((status, error["code"]), (400, "invalid_request"))
        status, _ = self.error_of("DELETE", f"/devices/{SERIAL}/apps/x;reboot")
        self.assertEqual(status, 400)
        self.assertNotIn("reboot", self.adb_log.read_text())

    def test_missing_parameter_is_a_client_error_not_a_device_error(self):
        status, error = self.error_of("POST", f"/devices/{SERIAL}/actions", {"action": "tap", "x": 1})
        self.assertEqual((status, error["code"]), (400, "invalid_request"))
        self.assertIn("y", error["message"])

    def test_unknown_action_and_bad_json_are_client_errors(self):
        status, error = self.error_of("POST", f"/devices/{SERIAL}/actions", {"action": "explode"})
        self.assertEqual((status, error["code"]), (400, "unknown_action"))
        req = urllib.request.Request(f"{self.url}/devices/{SERIAL}/actions", b"{not json")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(req, timeout=20)
        self.assertEqual(caught.exception.code, 400)

    def test_device_failures_are_structured_502s(self):
        with patch.object(controller, "adb", side_effect=RuntimeError("no such device")):
            status, error = self.error_of("POST", f"/devices/{SERIAL}/actions", {"action": "tap", "x": 1, "y": 2})
        self.assertEqual((status, error), (502, {"code": "device_error", "message": "no such device"}))

    def test_oversized_json_is_refused_unread(self):
        with patch.object(controller, "MAX_JSON_BYTES", 8):
            status, error = self.error_of("POST", f"/devices/{SERIAL}/actions", {"action": "unlock"})
        self.assertEqual((status, error["code"]), (413, "body_too_large"))

    def test_unknown_route_is_404(self):
        status, error = self.error_of("GET", "/nope")
        self.assertEqual((status, error["code"]), (404, "not_found"))

    def test_health_is_open_but_everything_else_needs_the_token(self):
        with patch.object(controller, "TOKEN", "secret"):
            self.assertTrue(json.loads(self.get("/health"))["ok"])
            status, error = self.error_of("GET", "/devices")
            self.assertEqual((status, error["code"]), (401, "unauthorized"))
            req = urllib.request.Request(self.url + "/devices", headers={"X-Controller-Token": "secret"})
            with urllib.request.urlopen(req, timeout=20) as r:
                self.assertEqual(r.status, 200)

    def test_health_does_not_expose_devices(self):
        body = json.loads(self.get("/health"))
        self.assertNotIn("devices", body)
        self.assertNotIn("android", body)

    def test_one_platform_failing_does_not_hide_the_other(self):
        with patch.object(controller, "list_devices", return_value=([], "no Xcode")):
            controller._snapshot_cache.update(at=0.0, body=None)
            with urllib.request.urlopen(self.url + "/devices", timeout=20) as r:
                self.assertEqual(r.status, 200)
                body = json.loads(r.read())
        self.assertEqual([d["id"] for d in body["devices"]], [SERIAL])
        self.assertEqual(body["errors"], {"ios": "no Xcode"})


DEVICECTL_OUTPUT = """\
Name              Hostname   Identifier                         State                Model                    Reality
---------------   --------   --------------------------------   ------------------   ----------------------   --------
Server\u2019s iPhone              00008030-000C50D42EE3802E (UDID)   available (paired)   iPhone SE (iPhone12,8)   physical
Plugged iPhone               00008030-AAAAAAAAAAAAAAAA (UDID)   connected            iPhone 15                physical
Gone iPhone                  00008030-BBBBBBBBBBBBBBBB (UDID)   unavailable          iPhone 12                physical
"""


class DeviceListingTests(unittest.TestCase):
    def test_paired_and_connected_phones_are_usable_and_unavailable_is_not(self):
        # The first row is verbatim output from a real iPhone on macOS 27.
        self.assertEqual(controller.parse_devicectl_devices(DEVICECTL_OUTPUT),
                         ["00008030-000C50D42EE3802E", "00008030-AAAAAAAAAAAAAAAA"])

    def test_hex_usb_android_serial_is_not_mistaken_for_a_udid(self):
        controller._android_serials.update(at=0.0, serials=frozenset())
        with patch.object(controller, "adb_connected", return_value=["ce0417c1d3a5"]):
            self.assertEqual(controller.detect_platform("ce0417c1d3a5"), "android")
            self.assertEqual(controller.detect_platform("00008030-ABCDEF"), "ios")
        controller._android_serials.update(at=0.0, serials=frozenset())

    def test_explicit_platform_wins(self):
        self.assertEqual(controller.detect_platform("1.2.3.4:5", "ios"), "ios")


class IosGeometryTests(unittest.TestCase):
    def setUp(self):
        controller._screen_scales.clear()

    def test_scale_is_asked_once_per_device(self):
        with patch.object(controller, "mobile", return_value={"scale": 3}) as mobile:
            self.assertEqual(controller.px_to_pt("U", 300, 600), (100, 200))
            self.assertEqual(controller.px_to_pt("U", 30, 60), (10, 20))
        self.assertEqual(mobile.call_count, 1)

    def test_unknown_scale_fails_rather_than_tapping_the_wrong_place(self):
        with patch.object(controller, "mobile", return_value={}):
            with self.assertRaises(RuntimeError):
                controller.px_to_pt("U", 300, 600)
        self.assertNotIn("U", controller._screen_scales)

    def test_screen_size_comes_from_a_real_screenshot(self):
        sys.path.insert(0, str(ROOT / "tests"))
        import fake_adb
        with patch.object(controller, "screenshot_png", return_value=fake_adb.png(750, 1334)):
            self.assertEqual(controller.screen_size("U"), (750, 1334))

    def test_non_png_is_an_error(self):
        with self.assertRaises(RuntimeError):
            controller.png_size(b"not a png")


# Shaped like XCUITest's page source (attributes trimmed): coordinates in points.
XCUITEST_SOURCE = """<?xml version="1.0" encoding="UTF-8"?>
<XCUIElementTypeApplication type="XCUIElementTypeApplication" name="TempSensor" label="TempSensor"
    enabled="true" visible="true" accessible="false" x="0" y="0" width="375" height="667" index="0">
  <XCUIElementTypeWindow type="XCUIElementTypeWindow" enabled="true" visible="true"
      accessible="false" x="0" y="0" width="375" height="667" index="0">
    <XCUIElementTypeStaticText type="XCUIElementTypeStaticText" value="End User License Agreement"
        name="eula_title" label="End User License Agreement" enabled="true" visible="true"
        accessible="true" x="16" y="40.5" width="343" height="24.25" index="0"/>
    <XCUIElementTypeButton type="XCUIElementTypeButton" name="accept_button" enabled="true"
        visible="true" accessible="true" x="87.5" y="600" width="200" height="44" index="1"/>
    <XCUIElementTypeButton type="XCUIElementTypeButton" name="offscreen_button" label="Later"
        enabled="true" visible="false" accessible="true" x="87.5" y="900" width="200" height="44"/>
    <XCUIElementTypeOther type="XCUIElementTypeOther" enabled="true" visible="true"
        accessible="false" x="0" y="0" width="375" height="20"/>
  </XCUIElementTypeWindow>
</XCUIElementTypeApplication>"""


class ElementParsingTests(unittest.TestCase):
    def test_xcuitest_points_become_pixels(self):
        self.assertEqual(controller.parse_xcuitest_elements(XCUITEST_SOURCE, 2.0), [
            {"id": "TempSensor", "x": 0, "y": 0, "w": 750, "h": 1334, "label": "TempSensor"},
            {"id": "eula_title", "x": 32, "y": 81, "w": 686, "h": 48,
             "label": "End User License Agreement"},
            {"id": "accept_button", "x": 175, "y": 1200, "w": 400, "h": 88},
        ])

    def test_xcuitest_fractional_scale_rounds(self):
        el = controller.parse_xcuitest_elements(XCUITEST_SOURCE, 3.0)[1]
        self.assertEqual((el["x"], el["y"], el["w"], el["h"]), (48, 122, 1029, 73))

    def test_uiautomator_prefix_is_removed_and_unnamed_nodes_dropped(self):
        sys.path.insert(0, str(ROOT / "tests"))
        import fake_adb
        ids = [e["id"] for e in controller.parse_uiautomator_elements(fake_adb.WINDOW_XML)]
        self.assertEqual(ids, ["content", "title", "accept_button"])

    def test_density_override_wins(self):
        self.assertEqual(controller.parse_wm_density("Physical density: 390"), 390)
        self.assertEqual(controller.parse_wm_density(
            "Physical density: 420\nOverride density: 480"), 480)
        with self.assertRaises(RuntimeError):
            controller.parse_wm_density("error: no display")


class RecordingStateTests(unittest.TestCase):
    def tearDown(self):
        controller._recordings.clear()

    def test_failed_start_releases_the_device(self):
        with patch.object(controller, "mobile", side_effect=RuntimeError("no appium")):
            with self.assertRaises(RuntimeError):
                controller.record_start("U")
        self.assertEqual(controller._recordings, {})

    def test_failed_stop_releases_the_device(self):
        with patch.object(controller, "mobile", return_value={"uuid": "x"}):
            token = controller.record_start("U")
        with patch.object(controller, "mobile", side_effect=RuntimeError("appium died")):
            with self.assertRaises(RuntimeError):
                controller.record_stop(token)
        with patch.object(controller, "mobile", return_value={"uuid": "y"}):
            controller.record_start("U")  # would raise 409 if still marked active

    def test_only_old_finished_recordings_are_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, recent = Path(tmp) / "old.mp4", Path(tmp) / "new.mp4"
            old.write_bytes(b"x")
            recent.write_bytes(b"x")
            controller._recordings.update({
                "old": {"path": str(old), "udid": "U", "done": True, "finished": 100.0},
                "new": {"path": str(recent), "udid": "U", "done": True, "finished": 990.0},
                "active": {"path": "unused", "udid": "V", "done": False, "finished": None},
            })
            self.assertEqual(controller.prune_recordings(max_age=100, now=1000.0), ["old"])
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertEqual(sorted(controller._recordings), ["active", "new"])


class ShutdownTests(unittest.TestCase):
    def test_sigterm_stops_the_service_cleanly(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = dict(os.environ, CONTROLLER_PORT=str(port), CONTROLLER_BIND="127.0.0.1", ADB_BIN=FAKE_ADB)
        proc = subprocess.Popen([sys.executable, str(ROOT / "device_controller.py")], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2):
                        break
                except OSError:
                    time.sleep(0.1)
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(proc.wait(timeout=15), 0)
        finally:
            proc.kill()
            proc.wait()

    def test_appium_listens_only_where_appium_url_points(self):
        started = []

        class Proc:
            def poll(self):
                return None
        with patch.object(controller, "appium_ready", side_effect=[False, True]), \
                patch.object(controller.shutil, "which", return_value="/bin/appium"), \
                patch.object(controller.subprocess, "Popen",
                             side_effect=lambda cmd, **kw: started.append(cmd) or Proc()), \
                patch.object(controller, "_appium_proc", None), \
                patch.object(controller, "APPIUM_URL", "http://127.0.0.1:4799"):
            self.assertTrue(controller._ensure_appium_locked())
        cmd = started[0]
        self.assertEqual(cmd[cmd.index("--address") + 1], "127.0.0.1")
        self.assertEqual(cmd[cmd.index("--port") + 1], "4799")

    def test_stop_appium_terminates_our_child_only(self):
        child = subprocess.Popen(["sleep", "60"])
        with patch.object(controller, "_appium_proc", child):
            controller.stop_appium()
        self.assertIsNotNone(child.poll())
        controller.stop_appium()  # nothing started: a no-op


if __name__ == "__main__":
    unittest.main()
