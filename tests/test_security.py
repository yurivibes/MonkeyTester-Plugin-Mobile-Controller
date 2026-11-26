"""Security behaviour: the bind/token rule, auth, validators, path traversal,
size caps and upload cleanup. Nothing here needs Appium or a real phone."""
import http.client
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
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import android_stream
import device_controller as controller

FAKE_ADB = str(ROOT / "tests" / "fake_adb.py")
SERIAL = "10.0.0.9:5555"
UDID = "00008030-ABCDEF"
TOKEN = "s3cret-token-for-tests"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def controller_env(**overrides):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CONTROLLER_")}
    env.update(ADB_BIN=FAKE_ADB, DEVICECTL="false")
    env.update(overrides)
    return env


def zip_of(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buf.getvalue()


class StartupRuleTests(unittest.TestCase):
    """The real script, started as the launchd agent would start it."""

    def run_refused(self, **env):
        proc = subprocess.run([sys.executable, str(ROOT / "device_controller.py")],
                              env=controller_env(**env), capture_output=True, text=True,
                              timeout=30)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stderr

    def test_lan_bind_without_token_exits_non_zero(self):
        for bind in ("0.0.0.0", "192.168.125.71", "::"):
            with self.subTest(bind=bind):
                err = self.run_refused(CONTROLLER_BIND=bind, CONTROLLER_PORT=str(free_port()))
                self.assertIn("CONTROLLER_TOKEN", err)
                self.assertIn("refusing to start", err)

    def test_default_bind_without_token_exits_non_zero(self):
        err = self.run_refused(CONTROLLER_PORT=str(free_port()))
        self.assertIn("CONTROLLER_BIND=0.0.0.0", err)

    def test_blank_token_counts_as_missing(self):
        self.run_refused(CONTROLLER_BIND="0.0.0.0", CONTROLLER_TOKEN="   ",
                         CONTROLLER_PORT=str(free_port()))

    def test_non_http_appium_url_exits_non_zero(self):
        err = self.run_refused(CONTROLLER_BIND="127.0.0.1", APPIUM_URL="file:///etc/passwd",
                               CONTROLLER_PORT=str(free_port()))
        self.assertIn("APPIUM_URL", err)

    def start(self, **env):
        port = free_port()
        proc = subprocess.Popen([sys.executable, str(ROOT / "device_controller.py")],
                                env=controller_env(CONTROLLER_PORT=str(port), **env),
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (proc.kill(), proc.wait(), proc.stderr.close()))
        for _ in range(100):
            if proc.poll() is not None:
                self.fail(f"exited {proc.returncode}: {proc.stderr.read().decode()}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
                    return proc, port, json.loads(r.read())
            except OSError:
                time.sleep(0.1)
        self.fail("controller never answered /health")

    def test_loopback_without_token_starts(self):
        proc, port, health = self.start(CONTROLLER_BIND="127.0.0.1")
        self.assertTrue(health["ok"])
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/devices", timeout=20) as r:
            self.assertEqual(r.status, 200, "no token needed on loopback")
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=15), 0)

    def test_localhost_without_token_starts(self):
        proc, _, health = self.start(CONTROLLER_BIND="localhost")
        self.assertTrue(health["ok"])

    def test_lan_bind_with_token_starts_and_enforces_it(self):
        proc, port, health = self.start(CONTROLLER_BIND="0.0.0.0", CONTROLLER_TOKEN=TOKEN)
        self.assertNotIn(TOKEN, json.dumps(health))
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/devices", timeout=20)
        self.assertEqual(caught.exception.code, 401)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/devices",
                                     headers={"X-Controller-Token": TOKEN})
        with urllib.request.urlopen(req, timeout=20) as r:
            self.assertEqual(r.status, 200)


class ValidatorTests(unittest.TestCase):
    def test_loopback_detection(self):
        for host in ("127.0.0.1", "127.1.2.3", "::1", "[::1]", "localhost", "LOCALHOST"):
            self.assertTrue(controller.is_loopback(host), host)
        for host in ("0.0.0.0", "::", "", "192.168.125.71", "localhost.evil", "10.0.0.1"):
            self.assertFalse(controller.is_loopback(host), host)

    def test_bind_token_rule(self):
        self.assertIsNone(controller.check_bind_token("127.0.0.1", ""))
        self.assertIsNone(controller.check_bind_token("::1", ""))
        self.assertIsNone(controller.check_bind_token("0.0.0.0", "t"))
        message = controller.check_bind_token("0.0.0.0", "")
        self.assertIn("CONTROLLER_TOKEN", message)
        self.assertIn("EnvironmentVariables", message)
        self.assertIn("Settings", message)
        self.assertIn("placeholder", controller.check_bind_token("0.0.0.0", "REPLACE_WITH_TOKEN"))

    def test_appium_url_must_be_http(self):
        self.assertIsNone(controller.check_appium_url("http://127.0.0.1:4723"))
        self.assertIsNotNone(controller.check_appium_url("file:///etc/passwd"))
        self.assertIsNotNone(controller.check_appium_url("ftp://x"))

    def test_device_ids(self):
        for dev in ("00008030-000C50D42EE3802E", "R58N123ABC", "10.0.0.9:5555",
                    "adb-ABC123._adb-tls-connect._tcp"):
            self.assertEqual(controller.validate_device_id(dev), dev)
        for dev in ("-s", "--help", "a;b", "../..", "abc", "x" * 200, "a b c d", "abcd\x00", None):
            with self.assertRaises(controller.ApiError, msg=repr(dev)):
                controller.validate_device_id(dev)

    def test_bundle_ids_and_package_names(self):
        for bid in ("com.example.app", "com.example.my_app", "com.blackjackfruit.Temp-Sensor"):
            controller.validate_bundle_id(bid)
        for bid in ("-rf", "x;reboot", "a b", "$(id)", "a/b", "..", "", "a" * 300, 5, None):
            with self.assertRaises(controller.ApiError, msg=repr(bid)):
                controller.validate_bundle_id(bid)

    def test_recording_tokens(self):
        self.assertEqual(controller.validate_recording_token("0123456789ab"), "0123456789ab")
        for token in ("..", "../../etc", "0123456789AB", "0123456789abc", "%2e%2e"):
            with self.assertRaises(controller.ApiError):
                controller.validate_recording_token(token)

    def test_launch_component_from_device_cannot_inject(self):
        self.assertEqual(controller.parse_launch_component("a.b/.Main; reboot", "a.b"),
                         "a.b/.MainActivity")
        self.assertEqual(controller.parse_launch_component("a.b/a.b.Outer$Inner", "a.b"),
                         "a.b/a.b.Outer$Inner")

    def test_device_xml_with_entities_is_refused(self):
        bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x name="&a;"/>'
        with self.assertRaises(RuntimeError):
            controller.parse_xcuitest_elements(bomb, 2.0)
        with self.assertRaises(RuntimeError):
            controller.parse_uiautomator_elements(bomb.encode())

    def test_safe_path_under(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            root = Path(tmp)
            inside = root / "a.mp4"
            inside.write_bytes(b"x")
            (root / "link.mp4").symlink_to(Path(other) / "secret")
            self.assertEqual(controller.safe_path_under(root, inside), os.path.realpath(inside))
            self.assertIsNone(controller.safe_path_under(root, root / ".." / "x"))
            self.assertIsNone(controller.safe_path_under(root, "/etc/passwd"))
            self.assertIsNone(controller.safe_path_under(root, root / "link.mp4"))
            self.assertIsNone(controller.safe_path_under(root, str(root) + "/a\x00b"))
            self.assertIsNone(controller.safe_path_under(root, str(root) + "-sibling/x"))

    def test_archive_member_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("../evil", "/abs", "a/../../evil", "C:/x", "a\\..\\..\\evil"):
                path = Path(tmp) / "a.zip"
                path.write_bytes(zip_of({name: b"x"}))
                with self.assertRaises(controller.ApiError, msg=name) as caught:
                    controller.check_archive_members(path, 10 ** 6)
                self.assertEqual(caught.exception.status, 400)
            path.write_bytes(zip_of({"Payload/My.app/big": b"\0" * 5000}))
            with self.assertRaises(controller.ApiError) as caught:
                controller.check_archive_members(path, 1000)
            self.assertEqual(caught.exception.status, 413)
            path.write_bytes(b"not a zip")
            with self.assertRaises(controller.ApiError):
                controller.check_archive_members(path, 1000)

    def test_upload_cap_setting(self):
        self.assertEqual(controller._upload_cap_bytes("10"), 10 * 1024 * 1024)
        self.assertEqual(controller._upload_cap_bytes("nope"), 2048 * 1024 * 1024)
        self.assertEqual(controller._upload_cap_bytes("-1"), 2048 * 1024 * 1024)

    def test_leftover_uploads_are_removed_at_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "install_abc").mkdir()
            (Path(tmp) / "install_abc" / "upload.zip").write_bytes(b"x")
            (Path(tmp) / "upload_1.apk").write_bytes(b"x")
            (Path(tmp) / "keep.txt").write_bytes(b"x")
            self.assertEqual(sorted(controller.clean_app_dir(tmp)), ["install_abc", "upload_1.apk"])
            self.assertEqual(os.listdir(tmp), ["keep.txt"])

    def test_appium_is_never_spawned_on_a_lan_address(self):
        with patch.object(controller, "appium_ready", return_value=False), \
                patch.object(controller.shutil, "which", return_value="/bin/appium"), \
                patch.object(controller.subprocess, "Popen") as popen, \
                patch.object(controller, "APPIUM_URL", "http://192.168.125.71:4723"):
            self.assertFalse(controller._ensure_appium_locked())
        popen.assert_not_called()


class HttpSecurityTests(unittest.TestCase):
    """The real HTTP handler with a token set, adb faked, Appium never touched."""

    @classmethod
    def setUpClass(cls):
        os.chmod(FAKE_ADB, os.stat(FAKE_ADB).st_mode | stat.S_IEXEC)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app_dir = Path(cls.tmp.name) / "apps"
        cls.video_dir = Path(cls.tmp.name) / "video"
        cls.app_dir.mkdir()
        cls.video_dir.mkdir()
        os.environ["FAKE_ADB_LOG"] = str(Path(cls.tmp.name) / "adb.log")
        cls.patches = [
            patch.object(controller, "ADB_BIN", FAKE_ADB),
            patch.object(controller, "_streams", android_stream.StreamManager(FAKE_ADB)),
            patch.object(controller, "list_devices", return_value=([UDID], None)),
            patch.object(controller, "appium_ready", return_value=False),
            patch.object(controller, "TOKEN", TOKEN),
            patch.object(controller, "APP_DIR", cls.app_dir),
            patch.object(controller, "VIDEO_DIR", cls.video_dir),
        ]
        for p in cls.patches:
            p.start()
        cls.server = controller.ControllerServer(("127.0.0.1", 0), controller.Handler)
        cls.port = cls.server.server_address[1]
        cls.url = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        for p in cls.patches:
            p.stop()
        cls.tmp.cleanup()

    def tearDown(self):
        controller._recordings.clear()

    def request(self, method, path, body=None, headers=None, token=TOKEN):
        """(status, parsed body) of a raw request; http.client sends the path verbatim."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            hdrs = dict(headers or {})
            if token is not None:
                hdrs["X-Controller-Token"] = token
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            try:
                return resp.status, json.loads(data)
            except ValueError:
                return resp.status, data
        finally:
            conn.close()

    def test_missing_and_wrong_token_are_401(self):
        for token in (None, "", "wrong", TOKEN + "x", TOKEN[:-1]):
            with self.subTest(token=token):
                status, body = self.request("GET", "/devices", token=token)
                self.assertEqual((status, body["error"]["code"]), (401, "unauthorized"))
        self.assertEqual(self.request("GET", "/devices")[0], 200)

    def test_token_is_checked_before_an_upload_is_read(self):
        status, _ = self.request("POST", f"/devices/{SERIAL}/apps", b"x" * 1000,
                                 {"Content-Type": "application/zip"}, token="wrong")
        self.assertEqual(status, 401)
        self.assertEqual(os.listdir(self.app_dir), [])

    def test_health_is_open_and_leaks_nothing(self):
        status, body = self.request("GET", "/health", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"ok", "service", "api_version", "appium", "adb", "recordings",
                                     "docs"})
        self.assertEqual(body["docs"], "/docs")
        text = json.dumps(body)
        for secret in (TOKEN, FAKE_ADB, controller.APPIUM_URL, SERIAL, UDID):
            self.assertNotIn(secret, text)

    def test_health_omits_docs_without_readme(self):
        with patch.object(controller, "README_PATH", Path(self.tmp.name) / "missing.md"):
            status, body = self.request("GET", "/health", token=None)
        self.assertEqual(status, 200)
        self.assertNotIn("docs", body)

    def test_docs_renders_readme_as_html(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.request("GET", "/docs", headers={"X-Controller-Token": TOKEN})
            resp = conn.getresponse()
            data = resp.read().decode()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "text/html; charset=utf-8")
            self.assertEqual(resp.getheader("Content-Security-Policy"), controller.DOCS_CSP)
            self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))
            self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy"))
            self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        finally:
            conn.close()
        self.assertIn('<h1 id="monkeytester-plugin-mobile-controller">', data)
        self.assertIn("monkeytester-mobile-controller documentation", data)

    def test_docs_needs_the_token(self):
        for token in (None, "wrong"):
            with self.subTest(token=token):
                status, body = self.request("GET", "/docs", token=token)
                self.assertEqual((status, body["error"]["code"]), (401, "unauthorized"))

    def test_docs_missing_readme_is_404_json(self):
        with patch.object(controller, "README_PATH", Path(self.tmp.name) / "missing.md"):
            status, body = self.request("GET", "/docs")
        self.assertEqual((status, body["error"]["code"]), (404, "not_found"))

    def test_recording_traversal_is_rejected(self):
        for path in ("/recordings/..%2F..%2Fetc%2Fpasswd/video", "/recordings/../../etc/passwd/video",
                     "/recordings/%2e%2e/video", "/recordings/..%00/stop"):
            method = "POST" if path.endswith("stop") else "GET"
            with self.subTest(path=path):
                status, _ = self.request(method, path, b"{}" if method == "POST" else None)
                self.assertIn(status, (400, 404))

    def test_recording_whose_file_escapes_the_video_dir_is_not_served(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "secret.mp4"
            outside.write_bytes(b"secret")
            link = self.video_dir / "aaaaaaaaaaaa.mp4"
            link.symlink_to(outside)
            controller._recordings.update({
                "aaaaaaaaaaaa": {"path": str(link), "udid": UDID, "done": True, "finished": time.time()},
                "bbbbbbbbbbbb": {"path": str(outside), "udid": UDID, "done": True, "finished": time.time()},
            })
            try:
                for token in ("aaaaaaaaaaaa", "bbbbbbbbbbbb"):
                    status, body = self.request("GET", f"/recordings/{token}/video")
                    self.assertEqual((status, body["error"]["code"]), (404, "recording_not_found"))
            finally:
                link.unlink()

    def test_bundle_id_traversal_is_rejected(self):
        for bid in ("..%2F..%2Fetc", "..", "-rf"):
            status, _ = self.request("DELETE", f"/devices/{SERIAL}/apps/{bid}")
            self.assertEqual(status, 400, bid)

    def test_device_id_traversal_has_no_route(self):
        status, body = self.request("GET", "/devices/..%2F..%2Fetc/frame")
        self.assertEqual((status, body["error"]["code"]), (404, "not_found"))

    def test_oversized_json_is_413(self):
        # Only the headers are sent: the server must refuse on Content-Length
        # alone, without reading (or waiting for) a 1 MiB+ body.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.putrequest("POST", f"/devices/{SERIAL}/actions")
            conn.putheader("X-Controller-Token", TOKEN)
            conn.putheader("Content-Length", str(controller.MAX_JSON_BYTES + 1))
            conn.endheaders()
            resp = conn.getresponse()
            body = json.loads(resp.read())
            self.assertEqual((resp.status, body["error"]["code"]), (413, "body_too_large"))
        finally:
            conn.close()

    def test_oversized_upload_is_413_and_unread(self):
        with patch.object(controller, "MAX_APP_BYTES", 100):
            status, body = self.request("POST", f"/devices/{SERIAL}/apps", b"x" * 101)
        self.assertEqual((status, body["error"]["code"]), (413, "body_too_large"))
        self.assertEqual(os.listdir(self.app_dir), [])

    def test_upload_without_content_length_is_411(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.putrequest("POST", f"/devices/{SERIAL}/apps")
            conn.putheader("X-Controller-Token", TOKEN)
            conn.putheader("Transfer-Encoding", "chunked")
            conn.endheaders()
            conn.send(b"5\r\nhello\r\n0\r\n\r\n")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 411)
        finally:
            conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.putrequest("POST", f"/devices/{SERIAL}/apps")
            conn.putheader("X-Controller-Token", TOKEN)
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 411)
        finally:
            conn.close()

    def test_malformed_json_is_400(self):
        for raw in (b"{not json", b"[1,2]", b"\xff\xfe", b"[" * 100000 + b"]" * 100000):
            with self.subTest(raw=raw[:10]):
                status, body = self.request("POST", f"/devices/{SERIAL}/actions", raw)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_request")

    def test_recording_options_must_be_integers(self):
        for body in ({"time_limit": "1; reboot"}, {"time_limit": -1}, {"time_limit": True}):
            status, err = self.request("POST", f"/devices/{SERIAL}/recordings", json.dumps(body))
            self.assertEqual((status, err["error"]["code"]), (400, "invalid_request"), body)
        status, _ = self.request("POST", f"/devices/{UDID}/recordings", json.dumps({"fps": "x"}))
        self.assertEqual(status, 400)

    def test_unexpected_errors_send_no_traceback(self):
        with patch.object(controller, "device_snapshot", side_effect=KeyError("/private/secret")):
            status, body = self.request("GET", "/devices")
        self.assertEqual((status, body["error"]["code"]), (502, "device_error"))
        self.assertNotIn("secret", body["error"]["message"])
        self.assertNotIn("Traceback", body["error"]["message"])

    def test_apk_upload_is_cleaned_up(self):
        apk = zip_of({"AndroidManifest.xml": b"x"})
        for payload in (apk, zip_of({"build/app.apk": apk}), b"not a zip", zip_of({"x.txt": b"x"})):
            self.request("POST", f"/devices/{SERIAL}/apps", payload)
            self.assertEqual(os.listdir(self.app_dir), [], "upload left behind")

    def test_ios_archive_with_traversal_is_refused_and_cleaned_up(self):
        escape = Path(self.tmp.name) / "evil"
        with patch.object(controller, "devicectl", return_value=(0, "", "")) as devicectl:
            status, body = self.request("POST", f"/devices/{UDID}/apps",
                                        zip_of({"../../evil": b"x", "Payload/A.app/x": b"x"}))
        self.assertEqual((status, body["error"]["code"]), (400, "invalid_app"))
        self.assertFalse(escape.exists())
        devicectl.assert_not_called()
        self.assertEqual(os.listdir(self.app_dir), [])

    def test_ios_install_is_cleaned_up(self):
        with patch.object(controller, "devicectl", return_value=(0, "", "")) as devicectl:
            status, body = self.request("POST", f"/devices/{UDID}/apps",
                                        zip_of({"Payload/A.app/Info.plist": b"x"}))
        self.assertEqual((status, body), (200, {"ok": True, "platform": "ios"}))
        args = devicectl.call_args.args
        self.assertEqual(args[:5], ("device", "install", "app", "--device", UDID))
        self.assertTrue(args[5].endswith("A.app"))
        self.assertEqual(os.listdir(self.app_dir), [])


class NoShellTests(unittest.TestCase):
    def test_no_subprocess_call_uses_a_shell(self):
        for name in ("device_controller.py", "android_stream.py"):
            source = (ROOT / name).read_text()
            self.assertNotIn("shell=True", source, name)
            self.assertNotIn("os.system(", source, name)
            self.assertNotIn("os.popen(", source, name)


if __name__ == "__main__":
    unittest.main()
