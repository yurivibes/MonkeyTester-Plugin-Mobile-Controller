#!/usr/bin/env python3
"""Stand-in for adb, so the HTTP service can be tested without a phone.

Logs each call to $FAKE_ADB_LOG, serves a real PNG for screenshots, and real
H.264 from ffmpeg for screenrecord.
"""
import os
import signal
import subprocess
import tempfile
import sys
import time
import zlib
import struct

SERIAL = "10.0.0.9:5555"

# A trimmed `uiautomator dump` of a Compose screen with testTagsAsResourceId.
WINDOW_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\
<hierarchy rotation="0">\
<node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.app" \
content-desc="" bounds="[0,0][1080,2400]">\
<node index="0" text="" resource-id="com.example.app:id/content" class="android.view.View" \
package="com.example.app" content-desc="" bounds="[0,0][1080,2400]">\
<node index="0" text="Welcome" resource-id="title" class="android.widget.TextView" \
package="com.example.app" content-desc="" bounds="[100,200][980,300]"/>\
<node index="1" text="" resource-id="accept_button" class="android.widget.Button" \
package="com.example.app" content-desc="Accept" bounds="[340,2000][740,2140]"/>\
<node index="2" text="" resource-id="" class="android.view.View" \
package="com.example.app" content-desc="no id" bounds="[0,0][10,10]"/>\
<node index="3" text="" resource-id="collapsed" class="android.view.View" \
package="com.example.app" content-desc="" bounds="[5,5][5,5]"/>\
</node></node></hierarchy>"""


def sdcard(remote):
    """Where the fake phone keeps /sdcard/<name>."""
    root = os.environ.get("FAKE_ADB_SDCARD") or os.path.join(tempfile.gettempdir(), "fake-adb-sdcard")
    os.makedirs(root, exist_ok=True)
    return os.path.join(root, os.path.basename(remote))


def png(width=4, height=4):
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    raw = b"".join(b"\0" + b"\xff\0\0" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def main(argv):
    log = os.environ.get("FAKE_ADB_LOG")
    if log:
        with open(log, "a") as f:
            f.write(" ".join(argv) + "\n")
    args = argv[2:] if argv[:1] == ["-s"] else argv
    joined = " ".join(args)
    if args == ["devices"]:
        print(f"List of devices attached\n{SERIAL}\tdevice")
    elif args[:2] == ["mdns", "services"]:
        print(f"adb-X _adb-tls-connect._tcp. {SERIAL}")
    elif args[:2] == ["shell", "screenrecord"] and args[-1].startswith("/sdcard/"):
        # Recording to a file on the phone: write a real MP4 until SIGINT.
        local = sdcard(args[-1])
        with open(local + ".pid", "w") as f:
            f.write(str(os.getpid()))
        if os.environ.get("FAKE_ADB_NO_UNLIMITED") and args[args.index("--time-limit") + 1] == "0":
            print("Time limit 0 not in range [1,180]")
            return 1
        os.execvp("ffmpeg", ["ffmpeg", "-loglevel", "error", "-y", "-re", "-f", "lavfi",
                             "-i", "testsrc=size=640x480:rate=15", "-t", "60",
                             "-c:v", "libx264", "-pix_fmt", "yuv420p", "-f", "mp4", local])
    elif args[:3] == ["shell", "pkill", "-INT"]:
        pid_file = sdcard(args[-1]) + ".pid"
        if os.path.exists(pid_file):
            os.kill(int(open(pid_file).read()), signal.SIGINT)
    elif args[:1] == ["pull"]:
        if not os.path.exists(sdcard(args[1])):
            print(f"adb: error: remote object '{args[1]}' does not exist", file=sys.stderr)
            return 1
        with open(sdcard(args[1]), "rb") as src, open(args[2], "wb") as dst:
            dst.write(src.read())
    elif args[:3] == ["shell", "rm", "-f"]:
        for p in (sdcard(args[3]), sdcard(args[3]) + ".pid"):
            if os.path.exists(p):
                os.unlink(p)
    elif args[:3] == ["exec-out", "screencap", "-p"]:
        sys.stdout.buffer.write(png(64, 128))
    elif "screenrecord" in args and os.environ.get("FAKE_ADB_SCREENRECORD") == "burst":
        # Like screenrecord after a tap on an otherwise idle screen: a short
        # burst of frames, then nothing while the stream stays open.
        burst = subprocess.run(
            ["ffmpeg", "-loglevel", "error", "-f", "lavfi",
             "-i", "testsrc=size=1080x2400:rate=15", "-frames:v", "30",
             "-c:v", "libx264", "-pix_fmt", "yuv420p", "-bf", "0",
             "-f", "h264", "-"], capture_output=True, check=True).stdout
        sys.stdout.buffer.write(burst)
        sys.stdout.buffer.flush()
        time.sleep(30)
    elif "screenrecord" in args:
        os.execvp("ffmpeg", ["ffmpeg", "-loglevel", "error", "-re", "-f", "lavfi",
                             "-i", "testsrc=size=640x480:rate=15,noise=alls=40:allf=t", "-t", "30",
                             "-c:v", "libx264", "-pix_fmt", "yuv420p",
                             "-tune", "zerolatency", "-f", "h264", "-"])
    elif args[:2] == ["exec-out", "cat"] and args[2].endswith(".xml"):
        with open(sdcard(args[2]), "rb") as f:
            sys.stdout.buffer.write(f.read())
    elif args[:2] == ["exec-out", "cat"]:
        sys.stdout.buffer.write(png())
    elif args[:3] == ["shell", "uiautomator", "dump"]:
        with open(sdcard(args[3]), "w") as f:
            f.write(WINDOW_XML)
        print(f"UI hierchary dumped to: {args[3]}")
    elif "getprop" in joined:
        print("Fake-Model")
    elif "wm size" in joined:
        print("Physical size: 1080x2400")
    elif "wm density" in joined:
        print("Physical density: 420\nOverride density: 480")
    elif "resolve-activity" in joined:
        print("priority=0\ncom.example.app/com.other.MainActivity")
    elif "pm uninstall" in joined or args[:1] == ["install"]:
        print("Success")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
