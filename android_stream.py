#!/usr/bin/env python3
"""Live video and recording for Android devices.

Live view mirrors a device with `adb exec-out screenrecord` piped through
ffmpeg into JPEG frames. One capture runs per device, shared by every stream
viewer, and stops when the last of them lets go. Recordings are separate: a
second screenrecord writes the MP4 on the phone.
"""
import os
import select
import subprocess
import threading
import time

# screenrecord stops by itself at about 180 s, so restart just before that.
SCREENRECORD_TIME_LIMIT = 170
MAX_BUFFERED_BYTES = 5_000_000


def extract_frames(buf):
    """Pull complete JPEG frames (SOI...EOI) out of a growing byte buffer.

    Returns (frames, remainder); the remainder is a trailing partial frame to
    prepend to the next chunk.
    """
    frames = []
    i = 0
    n = len(buf)
    while i < n - 1:
        if buf[i] == 0xFF and buf[i + 1] == 0xD8:  # SOI
            start = i
            i += 2
            while i < n - 1:
                if buf[i] == 0xFF and buf[i + 1] == 0xD9:  # EOI
                    frames.append(buf[start: i + 2])
                    i += 2
                    break
                if buf[i] == 0xFF and buf[i + 1] == 0x00:
                    i += 2
                else:
                    i += 1
            else:
                return frames, buf[start:]
        else:
            i += 1
    return frames, b""


def count_pictures(data):
    """Count the H.264 pictures that start in `data`, and return the bytes to
    carry into the next call (a start code may be split across reads).

    A picture starts at a coded slice NAL (type 1 or 5) whose first_mb_in_slice
    is 0, i.e. the first bit of the slice header is 1, so multi-slice pictures
    count once."""
    count = 0
    limit = len(data) - 4  # need the NAL header and the byte after it
    i = data.find(b"\x00\x00\x01")
    while 0 <= i < limit:
        nal_type = data[i + 3] & 0x1F
        if nal_type in (1, 5) and data[i + 4] & 0x80:
            count += 1
        i = data.find(b"\x00\x00\x01", i + 3)
    return count, data[-4:]


class _Capture:
    """Live frames for one device.

    screenrecord sends a picture only when the screen changes, and the H.264
    parser can only end a picture when the next one starts, so the last picture
    of every change would stay inside ffmpeg until the screen changes again
    (and the first one, on an idle screen, would never show). When the stream
    goes quiet, a screenshot stands in for that held picture; the picture
    itself is dropped when it finally comes out."""

    IDLE_FILL_SECS = 0.3

    def __init__(self, adb_bin, serial, log):
        self.adb_bin = adb_bin
        self.serial = serial
        self.log = log
        self.users = 0
        self.frame = None
        self.seq = 0
        self.changed = threading.Condition()
        self.stop_event = threading.Event()
        self.procs = []
        self._order = threading.Lock()
        self._pictures_in = 0      # pictures handed to ffmpeg
        self._pictures_out = 0     # pictures ffmpeg has decoded
        self._skip_through = 0     # decoded pictures up to here are stale
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name=f"capture-{serial}")

    def _publish(self, frame):
        with self.changed:
            self.frame = frame
            self.seq += 1
            self.changed.notify_all()

    def _on_decoded(self, frame):
        """A picture came out of ffmpeg: publish it unless a screenshot taken
        after it was already published."""
        with self._order:
            self._pictures_out += 1
            if self._pictures_out <= self._skip_through:
                return
            self._publish(frame)

    def _fill_idle(self):
        """The stream went quiet: publish a screenshot of what's on screen now."""
        jpeg = self._screenshot_jpeg()
        if not jpeg:
            return
        with self._order:
            self._skip_through = self._pictures_in
            if self._pictures_out < self._skip_through:
                self._publish(jpeg)

    def _screenshot_jpeg(self):
        try:
            png = subprocess.run([self.adb_bin, "-s", self.serial, "exec-out",
                                  "screencap", "-p"],
                                 capture_output=True, timeout=10).stdout
            if not png.startswith(b"\x89PNG"):
                return None
            jpeg = subprocess.run(["ffmpeg", "-loglevel", "error", "-f", "png_pipe",
                                   "-i", "-", "-f", "mjpeg", "-q:v", "5", "-"],
                                  input=png, capture_output=True, timeout=10).stdout
            return jpeg if jpeg.startswith(b"\xff\xd8") else None
        except (OSError, subprocess.SubprocessError) as e:
            self.log(f"idle screenshot failed for {self.serial}: {e}")
            return None

    def _run(self):
        while not self.stop_event.is_set():
            self._mirror_once()
            if not self.stop_event.is_set():
                time.sleep(0.2)

    def _pump(self, adb_proc, ffmpeg_proc):
        """Copy screenrecord's H.264 into ffmpeg, counting pictures, and fill
        in a screenshot each time the stream goes quiet."""
        fd = adb_proc.stdout.fileno()
        carry = b""
        pending = False
        try:
            while not self.stop_event.is_set():
                ready, _, _ = select.select([fd], [], [], self.IDLE_FILL_SECS)
                if not ready:
                    if pending:
                        pending = False
                        self._fill_idle()
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                count, carry = count_pictures(carry + chunk)
                with self._order:
                    self._pictures_in += count
                ffmpeg_proc.stdin.write(chunk)
                ffmpeg_proc.stdin.flush()
                pending = True
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            try:
                ffmpeg_proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    def _mirror_once(self):
        adb_proc = ffmpeg_proc = None
        with self._order:
            self._pictures_in = self._pictures_out = self._skip_through = 0
        try:
            adb_proc = subprocess.Popen(
                [self.adb_bin, "-s", self.serial, "exec-out", "screenrecord",
                 "--output-format=h264", "--bit-rate", "4000000",
                 "--time-limit", str(SCREENRECORD_TIME_LIMIT), "-"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
            # Frame-threaded decoding holds back about one picture per CPU,
            # and the encoder side a few more, so decode and encode on one
            # thread with low_delay.
            ffmpeg_proc = subprocess.Popen(
                ["ffmpeg", "-f", "h264", "-probesize", "32k",
                 "-analyzeduration", "0", "-threads", "1", "-flags", "low_delay",
                 "-i", "-", "-threads", "1",
                 "-f", "mjpeg", "-q:v", "5", "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0)
            self.procs = [ffmpeg_proc, adb_proc]
            pump = threading.Thread(target=self._pump, args=(adb_proc, ffmpeg_proc),
                                    daemon=True, name=f"pump-{self.serial}")
            pump.start()
            buf = b""
            while not self.stop_event.is_set():
                chunk = ffmpeg_proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                frames, buf = extract_frames(buf)
                for frame in frames:
                    self._on_decoded(frame)
                if not frames and len(buf) > MAX_BUFFERED_BYTES:
                    buf = b""
        except Exception as e:
            self.log(f"capture error for {self.serial}: {e}")
        finally:
            self._terminate(ffmpeg_proc, adb_proc)

    @staticmethod
    def _terminate(*procs):
        for proc in procs:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)

    def stop(self):
        self.stop_event.set()
        self._terminate(*self.procs)
        with self.changed:
            self.changed.notify_all()


class StreamManager:
    def __init__(self, adb_bin, log=print):
        self.adb_bin = adb_bin
        self.log = log
        self._captures = {}
        self._lock = threading.Lock()

    def acquire(self, serial):
        """Join (or start) the device's capture. Pair with release()."""
        with self._lock:
            capture = self._captures.get(serial)
            if capture is None:
                capture = _Capture(self.adb_bin, serial, self.log)
                self._captures[serial] = capture
                capture.thread.start()
            capture.users += 1
            return capture

    def release(self, serial):
        with self._lock:
            capture = self._captures.get(serial)
            if capture is None:
                return
            capture.users -= 1
            if capture.users <= 0:
                del self._captures[serial]
                capture.stop()

    def frames(self, serial, idle_resend_secs=1.0):
        """Yield JPEG frames until the consumer stops iterating.

        screenrecord only emits when the screen changes, so the last frame is
        re-sent while the screen is idle; otherwise viewers would stall.
        """
        capture = self.acquire(serial)
        try:
            last_seq = -1
            while not capture.stop_event.is_set():
                with capture.changed:
                    if capture.seq == last_seq:
                        capture.changed.wait(timeout=idle_resend_secs)
                    frame, last_seq = capture.frame, capture.seq
                if frame is not None:
                    yield frame
        finally:
            self.release(serial)


class AndroidRecording:
    """Record a device to MP4 with screenrecord writing on the phone.

    The phone timestamps every picture, so idle stretches keep their real
    length, and nothing depends on the live view's decoder. It runs alongside
    the live view (Android allows two screenrecords at once). The file goes to
    /sdcard while recording and is copied to `path` and deleted on stop.
    """

    START_CHECK_SECS = 1.0

    def __init__(self, adb_bin, serial, path, time_limit=None, log=print):
        self.adb_bin = adb_bin
        self.serial = serial
        self.path = path
        self.log = log
        self.remote = f"/sdcard/mt_rec_{os.path.splitext(os.path.basename(path))[0]}.mp4"
        # 0 = no limit. Older Androids cap screenrecord at 180 s and may refuse
        # 0; retry with their maximum then.
        limits = [int(time_limit)] if time_limit else [0, 180]
        for limit in limits:
            self.proc = subprocess.Popen(
                [adb_bin, "-s", serial, "shell", "screenrecord",
                 "--bit-rate", "4000000", "--time-limit", str(limit), self.remote],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                out, _ = self.proc.communicate(timeout=self.START_CHECK_SECS)
            except subprocess.TimeoutExpired:
                return  # still recording: started fine
            self.log(f"screenrecord on {serial} exited at once "
                     f"(--time-limit {limit}): {out.decode(errors='replace').strip()[:200]}")
        raise RuntimeError(f"screenrecord would not start on {serial}")

    def _adb(self, *args, timeout=60):
        return subprocess.run([self.adb_bin, "-s", self.serial, *args],
                              capture_output=True, timeout=timeout)

    def stop(self):
        """Finish the MP4. Raises RuntimeError if nothing usable was recorded."""
        try:
            if self.proc.poll() is None:
                # SIGINT makes screenrecord finish the MP4 before exiting.
                self._adb("shell", "pkill", "-INT", "-f", self.remote, timeout=15)
                try:
                    self.proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
            pulled = self._adb("pull", self.remote, self.path, timeout=300)
        finally:
            try:
                self._adb("shell", "rm", "-f", self.remote, timeout=15)
            except subprocess.SubprocessError:
                pass
        if pulled.returncode != 0 or not os.path.exists(self.path) \
                or os.path.getsize(self.path) == 0:
            raise RuntimeError(f"no video from {self.serial}: "
                               f"{(pulled.stderr or pulled.stdout).decode(errors='replace').strip()[:200]}")
        return self.path
