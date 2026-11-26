# Architecture

The Mobile Controller owns every phone and exposes them over HTTP. It knows nothing about
tests or vision models. For setup, see [README.md](README.md). For the exact contract, see
[API.md](API.md).

## Where it fits

```
MonkeyTester viewer ──┐                       ┌── Appium :4723 + WDA ──► iPhone
                      ├─ HTTP ─► controller ──┼── xcrun devicectl ─────► iPhone (list, install)
MonkeyTester runner ──┘           :8090       └── adb + ffmpeg ────────► Android
```

Clients are the viewer and test runner in MonkeyTester. The API is the only coupling to them.

## Files

| File | Responsibility |
|---|---|
| `device_controller.py` | Startup checks, HTTP routes, validation, Appium sessions, adb and devicectl calls, recordings |
| `android_stream.py` | One shared `screenrecord | ffmpeg` capture per Android device, for streams and recordings |
| `docs_page.py` | Renders README.md as the `GET /docs` HTML page. Shared verbatim by every MonkeyTester plugin; don't edit this copy |
| `tests/fake_adb.py` | Stand-in for adb that serves real PNG and H.264 |
| `tests/test_security.py` | Bind/token rule, auth, validators, traversal, size limits, upload cleanup, `/docs` |
| `tests/test_docs_page.py` | The shared README renderer (copied with `docs_page.py`) |

Only the Python standard library is used.

## Startup

`main()` runs `check_bind_token` and `check_appium_url` before binding. If `CONTROLLER_BIND` is
not loopback and `CONTROLLER_TOKEN` is empty (or is still the plist placeholder), or
`APPIUM_URL` isn't http(s), it prints the reason to stderr and exits with code 2. It then deletes
upload leftovers in the app directory. `ControllerServer` picks an IPv6 socket for binds like
`::1`.

## Request handling

Every request goes through `Handler._dispatch`, which:

1. Checks the token, except on `/health`, before any body is read.
2. Runs the route. Routes raise `ApiError(status, code, message)` for failures they understand.
3. Turns any failure into the one error body in API.md. `RuntimeError`/`OSError` from devices and
   tools become a 502 `device_error` with their message. Any other exception becomes the same 502
   with a generic message, and its traceback goes only to the log.

Bodies need a `Content-Length` within the limit (JSON 1 MiB, uploads `CONTROLLER_MAX_UPLOAD_MB`),
otherwise 413 is sent before the body is read. Chunked bodies get 411. Uploads are streamed into
a private per-request work directory, which is deleted before the reply.

Once a stream has sent its headers, a failure can only close the connection, so it's logged.

Actions are validated by `validate_action` before anything reaches a device. This also keeps
input out of the device shell: `adb shell` joins its arguments into a command line, so bundle
ids must match a strict pattern, numbers must be integers, and text is quoted.

## Telling platforms apart

Each request works out its device's platform in `detect_platform`:

1. An explicit `platform` wins.
2. A `:` means a wireless adb serial.
3. Anything adb currently lists is Android. This is cached for 3 seconds.
4. Everything else is treated as iOS.

adb has to be asked because many USB Android serials are plain hex, the same shape as a UDID.

## Concurrency

The server uses one thread per request.

| Shared state | Protection |
|---|---|
| Appium sessions | One lock per device, because creating a session can take minutes while WDA builds. Other phones keep working meanwhile |
| Starting Appium | One lock, so two devices can't both start it |
| Recordings | One lock. The device is claimed before the slow start call, so two starts can't both succeed |
| Device list | Shared for 1 second, so event subscribers don't each run `devicectl` and `adb` every poll |
| Android capture | One per device, reference counted, in `android_stream.py` |

## Failure behaviour

- **Devices:** one platform failing leaves the other listed, with the reason in `errors`.
- **iOS coordinates:** the screen scale comes from the device and is cached. If it can't be read,
  the action fails instead of guessing a scale and tapping the wrong place. The screen size comes
  from a real screenshot, so it can't disagree with one.
- **Recordings:** a failed start or stop still releases the device. Finished videos are deleted
  after 24 hours.
- **Wireless Android:** a background thread reconnects configured and mDNS-advertised phones
  every 30 seconds.
- **Shutdown:** SIGTERM and SIGINT stop the server and the Appium this process started. An Appium
  it didn't start is left running.

## Security

See [SECURITY.md](SECURITY.md) for the full list. In short: a token is mandatory on any
non-loopback bind (and the default bind is `0.0.0.0`), compared in constant time. `/health` needs no
token and reports only service status, no config or device ids. Appium is spawned only on loopback.
Every subprocess gets an argument list, ids are allowlisted, and file paths are resolved and kept
under their directory. Traffic is plain HTTP, so anyone who can sniff the network can read the
token and screenshots. Keep it on a network you trust, or use a VPN.

## Testing

`tests/` runs the real HTTP service with only adb faked, on Linux or macOS, and needs ffmpeg with
libx264. The `devicectl` parser is tested against output captured from a real iPhone. Paths that
need Appium are tested with mocks only, so they don't show that a real phone responds as expected.
