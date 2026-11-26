# MonkeyTester-Plugin-Mobile-Controller

The device-control backend for MonkeyTester.
It runs on a Mac, owns every iPhone and Android phone, and exposes them over HTTP
(see [API.md](API.md)). It knows nothing about tests or vision models.

```
MonkeyTester (Linux) ──HTTP──► device_controller.py (Mac, :8090)
                                 ├── Appium (:4723) ──► iPhone (XCUITest)
                                 ├── xcrun devicectl ─► iPhone (install)
                                 └── adb + ffmpeg ────► Android (input, video)
```

> **Warning: a token is required by default.** The service listens on every interface
> (`CONTROLLER_BIND=0.0.0.0`) so the MonkeyTester viewer can reach it over the LAN.
> It **refuses to start** (exit code 2) unless `CONTROLLER_TOKEN` is set, or
> `CONTROLLER_BIND` is loopback (`127.0.0.1`, `::1`, `localhost`). Enter the same
> token in the MonkeyTester viewer under **Settings**. See [SECURITY.md](SECURITY.md).

## Setup

The service itself needs only the Python standard library. On the Mac, install
Xcode, Appium with the XCUITest driver, Android platform-tools and ffmpeg
(`brew install ffmpeg`). Android live view and recording need ffmpeg.

```bash
CONTROLLER_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))') \
APPIUM_ORG_ID=<Xcode team id> \
APPIUM_SIGNING_ID="Apple Development" \
APPIUM_WDA_BUNDLE_ID=com.blackjackfruit.WebDriverAgentRunner \
python3 device_controller.py
# -> 0.0.0.0:8090; without CONTROLLER_TOKEN it exits with a message saying how to set one
```

Check it with `curl http://localhost:8090/health` (no token needed there) and
`curl -H "X-Controller-Token: <token>" http://localhost:8090/devices`. It starts Appium itself if
nothing is listening. The first iOS session may build WDA, so it can take a while.

To start it at login, fill in the placeholders in
`packaging/launchd/com.blackjackfruit.monkeytester-mobile-controller.plist`, including
`CONTROLLER_TOKEN` in its `EnvironmentVariables` (the service refuses to start while it
still says `REPLACE_WITH_TOKEN`). Copy it to `~/Library/LaunchAgents/`, run `chmod 600` on
it (the token is in plain text), and run `launchctl load` on it. The signing identity
must be usable from that LaunchAgent (keychain unlocked).

The LaunchAgent runs `device_controller.py` from this checkout, so this README is there at
runtime: `GET /docs` serves it as an HTML page (token required) and `/health` reports
`"docs": "/docs"`. A copy without README.md next to `device_controller.py` omits the `docs`
field instead of advertising a broken page.

## Network and environment

| Variable | Default | Meaning |
|---|---|---|
| `CONTROLLER_PORT` | `8090` | HTTP port |
| `CONTROLLER_BIND` | `0.0.0.0` | Bind address. Anything other than loopback requires `CONTROLLER_TOKEN` |
| `CONTROLLER_TOKEN` | unset | Shared secret. Clients send it as `X-Controller-Token`. Required unless the bind is loopback |
| `CONTROLLER_MAX_UPLOAD_MB` | `2048` | Largest app upload. Bigger uploads get 413 |
| `APPIUM_URL` | `http://127.0.0.1:4723` | Appium. The controller spawns Appium only on a loopback host, with `--address` set to it, so the unauthenticated Appium never listens on the LAN |

Traffic is plain HTTP and the token is stored in plain text. See [SECURITY.md](SECURITY.md)
for the threat model and what is not covered.

## Devices

- **iPhone:** connected by USB, trusted, unlocked and awake, with Developer Mode on.
- **Android:** USB, or wireless debugging paired **with this Mac** (`adb pair`).
  Pairing is per host, so a pairing with another machine doesn't carry over. Paired
  phones advertised over mDNS are connected automatically every 30 s. Set
  `ADB_CONNECT` to a comma-separated `IP:PORT` list to add others.

See the top of `device_controller.py` for every environment variable.

For how it works inside, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Tests

```bash
python3 -m unittest discover tests
```

These need ffmpeg with libx264, and use `tests/fake_adb.py` in place of a phone. iOS
paths that require Appium use mocks, so they don't prove a real phone behaves the same way.
