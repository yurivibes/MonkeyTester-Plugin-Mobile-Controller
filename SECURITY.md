# Security

This service controls real phones: whoever can call it can install apps, tap, type and take
screenshots. This page says what is protected, how to set it up, and what is not covered.
It doesn't claim the service has no vulnerabilities. It closes the known holes and keeps the
attack surface small.

## Threat model

- **Where it runs:** a home lab LAN (192.168.125.0/24), one user. The controller runs on the
  Mac (192.168.125.71, port 8090). The MonkeyTester viewer and runner on the Linux host
  (192.168.125.70) reach it over the LAN.
- **Who we defend against:** another device on the same network (a guest, an IoT gadget,
  compromised software) that can open a TCP connection to the Mac.
- **Who we trust:** whoever holds `CONTROLLER_TOKEN`, the user logged in on the Mac, and the
  phones and apps under test. A hostile app under test is only partly covered (see below).

## What is protected, and how

| Area | Protection |
|---|---|
| Authentication | Every route except `GET /health` needs `X-Controller-Token: <token>`, compared in constant time (`hmac.compare_digest`). Missing or wrong token: `401 unauthorized`. The token is checked before any request body is read |
| Bind rule | If `CONTROLLER_BIND` is not loopback (`127.0.0.1`, any `127.x`, `::1`, `localhost`) and `CONTROLLER_TOKEN` is empty, the service **refuses to start** (exit code 2, with a message on stderr saying how to fix it). On loopback the token is optional. The default bind is `0.0.0.0`, so **by default a token is required** |
| `/health` | Unauthenticated, so readiness checks work. Returns only `ok`, `service`, `api_version`, whether Appium and adb are up, and the number of active recordings. No token, paths, URLs or device ids |
| Appium | Appium has no authentication. The controller starts it with `--address <APPIUM_URL host>` (default `127.0.0.1`), so it never listens on the LAN. If `APPIUM_URL` points at a non-loopback host, the controller won't spawn Appium there at all. `APPIUM_URL` must be http(s) or the service refuses to start |
| Subprocesses | `xcrun devicectl`, `adb`, `appium`, `ffmpeg` and `ditto` are run with argument lists, never through a local shell |
| Input validation | Device ids must match `[0-9A-Za-z][0-9A-Za-z:._-]{3,127}`. Bundle ids and package names must match `[A-Za-z0-9][A-Za-z0-9._-]{0,254}`. Both start with a letter or digit, so neither can be read as an option. Numbers must be integers. `adb shell` joins its arguments into a device shell command, so typed text and launch components are quoted with `shlex.quote`, and a launch component the device reports is used only if it's a plain `pkg/activity` name |
| Paths | Recording tokens must be 12 lowercase hex characters. The video file is resolved with `realpath` and served only if it stays under the video directory, so a symlink pointing out of it is refused. Uploaded archives are refused (400) if any member is absolute, contains `..`, a drive letter or NUL |
| Size limits | JSON bodies: 1 MiB. App uploads: `CONTROLLER_MAX_UPLOAD_MB` (default 2048), streamed to disk, never held in memory. Larger requests get `413` before the body is read. An archive that unpacks to more than 4× the upload limit gets `413`. Chunked bodies, and uploads without `Content-Length`, get `411` |
| Errors | Malformed JSON gets `400`. An unexpected exception becomes `502 device_error` with a generic message. The traceback goes to the log only, never to the client |
| Uploads | Each install uses a private work directory (mode 0700) under the temp dir, deleted before the reply is sent, whether the install worked or not. Leftovers from a killed run are deleted at startup |
| Device XML | Page sources from Appium and `uiautomator dump` are refused if they contain a `DOCTYPE` or `ENTITY`, so entity-expansion tricks can't work |

## Setting up the token

1. Generate a token on any machine:

   ```bash
   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```

2. Give it to the controller. With launchd (the normal setup), add it to the
   `EnvironmentVariables` dict of
   `~/Library/LaunchAgents/com.blackjackfruit.monkeytester-mobile-controller.plist`:

   ```xml
   <key>CONTROLLER_TOKEN</key>
   <string>paste-the-token-here</string>
   ```

   Then reload it: `launchctl unload <plist> && launchctl load <plist>`. The template in
   `packaging/launchd/` has a `REPLACE_WITH_TOKEN` placeholder. The service refuses to start
   while the placeholder is still there, so the template can't run with a known token. Run
   `chmod 600` on the plist, because the token is stored there in plain text.

3. Enter **the same token** in the MonkeyTester viewer: **Settings → Mobile Controller token**.
   The viewer stores it and sends it as `X-Controller-Token` (this Settings field is being
   added in a MonkeyTester PR that is still open). The old `CONTROLLER_TOKEN` /
   `IOS_CONTROLLER_TOKEN` environment variables on the viewer side are imported once, then
   ignored.

4. Check it:

   ```bash
   curl http://192.168.125.71:8090/health                                      # 200, no token needed
   curl -H "X-Controller-Token: <token>" http://192.168.125.71:8090/devices   # 200
   curl http://192.168.125.71:8090/devices                                     # 401
   ```

If you only use the controller from the Mac itself, `CONTROLLER_BIND=127.0.0.1` makes the
token optional.

To rotate the token, generate a new one, change it in the plist and in the viewer's
Settings, then reload the agent.

## What is NOT covered

- **No TLS.** Traffic is plain HTTP, so anyone who can sniff the LAN can read the token,
  screenshots and uploaded apps. For access from outside the LAN, use a VPN or Tailscale.
  Never forward port 8090 on the router.
- **The secret is stored in plain text** in the launchd plist (and in the process
  environment). Anyone who can read your files on the Mac can read the token.
- **No rate limiting or lockout** on wrong tokens. A long random token is what protects you.
- **Single shared token.** No users, roles or per-client tokens. Whoever has the token has
  full control of every phone.
- **The app under test is trusted.** An app's own code runs on the phone, and an IPA's
  contents (including symlinks inside the bundle) are handed to `devicectl` as they are.
- **The phones themselves** (paired hosts, wireless adb pairing, Developer Mode) are outside
  this service's control.
- **Tier 3 items are not done:** TLS/VPN, launchd/sandbox hardening, running as a dedicated
  user. CI security scanning (tier 4) is also not done.

## Checking it yourself

```bash
python3 -m unittest discover tests     # tests/test_security.py covers the rules above
nix run nixpkgs#python3Packages.bandit -- -r . -x ./tests
```

## Reporting a problem

This is a private home-lab project. Open an issue on the GitHub repository
(`https://github.com/yurivibes/MonkeyTester-Plugin-Mobile-Controller/issues`) or tell the owner directly. Don't post a working
token in the issue.
