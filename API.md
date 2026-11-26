# Mobile Controller HTTP API (api_version 2)

This contract is the only coupling between MonkeyTester and this service. Change
`API_VERSION` in `device_controller.py` when you break it.

Device ids are iPhone UDIDs or adb serials (`R58N123`, `IP:PORT`). Coordinates are
always device pixels. If `CONTROLLER_TOKEN` is set, every request except `GET /health`
must send it as `X-Controller-Token`. The token is mandatory whenever the service listens beyond
loopback, which it does by default (see SECURITY.md).

## Errors

Every failure has a non-2xx status and the same body:

```json
{"error": {"code": "device_error", "message": "adb: device offline"}}
```

Branch on `code`. `message` is for people and can change.

| Status | Codes | Meaning |
|---|---|---|
| 400 | `invalid_request`, `unknown_action`, `invalid_app` | The request is wrong. Retrying won't help |
| 401 | `unauthorized` | Missing or wrong token |
| 404 | `not_found`, `recording_not_found`, `stream_unsupported` | No such route or recording, or the device can't do this |
| 409 | `device_locked` | The device's state prevents this right now |
| 411 | `length_required` | An upload without `Content-Length`, or any chunked body |
| 413 | `body_too_large` | JSON over 1 MiB, an app over `CONTROLLER_MAX_UPLOAD_MB` (default 2048 MiB), or an archive that unpacks to more than 4× that |
| 502 | `device_error`, `install_failed`, `uninstall_failed` | The device or its tooling failed |

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | `{ok, service, api_version, appium, adb, recordings, docs?}`. Needs no token, doesn't touch any device, and answers quickly, so use it for readiness checks. `docs` is `"/docs"` when README.md is readable, and is omitted otherwise |
| `GET /docs` | README.md rendered as a self-contained HTML page (`text/html; charset=utf-8`, strict `Content-Security-Policy`, `Cache-Control: no-store`). Needs the token like every other route. 404 `not_found` if README.md can't be read. The MonkeyTester viewer shows it via its `/plugins/docs/<name>` link |
| `GET /devices` | `{devices: [{id, platform, model}], errors: {ios?, android?}}`. Always 200: one platform failing leaves the other listed, with the reason in `errors`. `model` is `null` on iOS |
| `GET /devices/events` | Device list changes, see below |
| `GET /devices/<id>/frame` | One PNG screenshot |
| `GET /devices/<id>/screen` | `{width, height, scale}`. `width`/`height` in device pixels; `scale` is pixels per point (iOS, from `mobile: deviceScreenInfo`) or per dp (Android, `wm density` / 160, the override density when one is set) |
| `GET /devices/<id>/elements` | Layout of the current screen, see below |
| `GET /devices/<id>/stream` | Live MJPEG, `multipart/x-mixed-replace; boundary=frame`. Android only; iOS returns `stream_unsupported`, so poll `frame` |
| `POST /devices/<id>/actions` | `{action, ...}`, see below. Returns `{ok, value}` |
| `POST /devices/<id>/apps` | Raw `.ipa`, `.apk` or zip body installs it. Returns `{ok, platform}` |
| `DELETE /devices/<id>/apps/<bundle_id>` | Uninstalls. Returns `{ok}` |
| `POST /devices/<id>/recordings` | Body `{time_limit?, fps?, codec?}` starts recording and returns `{ok, token, replaced}`. `time_limit` applies to Android; `fps` and `codec` to iOS. One recording per device: starting one while an earlier recording on that device was never stopped (its run died) stops the earlier one first and lists its token in `replaced`; that video stays downloadable. Android records with `screenrecord` writing the MP4 on the phone (no length limit, idle stretches keep their real length), separately from the live stream, so the two can run at once |
| `POST /recordings/<token>/stop` | Finishes it. Returns `{ok}`. Stopping twice is fine |
| `GET /recordings/<token>/video` | The MP4, once stopped. Kept for 24 hours |

## Elements

`GET /devices/<id>/elements` returns the visible elements that have an id, for layout
assertions:

```json
{"width": 750, "height": 1334, "scale": 2.0,
 "elements": [{"id": "accept_button", "x": 175, "y": 1200, "w": 400, "h": 88, "label": "Accept"}]}
```

`width`, `height` and `scale` are the same as `/screen`. `x, y, w, h` are device pixels;
divide by `scale` for points/dp. `label` is present only when the element has one.
Elements are listed in tree order, parents before children.

| Platform | Source | `id` | `label` |
|---|---|---|---|
| Android | `uiautomator dump`. Only nodes on screen are dumped; nodes with no area are dropped | `resource-id` without any `<pkg>:id/` prefix. A Compose `testTag` shows up here when the root sets `testTagsAsResourceId = true` | `text`, else `content-desc` |
| iOS | Appium page source, elements with `visible="true"`. Points are multiplied by `scale` and rounded | `name`, which is the accessibility identifier when one is set (Compose Multiplatform puts the `testTag` there) | `label` |

## Device events

`GET /devices/events` is a [server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
stream (`text/event-stream`) that stays open until the subscriber disconnects. It
sends one event on connect and one each time the list changes, checked every 2
seconds:

```
event: devices
data: {"devices": [{"id", "platform", "model"}], "errors": {}}
```

`data` is the same as the body of `GET /devices`. A failed device listing is an event
with `errors` set, not a dropped connection. A `: keepalive` comment is sent after 15
seconds without an event.

## Actions

The action's name and parameters go in one JSON object, for example
`{"action": "tap", "x": 100, "y": 200}`. Add `"platform": "ios"` or `"android"` to skip
auto-detection. A missing or malformed parameter returns 400 without touching the device.

| Action | Params | Notes |
|---|---|---|
| `tap` | `x, y` | |
| `swipe` | `x1, y1, x2, y2, duration_ms?` | |
| `text` | `text` | |
| `delete` | `count?` | Backspace `count` times |
| `dismiss-keyboard` | | |
| `keyevent` | `code` | Android key code; iOS maps 3, 4 and 66 and skips the rest |
| `launch` | `bundle_id` | |
| `terminate` | `bundle_id` | |
| `clear-data` | `bundle_id` | Android only; iOS returns `value: {skipped}` because data can't be cleared there |
| `unlock` | | Wakes the device; returns `device_locked` on iOS if a passcode is required |

## Migrating from version 1

| Version 1 | Version 2 |
|---|---|
| `{"error": "text"}` | `{"error": {"code", "message"}}` |
| `/frame/<id>`, `/screen/<id>`, `/stream/<id>` | `/devices/<id>/frame`, `/screen`, `/stream` |
| `POST /action` with `udid` | `POST /devices/<id>/actions` |
| `POST /app` with `X-App-UDID` | `POST /devices/<id>/apps` |
| `POST /app` with `op: uninstall` | `DELETE /devices/<id>/apps/<bundle_id>` |
| `POST /record` with `op` | `POST /devices/<id>/recordings`, `POST /recordings/<token>/stop` |
| `GET /video/<token>` | `GET /recordings/<token>/video` |
| `/devices`: `udids`, `android`, `error`, 502 on any failure | `devices`, `errors`, always 200 |
| `/health`: `devices`, `android`, `device_error`; needs the token | Removed, use `/devices`; no token needed |
