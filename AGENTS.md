# AGENTS.md — MonkeyTester-Plugin-Mobile-Controller

## Purpose
The device-control backend for MonkeyTester: runs on a Mac (`device_controller.py`, :8090), owns
every iPhone and Android phone, and exposes them over HTTP. It knows nothing about tests or vision
models. See README.md (setup), ARCHITECTURE.md (design), API.md (the HTTP contract) and
SECURITY.md (threat model).

## Setup (do this first)
README.md → **Setup** is the single source for dependencies: Python standard library for the
service, plus Xcode, Appium with the XCUITest driver, Android platform-tools and ffmpeg on the Mac.

## Tests
`python3 -m unittest discover tests`. They need ffmpeg with libx264 and use `tests/fake_adb.py`
instead of a phone; iOS paths that need Appium are mocked.

## Hosting and review workflow
This repo isn't tied to one code host: it can live on GitHub, Gitea/Forgejo, GitLab, Bitbucket or a
mirror. Find the host from the remote you were asked to work against (`git remote -v`, usually
`origin`) and use that host's tools; the docs never assume one.

| Remote host | Review is called | CLI |
|---|---|---|
| github.com or GitHub Enterprise | pull request | `gh pr create` |
| Gitea / Forgejo | pull request | `tea pr create` |
| GitLab | merge request | `glab mr create` |
| Bitbucket | pull request | web UI or REST API |

- `master` changes only through a reviewed PR/MR that a maintainer merges. Never push to `master`
  and never merge your own PR/MR.
- Work on a feature branch in its own git worktree, based on the remote's `master`.
- CI is in `.github/workflows/`, which both GitHub Actions and Gitea Actions run. Its test job runs the same command as `python3 -m unittest discover tests`; on a host without Actions, run that locally before opening the PR/MR.
- In docs, name sibling repos (e.g. MonkeyTester-Plugin-AI) instead of linking a host URL, link
  files in this repo with relative paths, and stick to CommonMark plus GFM tables and code
  fences (no host-only syntax such as `> [!NOTE]` callouts or `#123` autolinks).
