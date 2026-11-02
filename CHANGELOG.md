# Changelog

All notable changes to Network Diagnostics, version by version.
This project follows [Semantic Versioning](https://semver.org) and a
"born beta" workflow: early public versions, honest changelogs.

## [0.3.2] — 2026-11-02 — Android actually works now 📱

- **The Fetch button was dead on Android — fixed at the root.**
  Source fetching shelled out to the system `curl`, which Android
  does not have (the Windows PowerShell fallback was equally absent).
  Fetching is now **in-process HTTPS (ureq + rustls)** — identical on
  every platform, no system tools. Verified end-to-end: 52/52 source
  files, ~69,800 unique proxies. `curl` remains only as a desktop
  fallback for TLS-intercepting corporate proxies, and the standard
  `HTTPS_PROXY` env vars are honoured.
- **Android is now a real release build.** v0.3.1's APK was a debug
  build — unoptimized and 443 MB. This one is release-profile,
  stripped, arm64-only (every modern phone), signed in CI for
  sideloading, and named `network-diagnostics-android.apk`.
  Expect a fraction of the size and native speed.
- **Phone UI pass:** 44px tap targets, two-column stats, larger
  hero button, 16px inputs (no focus auto-zoom).

## [0.3.1] — 2026-11-02 — Android arrives 🤖

- **Android APK fixed.** Every Android build up to now failed in CI
  with `no library targets found in package` — the app crate was a
  desktop-style binary-only crate, and Tauri mobile builds require a
  library target. The app is restructured the standard Tauri 2 way:
  logic in `lib.rs` (`mobile_entry_point`), `main.rs` is a thin shim.
  Desktop builds are unchanged.
- The APK is **debug-signed** so it installs directly (sideload):
  `app-universal-debug.apk`. Note the CI debug key changes per build,
  so installing a newer APK over an older one may require uninstalling
  the old app first — proper release signing is on the roadmap.
- The Android CI job now attaches the APK to the release directly.

## [0.3.0] — 2026-11-02 — The GUI grows up 👑

- **New dashboard GUI.** The first screen is now built around one hero
  action — **⚡ GET FREE PROXIES** — which fetches the 18 built-in
  sources and (with auto-check on) immediately starts checking.
  Live stats (fetched / checked / working / elite / residential /
  fastest), a real progress bar, filter chips, anonymity and
  residential/datacenter badges, speed bars, and one-click exports
  (working / residential / datacenter / full JSON).
- **Batched checking with progress.** Lists are checked in chunks of
  200 with results streaming into the table and a Stop button, instead
  of one silent wait. Fetched lists are capped at 6,000 for a check
  run so a session stays practical.
- **Windows fetch fallback.** If `curl.exe` is missing, source
  fetching falls back to PowerShell's Invoke-WebRequest.
- CLI release assets are now named per platform
  (`nd-check-linux-x64`, `nd-check-macos-arm64`,
  `nd-check-windows-x64.exe`) — no more shared-name overwrite.

## [0.2.3] — 2026-11-02 — The actual root cause

- The workflow was missing its top-level `permissions: contents: write`
  block (lost when the file was first generated). Without it, the
  Actions token is read-only in this repository, so **every** release
  create/upload from CI failed with 403 "Resource not accessible by
  integration" — while artifact uploads (a different mechanism) kept
  working, which masked the cause through three releases. Fixed.

## [0.2.2] — 2026-11-02 — Release factory, fixed for real

Root causes found in the actual CI logs (not guessed):

- The Tauri action was never given its release inputs, so it built
  every installer and then logged "No releaseId or tagName provided,
  skipping all uploads..." — the inputs are now set, and bundles are
  also kept as workflow artifacts as a safety net.
- `bundle.icon` was missing from tauri.conf.json, which killed the
  Windows build at the MSI/NSIS step ("Couldn't find a .ico icon").
  The icon set is now declared, and icon.ico is a proper multi-size
  ICO (16→256 px).
- The CLI release-attach step looked up the tag by its full git ref
  and then failed to create the release (403); it now passes the
  explicit tag name and attaches to the existing release.
- Android: the setup-android action's sdkmanager call fails on
  current runner images ("Failed to find package 'tools'"); the job
  now uses the runner's preinstalled SDK directly.

## [0.2.1] — 2026-11-02 — Release-assets fix

- Fixed the Tauri app build: the app crate now declares its own
  workspace (the parent workspace excludes it), curing the
  `cargo metadata` failure that broke every desktop and Android CI job
  for 0.2.0 — installers now build and attach to the release.
- CLI binaries are now attached to the GitHub release as well as kept
  as workflow artifacts.
- Android CI now installs the NDK explicitly.

## [0.2.0] — 2026-11-02 — Source Engine

- **18 built-in free proxy sources** (52 files), fetched at runtime from
  the user's machine — nothing bundled, everything credited in
  SOURCES.md. Measured live: **67,599 unique proxies** after
  de-duplication.
- CLI: `nd-check fetch` pulls and merges the catalog; `fetch --check`
  tests the whole pool in one run.
- App: **Fetch fresh list** button; residential/datacenter classification
  on by default, with a Network column in results.
- `--geo` checks now export separate `residential.txt` and
  `datacenter.txt` lanes.
- Tolerant list parser: `host:port:Country` style lists (e.g. hideip.me)
  now parse instead of being dropped.
- Owner link review: 31 submitted repositories classified in SOURCES.md
  (added / already present / tools credited / different protocol family).

## [0.1.0] — 2026-11-02 — First beta

- `nd-core`: dependency-free Rust engine — HTTP / SOCKS5 / SOCKS4 proxy
  checking over raw sockets, anonymity grading (elite / anonymous /
  transparent) against a judge endpoint, target-site compatibility test,
  optional GeoIP enrichment.
- Domain health: A / MX / SPF / DMARC via raw DNS wire queries.
- `nd-check` CLI (~600 KB): batch checking with `results.json`,
  `working.txt`, `target_ok.txt` exports.
- Tauri 2 desktop/mobile app shell with the 3-screen UI
  (Paste → Results → Export) and DESIGN.md design system.
- Release factory: GitHub Actions builds for Windows, macOS, Linux,
  Debian and Android, gated by tests and a secret scan.
- Verified end-to-end against local fixtures (judge + transparent /
  anonymous / elite proxies): all anonymity grades correct.
