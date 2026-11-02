<p align="center">
  <img src="assets/banner.webp" alt="Network Diagnostics — free proxy checker dashboard" width="100%">
</p>

<h1 align="center">👑 Network Diagnostics — Free Proxy Checker & Proxy List Tester</h1>

<p align="center">
  <strong>🚀 Test a proxy list on your own machine. Keep the ones that work. 👑</strong>
</p>

<p align="center">
  <a href="https://github.com/shawonlilo/network-diagnostics/releases"><img src="https://img.shields.io/github/v/release/shawonlilo/network-diagnostics?include_prereleases&label=Release&color=brightgreen" alt="Release v0.2.1"></a>
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20Debian%20%7C%20Android-blue.svg" alt="Platforms: Windows | macOS | Linux | Debian | Android">
  <img src="https://img.shields.io/badge/Free%20proxy%20sources-18-orange.svg" alt="18 free proxy sources">
  <img src="https://img.shields.io/badge/Built%20with-Rust%20%2B%20Tauri-red.svg" alt="Built with Rust + Tauri">
</p>

<p align="center">
  <a href="https://github.com/shawonlilo/network-diagnostics/releases">⬇️ <strong>Download</strong></a> ·
  <a href="#-quick-start">⚡ Quick start</a> ·
  <a href="#-features">✨ Features</a> ·
  <a href="#-thanks--credits">🙏 Thanks</a> ·
  <a href="SOURCES.md">📚 Proxy sources</a> ·
  <a href="CHANGELOG.md">📝 Changelog</a>
</p>

---

A **free, open-source proxy checker** for **HTTP, HTTPS, SOCKS4 and SOCKS5** proxies — for **Windows, macOS, Linux, Debian and Android** 🎉

Check thousands of free proxies **locally** for ⚡ speed, 🕵️ anonymity (**elite / anonymous / transparent**), 🏠 **residential vs 🏢 datacenter**, and 🎯 whether they reach **the site you actually need**. Ships with **18 built-in free proxy list sources** — **67,000+ unique proxies**, fetched fresh at runtime — so you go from zero to a working proxy pool in **two clicks**. No signup. No API key. No cost. Forever. 💚

> 🛡️ **Private by design:** your list is tested from your own device and is **never uploaded** to a third-party checker service.
> ⚖️ Only test proxies and systems you own or are authorized to test.

## 👑 Why this one?

| | |
|---|---|
| 🎯 **Target test** | Most checkers only ping a generic endpoint. This one verifies the proxy reaches **your** site — the only result that matters. |
| 🕵️ **True anonymity grading** | Elite / anonymous / transparent, graded from what the judge endpoint actually sees — not guessed. |
| 🏠 **Residential vs datacenter lanes** | Geo enrichment splits your exports into `residential.txt` and `datacenter.txt`. |
| 📚 **18 sources built in** | One click fetches and merges the best free lists on GitHub, de-duplicated. |
| 🪶 **Featherweight** | The `nd-check` engine is a ~600 KB dependency-free Rust binary. The app is Tauri — megabytes, not hundreds of megabytes. |
| 🔓 **No keys, no accounts** | Nothing to configure. Download, paste, check. |
| 🌍 **Domain health too** | A / MX / SPF / DMARC for any domain, in plain words. |

## ⚡ Quick start

**App:** Download → press **✨ Fetch fresh list** → press **✅ Check proxies** → copy the winners. Done.

**CLI:**

```bash
nd-check fetch --check --geo --target https://example.com --out ./results
# pulls all 18 sources, checks them, splits residential / datacenter lanes
```

## 📥 Install

Grab the current release from the **[Releases page](https://github.com/shawonlilo/network-diagnostics/releases)** 📦

| Platform | File |
|---|---|
| 🪟 Windows | `Network-Diagnostics_x64-setup.exe` or `.msi` |
| 🍎 macOS | `Network-Diagnostics.dmg` (Apple Silicon + Intel) |
| 🐧 Linux | `.AppImage` |
| 🐧 Debian / Ubuntu | `.deb` |
| 🤖 Android | `.apk` (beta) |
| 🐳 Docker / server | `nd-check` CLI image (below) |
| 📱 iOS | Planned: companion mode (UI connects to checks on your own desktop/VPS) — not yet released |

Installers are produced by this repo's **GitHub Actions release factory** 🤖 — every tag builds the CLI for Windows/macOS/Linux and the app for Windows, macOS (×2), Linux/Debian and Android. Born-beta software: shipped early, in the open, with a public issue list — ⭐ it, try it, tell us what breaks!

## ✨ Features

- ✅ **Proxy checking** — HTTP, HTTPS, SOCKS4, SOCKS5, 50 in parallel, sorted by speed
- 🕵️ **Anonymity grading** — elite / anonymous / transparent, in plain words
- 🎯 **Target-site test** — pass/fail against the exact site you need
- 📚 **18 built-in free sources** — 52 lists, runtime-fetched, auto de-duplicated (67,599 unique when last measured)
- 🏠 **Residential / datacenter split** — one toggle, two clean export lanes
- 🌍 **Domain health** — DNS A, MX, SPF, DMARC with a one-line verdict
- 📤 **Clean exports** — working.txt, target_ok.txt, results.json
- 🎨 **Three screens, one job each** — paste → results → export (see [DESIGN.md](DESIGN.md))

## 🖥️ Use it (app)

0. No list handy? Press **✨ Fetch fresh list** — the app pulls the built-in catalog of 18 public free sources (see [SOURCES.md](SOURCES.md)), merges them and removes duplicates. Or paste your own:
1. 📋 Paste your proxy list — one per line. `host:port`, `socks5://host:port`, `user:pass@host:port` all work.
2. 🎯 Optional: type the site you need to reach.
3. ✅ Press **Check proxies**. Working proxies rise to the top, fastest first.
4. 📤 Copy the working ones, or download `.txt` / the full `.json` report.

Anonymity, in plain words:

- 🥷 **elite** — the site cannot tell a proxy is involved.
- 🕵️ **anonymous** — it can tell, but cannot see your IP.
- ⚠️ **transparent** — it can see your real IP. Avoid for private work.

## ⌨️ Use it (CLI / Docker / server)

The same engine ships as a small (600 KB) command-line binary, `nd-check` — handy for scheduled pool refreshes on a VPS:

```bash
nd-check fetch --out ./pool
# pulls all 18 sources at runtime -> pool/candidates.txt (deduped)

nd-check fetch --check --geo --target https://example.com --out ./results
# fetch + check in one run; --geo also splits exports into
# residential.txt / datacenter.txt lanes

nd-check check --file proxies.txt --target https://example.com \
  --threads 50 --out ./results
# writes results.json, working.txt, target_ok.txt

nd-check domain example.com
# A / MX / SPF / DMARC + one-line verdict
```

```bash
docker build -t nd-check .
docker run --rm -v "$PWD:/data" nd-check check --file /data/proxies.txt --out /data/results
```

> 💡 Proxy lists rot fast — a large share of any free list is already dead, and datacenter ranges are blocked by many sites outright. Re-check close to when you use the list, and prefer the 🎯 target test over a generic "alive".

## 🔧 Build from source

```bash
# Engine + CLI (no dependencies beyond a Rust toolchain)
cargo build --release          # produces target/release/nd-check
cargo test                     # DNS wire parsing, grading, list parsing

# Desktop / Android app (Tauri 2)
cd app/src-tauri
cargo tauri build              # installers for your platform
cargo tauri android build      # Android beta (.apk)
```

Linux desktop builds need the usual Tauri system packages
(`libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`).

## 🧠 How it works

```
paste list ─► parse + dedupe ─► nd-core checks (50 parallel)
                                  ├─ HTTP / SOCKS5 / SOCKS4 to a judge endpoint
                                  │    → alive? latency? exit IP?
                                  │    → anonymity from judge-echoed headers
                                  ├─ optional target test (your site, via CONNECT or GET)
                                  └─ optional GeoIP enrichment (app: on by default; CLI: --geo)
                             ─► sorted table ─► copy / .txt / .json
```

The core (`nd-core`) is a dependency-free Rust library 🦀 — the same code powers the app, the CLI and the Docker image. A judge endpoint grades anonymity; use the default or point `--judge` at your own, so your list is only ever seen by infrastructure you control.

## 🎨 Design

One job per screen, three screens total: paste → results → export.
Direction and tokens live in [DESIGN.md](DESIGN.md). Every build is gated in CI by a code-slop scan and a secret scan 🔒 — **no credentials ship in this repo, ever**. Network Diagnostics needs no keys at all.

## 🗺️ Roadmap

- 🏠 Self-hosted judge endpoint (one-command Docker) as the default
- ⚠️ HTTPS interception warnings (proxies that present their own certs)
- 🧰 Subnet calculator + DNS lookup tools
- 📱 iOS companion mode
- ⏰ Scheduled pool refresh profiles in the app (CLI already supports it)

## 📚 Proxy sources

The built-in catalog — TheSpeedX, monosans, ProxyScrape, stormsia, HProxy, proxifly, jetkai, databay, iplocate, roosterkid, clarketm, hookzof, proxmint, relayglass, hideip.me, vakhov, mmpx12, Zaeem20 — is documented with refresh rates and license notes in [SOURCES.md](SOURCES.md). Full credits below 👇

## 🙏 Thanks & credits

**This project stands on the shoulders of the free-proxy community.** 💚 Every source below is fetched at runtime from its publisher — we host nothing of theirs — and we are deeply grateful to each maintainer who keeps these lists alive for everyone, for free. **Thank you!** 🙌

| 🙏 Source | What they give the world |
|---|---|
| [TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List) | The classic — huge HTTP / SOCKS4 / SOCKS5 lists, refreshed ~30 min |
| [monosans/proxy-list](https://github.com/monosans/proxy-list) | Hourly lists, geolocation-enriched |
| [ProxyScrape](https://github.com/ProxyScrape/free-proxy-list) | The free-proxy-list API — HTTP / SOCKS4 / SOCKS5 |
| [stormsia](https://github.com/stormsia) | `working_proxies.txt` — the rare pre-tested list |
| [hproxy-com](https://github.com/hproxy-com) | Aggregated lists, all protocols |
| [proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list) | Clean per-protocol lists, ~5 min refresh |
| [jetkai/proxy-list](https://github.com/jetkai/proxy-list) | Online proxy lists, ~1 h refresh |
| [databay-labs/free-proxy-list](https://github.com/databay-labs/free-proxy-list) | Multi-protocol lists incl. HTTPS |
| [iplocate/free-proxy-list](https://github.com/iplocate/free-proxy-list) | Honest per-protocol lists (SOCKS4 is upstream-limited) |
| [roosterkid/openproxylist](https://github.com/roosterkid/openproxylist) | Big all-protocol lists |
| [clarketm/proxy-list](https://github.com/clarketm/proxy-list) | The long-running daily list |
| [hookzof/socks5_list](https://github.com/hookzof/socks5_list) | Pure SOCKS5, updated very frequently |
| [Proxmint](https://github.com/Proxmint/free-proxy-list) | Aggregated lists + implementation notes |
| [relayglass](https://github.com/relayglass/free-proxy-list) | Simple per-protocol lists |
| [zloi-user/hideip.me](https://github.com/zloi-user/hideip.me) | Country-tagged lists ✨ (added from the community, 0.2.0) |
| [vakhov/fresh-proxy-list](https://github.com/vakhov/fresh-proxy-list) | Fresh per-protocol lists ✨ (0.2.0) |
| [mmpx12/proxy-list](https://github.com/mmpx12/proxy-list) | Fresh aggregated lists ✨ (0.2.0) |
| [Zaeem20/FREE_PROXIES_LIST](https://github.com/Zaeem20/FREE_PROXIES_LIST) | Fresh aggregated lists ✨ (0.2.0) |

🧰 **Tools & ideas we learned from:** [mubeng](https://github.com/mubeng/mubeng) (fast checker in Go), [monosans/proxy-scraper-checker](https://github.com/monosans/proxy-scraper-checker), [proxybd](https://github.com/fahimscirex/proxybd), and the design bar set by HProxy, ProxyReaper and Networking Toolbox. 🌟

🦀 **Built with:** [Rust](https://www.rust-lang.org/), [Tauri 2](https://tauri.app/), and the original checklist logic from Shawon's own `gab_proxy.py` "Perfect Version".

Full source review — including every repository we evaluated — lives in [THANKS.md](THANKS.md) and [SOURCES.md](SOURCES.md). If we use your work and missed you, open an issue and we'll fix it with pride. 💚

## 📄 License

MIT. Built with an AI-assisted, beta-first workflow ("born beta"): issues and pull requests welcome 🤝

---

<sub>free proxy · proxy checker · free proxy list · proxy tester · socks5 proxy · socks4 proxy · http proxy · https proxy · proxy list · free proxies · proxy scraper · working proxies · elite proxy · anonymous proxy · residential proxy · proxy checker online alternative · open source proxy tool</sub>
