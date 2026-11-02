# Network Diagnostics

**Test a proxy list on your own machine. Keep the ones that work.**

Paste any list of proxies and Network Diagnostics checks every one locally:
live status, protocol, speed, anonymity level, and exit IP. HTTP, HTTPS,
SOCKS4 and SOCKS5. Then — the part most checkers skip — it can test the
working proxies against **the specific site you need to reach**, because a
proxy that answers a generic test can still be blocked by your target.

It also checks **domain health**: A records, MX, SPF and DMARC in one pass,
in plain words.

Free and open source (MIT). No account. No list uploads — your proxies are
tested from your device, where they will actually be used, and are never
sent to a third-party checker service.

> Only test proxies and systems you own or are authorized to test.

## Install

Download the current beta from the Releases page:

| Platform | File |
|---|---|
| Windows | `Network-Diagnostics_x64-setup.exe` or `.msi` |
| macOS | `Network-Diagnostics.dmg` (Apple Silicon + Intel) |
| Linux | `.AppImage` |
| Debian / Ubuntu | `.deb` |
| Android | `.apk` (beta) |
| iOS | Companion mode (beta): UI connects to checks running on your own desktop/VPS |
| Docker / server | `docker run` image with the `nd-check` CLI (below) |

These installers are produced by the GitHub Actions release workflow in
this repo. Version 0.1.x is a **born-beta** release: shipped early, in the
open, with a public issue list.

## Use it (app)

1. Paste your proxy list — one per line. `host:port`,
   `socks5://host:port`, `user:pass@host:port` all work.
2. Optional: type the site you need to reach.
3. Press **Check proxies**. Working proxies rise to the top.
4. Copy the working ones, or download them as `.txt` / the full report as
   `.json`.

Anonymity, in plain words:

- **elite** — the site cannot tell a proxy is involved.
- **anonymous** — it can tell, but cannot see your IP.
- **transparent** — it can see your real IP. Avoid for private work.

## Use it (CLI / Docker / server)

The same engine ships as a small (600 KB) command-line binary, `nd-check` —
handy for scheduled pool refreshes on a VPS:

```bash
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

Proxy lists rot fast — a large share of any free list is already dead, and
datacenter ranges are blocked by many sites outright. Re-check close to
when you use the list, and prefer the target test over a generic "alive".

## Build from source

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

## How it works

```
paste list ─► parse + dedupe ─► nd-core checks (50 parallel)
                                  ├─ HTTP / SOCKS5 / SOCKS4 to a judge endpoint
                                  │    → alive? latency? exit IP?
                                  │    → anonymity from judge-echoed headers
                                  ├─ optional target test (your site, via CONNECT or GET)
                                  └─ optional GeoIP enrichment (off by default)
                             ─► sorted table ─► copy / .txt / .json
```

The core (`nd-core`) is a dependency-free Rust library — the same code
powers the app, the CLI and the Docker image. A judge endpoint grades
anonymity; use the default or point `--judge` at your own so your list is
only ever seen by infrastructure you control.

## Design

One job per screen, three screens total: paste → results → export.
Direction and tokens live in [DESIGN.md](DESIGN.md). Every build is gated
in CI by a code-slop scan and a secret scan — no credentials ship in this
repo, ever. Services that need keys elsewhere in the suite take the
user's own keys, stored in the OS keychain — not here: Network
Diagnostics needs no keys at all.

## Roadmap

- [ ] Self-hosted judge endpoint (one-command Docker) as the default
- [ ] HTTPS interception warnings (proxies that present their own certs)
- [ ] Subnet calculator + DNS lookup tools (Networking Toolbox pattern)
- [ ] iOS companion mode
- [ ] Scheduled pool refresh profiles in the app (CLI already supports it)

## License

MIT. Built with an AI-assisted, beta-first workflow ("born beta"):
issues and pull requests welcome.
