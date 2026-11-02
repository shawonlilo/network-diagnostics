# Changelog

All notable changes to Network Diagnostics, version by version.
This project follows [Semantic Versioning](https://semver.org) and a
"born beta" workflow: early public versions, honest changelogs.

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
