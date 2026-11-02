# Proxy sources

Network Diagnostics does **not** bundle proxy data. The app and CLI fetch
public free lists **at runtime, from your own machine**, merge them, and
remove duplicates — on 2026-11-02 the catalog below produced **67,599
unique candidates from 52 files**. Expect most of them to be dead; that is
what the checker is for. Lists rot within hours, so fetch close to when
you check.

Rules the catalog follows:

- Only lists published for **free programmatic use** (raw files, official
  free APIs). No logins, no API keys, no paywalls, no scraping of HTML.
- Every source is **credited here and in [THANKS.md](THANKS.md)**, with
  its license noted where the project states one. Data fetched at runtime
  remains under its source's terms — we redistribute nothing.
- Files are fetched over HTTPS via the system `curl`. Checking itself
  speaks the raw proxy protocols and never touches these sites.
- Safety: a free proxy is an open relay run by a stranger. Never send
  passwords, cookies, or anything sensitive through one.

## Built-in catalog (18 sources, all URLs verified live 2026-11-02)

| Source | Protocols | Refresh | Notes |
|---|---|---|---|
| [TheSpeedX/PROXY-List](https://github.com/TheSpeedX/PROXY-List) | HTTP, SOCKS4, SOCKS5 | ~daily | The original checker's source; ~7,300 raw entries |
| [monosans/proxy-list](https://github.com/monosans/proxy-list) | HTTP, SOCKS4, SOCKS5 | hourly | MIT; re-checked hourly, fastest first |
| [ProxyScrape free API](https://github.com/proxyscrape/free-proxy-list) | HTTP, HTTPS, SOCKS4, SOCKS5 | every minute | Official free v4 API + GitHub mirror |
| [stormsia/proxy-list](https://github.com/stormsia/proxy-list) | all four | 15 min | ASN metadata; known for ISP/residential entries that pass strict sites |
| [hproxy-com/free-proxy-list](https://github.com/hproxy-com/free-proxy-list) | all four | several×/day | Aggregates 100+ public sources, re-tested around the clock |
| [proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list) | all four | 5 min | GPL-3.0 data — fetched at runtime only, never bundled |
| [jetkai/proxy-list](https://github.com/jetkai/proxy-list) | all four | hourly | Only proxies online at test time |
| [databay-labs/free-proxy-list](https://github.com/databay-labs/free-proxy-list) | all four | 5 min | 10k+ endpoints, HTTPS-validated, by-country files |
| [iplocate/free-proxy-list](https://github.com/iplocate/free-proxy-list) | all four | 30 min | Highest measured live rate in independent testing (Jul 2026) |
| [roosterkid/openproxylist](https://github.com/roosterkid/openproxylist) | HTTPS, SOCKS4, SOCKS5 | hourly | |
| [clarketm/proxy-list](https://github.com/clarketm/proxy-list) | HTTP | daily | Long-running classic list |
| [hookzof/socks5_list](https://github.com/hookzof/socks5_list) | SOCKS5 | auto | SOCKS5 specialist |
| [proxmint/free-proxy-list](https://github.com/proxmint/free-proxy-list) | HTTP, SOCKS4, SOCKS5 | 30 min | Every entry re-tested by a real request |
| [relayglass/free-proxy-list](https://github.com/relayglass/free-proxy-list) | HTTP, HTTPS, SOCKS5 | 5 min | Checked against its own test server |
| [zloi-user/hideip.me](https://github.com/zloi-user/hideip.me) | all four | — | hideip.me lists mirrored to GitHub |
| [vakhov/fresh-proxy-list](https://github.com/vakhov/fresh-proxy-list) | all four | — | Also publishes JSON/CSV |
| [mmpx12/proxy-list](https://github.com/mmpx12/proxy-list) | all four | — | Tor exit-node file deliberately excluded — Tor exits are not proxies |
| [Zaeem20/FREE_PROXIES_LIST](https://github.com/Zaeem20/FREE_PROXIES_LIST) | all four | — | Per-protocol files |

Researched but not wired yet: **Geonode** free API (JSON format with
uptime/ASN filters — needs a JSON source adapter).

## Owner-submitted links, reviewed 2026-11-02

The project owner submitted 31 links for this catalog. Each one was
checked against a simple rule: *is it a machine-readable list of open
IP:PORT proxies (HTTP / HTTPS / SOCKS4 / SOCKS5) that this checker can
fetch and test?*

- **Added as fetch sources (5):** zloi-user/hideip.me,
  vakhov/fresh-proxy-list, mmpx12/proxy-list, Zaeem20/FREE_PROXIES_LIST,
  and gfpcom/free-proxy-list — *correction:* gfpcom's `sources/*.txt`
  turned out to be a registry of upstream URLs rather than proxy data,
  so gfpcom is **credited below, not fetched**. Net new fetch sources: 4,
  taking the catalog from 14 to 18.
- **Already in the catalog (4):** TheSpeedX/PROXY-List,
  proxifly/free-proxy-list, hookzof/socks5_list, monosans/proxy-list.
- **Related tools — credited, not sources (3):** mubeng/mubeng (proxy
  checker/rotator), monosans/proxy-scraper-checker (the generator behind
  monosans/proxy-list), fahimscirex/proxybd (a scraper script; it
  publishes no static list files to fetch).
- **Not added (19) — different protocol family:** the V2Ray / Xray /
  WireGuard ecosystem — v2rayN, Nekoray, Throne, Hiddify (Manager, app,
  hiddify.com), XTLS/Xray-core, MHSanaei/3x-ui, wg-easy, the xray and
  wireguard-ui topic pages, and the config-subscription collections
  (ClashX-V2Ray-TopFreeProxy, freenodes, Epodonios/v2ray-configs,
  V2RayAggregator, TGParse, Alvin9999/new-pac, 1234567Yang/cf-proxy-ex).
  These distribute encrypted **config subscriptions**
  (VMess/VLESS/Trojan/Shadowsocks/WireGuard) for client apps — there is
  no IP:PORT endpoint for a proxy checker to test, and many entries are
  shared private nodes. A config-client is a different product; if it is
  ever built, these projects are its foundation and will be credited
  there.
