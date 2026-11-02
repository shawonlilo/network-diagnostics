---
name: Network Diagnostics
version: 0.1.0
colors:
  bg: "#0e1116"
  surface: "#161b22"
  border: "#2a3140"
  text: "#e8ecf1"
  muted: "#8b94a3"
  accent: "#3fb950"
  warn: "#d29922"
  danger: "#f85149"
typography:
  font-family: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
  base-size: "15px"
  mono: "ui-monospace, 'Cascadia Mono', Consolas, monospace"
spacing:
  unit: 8px
  radius: 10px
---

# Network Diagnostics — design direction

One job per screen. Three screens total: **Paste → Results → Export**.

- The first screen is a single large paste box, one optional field
  ("Site I need to reach"), and one big **Check proxies** button.
  Nothing else competes with it.
- Results stream into a table; working proxies rise to the top.
  Columns a person actually reads: status dot, speed, type, anonymity,
  country, exit IP. Everything else lives in an expandable row.
- Anonymity is a word, not a code: **elite / anonymous / transparent**,
  with a one-line plain-English explainer under the table.
- Colors mean things and nothing else: green = works, amber = works with
  caveats (transparent), red = dead, grey = not checked yet.
- No gradients, no glass, no stock imagery, no emoji UI. System font.
  Dark theme only in v0.1 — it is a tool people run next to terminals.
- Every action reachable in ≤3 clicks: paste → check → copy/download.
- Buttons say what happens: "Copy working proxies", "Download .txt",
  "Download full report (.json)". Never "Submit" or "OK".
