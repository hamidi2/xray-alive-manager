# Xray Alive Manager

A desktop GUI + a CLI collector for keeping your Xray proxy fed with **verified-alive links**.

## What's inside

| Tool | What it does |
|---|---|
| **`xray_manager/`** (GUI) | Qt desktop app to manage your xray `config.json`: list connections with live status & ping, add share links, prioritize, enable/disable, save & restart the service |
| **`collect_alive.py`** (CLI) | Scans every file in a folder (any extension, plus base64 subscription blobs), extracts share links, tests them repeatedly through a real xray tunnel, and emits `alive_links.txt` + a ready `alive_config.json` with **auto-failover** |

## Requirements

- Python 3.8+
- **PyQt6** or **PySide6** for the GUI (`pip install PyQt6` — the CLI script doesn't need Qt)
- The `xray` binary (auto-detected; set a custom path in the app's Settings menu)
- `curl` (used for the real request through each tunnel)

## GUI

```bash
./run.sh          # or: python3 -m xray_manager
```

Features:

- **Connections table**: priority order, name, protocol, address:port, which local inbound ports route to it, status (🟢 alive / 🔴 dead / ⏳ testing), ping time
- **Real tunnel testing**: for every connection a temporary xray instance is started and a real HTTP request is sent through the tunnel — not just a TCP ping. Failure reasons (e.g. `websocket: bad handshake`) are shown as a tooltip on the status cell
- **Add links**: paste `vless://` / `vmess://` / `trojan://` / `ss://` links (multiple at once). Adding triggers a fresh test round
- **Prioritize**: move connections up/down; the order is written to the config
- **Enable/disable**: checkbox per row; disabled connections are kept in `~/.config/xray-manager/state.json`, not lost
- **Rename** (double-click), **copy link**, **delete**, right-click context menu
- **Save & restart service**: automatic backup first (last 10 kept), then `systemctl restart xray` — the **user service** (`systemctl --user`) is used automatically when the config lives in your home directory (no root needed)
- **Link box**: click any row to see its full share link; one click to copy
- Status column colors; `Test all` shows live progress and a final summary (alive/dead counts)

## CLI collector

```bash
python3 collect_alive.py                 # scan current folder
python3 collect_alive.py ~/mylinks -n 3  # custom folder, 3 attempts per link
python3 collect_alive.py --strict        # keep only links alive in the majority of attempts
```

How it works:

1. Reads every file (any extension; files >5 MB skipped), decodes pure-base64 subscription files
2. Extracts unique share links
3. Tests each link `n` times through a real temporary xray tunnel (4 workers in parallel)
4. Keeps every link that succeeded **at least once** (survives flaky servers with poor ping)
5. Sorts survivors by success rate, then by speed
6. Writes:
   - **`alive_links.txt`** — the live links with per-link stats
   - **`alive_config.json`** — a ready xray config where all live outbounds are behind a **`leastPing` balancer** + a **burst observatory** that pings every node every 2 minutes. The xray service then automatically routes traffic to the fastest healthy node — no external tooling needed

Your original files are never modified; outputs are separate files.

## Notes

- The config path is configurable in the app (default `/usr/local/etc/xray/config.json`)
- State (disabled links, custom names) lives in `~/.config/xray-manager/state.json`
- If the config path is inside your home directory, the app treats it as a **user service** and uses `systemctl --user` for status/restart — useful when xray runs without root

## License

MIT
