#!/usr/bin/env python3
"""collect_alive.py — collect live links from every file in a folder

Scans all files (any extension), extracts vless/vmess/trojan/ss links, tests each
one several times through a real xray tunnel, and writes the survivors — sorted
by success rate and speed — to `alive_links.txt`. It also generates
`alive_config.json`: a ready-to-use xray config where the live outbounds are
backed by a leastPing balancer + a burst observatory, so the xray service itself
keeps prioritizing the fastest healthy node without any extra tooling.

Examples:
    python3 collect_alive.py                  # scan current folder
    python3 collect_alive.py ~/links -n 3 -o out
    python3 collect_alive.py --strict         # keep only majority-alive links
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xray_manager import config_io, link_parser, tester

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>\\]+", re.IGNORECASE)
B64_RE = re.compile(r"^[A-Za-z0-9+/_=\-\s]{40,}$")
OUT_LINKS = "alive_links.txt"
OUT_CONFIG = "alive_config.json"


def iter_texts(path: str):
    """Yield the file's text content + (if the file is pure base64) its decoded form."""
    try:
        if os.path.getsize(path) > 5 * 1024 * 1024:
            return
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", errors="ignore")
        yield text
        # subscription files that are entirely a base64-encoded list of links
        for line in text.splitlines():
            line = line.strip()
            if len(line) >= 40 and B64_RE.match(line) and "://" not in line:
                try:
                    yield base64.b64decode(line.replace("-", "+").replace("_", "/") + "===", validate=False).decode("utf-8", errors="ignore")
                except Exception:  # noqa: BLE001
                    pass
    except OSError:
        return


def extract_links(path: str) -> set[str]:
    links: set[str] = set()
    for text in iter_texts(path):
        for m in LINK_RE.findall(text):
            links.add(m.rstrip(".,;)]}»\""))
    return links


def test_link(args: tuple) -> dict | None:
    """Test one link N times; return its success rate + best ping."""
    link, attempts, strict, timeout, xbin, test_url = args
    try:
        ob = link_parser.parse_link(link)
    except ValueError:
        return None
    ob.pop("_key", None)
    ok = 0
    best_ping, last_err = None, ""
    for i in range(attempts):
        if i:
            import time
            time.sleep(0.3)
        r = tester._attempt(xbin, ob, test_url, timeout)
        if r["ok"]:
            ok += 1
            if best_ping is None or (r["ping_ms"] or 1 << 30) < best_ping:
                best_ping = r["ping_ms"]
        elif not last_err:
            last_err = r["error"]
    rate = ok / attempts
    if rate == 0 or (strict and rate <= 0.5):
        return None
    return {"link": link, "name": link_parser._finalize(ob).get("tag", "?"),
            "ok": ok, "attempts": attempts, "rate": rate,
            "ping": best_ping, "outbound": ob}


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect live links from files in a folder")
    ap.add_argument("folder", nargs="?", default=".", help="folder to scan (default: current)")
    ap.add_argument("-n", type=int, default=3, help="test attempts per link (default 3)")
    ap.add_argument("-o", default=None, help="output folder (default: same as scanned folder)")
    ap.add_argument("--strict", action="store_true", help="keep only links alive in the majority of attempts")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--workers", type=int, default=4, help="concurrent tests (default 4)")
    args = ap.parse_args()

    folder = os.path.abspath(args.folder)
    outdir = os.path.abspath(args.o) if args.o else folder
    os.makedirs(outdir, exist_ok=True)

    xbin = config_io.find_xray()
    if not xbin:
        print("Error: xray binary not found.", file=sys.stderr)
        return 1
    test_url = "https://www.gstatic.com/generate_204"

    # --- extraction ---
    all_links: dict[str, str] = {}
    n_files = 0
    for root, dirs, files in os.walk(folder):
        for fn in files:
            if fn in (OUT_LINKS, OUT_CONFIG):
                continue
            p = os.path.join(root, fn)
            n_files += 1
            for link in extract_links(p):
                all_links.setdefault(link, p)
    print(f"Scanned {n_files} files — found {len(all_links)} unique links.")

    if not all_links:
        print("No links found.")
        return 0

    # --- testing ---
    jobs = [(link, args.n, args.strict, args.timeout, xbin, test_url) for link in all_links]
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, res in enumerate(ex.map(test_link, jobs), 1):
            if res:
                results.append(res)
            print(f"\rTesting: {i}/{len(jobs)} — alive: {len(results)}   ", end="", flush=True)
    print()

    # --- sort: higher success rate first, then lower ping ---
    results.sort(key=lambda r: (-r["rate"], r["ping"] if r["ping"] is not None else 1 << 30))

    # --- links output ---
    links_path = os.path.join(outdir, OUT_LINKS)
    with open(links_path, "w", encoding="utf-8") as f:
        f.write("# Live links — sorted by success rate and speed\n")
        for r in results:
            ping = f"{r['ping']}ms" if r["ping"] is not None else "—"
            f.write(f"# {r['name']}  [{r['ok']}/{r['attempts']} ok, {ping}]\n{r['link']}\n")

    # --- ready-to-use xray config with priority order ---
    try:
        base_cfg = config_io.load_config("/usr/local/etc/xray/config.json")
    except (OSError, json.JSONDecodeError):
        base_cfg = {"log": {"loglevel": "warning"}, "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {}}],
            "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]}}
    new_cfg = dict(base_cfg)
    proxy_tags = [r["outbound"]["tag"] for r in results]
    new_cfg["outbounds"] = [r["outbound"] for r in results] + [
        o for o in base_cfg.get("outbounds", []) if o.get("protocol") not in config_io.USER_PROTOCOLS]
    # balancer + observatory: xray pings every node every 2 minutes and always
    # sends traffic to the fastest healthy one — no external tooling needed
    new_cfg["routing"] = dict(new_cfg.get("routing", {}))
    new_cfg["routing"]["balancers"] = [
        {"tag": "pool", "selector": proxy_tags, "strategy": {"type": "leastPing"}}]
    new_cfg["routing"]["rules"] = [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp", "balancerTag": "pool"}]
    new_cfg["burstObservatory"] = {
        "subjectSelector": proxy_tags,
        "pingConfig": {"destination": test_url, "connectivity": test_url,
                       "interval": "2m", "sampling": 3, "timeout": "5s"}}
    cfg_path = os.path.join(outdir, OUT_CONFIG)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(new_cfg, f, ensure_ascii=False, indent=2)

    print(f"\n✅ {len(results)} live links → {links_path}")
    print(f"   ready config with auto-failover → {cfg_path}")
    print("   (your old files are untouched; the outputs are separate files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
