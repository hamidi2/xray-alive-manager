"""Read/write the xray service config.json + connection management."""
from __future__ import annotations

import json
import os
import shutil
import time

BUILTIN_PROTOCOLS = ("freedom", "blackhole", "dns", "http", "socks", "wireguard", "loopback")
USER_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")


def find_xray(explicit: str = "") -> str:
    if explicit and os.path.isfile(explicit):
        return explicit
    for cand in ("xray", "/usr/local/bin/xray", "/usr/bin/xray"):
        found = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if found:
            return found
    return ""


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def user_outbounds(config: dict) -> list[dict]:
    """Only user-facing proxy outbounds (not freedom/blackhole/...), in priority order."""
    return [o for o in config.get("outbounds", []) if o.get("protocol") in USER_PROTOCOLS]


def serving_ports(config: dict, tag: str) -> str:
    """Which local inbound ports route to this outbound, based on routing rules."""
    inbound_ports = {i.get("tag"): str(i.get("port")) for i in config.get("inbounds", []) if i.get("port")}
    ports, catch_all = [], False
    for rule in config.get("routing", {}).get("rules", []):
        if rule.get("outboundTag") != tag:
            continue
        if rule.get("inboundTag"):
            for it in rule["inboundTag"]:
                if it in inbound_ports and inbound_ports[it] not in ports:
                    ports.append(inbound_ports[it])
        elif rule.get("port"):
            for p in str(rule["port"]).split(","):
                p = p.strip()
                if p and p not in ports:
                    ports.append(p)
        else:
            catch_all = True  # unconstrained rule = all traffic
    joiner = ", "
    if ports:
        return joiner.join(ports) + (" (all traffic)" if catch_all else "")
    if catch_all:
        return f"all traffic ({joiner.join(inbound_ports.values())})"
    # no rule references it; if it is the first user outbound, it is the default
    users = [o.get("tag") for o in config.get("outbounds", []) if o.get("protocol") in USER_PROTOCOLS]
    if users and users[0] == tag:
        return "default (no rule)"
    return "—"


def backup_config(path: str, keep: int = 10) -> str:
    dest = f"{path}.bak-manager-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, dest)
    # keep at most the last `keep` backups
    import glob
    baks = sorted(glob.glob(f"{path}.bak-manager-*"))
    for old in baks[:-keep]:
        try:
            os.remove(old)
        except OSError:
            pass
    return dest


def build_config(config: dict, outbounds: list[dict]) -> dict:
    """New config: user outbounds in priority order + everything else untouched."""
    new = dict(config)
    others = [o for o in config.get("outbounds", []) if o.get("protocol") not in USER_PROTOCOLS]
    # priority: the first user outbound stays at the top as the default
    new["outbounds"] = outbounds + others
    for o in new["outbounds"]:
        o.pop("_key", None)  # internal key is never written to the file
    return new


def save_config(path: str, config: dict) -> str:
    backup_config(path)
    tmp = path + ".tmp-manager"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return path


def is_user_config(path: str) -> bool:
    """Does this config belong to the user-level service (inside home)?"""
    return path.startswith(os.path.expanduser("~"))


def service_action(action: str, user: bool = False) -> tuple[bool, str]:
    """Run systemctl (restart/stop/start) on the xray service (system or user)."""
    import subprocess

    base = ["systemctl"] + (["--user"] if user else []) + [action, "xray"]
    # user service needs no root; system service is tried via pkexec/sudo first
    prefixes = [[]] if user else [["pkexec"], ["sudo", "-n"], []]
    last_err = "not allowed to run systemctl"
    for prefix in prefixes:
        cmd = prefix + base
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return False, "systemctl timed out"
        if r.returncode == 0:
            return True, r.stdout.strip() or "done"
        err = (r.stderr or r.stdout).strip()
        if err:
            last_err = err
    return False, last_err
