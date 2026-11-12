"""Persist per-connection state (disabled set, custom names, settings) outside config.json."""
from __future__ import annotations

import json
import os

STATE_DIR = os.path.expanduser("~/.config/xray-manager")
STATE_FILE = os.path.join(STATE_DIR, "state.json")

DEFAULTS = {
    "config_path": "/usr/local/etc/xray/config.json",
    "xray_binary": "",          # empty = auto-detect
    "test_url": "https://www.gstatic.com/generate_204",
    "test_timeout": 10,
    "auto_interval": 120,       # auto re-test interval (seconds)
    "disabled": [],             # keys of disabled connections
    "renames": {},              # key -> custom name
}


class State:
    def __init__(self):
        self.data = dict(DEFAULTS)
        self.load()

    def load(self):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                saved = json.load(f)
            self.data.update(saved)
        except (OSError, json.JSONDecodeError):
            pass

    def save(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    # --- each connection is identified by a stable key ---
    def is_disabled(self, key: str) -> bool:
        return key in self.data["disabled"]

    def set_disabled(self, key: str, disabled: bool):
        lst = self.data["disabled"]
        if disabled and key not in lst:
            lst.append(key)
        elif not disabled and key in lst:
            lst.remove(key)
        self.save()

    def display_name(self, outbound: dict) -> str:
        return self.data["renames"].get(outbound["_key"], outbound.get("tag", "?"))

    def set_name(self, key: str, name: str):
        self.data["renames"][key] = name
        self.save()
