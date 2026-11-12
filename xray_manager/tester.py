"""Real liveness/ping testing: a temporary xray instance with the target outbound is
started and a real HTTP request is sent through the tunnel (socks)."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_outbound(xray_bin: str, outbound: dict, test_url: str, timeout: int, attempts: int = 2) -> dict:
    """Multi-attempt test: alive if at least one attempt succeeds (ping = best),
    dead only if every attempt fails. Returns {'ok': bool, 'ping_ms': int|None, 'error': str}."""
    best: dict | None = None
    for i in range(attempts):
        if i:
            time.sleep(0.5)  # short pause between attempts
        r = _attempt(xray_bin, outbound, test_url, timeout)
        if r["ok"]:
            # success always beats failure; among successes pick the lower ping
            if best is None or not best["ok"] or (r["ping_ms"] or 0) < (best["ping_ms"] or 1 << 30):
                best = r
        elif best is None:
            best = r  # keep the latest failure (its error reason) until we get a success
    return best or {"ok": False, "ping_ms": None, "error": "test failed"}


def _attempt(xray_bin: str, outbound: dict, test_url: str, timeout: int) -> dict:
    """A single test attempt. Returns {'ok': bool, 'ping_ms': int|None, 'error': str}."""
    ob = dict(outbound)
    ob.pop("_key", None)
    port = _free_port()
    cfg = {
        "log": {"loglevel": "info"},  # info level so we can extract the failure reason
        "inbounds": [{
            "tag": "test-in", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [ob, {"tag": "direct", "protocol": "freedom"}],
    }
    fd, cfg_path = tempfile.mkstemp(prefix="xray-test-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        # xray writes its logs to stdout; merge stderr into it
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", cfg_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        try:
            # wait for the port to be ready (max 4s)
            deadline = time.time() + 4
            ready = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    return {"ok": False, "ping_ms": None,
                            "error": "xray failed to run (invalid config?) " + _last_xray_error(proc)}
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                    ready = True
                    break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                return {"ok": False, "ping_ms": None, "error": "test port never became ready"}

            proxy = f"socks5h://127.0.0.1:{port}"
            r = subprocess.run(
                ["curl", "-x", proxy, "-o", "/dev/null", "-s", "-w", "%{http_code} %{time_total}",
                 "--max-time", str(timeout), test_url],
                capture_output=True, text=True, timeout=timeout + 3,
            )
            out = r.stdout.strip().split()
            if len(out) == 2 and out[0].startswith(("2", "3")):
                return {"ok": True, "ping_ms": int(float(out[1]) * 1000), "error": ""}
            # extract the real reason from the xray log (e.g. WebSocket 404 handshake)
            detail = _last_xray_error(proc)
            if out and out[0] == "000":
                return {"ok": False, "ping_ms": None, "error": detail or "connection failed"}
            return {"ok": False, "ping_ms": None,
                    "error": f"HTTP code: {out[0] if out else r.returncode}" + (f" — {detail}" if detail else "")}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        try:
            os.remove(cfg_path)
        except OSError:
            pass


def _last_xray_error(proc: subprocess.Popen) -> str:
    """Last meaningful error line from the temp xray instance's output (non-blocking)."""
    try:
        import fcntl
        import os as _os
        import select
        fd = proc.stdout.fileno()
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | _os.O_NONBLOCK)
        data = b""
        for _ in range(3):  # read a few times until the buffer settles
            time.sleep(0.15)
            while select.select([fd], [], [], 0)[0]:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                data += chunk
        text = data.decode(errors="replace")
        errs = [l.split("] ", 1)[-1] for l in text.splitlines() if "[Error]" in l or "failed" in l]
        if not errs:
            return ""
        # error chains look like "a > b > c"; the last segment is the root cause
        cause = errs[-1].split(">")[-1].strip()
        return cause[:200]
    except Exception:  # noqa: BLE001
        return ""
