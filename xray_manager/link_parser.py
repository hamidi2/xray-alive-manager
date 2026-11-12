"""Convert share links (vless/vmess/trojan/ss) to xray outbounds and back."""
from __future__ import annotations

import base64
import json
import urllib.parse
import uuid


def _b64decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _name_from_fragment(fragment: str, fallback: str) -> str:
    return urllib.parse.unquote(fragment) if fragment else fallback


def parse_link(link: str) -> dict:
    """Convert a share link into an xray outbound."""
    link = link.strip()
    scheme = urllib.parse.urlsplit(link).scheme.lower()
    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "vless":
        return _parse_vless(link)
    if scheme == "trojan":
        return _parse_trojan(link)
    if scheme == "ss":
        return _parse_ss(link)
    raise ValueError(f"unsupported protocol '{scheme or '?'}' (vless/vmess/trojan/ss)")


def _parse_vmess(link: str) -> dict:
    payload = link.split("://", 1)[1]
    data = json.loads(_b64decode(payload.split("#", 1)[0]))
    name = _name_from_fragment(payload.split("#", 1)[1] if "#" in payload else "", data.get("ps") or "vmess")
    net = data.get("net", "tcp")
    stream = {"network": net, "security": data.get("tls") or "none"}
    if (data.get("tls") or "").lower() in ("tls", "reality"):
        stream["security"] = "tls"
        tls = {"allowInsecure": True}
        if data.get("sni"):
            tls["serverName"] = data["sni"]
        if data.get("host") and net in ("ws", "grpc", "h2"):
            tls["alpn"] = [data["host"]]
        stream["tlsSettings"] = tls
    if net == "ws":
        ws = {"path": data.get("path") or "/"}
        if data.get("host"):
            ws["headers"] = {"Host": data["host"]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path") or ""}
    outbound = {
        "tag": name,
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data.get("add"),
                "port": int(data.get("port", 443)),
                "users": [{
                    "id": data.get("id"),
                    "alterId": int(data.get("aid") or 0),
                    "security": data.get("scy") or "auto",
                    "level": 0,
                }],
            }]
        },
        "streamSettings": stream,
    }
    return _finalize(outbound)


def _parse_vless(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = urllib.parse.parse_qs(u.query)
    name = _name_from_fragment(u.fragment, u.hostname or "vless")
    net = q.get("type", ["tcp"])[0]
    security = q.get("security", ["none"])[0]
    stream = {"network": net, "security": security}
    if security == "tls":
        tls = {"allowInsecure": q.get("allowInsecure", ["0"])[0] in ("1", "true")}
        if q.get("sni"):
            tls["serverName"] = q["sni"][0]
        if q.get("alpn"):
            tls["alpn"] = q["alpn"][0].split(",")
        if q.get("fp"):
            tls["fingerprint"] = q["fp"][0]
        stream["tlsSettings"] = tls
    elif security == "reality":
        real = {
            "show": False,
            "fingerprint": q.get("fp", ["chrome"])[0],
            "serverName": q.get("sni", [""])[0],
        }
        if q.get("pbk"):
            real["publicKey"] = q["pbk"][0]
        if q.get("sid"):
            real["shortId"] = q["sid"][0]
        if q.get("spx"):
            real["spiderX"] = q["spx"][0]
        stream["realitySettings"] = real
    if net == "ws":
        ws = {"path": q.get("path", ["/"])[0]}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"][0]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}
    elif net == "kcp":
        stream["kcpSettings"] = {"mtu": 1350, "tti": 50, "headerType": q.get("headerType", ["none"])[0]}
    user = {"id": urllib.parse.unquote(u.username or ""), "encryption": "none", "level": 0}
    if q.get("flow"):
        user["flow"] = q["flow"][0]
    outbound = {
        "tag": name,
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": u.hostname,
            "port": u.port or 443,
            "users": [user],
        }]},
        "streamSettings": stream,
    }
    return _finalize(outbound)


def _parse_trojan(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = urllib.parse.parse_qs(u.query)
    name = _name_from_fragment(u.fragment, u.hostname or "trojan")
    net = q.get("type", ["tcp"])[0]
    stream = {"network": net, "security": "tls"}
    tls = {"allowInsecure": q.get("allowInsecure", ["0"])[0] in ("1", "true")}
    if q.get("sni"):
        tls["serverName"] = q["sni"][0]
    stream["tlsSettings"] = tls
    if net == "ws":
        stream["wsSettings"] = {"path": q.get("path", ["/"])[0]}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}
    outbound = {
        "tag": name,
        "protocol": "trojan",
        "settings": {"servers": [{
            "address": u.hostname,
            "port": u.port or 443,
            "password": urllib.parse.unquote(u.username or ""),
            "level": 0,
        }]},
        "streamSettings": stream,
    }
    return _finalize(outbound)


def _parse_ss(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    name = _name_from_fragment(u.fragment, u.hostname or "shadowsocks")
    if u.username and u.port:  # ss://b64(method:pass)@host:port
        method, password = _b64decode(u.username).decode(errors="replace").split(":", 1)
        host, port = u.hostname, u.port
    else:  # ss://b64(method:pass@host:port)
        raw = _b64decode(link.split("://", 1)[1].split("#", 1)[0]).decode(errors="replace")
        userinfo, _, hostport = raw.rpartition("@")
        method, password = userinfo.split(":", 1)
        host, _, port = hostport.rpartition(":")
    outbound = {
        "tag": name,
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": host,
            "port": int(port),
            "method": method,
            "password": password,
            "level": 0,
        }]},
    }
    return _finalize(outbound)


def _finalize(outbound: dict) -> dict:
    addr = _address_of(outbound)
    # a stable key based on the connection details, so enabled/disabled state survives restarts
    stable = uuid.uuid5(uuid.NAMESPACE_URL, f"{outbound['protocol']}|{addr}|{json.dumps(outbound['settings'], sort_keys=True)}")
    outbound["_key"] = str(stable)[:8]
    if not outbound.get("tag"):
        outbound["tag"] = f"{outbound['protocol']}-{outbound['_key']}"
    return outbound


def _address_of(outbound: dict) -> str:
    s = outbound.get("settings", {})
    if s.get("vnext"):
        return f"{s['vnext'][0].get('address')}:{s['vnext'][0].get('port')}"
    if s.get("servers"):
        return f"{s['servers'][0].get('address')}:{s['servers'][0].get('port')}"
    return "?"


def to_link(outbound: dict) -> str:
    """Rebuild a share link from an outbound (for display/copying)."""
    p = outbound["protocol"]
    stream = outbound.get("streamSettings") or {}
    sec = stream.get("security", "none")
    name = urllib.parse.quote(outbound.get("tag", p))
    try:
        if p == "vmess":
            v = outbound["settings"]["vnext"][0]
            usr = v["users"][0]
            data = {
                "v": "2", "ps": outbound.get("tag", "vmess"),
                "add": v.get("address"), "port": str(v.get("port")),
                "id": usr.get("id"), "aid": str(usr.get("alterId", 0)),
                "scy": usr.get("security", "auto"), "net": stream.get("network", "tcp"),
                "type": "none", "tls": sec if sec == "tls" else "",
            }
            if stream.get("network") == "ws":
                ws = stream.get("wsSettings") or {}
                data["path"] = ws.get("path", "/")
                data["host"] = (ws.get("headers") or {}).get("Host", "")
            if sec == "tls":
                data["sni"] = (stream.get("tlsSettings") or {}).get("serverName", "")
            return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
        if p == "vless":
            v = outbound["settings"]["vnext"][0]
            usr = v["users"][0]
            q = {"type": stream.get("network", "tcp"), "security": sec,
                 "encryption": "none", "flow": usr.get("flow", "")}
            if sec == "tls":
                t = stream.get("tlsSettings") or {}
                if t.get("serverName"):
                    q["sni"] = t["serverName"]
                if t.get("fingerprint"):
                    q["fp"] = t["fingerprint"]
            elif sec == "reality":
                r = stream.get("realitySettings") or {}
                q.update({"fp": r.get("fingerprint", "chrome"), "sni": r.get("serverName", ""),
                          "pbk": r.get("publicKey", ""), "sid": r.get("shortId", "")})
            if stream.get("network") == "ws":
                ws = stream.get("wsSettings") or {}
                q["path"] = ws.get("path", "/")
                if (ws.get("headers") or {}).get("Host"):
                    q["host"] = ws["headers"]["Host"]
            if stream.get("network") == "grpc":
                q["serviceName"] = (stream.get("grpcSettings") or {}).get("serviceName", "")
            qs = urllib.parse.urlencode({k: v for k, v in q.items() if v})
            return f"vless://{usr.get('id')}@{v.get('address')}:{v.get('port')}?{qs}#{name}"
        if p == "trojan":
            s = outbound["settings"]["servers"][0]
            sni = (stream.get("tlsSettings") or {}).get("serverName", "")
            qs = urllib.parse.urlencode({k: v for k, v in {"sni": sni, "type": stream.get("network", "tcp")}.items() if v})
            return f"trojan://{urllib.parse.quote(s.get('password',''))}@{s.get('address')}:{s.get('port')}?{qs}#{name}"
        if p == "shadowsocks":
            s = outbound["settings"]["servers"][0]
            userinfo = base64.b64encode(f"{s.get('method')}:{s.get('password')}".encode()).decode()
            return f"ss://{userinfo}@{s.get('address')}:{s.get('port')}#{name}"
    except (KeyError, IndexError, TypeError):
        return ""
    return ""
