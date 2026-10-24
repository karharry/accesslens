"""Query layer: filters, summaries, breakdowns, time series, insights."""
import time
from datetime import datetime

import db

RANGES = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000,
          "90d": 7776000, "365d": 31536000, "all": None}

FROM = ("FROM events e LEFT JOIN service_meta sm ON sm.service=e.service "
        "LEFT JOIN aliases al ON al.ip=e.ip")

DIMS = {  # key -> (label, SQL expression)
    "service": ("Service", "e.service"),
    "ip": ("IP address", "e.ip"),
    "client": ("Client (named)", "COALESCE(al.label, e.ip)"),
    "device": ("Device", "e.device"),
    "app": ("App / browser", "e.app"),
    "os": ("Operating system", "e.os"),
    "country": ("Country", "COALESCE(NULLIF(e.country,''),'Unknown')"),
    "category": ("Category", "COALESCE(sm.category,'Other')"),
    "scope": ("Local / Remote", "CASE WHEN e.is_local=1 THEN 'Local' ELSE 'Remote' END"),
    "status": ("Status class", "CAST(e.status/100 AS TEXT)||'xx'"),
    "source": ("Data source", "e.source"),
    "network": ("Network path", "e.network"),
    "path": ("Path", "e.path"),
    "hour": ("Hour of day", "strftime('%H:00', e.ts,'unixepoch','localtime')"),
    "weekday": ("Weekday", "strftime('%w', e.ts,'unixepoch','localtime')"),
}
BUCKETS = {
    "hour": "strftime('%Y-%m-%d %H:00', e.ts,'unixepoch','localtime')",
    "day": "strftime('%Y-%m-%d', e.ts,'unixepoch','localtime')",
    "week": "strftime('%Y-W%W', e.ts,'unixepoch','localtime')",
    "month": "strftime('%Y-%m', e.ts,'unixepoch','localtime')",
}
FILTER_KEYS = ["service", "ip", "scope", "status", "country", "device", "app", "os", "source", "network",
               "category", "q"]

# key -> (name, short, unit, description)
SOURCES = {
    "npm": ("Local proxy (NPM)", "NPM", "requests",
            "HTTP requests that went through Nginx Proxy Manager: LAN and Tailscale clients using your .home names."),
    "cloudflare": ("Cloudflare tunnel", "CF tunnel", "requests",
                   "HTTP requests from the internet through Cloudflare tunnels (Cloudflare Analytics API)."),
    "connection": ("Direct connections", "Direct", "connections",
                   "TCP connections made straight to a host ip:port, bypassing the proxy (e.g. over Tailscale). "
                   "Connection counts only: no path, status or user-agent."),
    "file": ("Log files", "Log", "requests", "Requests parsed from additional log files."),
    "api": ("Ingest API", "API", "events", "Events pushed by other tools via the ingest API."),
}
_COL = {"network": "e.network", "service": "e.service", "ip": "e.ip", "country": "COALESCE(NULLIF(e.country,''),'Unknown')",
        "device": "e.device", "app": "e.app", "os": "e.os", "source": "e.source",
        "category": "COALESCE(sm.category,'Other')"}


def parse_filters(params, default_range="24h"):
    f = {k: (params.get(k) or "").strip() for k in FILTER_KEYS}
    rng = params.get("range") or default_range
    if rng not in RANGES:
        rng = default_range
    f["range"] = rng
    now = int(time.time())
    f["until"] = now + 1
    f["since"] = now - RANGES[rng] if RANGES[rng] else 0
    for key, field in (("from", "since"), ("to", "until")):
        v = (params.get(key) or "").strip()
        f[key] = v
        if v:
            try:
                d = datetime.strptime(v, "%Y-%m-%d")
                f[field] = int(d.timestamp()) + (86400 if key == "to" else 0)
                f["range"] = "custom"
            except ValueError:
                f[key] = ""
    return f


def qs(f, **over):
    """Query-string for the current filters (used in links / exports)."""
    from urllib.parse import urlencode
    d = {k: f[k] for k in FILTER_KEYS if f.get(k)}
    if f.get("from") or f.get("to"):
        d.update({k: f[k] for k in ("from", "to") if f.get(k)})
    else:
        d["range"] = f["range"]
    for k, v in over.items():
        if v in (None, ""):
            d.pop(k, None)
        else:
            d[k] = v
    return urlencode(d)


def where(f):
    c, p = ["e.ts>=?", "e.ts<?"], [f["since"], f["until"]]
    for k, col in _COL.items():
        if f.get(k):
            c.append(f"{col}=?")
            p.append(f[k])
    if f.get("scope") in ("local", "remote"):
        c.append("e.is_local=?")
        p.append(1 if f["scope"] == "local" else 0)
    st = f.get("status")
    if st:
        if st == "err":
            c.append("e.status>=400")
        elif len(st) == 3 and st[0].isdigit() and st.endswith("xx"):
            c.append("e.status/100=?")
            p.append(int(st[0]))
    if f.get("q"):
        like = "%" + f["q"].replace("%", r"\%").replace("_", r"\_") + "%"
        c.append("(e.service LIKE ? ESCAPE '\\' OR e.path LIKE ? ESCAPE '\\' OR e.ip LIKE ? ESCAPE '\\' "
                 "OR e.ua LIKE ? ESCAPE '\\' OR al.label LIKE ? ESCAPE '\\')")
        p += [like] * 5
    return " WHERE " + " AND ".join(c), p


def summary(f):
    w, p = where(f)
    r = db.one(f"""SELECT COALESCE(SUM(e.count),0) total, COUNT(DISTINCT e.ip) ips,
        COUNT(DISTINCT e.service) services,
        COALESCE(SUM(CASE WHEN e.is_local=1 THEN e.count END),0) local,
        COALESCE(SUM(CASE WHEN e.is_local=0 THEN e.count END),0) remote,
        COALESCE(SUM(CASE WHEN e.status>=400 THEN e.count END),0) errors,
        COUNT(DISTINCT CASE WHEN e.is_local=0 THEN e.ip END) remote_ips,
        COALESCE(SUM(e.bytes),0) bytes {FROM}{w}""", p)
    return dict(r)


def explore(dim, f, limit=100, offset=0, order="requests"):
    expr = DIMS[dim][1]
    w, p = where(f)
    order_sql = {"requests": "requests DESC", "last": "last_seen DESC", "name": "v ASC",
                 "errors": "errors DESC", "clients": "clients DESC"}.get(order, "requests DESC")
    rows = db.q(f"""SELECT {expr} v, MAX(al.label) alias, COALESCE(SUM(e.count),0) requests,
        COUNT(DISTINCT e.ip) clients, SUM(CASE WHEN e.is_local=1 THEN e.count ELSE 0 END) local,
        SUM(CASE WHEN e.status>=400 THEN e.count ELSE 0 END) errors, SUM(e.bytes) bytes,
        MIN(e.ts) first_seen, MAX(e.ts) last_seen, COUNT(DISTINCT e.service) services
        {FROM}{w} GROUP BY v ORDER BY {order_sql} LIMIT ? OFFSET ?""", p + [limit, offset])
    return [dict(r) for r in rows]


def events(f, limit=100, offset=0):
    w, p = where(f)
    total = db.one(f"SELECT COUNT(*) n {FROM}{w}", p)["n"]
    rows = db.q(f"""SELECT e.*, al.label alias, COALESCE(sm.category,'Other') category {FROM}{w}
        ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?""", p + [limit, offset])
    return total, [dict(r) for r in rows]


def timeseries(f, bucket_s=None):
    since = f["since"] or (db.one("SELECT MIN(ts) m FROM events")["m"] or int(time.time()) - 86400)
    span = max(60, f["until"] - since)
    if bucket_s is None:
        bucket_s = next((b for b in (60, 300, 900, 3600, 14400, 86400) if span / b <= 96), 86400)
    off = datetime.now().astimezone().utcoffset().total_seconds() if bucket_s >= 86400 else 0
    w, p = where(f)
    rows = db.q(f"""SELECT ((e.ts+?)/?)*?-? t,
        SUM(CASE WHEN e.is_local=1 THEN e.count ELSE 0 END) local,
        SUM(CASE WHEN e.is_local=0 THEN e.count ELSE 0 END) remote,
        SUM(CASE WHEN e.status>=400 THEN e.count ELSE 0 END) errors
        {FROM}{w} GROUP BY t ORDER BY t""", [int(off), bucket_s, bucket_s, int(off)] + p)
    have = {r["t"]: dict(r) for r in rows}
    start = ((since + int(off)) // bucket_s) * bucket_s - int(off)
    out, t = [], start
    while t < f["until"] and len(out) < 2000:
        out.append(have.get(t, {"t": t, "local": 0, "remote": 0, "errors": 0}))
        t += bucket_s
    return bucket_s, out


def matrix(dim, bucket, f, top=12):
    expr, bexpr = DIMS[dim][1], BUCKETS[bucket]
    w, p = where(f)
    tops = [r["v"] for r in db.q(f"SELECT {expr} v {FROM}{w} GROUP BY v ORDER BY SUM(e.count) DESC LIMIT ?", p + [top])]
    if not tops:
        return [], [], {}
    marks = ",".join("?" * len(tops))
    rows = db.q(f"""SELECT {bexpr} b, {expr} v, SUM(e.count) n {FROM}{w} AND {expr} IN ({marks})
        GROUP BY b, v""", p + tops)
    buckets = sorted({r["b"] for r in rows})[-60:]
    data = {}
    for r in rows:
        data.setdefault(r["v"], {})[r["b"]] = r["n"]
    return tops, buckets, data


def heatmap(f):
    w, p = where(f)
    rows = db.q(f"""SELECT CAST(strftime('%w', e.ts,'unixepoch','localtime') AS INT) d,
        CAST(strftime('%H', e.ts,'unixepoch','localtime') AS INT) h, SUM(e.count) n {FROM}{w} GROUP BY d, h""", p)
    grid = [[0] * 24 for _ in range(7)]
    for r in rows:
        grid[(r["d"] - 1) % 7][r["h"]] = r["n"]  # Monday first
    return grid


def live():
    now = int(time.time())
    f = {"since": now - 1800, "until": now + 1, **{k: "" for k in FILTER_KEYS}}
    _, series = timeseries(f, 60)
    last5 = {"since": now - 300, "until": now + 1, **{k: "" for k in FILTER_KEYS}}
    total, recent = events({"since": now - 86400, "until": now + 1, **{k: "" for k in FILTER_KEYS}}, 30)
    return {"series": series, "last5": summary(last5), "recent": recent, "now": now}


def distinct(col, limit=200):
    expr = _COL[col]
    return [r["v"] for r in db.q(f"SELECT {expr} v {FROM} GROUP BY v ORDER BY SUM(e.count) DESC LIMIT ?", (limit,))]


def insights(f):
    since, until = f["since"], f["until"]
    xs, xp = "", []
    if f.get("source"):
        xs, xp = " AND source=?", [f["source"]]
    tw = f"ts>=? AND ts<?{xs}"
    tp = [since, until] + xp
    out = {}
    out["new_ips"] = [dict(r) for r in db.q(f"""SELECT ip, MIN(ts) first_seen, SUM(count) requests,
        COUNT(DISTINCT service) services, MAX(is_local) local, MAX(country) country, MAX(app) app,
        MAX(network) network, MAX(source) source
        FROM events WHERE 1=1{xs} GROUP BY ip HAVING MIN(ts)>=? ORDER BY first_seen DESC LIMIT 50""",
                                             xp + [since or 1])]
    out["suspicious"] = [dict(r) for r in db.q(f"""SELECT ip, SUM(count) requests,
        SUM(CASE WHEN status IN (401,403) THEN count ELSE 0 END) denied,
        SUM(CASE WHEN status=404 THEN count ELSE 0 END) notfound,
        COUNT(DISTINCT service) services, MAX(country) country, MAX(is_local) local, MAX(network) network
        FROM events WHERE {tw} GROUP BY ip
        HAVING denied>=10 OR notfound>=25 ORDER BY denied+notfound DESC LIMIT 50""", tp)]
    out["wide_remote"] = [dict(r) for r in db.q(f"""SELECT ip, SUM(count) requests,
        COUNT(DISTINCT service) services, MAX(country) country
        FROM events WHERE {tw} AND is_local=0 GROUP BY ip
        HAVING services>=4 ORDER BY services DESC LIMIT 25""", tp)]
    out["error_services"] = [dict(r) for r in db.q(f"""SELECT service, SUM(count) requests,
        SUM(CASE WHEN status>=400 THEN count ELSE 0 END) errors
        FROM events WHERE {tw} GROUP BY service
        HAVING errors*10>requests AND requests>=20 ORDER BY errors DESC LIMIT 25""", tp)]
    week = int(time.time()) - 7 * 86400
    out["quiet"] = [dict(r) for r in db.q(f"""SELECT service, MAX(source) source, MAX(ts) last_seen, SUM(count) requests
        FROM events WHERE 1=1{xs} GROUP BY service HAVING MAX(ts)<? ORDER BY last_seen DESC LIMIT 25""",
                                          xp + [week])]
    out["docker_nat"] = db.one(f"""SELECT COALESCE(SUM(count),0) n FROM events WHERE {tw} AND source='npm'
        AND ip LIKE '172.%' AND ip LIKE '%.0.1'""", tp)["n"]
    return out


def by_source(f):
    """Per-source totals; ignores the current source filter so every source stays visible."""
    w, p = where({**f, "source": ""})
    rows = db.q(f"""SELECT e.source v, SUM(e.count) n, COUNT(DISTINCT e.ip) clients,
        SUM(CASE WHEN e.network='LAN' THEN e.count ELSE 0 END) lan,
        SUM(CASE WHEN e.network='Tailscale' THEN e.count ELSE 0 END) tailscale,
        SUM(CASE WHEN e.network='Internet' THEN e.count ELSE 0 END) internet,
        SUM(CASE WHEN e.status>=400 THEN e.count ELSE 0 END) errors,
        MAX(e.ts) last_seen {FROM}{w} GROUP BY e.source""", p)
    return {r["v"]: dict(r) for r in rows}


def source_panels(f, status):
    data = by_source(f)
    out = []
    for key, (name, short, unit, desc) in SOURCES.items():
        if key not in data and key not in ("npm", "cloudflare", "connection"):
            continue
        d = data.get(key, {"n": 0, "clients": 0, "lan": 0, "tailscale": 0, "internet": 0, "errors": 0, "last_seen": None})
        top = explore("service", {**f, "source": key}, 5) if d["n"] else []
        out.append({"key": key, "name": name, "short": short, "unit": unit, "desc": desc, "d": d, "top": top,
                    "status": status.get(key, "")})
    return out


def uptime():
    now = int(time.time())
    out = []
    for p in db.q("SELECT * FROM probes ORDER BY name"):
        r24 = db.one("SELECT COUNT(*) n, SUM(ok) ok, AVG(ms) ms FROM probe_results WHERE probe_id=? AND ts>=?",
                     (p["id"], now - 86400))
        r7 = db.one("SELECT COUNT(*) n, SUM(ok) ok FROM probe_results WHERE probe_id=? AND ts>=?",
                    (p["id"], now - 7 * 86400))
        last = db.one("SELECT * FROM probe_results WHERE probe_id=? ORDER BY ts DESC LIMIT 1", (p["id"],))
        recent = [r["ok"] for r in db.q("SELECT ok FROM probe_results WHERE probe_id=? ORDER BY ts DESC LIMIT 60",
                                        (p["id"],))][::-1]
        out.append({"probe": dict(p), "last": dict(last) if last else None, "recent": recent,
                    "up24": (100.0 * (r24["ok"] or 0) / r24["n"]) if r24["n"] else None,
                    "up7": (100.0 * (r7["ok"] or 0) / r7["n"]) if r7["n"] else None,
                    "ms": r24["ms"]})
    return out
