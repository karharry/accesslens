"""Event normalisation and ingestion: log tailer, Cloudflare poller, uptime probes."""
import glob
import gzip
import ipaddress
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import db
import uaparse

log = logging.getLogger("accesslens.ingest")

# --------------------------------------------------------------------------- classification

_cidr_cache = {}


def parse_nets(raw):
    nets = []
    for part in raw.replace("\n", ",").split(","):
        try:
            nets.append(ipaddress.ip_network(part.strip(), strict=False))
        except ValueError:
            pass
    return nets


def _nets(key):
    raw = db.get(key)
    if _cidr_cache.get(key, ("",))[0] != raw:
        _cidr_cache[key] = (raw, parse_nets(raw))
    return _cidr_cache[key][1]


def local_nets():
    return _nets("local_cidrs")


def in_nets(ip, nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets if n.version == a.version)


def is_local(ip: str) -> bool:
    return in_nets(ip, local_nets())


def network_of(ip: str, source: str, local: int) -> str:
    """How the client reached us: Tailscale, LAN or Internet."""
    if source == "cloudflare":
        return "Internet"
    if in_nets(ip, _nets("tailscale_cidrs")):
        return "Tailscale"
    return "LAN" if local else "Internet"


UA_PARSER_VERSION = "2"


def reclassify_ua():
    """Re-derive device/os/app for stored events when the user-agent parser improves."""
    if db.get("ua_parser_version") == UA_PARSER_VERSION:
        return
    changed = 0
    for r in db.q("SELECT DISTINCT ua FROM events WHERE ua<>''"):
        device, os_, app = uaparse.parse(r["ua"])
        cur = db.ex("UPDATE events SET device=?, os=?, app=? WHERE ua=? AND (device<>? OR os<>? OR app<>?)",
                    (device, os_, app, r["ua"], device, os_, app))
        changed += cur.rowcount
    db.put("ua_parser_version", UA_PARSER_VERSION)
    if changed:
        log.info("re-classified %d stored events with the updated user-agent parser", changed)


def backfill_network():
    """Fill the network column for rows written before it existed."""
    for r in db.q("SELECT DISTINCT ip, source FROM events WHERE network=''"):
        loc = 0 if r["source"] == "cloudflare" else int(is_local(r["ip"]))
        db.ex("UPDATE events SET network=? WHERE network='' AND ip=? AND source=?",
              (network_of(r["ip"], r["source"], loc), r["ip"], r["source"]))


CATEGORY_RULES = [
    ("Media", "jellyfin plex emby sonarr radarr lidarr bazarr whisparr jackett prowlarr navidrome seerr tautulli immich photoprism metube qbittorrent jdownloader music movies tv".split()),
    ("Smart Home", "homeassistant home-assistant hass go2rtc frigate zigbee".split()),
    ("Security", "authentik vaultwarden bitwarden guacamole auth sso".split()),
    ("Network", "pihole pi-hole adguard netalertx unifi nebula dns glances beszel grafana prometheus speedtest myspeed uptime".split()),
    ("AI", "ollama openwebui omniroute llm ai".split()),
    ("Productivity", "docmost linkwarden freshrss floccus file-browser filebrowser syncthing searxng it-tools bookmarks homepage".split()),
    ("Infrastructure", "dockflare dockhand dozzle nginx npm portainer proxy cloudflare".split()),
]


def categorize(service: str) -> str:
    s = service.lower()
    for cat, words in CATEGORY_RULES:
        if any(w in s for w in words):
            return cat
    return "Other"


# --------------------------------------------------------------------------- normalisation

_known_services = set()
_ignore_cache = ("", None)


def _ignores():
    global _ignore_cache
    key = "|".join([db.get("ignore_ips"), db.get("ignore_paths"), db.get("ignore_services")])
    if _ignore_cache[0] != key:
        _ignore_cache = (key, (
            set(db.lines("ignore_ips")),
            tuple(db.lines("ignore_paths")),
            {s.lower() for s in db.lines("ignore_services")},
        ))
    return _ignore_cache[1]


def _strip_query(s: str) -> str:
    # Query strings often carry tokens/API keys; never store them.
    return s.split("?", 1)[0][:500]


def normalize(source, ts, service, ip, method="", path="", status=0, ua="", bytes_=0,
              referrer="", country="", count=1, app=None):
    """Return an events row tuple, or None if the event is ignored/invalid."""
    ip = (ip or "").strip()
    service = (service or "unknown").strip().lower()[:200]
    if not ip:
        return None
    ign_ips, ign_paths, ign_services = _ignores()
    path = _strip_query(path or "")
    if ip in ign_ips or service in ign_services or (ign_paths and path.startswith(ign_paths)):
        return None
    ua = (ua or "").strip()
    if ua == "-":
        ua = ""
    device, os_, ua_app = uaparse.parse(ua)
    app = app or ua_app
    # Cloudflare reports the real public client; for log sources judge by network.
    local = 0 if source == "cloudflare" else int(is_local(ip))
    return (int(ts), source, service, ip, local, (country or "")[:60], (method or "")[:12], path,
            int(status or 0), ua[:400], device, os_, app, int(bytes_ or 0),
            _strip_query(referrer or "") if referrer != "-" else "", int(count or 1),
            network_of(ip, source, local))


_INSERT = ("INSERT INTO events(ts,source,service,ip,is_local,country,method,path,status,ua,device,os,app,"
           "bytes,referrer,count,network) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")


def insert_events(rows):
    rows = [r for r in rows if r]
    if not rows:
        return 0
    new = {r[2] for r in rows} - _known_services
    with db.tx() as c:
        for s in new:
            c.execute("INSERT OR IGNORE INTO service_meta(service,category) VALUES(?,?)", (s, categorize(s)))
        c.executemany(_INSERT, rows)
    _known_services.update(new)
    return len(rows)


# --------------------------------------------------------------------------- log parsers

NPM_RE = re.compile(
    r'^\[(?P<time>[^\]]+)\] \S+ \S+ (?P<status>\S+) - (?P<method>\S+) \S+ (?P<host>\S+) "(?P<uri>[^"]*)" '
    r'\[Client (?P<ip>[^\]]+)\] \[Length (?P<len>[^\]]*)\] \[Gzip [^\]]*\] \[Sent-to [^\]]*\] '
    r'"(?P<ua>[^"]*)" "(?P<ref>[^"]*)"')
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<uri>\S+)[^"]*" (?P<status>\d{3}) '
    r'(?P<len>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"')


def _clf_time(s):
    return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()


def parse_line(fmt, label, line, source="npm"):
    m = None
    if fmt in ("npm", "auto"):
        m = NPM_RE.match(line)
        if m:
            service = m["host"]
    if m is None and fmt in ("combined", "auto"):
        m = COMBINED_RE.match(line)
        if m:
            service = label or "logfile"
            source = "file"
    if m is None:
        return None
    try:
        ts = _clf_time(m["time"])
        status = int(m["status"]) if m["status"].isdigit() else 0
        ln = int(m["len"]) if m["len"].isdigit() else 0
    except ValueError:
        return None
    return normalize(source, ts, service, m["ip"], m["method"], m["uri"], status, m["ua"], ln, m["ref"])


# --------------------------------------------------------------------------- tailer

def _sources():
    out = []
    for l in db.lines("log_sources"):
        parts = [p.strip() for p in l.split("|", 2)]
        if len(parts) == 3 and parts[2]:
            out.append((parts[0].lower() or "auto", parts[1], parts[2]))
    return out


def log_file_count():
    return sum(len(glob.glob(p)) for _, _, p in _sources())


def _state(path):
    return db.one("SELECT inode, offset FROM file_state WHERE path=?", (path,))


def _save_state(path, inode, offset):
    db.ex("INSERT INTO file_state(path,inode,offset) VALUES(?,?,?) ON CONFLICT(path) "
          "DO UPDATE SET inode=excluded.inode, offset=excluded.offset", (path, inode, offset))


def _ingest_lines(lines_iter, fmt, label):
    batch, n = [], 0
    for line in lines_iter:
        batch.append(parse_line(fmt, label, line.rstrip("\n")))
        if len(batch) >= 5000:
            n += insert_events(batch)
            batch = []
    return n + insert_events(batch)


def scan_once():
    first_pass = db.get("backfill_done") != "1"
    total = 0
    for fmt, label, pattern in _sources():
        for path in sorted(glob.glob(pattern)):
            try:
                total += _scan_file(path, fmt, label)
            except Exception:
                log.exception("scanning %s failed", path)
        # rotated archives: only backfilled once, on the very first scan
        for path in sorted(glob.glob(pattern + ".*.gz"), key=_gz_order, reverse=True):
            if _state(path):
                continue
            try:
                st = os.stat(path)
                if first_pass:
                    with gzip.open(path, "rt", errors="replace") as f:
                        total += _ingest_lines(f, fmt, label)
                _save_state(path, st.st_ino, -1)
            except Exception:
                log.exception("reading archive %s failed", path)
    if first_pass:
        db.put("backfill_done", "1")
    if total:
        log.info("ingested %d log events", total)
    return total


def _gz_order(p):
    m = re.search(r"\.(\d+)\.gz$", p)
    return int(m.group(1)) if m else 0


def _scan_file(path, fmt, label):
    st = os.stat(path)
    s = _state(path)
    offset = s["offset"] if s and s["inode"] == st.st_ino else 0
    if offset > st.st_size:
        offset = 0
    if offset == st.st_size:
        return 0
    n = 0
    with open(path, "rb") as f:
        f.seek(offset)
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            end = chunk.rfind(b"\n")
            if end < 0:
                if len(chunk) < 8 * 1024 * 1024:
                    break  # incomplete trailing line, retry next scan
                end = len(chunk) - 1
            f.seek(offset + end + 1)
            n += _ingest_lines(chunk[:end + 1].decode("utf-8", "replace").splitlines(), fmt, label)
            offset += end + 1
            _save_state(path, st.st_ino, offset)
    return n


# --------------------------------------------------------------------------- Cloudflare

CF_QUERY = """query($zone:String!,$since:Time!,$until:Time!){viewer{zones(filter:{zoneTag:$zone}){
httpRequestsAdaptiveGroups(limit:10000,filter:{datetime_gt:$since,datetime_leq:$until},orderBy:[datetime_ASC]){
count sum{edgeResponseBytes}
dimensions{datetime clientIP clientRequestHTTPHost clientCountryName userAgent edgeResponseStatus clientRequestPath clientRequestHTTPMethodName}}}}}"""


def cf_request(url, token, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": "accesslens"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def cf_discover_zones(token):
    data = cf_request("https://api.cloudflare.com/client/v4/zones?per_page=50", token)
    if not data.get("success"):
        raise RuntimeError(json.dumps(data.get("errors")))
    return [(z["id"], z["name"]) for z in data["result"]]


def cf_poll_once():
    token = db.get("cf_token").strip()
    if not token:
        return 0
    zones = [z.split(":")[0].strip() for z in db.lines("cf_zones")]
    total = 0
    now = time.time() - 60  # CF analytics lag
    for zone in zones:
        key = f"cf_cursor_{zone}"
        cursor = float(db.get(key, "0") or 0) or now - 3600
        cursor = max(cursor, now - 86000)  # free plans only retain ~1 day of adaptive data
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = cf_request("https://api.cloudflare.com/client/v4/graphql", token, {
            "query": CF_QUERY, "variables": {"zone": zone, "since": iso(cursor), "until": iso(now)}})
        if data.get("errors"):
            raise RuntimeError(json.dumps(data["errors"])[:400])
        groups = data["data"]["viewer"]["zones"][0]["httpRequestsAdaptiveGroups"]
        rows, last = [], cursor
        for g in groups:
            d = g["dimensions"]
            ts = datetime.fromisoformat(d["datetime"].replace("Z", "+00:00")).timestamp()
            last = max(last, ts)
            rows.append(normalize("cloudflare", ts, d["clientRequestHTTPHost"], d["clientIP"],
                                  d.get("clientRequestHTTPMethodName", ""), d.get("clientRequestPath", ""),
                                  d.get("edgeResponseStatus", 0), d.get("userAgent", ""),
                                  g["sum"]["edgeResponseBytes"], "", d.get("clientCountryName", ""), g["count"]))
        total += insert_events(rows)
        # if the 10k limit was hit, resume where we stopped; else jump to the window end
        db.put(key, last if len(groups) >= 10000 else now)
    return total


# --------------------------------------------------------------------------- probes

def run_probe(p):
    ctx = None
    if p["url"].startswith("https") and not p["verify_tls"]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    status, err = 0, None
    try:
        req = urllib.request.Request(p["url"], headers={"User-Agent": "accesslens-probe"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code  # reachable; auth-protected apps answer 401/403
    except Exception as e:
        err = str(e)[:200]
    ms = int((time.time() - t0) * 1000)
    ok = int(err is None and 0 < status < 500)
    db.ex("INSERT INTO probe_results(probe_id,ts,ok,status,ms,error) VALUES(?,?,?,?,?,?)",
          (p["id"], int(time.time()), ok, status, ms, err))


# --------------------------------------------------------------------------- background threads

def loop(name, fn, interval_fn):
    def run():
        while True:
            try:
                fn()
            except Exception as e:
                log.exception("%s failed", name)
                if name == "cloudflare":
                    db.put("cf_status", f"error {time.strftime('%F %T')}: {e}")
            time.sleep(max(2, interval_fn()))
    t = threading.Thread(target=run, name=name, daemon=True)
    t.start()


def _cf_tick():
    if not db.get("cf_token"):
        return
    n = cf_poll_once()
    db.put("cf_status", f"ok {time.strftime('%F %T')}: {n} new rows")


_last_probe = {}


def _probe_tick():
    now = time.time()
    for p in db.q("SELECT * FROM probes"):
        if now - _last_probe.get(p["id"], 0) >= p["interval_s"]:
            _last_probe[p["id"]] = now
            run_probe(p)


_last_prune = [0.0]


def _tail_tick():
    scan_once()
    if time.time() - _last_prune[0] > 86400:
        _last_prune[0] = time.time()
        days = int(db.get("retention_days") or 0)
        if days > 0:
            cutoff = int(time.time()) - days * 86400
            db.ex("DELETE FROM events WHERE ts<?", (cutoff,))
            db.ex("DELETE FROM probe_results WHERE ts<?", (cutoff,))


def start_background():
    _known_services.update(r["service"] for r in db.q("SELECT service FROM service_meta"))
    loop("tailer", _tail_tick, lambda: 5)
    loop("cloudflare", _cf_tick, lambda: int(db.get("cf_interval") or 300))
    loop("probes", _probe_tick, lambda: 5)
