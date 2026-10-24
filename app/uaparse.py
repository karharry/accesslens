"""Lightweight user-agent classification: (device, os, app). No external deps."""
import re

_APPS = [
    (r"Jellyfin[- ]?(Android|iOS|Media Player|Roku|Tizen|webOS|Kodi|Swiftfin)?", lambda m: "Jellyfin " + m.group(1) if m.group(1) else "Jellyfin"),
    (r"Swiftfin", lambda m: "Jellyfin Swiftfin"),
    (r"PlexAmp", lambda m: "Plexamp"),
    (r"Plex(?:MediaServer|/| for| Media)", lambda m: "Plex"),
    (r"Home ?Assistant", lambda m: "Home Assistant"),
    (r"Tautulli|Sonarr|Radarr|Lidarr|Bazarr|Prowlarr|Whisparr|Jackett|Overseerr|Seerr|Navidrome|Immich|Syncthing|Prometheus|Grafana|Uptime-Kuma|Homepage|Dockhand|Beszel|Glances|NetAlertX|FreshRSS|Linkwarden",
     lambda m: m.group(0)),
    (r"Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot|AhrefsBot|SemrushBot|MJ12bot|facebookexternalhit|[Bb]ot/|[Cc]rawler|[Ss]pider",
     lambda m: "Bot/Crawler"),
    (r"curl/", lambda m: "curl"),
    (r"Wget/", lambda m: "wget"),
    (r"python-requests|python-httpx|aiohttp|urllib", lambda m: "Python client"),
    (r"Go-http-client", lambda m: "Go client"),
    (r"okhttp", lambda m: "okhttp (Android app)"),
    (r"Dalvik", lambda m: "Android app"),
    (r"CFNetwork", lambda m: "Apple app"),
    (r"axios|node-fetch|got \(", lambda m: "Node client"),
    (r"Edg(?:e|A|iOS)?/", lambda m: "Edge"),
    (r"OPR/|Opera", lambda m: "Opera"),
    (r"Vivaldi/", lambda m: "Vivaldi"),
    (r"Brave", lambda m: "Brave"),
    (r"(?:Firefox|FxiOS)/", lambda m: "Firefox"),
    (r"(?:Chrome|CriOS)/", lambda m: "Chrome"),
    (r"Version/[\d.]+.*Safari/", lambda m: "Safari"),
    (r"Safari/", lambda m: "Safari"),
]
_APPS = [(re.compile(p), f) for p, f in _APPS]

_cache = {}


def parse(ua: str):
    ua = (ua or "").strip()
    if ua in _cache:
        return _cache[ua]
    r = _parse(ua)
    if len(_cache) > 5000:
        _cache.clear()
    _cache[ua] = r
    return r


def _parse(ua):
    if ua in ("", "-"):
        return ("Unknown", "Unknown", "Unknown")
    app = None
    for rx, fn in _APPS:
        m = rx.search(ua)
        if m:
            app = fn(m)
            break
    if app is None:
        tok = re.match(r"([A-Za-z][\w.\- ]{1,30}?)(?:[/ ]|$)", ua)
        app = tok.group(1) if tok and not ua.startswith("Mozilla") else "Other"

    os_ = "Unknown"
    device = "Unknown"
    low = ua.lower()
    if "iphone" in low:
        os_, device = "iOS", "iPhone"
    elif "ipad" in low:
        os_, device = "iPadOS", "iPad"
    elif "android" in low:
        os_ = "Android"
        device = "Android phone" if "mobile" in low else "Android tablet/TV"
    elif "windows" in low:
        os_, device = "Windows", "Windows PC"
    elif "cros" in low:
        os_, device = "ChromeOS", "Chromebook"
    elif "macintosh" in low or "mac os x" in low:
        os_, device = "macOS", "Mac"
    elif re.search(r"tizen|webos|smart-?tv|roku|appletv|tvos|bravia|firetv|aft[a-z]", low):
        os_, device = "TV OS", "Smart TV"
    elif "linux" in low or "x11" in low:
        os_, device = "Linux", "Linux PC"
    if device == "Unknown":
        if app in ("curl", "wget", "Python client", "Go client", "Node client"):
            device = "Script/CLI"
        elif app == "Bot/Crawler":
            device = "Bot"
        elif app in ("Home Assistant", "Prometheus", "Uptime-Kuma", "Homepage", "Glances", "Beszel", "NetAlertX", "Grafana"):
            device = "Service/Monitor"
    return (device, os_, app)
