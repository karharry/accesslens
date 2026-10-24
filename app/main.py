"""AccessLens web application."""
import csv
import io
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import quote, urlencode

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import auth
import conntrack
import db
import ingest
import mailer
import stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
BASE = os.path.dirname(__file__)
VERSION = "1.1.0"


@asynccontextmanager
async def lifespan(app):
    db.init()
    auth.bootstrap_admin()
    if not db.get("api_token"):
        db.put("api_token", secrets.token_urlsafe(32))
    ingest.backfill_network()
    ingest.start_background()
    conntrack.start()
    mailer.start_scheduler()
    yield


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))


# --------------------------------------------------------------------------- template helpers

def _dt(ts, fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.fromtimestamp(ts).strftime(fmt) if ts else "–"


def _ago(ts):
    if not ts:
        return "–"
    d = int(time.time() - ts)
    for n, u in ((86400, "d"), (3600, "h"), (60, "m")):
        if d >= n:
            return f"{d // n}{u} ago"
    return f"{max(d, 0)}s ago"


def _bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


templates.env.filters.update(dt=_dt, ago=_ago, nbytes=_bytes, num=lambda n: f"{int(n or 0):,}")
templates.env.globals.update(SRC=stats.SOURCES, SRC_SHORT={k: v[1] for k, v in stats.SOURCES.items()}, DIMS=stats.DIMS, RANGES=list(stats.RANGES), qs=stats.qs, version=VERSION,
                             weekdays=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])


class NeedLogin(Exception):
    pass


@app.exception_handler(NeedLogin)
async def _need_login(request, exc):
    return RedirectResponse("/login?next=" + quote(request.url.path), 303)


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.update({
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        "Cache-Control": "no-store" if not request.url.path.startswith("/static") else "no-cache"})
    return resp


def current_user(request: Request):
    c = request.cookies.get(auth.COOKIE)
    return auth.user_from_cookie(c) if c else None


def require_user(request: Request):
    u = current_user(request)
    if not u:
        raise NeedLogin()
    return u


def require_admin(request: Request):
    u = require_user(request)
    if u["role"] != "admin":
        raise NeedLogin()
    return u


def csrf_ok(request: Request, csrf: str = Form("")):
    c = request.cookies.get(auth.COOKIE, "")
    if not c or not secrets.compare_digest(csrf, auth.csrf_token(c)):
        from fastapi import HTTPException
        raise HTTPException(403, "Invalid CSRF token - reload the page and try again.")


def render(request, name, user=None, **ctx):
    c = request.cookies.get(auth.COOKIE, "")
    ctx.update(user=user, csrf=auth.csrf_token(c) if c else "", request=request,
               msg=request.query_params.get("msg"), ok=request.query_params.get("ok") == "1",
               default_pw=os.path.exists(auth.PW_FILE) and user is not None)
    return templates.TemplateResponse(request, name, ctx)


def back(path, msg, ok=True):
    return RedirectResponse(f"{path}?{urlencode({'msg': msg, 'ok': int(ok)})}", 303)


# --------------------------------------------------------------------------- auth routes

_fails = {}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    if current_user(request):
        return RedirectResponse("/", 303)
    return render(request, "login.html", next=next)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    ip = request.client.host if request.client else "?"
    n, until = _fails.get(ip, (0, 0))
    if until > time.time():
        return render(request, "login.html", next=next, error="Too many attempts. Try again in a minute.")
    u = db.one("SELECT * FROM users WHERE username=?", (username.strip(),))
    if not u or not auth.verify_password(password, u["pw_hash"]):
        n += 1
        _fails[ip] = (n, time.time() + 60 if n >= 5 else 0)
        time.sleep(0.5)
        return render(request, "login.html", next=next, error="Invalid username or password.")
    _fails.pop(ip, None)
    db.ex("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), u["id"]))
    dest = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(dest, 303)
    resp.set_cookie(auth.COOKIE, auth.make_cookie(u), max_age=auth.SESSION_TTL, httponly=True,
                    samesite="strict", secure=request.url.scheme == "https")
    return resp


@app.post("/logout")
def logout(_=Depends(csrf_ok)):
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(auth.COOKIE)
    return resp


@app.get("/healthz")
def healthz():
    db.one("SELECT 1")
    return PlainTextResponse("ok")


# --------------------------------------------------------------------------- dashboards

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user=Depends(require_user)):
    f = stats.parse_filters(request.query_params)
    n_logs = ingest.log_file_count()
    status = {
        "npm": f"Reading {n_logs} log file(s)" if n_logs else "No log files found - check Settings → Log sources",
        "cloudflare": (db.get("cf_status") or "Token configured, waiting for first poll") if db.get("cf_token")
        else "Not configured - add a Cloudflare API token in Settings",
        "connection": db.get("conn_status") or "Starting…",
        "file": "", "api": "",
    }
    return render(request, "dashboard.html", user, f=f, s=stats.summary(f),
                  panels=stats.source_panels(f, status),
                  nets=stats.explore("network", f, 5),
                  top={d: stats.explore(d, f, 8) for d in ("service", "client", "device", "app", "country", "category")},
                  heat=stats.heatmap(f), page="dashboard")


@app.get("/api/live")
def api_live(user=Depends(require_user)):
    return JSONResponse(stats.live())


@app.get("/api/timeseries")
def api_timeseries(request: Request, user=Depends(require_user)):
    f = stats.parse_filters(request.query_params)
    b, series = stats.timeseries(f)
    return {"bucket": b, "series": series}


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, user=Depends(require_user)):
    f = stats.parse_filters(request.query_params)
    per = 100
    page = max(1, int(request.query_params.get("page", "1") or 1))
    total, rows = stats.events(f, per, (page - 1) * per)
    return render(request, "events.html", user, f=f, rows=rows, total=total, page_n=page,
                  pages=max(1, -(-total // per)), page="events",
                  opts={k: stats.distinct(k) for k in ("service", "country", "device", "app", "category")})


@app.get("/explore", response_class=HTMLResponse)
def explore_page(request: Request, dim: str = "service", order: str = "requests", user=Depends(require_user)):
    f = stats.parse_filters(request.query_params, "7d")
    dim = dim if dim in stats.DIMS else "service"
    rows = stats.explore(dim, f, 500, 0, order)
    total = sum(r["requests"] for r in rows) or 1
    return render(request, "explore.html", user, f=f, dim=dim, rows=rows, grand=total, order=order, page="explore",
                  opts={k: stats.distinct(k) for k in ("service", "country", "device", "app", "category")})


@app.get("/aggregate", response_class=HTMLResponse)
def aggregate_page(request: Request, dim: str = "service", bucket: str = "day", user=Depends(require_user)):
    f = stats.parse_filters(request.query_params, "30d")
    dim = dim if dim in stats.DIMS else "service"
    bucket = bucket if bucket in stats.BUCKETS else "day"
    tops, buckets, data = stats.matrix(dim, bucket, f)
    return render(request, "aggregate.html", user, f=f, dim=dim, bucket=bucket, tops=tops, buckets=buckets,
                  data=data, page="aggregate", buckets_all=list(stats.BUCKETS))


@app.get("/insights", response_class=HTMLResponse)
def insights_page(request: Request, user=Depends(require_user)):
    f = stats.parse_filters(request.query_params, "7d")
    return render(request, "insights.html", user, f=f, i=stats.insights(f), page="insights")


@app.get("/uptime", response_class=HTMLResponse)
def uptime_page(request: Request, user=Depends(require_user)):
    return render(request, "uptime.html", user, uptime_items=stats.uptime(), page="uptime")


# --------------------------------------------------------------------------- CSV export

def _safe(v):
    """Neutralise spreadsheet formula injection (log fields are attacker-controlled)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _csv(filename, header, rows):
    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        yield buf.getvalue()
        for r in rows:
            buf.seek(0), buf.truncate()
            w.writerow([_safe(x) for x in r])
            yield buf.getvalue()
    return StreamingResponse(gen(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/export/events.csv")
def export_events(request: Request, user=Depends(require_user)):
    f = stats.parse_filters(request.query_params)
    w, p = stats.where(f)
    cur = db.conn().execute(f"""SELECT e.ts, e.source, e.service, COALESCE(sm.category,'Other'), e.ip, al.label,
        CASE WHEN e.is_local=1 THEN 'local' ELSE 'remote' END, e.country, e.method, e.path, e.status,
        e.device, e.os, e.app, e.bytes, e.count, e.ua {stats.FROM}{w} ORDER BY e.ts DESC""", p)
    header = ["time", "source", "service", "category", "ip", "client_name", "scope", "country", "method", "path",
              "status", "device", "os", "app", "bytes", "count", "user_agent"]
    rows = ([_dt(r[0])] + list(r[1:]) for r in cur)
    return _csv(f"accesslens-events-{time.strftime('%Y%m%d-%H%M')}.csv", header, rows)


@app.get("/export/explore.csv")
def export_explore(request: Request, dim: str = "service", user=Depends(require_user)):
    f = stats.parse_filters(request.query_params, "7d")
    dim = dim if dim in stats.DIMS else "service"
    rows = stats.explore(dim, f, 100000)
    return _csv(f"accesslens-{dim}-{time.strftime('%Y%m%d')}.csv",
                [stats.DIMS[dim][0], "alias", "requests", "unique_clients", "local_requests", "errors", "bytes",
                 "first_seen", "last_seen"],
                ([r["v"], r["alias"] or "", r["requests"], r["clients"], r["local"], r["errors"], r["bytes"] or 0,
                  _dt(r["first_seen"]), _dt(r["last_seen"])] for r in rows))


@app.get("/export/aggregate.csv")
def export_aggregate(request: Request, dim: str = "service", bucket: str = "day", user=Depends(require_user)):
    f = stats.parse_filters(request.query_params, "30d")
    dim = dim if dim in stats.DIMS else "service"
    bucket = bucket if bucket in stats.BUCKETS else "day"
    tops, buckets, data = stats.matrix(dim, bucket, f, 1000)
    return _csv(f"accesslens-{dim}-by-{bucket}.csv", [stats.DIMS[dim][0]] + buckets,
                ([t] + [data.get(t, {}).get(b, 0) for b in buckets] for t in tops))


# --------------------------------------------------------------------------- settings

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, user=Depends(require_admin)):
    g = db.get
    labels = {
        "aliases": "\n".join(f"{r['ip']},{r['label']}" for r in db.q("SELECT * FROM aliases ORDER BY ip")),
        "categories": "\n".join(f"{r['service']},{r['category']}" for r in db.q("SELECT * FROM service_meta ORDER BY service")),
    }
    ctx = {k: g(k) for k in ("local_cidrs", "log_sources", "ignore_ips", "ignore_paths", "ignore_services",
                              "retention_days", "cf_zones", "cf_interval", "cf_status", "smtp_host", "smtp_port",
                              "smtp_security", "smtp_user", "mail_from", "mail_to", "report_enabled", "report_day",
                              "report_hour", "api_token", "tailscale_cidrs", "conn_enabled", "conn_protocols",
                              "conn_ports_ignore", "conn_ports_only", "conn_labels", "conn_ignore_src",
                              "conn_host_ips", "conn_poll", "conn_status")}
    ctx["cf_token_set"] = bool(g("cf_token"))
    ctx["smtp_pass_set"] = bool(g("smtp_pass"))
    ctx["report_error"] = g("report_error", "")
    stat = db.one("SELECT COUNT(*) n, MIN(ts) a, MAX(ts) b FROM events")
    dbsize = os.path.getsize(db.DB_PATH) if os.path.exists(db.DB_PATH) else 0
    ctx["detected_hosts"] = sorted(conntrack.host_ips())
    ctx["detected_docker"] = [str(n) for n in conntrack.docker_nets()]
    return render(request, "settings.html", user, s=ctx, labels=labels, probes=db.q("SELECT * FROM probes ORDER BY name"),
                  dbstat=dict(stat), dbsize=dbsize, page="settings", tz=time.tzname[0])


@app.post("/settings/general")
def save_general(local_cidrs: str = Form(""), tailscale_cidrs: str = Form(""), log_sources: str = Form(""), ignore_ips: str = Form(""),
                 ignore_paths: str = Form(""), ignore_services: str = Form(""), retention_days: int = Form(365),
                 user=Depends(require_admin), _=Depends(csrf_ok)):
    import ipaddress
    for part in local_cidrs.split(","):
        try:
            ipaddress.ip_network(part.strip(), strict=False)
        except ValueError:
            return back("/settings", f"Invalid CIDR: {part.strip()}", False)
    for part in tailscale_cidrs.split(","):
        try:
            ipaddress.ip_network(part.strip(), strict=False)
        except ValueError:
            return back("/settings", f"Invalid Tailscale CIDR: {part.strip()}", False)
    for k, v in dict(local_cidrs=local_cidrs.strip(), tailscale_cidrs=tailscale_cidrs.strip(), log_sources=log_sources, ignore_ips=ignore_ips,
                     ignore_paths=ignore_paths, ignore_services=ignore_services,
                     retention_days=max(0, retention_days)).items():
        db.put(k, v)
    return back("/settings", "Settings saved. Log sources are re-scanned within 5 seconds.")


@app.post("/settings/connections")
def save_connections(conn_enabled: str = Form(""), conn_protocols: str = Form("tcp"), conn_ports_ignore: str = Form(""),
                     conn_ports_only: str = Form(""), conn_labels: str = Form(""), conn_ignore_src: str = Form(""),
                     conn_host_ips: str = Form(""), conn_poll: int = Form(5),
                     user=Depends(require_admin), _=Depends(csrf_ok)):
    import ipaddress
    for part in conn_ignore_src.replace("\n", ",").split(","):
        if part.strip():
            try:
                ipaddress.ip_network(part.strip(), strict=False)
            except ValueError:
                return back("/settings", f"Invalid CIDR: {part.strip()}", False)
    for part in conn_host_ips.replace("\n", ",").split(","):
        if part.strip():
            try:
                ipaddress.ip_address(part.strip())
            except ValueError:
                return back("/settings", f"Invalid host IP: {part.strip()}", False)
    protos = ",".join(p for p in ("tcp", "udp") if p in conn_protocols.lower()) or "tcp"
    for k, v in dict(conn_enabled="1" if conn_enabled else "0", conn_protocols=protos,
                     conn_ports_ignore=conn_ports_ignore.strip(), conn_ports_only=conn_ports_only.strip(),
                     conn_labels=conn_labels, conn_ignore_src=conn_ignore_src.strip(),
                     conn_host_ips=conn_host_ips.strip(), conn_poll=min(max(conn_poll, 2), 60)).items():
        db.put(k, v)
    return back("/settings", "Direct-connection settings saved.")


@app.post("/settings/labels")
def save_labels(aliases: str = Form(""), categories: str = Form(""), user=Depends(require_admin), _=Depends(csrf_ok)):
    with db.tx() as c:
        c.execute("DELETE FROM aliases")
        for l in aliases.splitlines():
            if "," in l and l.split(",", 1)[0].strip():
                ip, label = (x.strip() for x in l.split(",", 1))
                if label:
                    c.execute("INSERT OR REPLACE INTO aliases VALUES(?,?)", (ip, label[:80]))
        for l in categories.splitlines():
            if "," in l:
                svc, cat = (x.strip() for x in l.split(",", 1))
                if svc and cat:
                    c.execute("INSERT OR REPLACE INTO service_meta VALUES(?,?)", (svc.lower(), cat[:40]))
    return back("/settings", "Names and categories saved.")


@app.post("/settings/cloudflare")
def save_cf(cf_token: str = Form(""), cf_zones: str = Form(""), cf_interval: int = Form(300),
            user=Depends(require_admin), _=Depends(csrf_ok)):
    if cf_token.strip():
        db.put("cf_token", cf_token.strip())
    db.put("cf_zones", cf_zones)
    db.put("cf_interval", max(60, cf_interval))
    return back("/settings", "Cloudflare settings saved.")


@app.post("/settings/cloudflare/clear")
def clear_cf(user=Depends(require_admin), _=Depends(csrf_ok)):
    db.put("cf_token", "")
    return back("/settings", "Cloudflare token removed.")


@app.post("/settings/cloudflare/discover")
def discover_cf(user=Depends(require_admin), _=Depends(csrf_ok)):
    try:
        zones = ingest.cf_discover_zones(db.get("cf_token"))
    except Exception as e:
        return back("/settings", f"Cloudflare lookup failed: {e}", False)
    db.put("cf_zones", "\n".join(f"{i}:{n}" for i, n in zones))
    return back("/settings", f"Found {len(zones)} zone(s): " + ", ".join(n for _, n in zones))


@app.post("/settings/cloudflare/poll")
def poll_cf(user=Depends(require_admin), _=Depends(csrf_ok)):
    try:
        n = ingest.cf_poll_once()
        db.put("cf_status", f"ok {time.strftime('%F %T')}: {n} new rows")
    except Exception as e:
        return back("/settings", f"Cloudflare poll failed: {str(e)[:300]}", False)
    return back("/settings", f"Cloudflare poll OK: {n} new rows.")


@app.post("/settings/email")
def save_email(smtp_host: str = Form(""), smtp_port: int = Form(587), smtp_security: str = Form("starttls"),
               smtp_user: str = Form(""), smtp_pass: str = Form(""), mail_from: str = Form(""),
               mail_to: str = Form(""), report_enabled: str = Form(""), report_day: int = Form(0),
               report_hour: int = Form(8), user=Depends(require_admin), _=Depends(csrf_ok)):
    for k, v in dict(smtp_host=smtp_host.strip(), smtp_port=smtp_port,
                     smtp_security=smtp_security if smtp_security in ("starttls", "ssl", "none") else "starttls",
                     smtp_user=smtp_user.strip(), mail_from=mail_from.strip(), mail_to=mail_to.strip(),
                     report_enabled="1" if report_enabled else "0", report_day=min(max(report_day, 0), 6),
                     report_hour=min(max(report_hour, 0), 23)).items():
        db.put(k, v)
    if smtp_pass:
        db.put("smtp_pass", smtp_pass)
    return back("/settings", "Email settings saved.")


@app.post("/settings/email/test")
def test_email(user=Depends(require_admin), _=Depends(csrf_ok)):
    try:
        mailer.send_mail("AccessLens test email", "SMTP is configured correctly.",
                         "<p>SMTP is configured correctly.</p>")
    except Exception as e:
        return back("/settings", f"Send failed: {e}", False)
    return back("/settings", "Test email sent.")


@app.post("/settings/email/report")
def send_report_now(which: str = Form("last_week"), user=Depends(require_admin), _=Depends(csrf_ok)):
    try:
        if which == "last_7d":
            from datetime import timedelta
            end = datetime.now()
            title = mailer.send_report(end - timedelta(days=7), end)
        else:
            title = mailer.send_report()
    except Exception as e:
        return back("/settings", f"Send failed: {e}", False)
    return back("/settings", f"Sent: {title}")


@app.post("/settings/token")
def regen_token(user=Depends(require_admin), _=Depends(csrf_ok)):
    db.put("api_token", secrets.token_urlsafe(32))
    return back("/settings", "New ingest API token generated.")


@app.post("/settings/probes/add")
def add_probe(name: str = Form(...), url: str = Form(...), interval_s: int = Form(60), verify_tls: str = Form(""),
              user=Depends(require_admin), _=Depends(csrf_ok)):
    if not url.startswith(("http://", "https://")):
        return back("/settings", "Probe URL must start with http:// or https://", False)
    db.ex("INSERT INTO probes(name,url,interval_s,verify_tls) VALUES(?,?,?,?)",
          (name.strip()[:60], url.strip(), max(10, interval_s), 1 if verify_tls else 0))
    return back("/settings", "Probe added.")


@app.post("/settings/probes/delete")
def del_probe(id: int = Form(...), user=Depends(require_admin), _=Depends(csrf_ok)):
    db.ex("DELETE FROM probes WHERE id=?", (id,))
    db.ex("DELETE FROM probe_results WHERE probe_id=?", (id,))
    return back("/settings", "Probe deleted.")


@app.post("/settings/purge")
def purge(confirm: str = Form(""), user=Depends(require_admin), _=Depends(csrf_ok)):
    if confirm != "DELETE":
        return back("/settings", "Type DELETE to confirm.", False)
    db.ex("DELETE FROM events")
    db.ex("DELETE FROM file_state")
    db.put("backfill_done", "0")
    return back("/settings", "All events deleted; log files will be re-imported from the start.")


# --------------------------------------------------------------------------- users & account

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request, user=Depends(require_admin)):
    return render(request, "users.html", user, users=db.q("SELECT * FROM users ORDER BY id"), page="users")


@app.post("/users/create")
def create_user(username: str = Form(...), password: str = Form(...), role: str = Form("admin"),
                user=Depends(require_admin), _=Depends(csrf_ok)):
    username = username.strip()
    if not (2 <= len(username) <= 40) or not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
        return back("/users", "Username: 2-40 chars, letters/digits/._- only.", False)
    err = auth.valid_password(password)
    if err:
        return back("/users", err, False)
    if db.one("SELECT 1 FROM users WHERE username=?", (username,)):
        return back("/users", "That username already exists.", False)
    auth.create_user(username, password, role if role in ("admin", "viewer") else "admin")
    return back("/users", f"User '{username}' created.")


@app.post("/users/delete")
def delete_user(id: int = Form(...), user=Depends(require_admin), _=Depends(csrf_ok)):
    if id == user["id"]:
        return back("/users", "You cannot delete the account you are logged in with. "
                              "Log in as another admin to delete this one.", False)
    target = db.one("SELECT * FROM users WHERE id=?", (id,))
    if not target:
        return back("/users", "User not found.", False)
    db.ex("DELETE FROM users WHERE id=?", (id,))
    if str(id) == db.get("bootstrap_uid", "0"):
        auth.password_changed()
    return back("/users", f"User '{target['username']}' deleted.")


@app.post("/users/reset")
def reset_user(id: int = Form(...), password: str = Form(...), user=Depends(require_admin), _=Depends(csrf_ok)):
    err = auth.valid_password(password)
    if err:
        return back("/users", err, False)
    auth.set_password(id, password)
    if id == user["id"]:
        return RedirectResponse("/login", 303)
    return back("/users", "Password reset; that user's sessions were signed out.")


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user=Depends(require_user)):
    return render(request, "account.html", user, page="account")


@app.post("/account/password")
def change_password(current: str = Form(...), new: str = Form(...), confirm: str = Form(...),
                    user=Depends(require_user), _=Depends(csrf_ok)):
    if not auth.verify_password(current, user["pw_hash"]):
        return back("/account", "Current password is incorrect.", False)
    if new != confirm:
        return back("/account", "New passwords do not match.", False)
    err = auth.valid_password(new)
    if err:
        return back("/account", err, False)
    auth.set_password(user["id"], new)
    u = db.one("SELECT * FROM users WHERE id=?", (user["id"],))
    resp = back("/account", "Password changed.")
    resp.set_cookie(auth.COOKIE, auth.make_cookie(u), max_age=auth.SESSION_TTL, httponly=True, samesite="strict")
    return resp


@app.post("/account/rename")
def rename(username: str = Form(...), user=Depends(require_user), _=Depends(csrf_ok)):
    username = username.strip()
    if db.one("SELECT 1 FROM users WHERE username=? AND id<>?", (username, user["id"])):
        return back("/account", "That username is taken.", False)
    if not (2 <= len(username) <= 40):
        return back("/account", "Username must be 2-40 characters.", False)
    db.ex("UPDATE users SET username=? WHERE id=?", (username, user["id"]))
    return back("/account", "Username updated.")


# --------------------------------------------------------------------------- ingest API

@app.post("/api/ingest")
async def api_ingest(request: Request):
    tok = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not tok or not secrets.compare_digest(tok, db.get("api_token")):
        return JSONResponse({"error": "unauthorized"}, 401)
    body = await request.json()
    items = body if isinstance(body, list) else [body]
    rows = []
    for it in items[:5000]:
        rows.append(ingest.normalize(
            "api", it.get("ts") or time.time(), it.get("service", "api"), it.get("ip", ""),
            it.get("method", ""), it.get("path", ""), it.get("status", 0), it.get("user_agent", ""),
            it.get("bytes", 0), it.get("referrer", ""), it.get("country", ""), it.get("count", 1)))
    return {"accepted": ingest.insert_events(rows)}
