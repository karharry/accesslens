"""Weekly summary report: build (HTML + text), send via SMTP, schedule."""
import logging
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from html import escape

import db
import stats

log = logging.getLogger("accesslens.mail")
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def week_bounds(now=None):
    """Previous full Monday-Sunday week in local time."""
    now = now or datetime.now()
    start = (now - timedelta(days=now.weekday() + 7)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=7)


def _f(since, until, **kw):
    f = {k: "" for k in stats.FILTER_KEYS}
    f.update(since=int(since), until=int(until), range="custom", **kw)
    return f


def build_report(start: datetime, end: datetime):
    s, e = start.timestamp(), end.timestamp()
    prev = _f(s - (e - s), s)
    cur = _f(s, e)
    cs, ps = stats.summary(cur), stats.summary(prev)

    def delta(a, b):
        if not b:
            return "new" if a else "–"
        return f"{(a - b) * 100 / b:+.0f}%"

    top = lambda dim, n=8: stats.explore(dim, cur, n)
    hours = stats.explore("hour", cur, 1)
    wd = stats.explore("weekday", cur, 1)
    new_ips = [r for r in stats.insights(cur)["new_ips"] if r["first_seen"] <= e][:10]
    sus = stats.insights(cur)["suspicious"][:10]
    upt = stats.uptime()

    title = f"AccessLens weekly report: {start:%d %b} – {(end - timedelta(seconds=1)):%d %b %Y}"
    sections = []
    kpis = [("Requests", cs["total"], delta(cs["total"], ps["total"])),
            ("Unique clients", cs["ips"], delta(cs["ips"], ps["ips"])),
            ("Remote requests", cs["remote"], delta(cs["remote"], ps["remote"])),
            ("Local requests", cs["local"], delta(cs["local"], ps["local"])),
            ("Errors (4xx/5xx)", cs["errors"], delta(cs["errors"], ps["errors"]))]

    def table(name, rows, cols):
        sections.append((name, cols, rows))

    srcs = stats.by_source(cur)
    if srcs:
        table("Traffic by source", [[stats.SOURCES.get(k, (k,))[0], v["n"],
                                     f'{stats.SOURCES.get(k, ("", "", "requests"))[2]}; {v["clients"]} clients'
                                     f' ({v["lan"]:,} LAN / {v["tailscale"]:,} Tailscale / {v["internet"]:,} Internet)']
                                    for k, v in srcs.items()], ["Source", "Events", "Detail"])
    for name, dim in (("Network path", "network"), ("Top services", "service"), ("Top clients", "client"), ("Devices", "device"),
                      ("Apps / browsers", "app"), ("Countries (remote)", "country"), ("Categories", "category")):
        rows = top(dim)
        if dim == "country":
            rows = [r for r in stats.explore("country", {**cur, "scope": "remote"}, 8)]
        table(name, [[r["v"] if not r.get("alias") or dim == "client" else f'{r["alias"]} ({r["v"]})',
                      r["requests"], r["clients"]] for r in rows], ["Name", "Requests", "Clients"])
    if new_ips:
        table("New clients seen this week", [[r["ip"], r["requests"], "local" if r["local"] else (r["country"] or "remote")]
                                              for r in new_ips], ["IP", "Requests", "Where"])
    if sus:
        table("Suspicious clients (many denied / not-found)",
              [[r["ip"], r["requests"], f'{r["denied"]} denied, {r["notfound"]} 404'] for r in sus],
              ["IP", "Requests", "Detail"])
    if upt:
        table("Uptime (7 days)", [[u["probe"]["name"], f'{u["up7"]:.2f}%' if u["up7"] is not None else "–",
                                    f'{u["ms"]:.0f} ms' if u["ms"] else "–"] for u in upt], ["Probe", "Uptime", "Avg latency"])
    busy = ""
    if hours and wd:
        busy = f"Busiest hour: {hours[0]['v']} · busiest weekday: {DAYS[(int(wd[0]['v']) - 1) % 7]}"

    # ---- text
    t = [title, "=" * len(title), ""]
    t += [f"{k}: {v:,} ({d} vs previous week)" for k, v, d in kpis]
    if busy:
        t.append(busy)
    for name, cols, rows in sections:
        t += ["", name, "-" * len(name)] + ["  " + " | ".join(str(c) for c in r) for r in rows]
    # ---- html
    h = [f'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:680px;margin:auto;color:#1f2933">',
         f'<h2 style="margin:0 0 4px">{escape(title)}</h2>',
         '<table style="width:100%;border-collapse:separate;border-spacing:6px;margin:12px 0"><tr>']
    for k, v, d in kpis:
        col = "#6b7280"
        h.append(f'<td style="background:#f3f4f6;border-radius:8px;padding:10px;text-align:center">'
                 f'<div style="font-size:22px;font-weight:700">{v:,}</div><div style="font-size:12px">{k}</div>'
                 f'<div style="font-size:11px;color:{col}">{d} vs prev. week</div></td>')
    h.append("</tr></table>")
    if busy:
        h.append(f'<p style="color:#4b5563">{escape(busy)}</p>')
    for name, cols, rows in sections:
        h.append(f'<h3 style="margin:18px 0 6px;border-bottom:1px solid #e5e7eb">{escape(name)}</h3>'
                 '<table style="width:100%;border-collapse:collapse;font-size:13px"><tr>' +
                 "".join(f'<th style="text-align:left;padding:4px 6px;color:#6b7280">{c}</th>' for c in cols) + "</tr>")
        for i, r in enumerate(rows):
            bg = "#fafafa" if i % 2 else "#fff"
            h.append(f'<tr style="background:{bg}">' + "".join(
                f'<td style="padding:4px 6px">{escape(f"{c:,}" if isinstance(c, int) else str(c))}</td>' for c in r) + "</tr>")
        h.append("</table>")
    h.append('<p style="color:#9ca3af;font-size:11px;margin-top:24px">Sent by AccessLens</p></div>')
    return title, "\n".join(t), "".join(h)


def send_mail(subject, text, html, to=None):
    host = db.get("smtp_host").strip()
    to = to or [a.strip() for a in db.get("mail_to").split(",") if a.strip()]
    if not host or not to:
        raise RuntimeError("SMTP host and recipient must be configured.")
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, ", ".join(to)
    msg["From"] = db.get("mail_from") or db.get("smtp_user") or "accesslens@localhost"
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    port, sec = int(db.get("smtp_port") or 587), db.get("smtp_security")
    ctx = ssl.create_default_context()
    if sec == "ssl":
        s = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
    with s:
        if sec == "starttls":
            s.starttls(context=ctx)
        if db.get("smtp_user"):
            s.login(db.get("smtp_user"), db.get("smtp_pass"))
        s.send_message(msg)


def send_report(start=None, end=None):
    if start is None:
        start, end = week_bounds()
    title, text, html = build_report(start, end)
    send_mail(title, text, html)
    return title


def _tick():
    if db.get("report_enabled") != "1":
        return
    now = datetime.now()
    start, end = week_bounds(now)
    key = start.strftime("%Y-%m-%d")
    if now.weekday() == int(db.get("report_day")) and now.hour >= int(db.get("report_hour")) \
            and db.get("report_last_key") != key:
        db.put("report_last_key", key)  # set first so a failing SMTP can't spam retries every minute
        try:
            send_report(start, end)
            log.info("weekly report sent for %s", key)
        except Exception:
            log.exception("weekly report failed")
            db.put("report_error", f"{time.strftime('%F %T')} failed - see container logs")


def start_scheduler():
    def run():
        while True:
            try:
                _tick()
            except Exception:
                log.exception("scheduler error")
            time.sleep(60)
    threading.Thread(target=run, name="mailer", daemon=True).start()
