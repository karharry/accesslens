# AccessLens

[![Build and publish](https://github.com/karharry/accesslens/actions/workflows/docker.yml/badge.svg)](https://github.com/karharry/accesslens/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/karharry/accesslens)](https://hub.docker.com/r/karharry/accesslens)

Self-hosted access analytics for your homelab. See **which services are used, how often, by whom (IP, device, app),
and whether the visitor was on your LAN, on Tailscale, or on the Internet** - with live stats, summaries, tables,
CSV export and a weekly email report. One container, no external database.

## What it shows

Traffic comes from three sources that are **kept separate everywhere in the UI** (coloured source tabs, one panel per
source on the dashboard, a *Source* column in every table):

| Source | What it sees | How |
|---|---|---|
| **Local proxy (NPM)** | HTTP requests that went through Nginx Proxy Manager (or any nginx/Apache-style log) | reads the proxy's access logs, read-only |
| **Cloudflare tunnel** | HTTP requests from the Internet through Cloudflare tunnels (these never touch your reverse proxy) | Cloudflare GraphQL Analytics API, read-only token |
| **Direct connections** | TCP connections made straight to `host-ip:port`, e.g. `http://100.x.y.z:9090` over Tailscale, bypassing the proxy | the host's kernel connection-tracking table. Connection counts only: no path, status or user-agent |

Every event also carries a **network path** (LAN / Tailscale / Internet), device, OS and app (derived from the
user-agent), and country (Cloudflare).

* **Views:** live dashboard, event table with filters, *Explore* (group by service, IP, device, app, OS, country, category,
  network, ...), *Aggregate* (dimension x hour/day/week/month), *Insights* (new clients, suspicious clients, error-prone
  and silent services), *Uptime* (optional HTTP probes).
* **Weekly email** summarising the previous Monday-Sunday, compared with the week before.
* **Users:** `admin` with a random password generated on first start; extra admins or read-only viewers; any admin can
  delete any other user. Light / dark / system theme. Mobile friendly.
* **CSV export** of events, Explore tables and Aggregate matrices.
* Only parsed events are stored (SQLite, in your config folder). Raw log lines and URL query strings are **not** stored.

## Requirements

* A **Linux** Docker host (Docker Engine 20.10+ and the Compose plugin). The *Direct connections* source needs the
  kernel's `nf_conntrack` module, which is loaded whenever Docker's NAT is in use. On Docker Desktop (macOS/Windows)
  the app runs, but that source can't see your real network.
* Optional, per source: your reverse proxy's access-log folder (NPM: `<npm data>/logs`), a Cloudflare API token, SMTP
  credentials for the email.

## Quick start

**1. Create the config folder as your own user** (so it is owned by you, not root; the container writes its database there):

```bash
mkdir -p ~/accesslens/config && cd ~/accesslens
id -u; id -g          # your UID and GID, usually 1000 and 1000
```

**2a. Docker Compose (recommended).** Save [docker-compose.example.yml](docker-compose.example.yml) as
`docker-compose.yml`, edit the lines marked `<-` (image, UID:GID, timezone, log path), then:

```bash
docker compose up -d
```

**2b. Or `docker run`:**

```bash
docker run -d --name accesslens --restart unless-stopped \
  --user 1000:1000 \
  --network host --cap-drop ALL --cap-add DAC_READ_SEARCH \
  -e TZ=Europe/Athens \
  -v "$PWD/config":/config \
  -v /path/to/npm/data/logs:/logs/npm:ro \
  karharry/accesslens:latest
```

**3. Get the generated admin password** (shown once, on first start):

```bash
docker logs accesslens
```

It is also saved in `config/initial-admin-password.txt`, which is deleted as soon as you change the password.

**4. Open** `http://<your-server-ip>:8089`, sign in as `admin`, and change the password under **My account**.

> No NPM? Leave out the log mount. AccessLens still starts; just configure the sources you do have.

## First-run setup

1. **Settings -> Log sources**: one line per log: `format|label|path`. The default
   `npm||/logs/npm/proxy-host-*_access.log` matches the mount above. Existing and rotated (`.gz`) logs are imported once.
2. **Settings -> Device names & service categories**: give IPs friendly names (`192.168.1.50,Living-room TV`).
3. **Settings -> Cloudflare tunnel traffic** (optional): see below.
4. **Settings -> Direct connections**: name your ports (`9090,Navidrome`); unnamed ones show as `port 9090`.
5. **Settings -> Weekly email**: enter SMTP details, press *Send test email*, tick *Send weekly report*, pick day/hour.

### Cloudflare token

Tunnelled services bypass your reverse proxy, so their traffic is read from Cloudflare instead.

1. Cloudflare dashboard -> *My Profile* -> *API Tokens* -> *Create Token* -> custom token.
2. Permissions: **Account / Account Analytics / Read** and **Zone / Zone / Read** (read-only; nothing can be changed with it).
3. Paste it in Settings, *Save*, then *Discover zones* and *Poll now*. The dashboard panel shows the status.

Free plans keep roughly one day of detailed analytics, so AccessLens polls continuously (every 5 minutes by default) and
keeps its own history. If a tunnel points at your reverse proxy, those requests appear under both sources - use the source
tabs to look at one at a time.

### Direct connections: how it works

AccessLens reads `/proc/net/nf_conntrack` and records new connections to the host's own IP addresses (LAN, Tailscale...),
which is the only way to see services reached by plain `ip:port`.

* Needs `network_mode: host` (otherwise the table belongs to the container) and the `DAC_READ_SEARCH` capability (the table
  is root-only; a copy of `cat` holding just that capability reads it - the app itself runs unprivileged and every other
  capability is dropped). Without them everything else works and the dashboard tells you what is missing.
* Ignored by default: ports 80 and 443 (covered by the proxy), connections from Docker bridges and from the host
  itself, and unanswered connection attempts.
* Dashboards or monitoring agents that poll your services appear as clients. Add their IPs under *Ignore IPs*.
* Host networking means the UI listens on all host addresses; set `BIND` (e.g. `192.168.1.10`) to restrict it, and see
  *Security notes*.

## Configuration

| Item | Value |
|---|---|
| UI port | `8089`; env `PORT` to change (host networking: no `-p` mapping) |
| Bind address | env `BIND`, default `0.0.0.0` |
| Network / capabilities | `network_mode: host`, `cap_drop: [ALL]`, `cap_add: [DAC_READ_SEARCH]` |
| Config / data | `/config` bind mount: `accesslens.db`, `secret.key`, `initial-admin-password.txt` |
| User | `user: "UID:GID"` in compose / `--user` (image default `1000:1000`); must own the config folder |
| Timezone | env `TZ`, e.g. `Europe/Athens` (used for reports and "busy hours") |
| Health check | `GET /healthz` |
| Log mounts | any path, mounted read-only; reference it in *Settings -> Log sources* |
| Retention | *Settings*, default 365 days (0 = forever) |

Everything else (SMTP, tokens, sources, labels) is configured in the web UI and stored in the database.

## Updating, backup, reset

```bash
docker compose pull && docker compose up -d      # update
docker compose down                              # stop; data stays in ./config
```

Back up by stopping the container and copying `config/`.

**Forgot a password?** Another admin can reset it under *Users*. If you locked yourself out completely, stop the
container, delete `config/accesslens.db*` (this removes all history and users) and start again: a new `admin` password
is generated and printed in the log.

## Build from source

```bash
git clone https://github.com/karharry/accesslens.git && cd accesslens
docker build -t accesslens:local .
# then use image: accesslens:local in the compose file
```

## Security notes

* **Put it behind your reverse proxy with HTTPS** if you expose it beyond your LAN; when proxied, forward
  `X-Forwarded-Proto` so the session cookie is marked `Secure`. Login attempts are throttled and forms are CSRF-protected.
* Host networking and `DAC_READ_SEARCH` are only needed for *Direct connections*. If you don't want them, remove
  `network_mode: host` and `cap_*`, add `ports: ["8089:8089"]`, and turn the monitor off in Settings.
* The SMTP password and Cloudflare token are stored in the database in your config folder (readable only by the container
  user). Use a **read-only** Cloudflare token and an app-specific SMTP password.
* Log fields are attacker-controlled (user-agent, paths). They are HTML-escaped in the UI and neutralised in CSV exports.
* The NPM log mount is read-only; AccessLens never modifies your proxy.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Permission denied writing `/config` | The config folder isn't owned by the `user:` UID. `sudo chown -R 1000:1000 config` |
| NPM panel says "No log files found" | Check the volume path and the pattern in *Log sources* |
| Direct connections: "cannot read the conntrack table" | Add `cap_add: [DAC_READ_SEARCH]` and `network_mode: host`; check `sudo modprobe nf_conntrack` |
| Direct connections: "could not determine host IPs" | Enter them in *Settings -> Direct connections -> Host IPs* |
| Everything shows as `172.x.0.1` | Docker NAT hides client IPs in the proxy's logs; the Direct source is unaffected. See Insights |
| Cloudflare poll fails | The error is shown on the dashboard panel; check token permissions and zone IDs |
| Port 8089 in use | Set env `PORT` |

## License

[MIT](LICENSE)
