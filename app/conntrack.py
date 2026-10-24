"""Direct-connection monitor.

Reads the host's kernel connection-tracking table and records new connections made *to this host's own
addresses* (LAN, Tailscale, ...). This sees services reached by ip:port that bypass the reverse proxy.
It records connection counts only - there is no HTTP path/status/user-agent at this layer.

Needs `network_mode: host` (so /proc/net/nf_conntrack is the host's) and the DAC_READ_SEARCH capability
(the file is root-only; a file-capability copy of `cat` named `ctcat` does the reading).
"""
import logging
import os
import re
import subprocess
import time

import db
import ingest

log = logging.getLogger("accesslens.conntrack")
PATH = os.environ.get("CONNTRACK_PATH", "/proc/net/nf_conntrack")
READER = os.environ.get("CONNTRACK_READER", "ctcat")
TCP_ESTABLISHED = {"ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE"}
_TUPLE = re.compile(r"(src|dst|sport|dport)=(\S+)")

_seen = {}          # flow key -> already recorded?
_first = [True]     # first poll only learns pre-existing flows
_last_status = ["", 0.0]


def status(msg):
    if msg != _last_status[0] or time.time() - _last_status[1] > 60:
        _last_status[:] = [msg, time.time()]
        db.put("conn_status", f"{time.strftime('%F %T')} {msg}")


def read_table() -> str:
    try:
        with open(PATH) as f:
            return f.read()
    except PermissionError:
        pass
    except FileNotFoundError:
        raise RuntimeError("nf_conntrack is not available here. Run with network_mode: host and make sure the "
                           "nf_conntrack kernel module is loaded.")
    try:
        r = subprocess.run([READER, PATH], capture_output=True, timeout=20)
    except FileNotFoundError:
        raise RuntimeError("helper 'ctcat' missing from the image.")
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace").strip()
        raise RuntimeError("cannot read the conntrack table - add cap_add: [DAC_READ_SEARCH] (and "
                           f"network_mode: host). {err[:120]}")
    return r.stdout.decode(errors="replace")


def parse(line):
    t = line.split()
    if len(t) < 6 or t[2] not in ("tcp", "udp"):
        return None
    state = t[5] if "=" not in t[5] else ""
    pairs = _TUPLE.findall(line)
    if len(pairs) < 8:
        return None
    o = dict(pairs[:4])
    return {"proto": t[2], "state": state, "src": o["src"], "dst": o["dst"], "sport": o["sport"],
            "dport": int(o["dport"]), "unreplied": "[UNREPLIED]" in line}


def host_ips():
    """Addresses that belong to this host (override with the conn_host_ips setting)."""
    manual = [x.strip() for x in db.get("conn_host_ips").replace("\n", ",").split(",") if x.strip()]
    if manual:
        return set(manual)
    ips, last = set(), None
    try:
        for line in open("/proc/net/fib_trie"):
            s = line.strip()
            if s.startswith("|--"):
                last = s[4:].strip()
            elif s.startswith("/32 host LOCAL") and last:
                ips.add(last)
    except OSError:
        pass
    try:
        import ipaddress
        for line in open("/proc/net/if_inet6"):
            h = line.split()[0]
            ips.add(str(ipaddress.IPv6Address(int(h, 16))))
    except OSError:
        pass
    dn = docker_nets()
    return {i for i in ips if not i.startswith(("127.", "fe80:")) and i != "::1" and not ingest.in_nets(i, dn)}


def docker_nets():
    """Subnets of Docker bridges: traffic from them is container-to-host, not an outside client."""
    import ipaddress
    import socket
    import struct
    nets = []
    try:
        for line in list(open("/proc/net/route"))[1:]:
            f = line.split()
            if f[0].startswith(("docker", "br-", "veth")) and int(f[7], 16):
                dest = socket.inet_ntoa(struct.pack("<L", int(f[1], 16)))
                mask = socket.inet_ntoa(struct.pack("<L", int(f[7], 16)))
                nets.append(ipaddress.ip_network(f"{dest}/{mask}", strict=False))
    except (OSError, ValueError):
        pass
    return nets


def port_labels():
    out = {}
    for l in db.lines("conn_labels"):
        if "," in l:
            p, name = (x.strip() for x in l.split(",", 1))
            if p.isdigit() and name:
                out[int(p)] = name
    return out


def _ports(key):
    return {int(x) for x in db.get(key).replace("\n", ",").split(",") if x.strip().isdigit()}


def tick():
    if db.get("conn_enabled") != "1":
        status("disabled")
        return
    try:
        text = read_table()
    except RuntimeError as e:
        status(f"error: {e}")
        return
    hosts = host_ips()
    if not hosts:
        status("error: could not determine this host's IP addresses - set them in Settings")
        return
    skip_src = ingest.parse_nets(db.get("conn_ignore_src")) + docker_nets()
    protos = {p.strip() for p in db.get("conn_protocols").split(",") if p.strip()}
    skip_ports, only_ports, labels = _ports("conn_ports_ignore"), _ports("conn_ports_only"), port_labels()

    alive, new, flows = set(), {}, 0
    for line in text.splitlines():
        f = parse(line)
        if not f or f["proto"] not in protos or f["dst"] not in hosts or f["src"] in hosts:
            continue
        port = f["dport"]
        if port in skip_ports or (only_ports and port not in only_ports) or ingest.in_nets(f["src"], skip_src):
            continue
        flows += 1
        key = (f["proto"], f["src"], f["sport"], f["dst"], port)
        alive.add(key)
        answered = not f["unreplied"] and (f["proto"] != "tcp" or f["state"] in TCP_ESTABLISHED)
        if _first[0]:
            _seen[key] = True            # connections that predate the monitor are not "new"
        elif key not in _seen or (not _seen[key] and answered):
            _seen[key] = answered
            if answered:
                k = (f["proto"], f["src"], f["dst"], port)
                new[k] = new.get(k, 0) + 1
    for key in [k for k in _seen if k not in alive]:
        del _seen[key]
    _first[0] = False

    now = time.time()
    rows = [ingest.normalize("connection", now, labels.get(port, f"port {port}"), src, proto.upper(),
                             f"{dst}:{port}", 0, "", 0, "", "", n, app=f"{proto.upper()} connection")
            for (proto, src, dst, port), n in new.items()]
    ingest.insert_events(rows)
    status(f"ok: watching {len(hosts)} host IP(s), {flows} tracked flows, {sum(new.values())} new")


def start():
    ingest.loop("conntrack", tick, lambda: int(db.get("conn_poll") or 5))
