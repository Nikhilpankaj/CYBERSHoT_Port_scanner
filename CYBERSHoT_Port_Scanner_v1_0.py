#!/usr/bin/env python3
"""
CYBERSHoT Port Scanner v1.0

A TCP connect scanner : port/state detection
(open / closed / filtered), service + version detection, CIDR and hostname
targets, host discovery, timing templates, and normal / JSON / greppable output.

Only scan systems you own or have explicit permission to test.
"""
from __future__ import annotations

import argparse
import errno
import functools
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

VERSION = "1.0"

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# Timing templates, -T0..-T5.
#   timeout : seconds to wait for a connect() reply
#   workers : concurrent probes
#   delay   : minimum seconds between probe starts (global rate limit)
#   retries : extra attempts for ports that look filtered
TIMING = {
    0: dict(name="paranoid",   timeout=5.0, workers=1,   delay=1.0,  retries=2),
    1: dict(name="sneaky",     timeout=4.0, workers=5,   delay=0.25, retries=2),
    2: dict(name="polite",     timeout=3.0, workers=20,  delay=0.05, retries=1),
    3: dict(name="normal",     timeout=1.5, workers=100, delay=0.0,  retries=1),
    4: dict(name="aggressive", timeout=1.0, workers=300, delay=0.0,  retries=1),
    5: dict(name="insane",     timeout=0.5, workers=500, delay=0.0,  retries=0),
}

# TCP "ping" ports for host discovery. Any SYN/ACK or RST reply proves the host is up.
DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 8080)

HTTP_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}

# Approximate "most common ports" list (most popular first, then numeric).
# This is a hand-built approximation, not nmap's frequency database.
_COMMON_FIRST = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135,
                 3306, 8080, 1723, 111, 995, 993, 5900]
_COMMON_REST = [
    7, 9, 13, 26, 37, 79, 81, 88, 106, 113, 119, 144, 179, 199, 389, 427, 444,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
    3000, 3128, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
    5666, 5800, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8081, 8443, 8888, 9100,
    9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]
TOP_PORTS = list(dict.fromkeys(_COMMON_FIRST + _COMMON_REST))

# Banner signatures: (regex, service, version template). Text is latin-1 decoded.
SIGNATURES = [
    (r"^SSH-(\d\.\d+)-OpenSSH[_-]?(\S+)", "ssh", r"OpenSSH \2 (protocol \1)"),
    (r"^SSH-(\d\.\d+)-(\S+)", "ssh", r"\2 (protocol \1)"),
    (r"^220[^\r\n]*?\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server)\b[ )]*([\d.]+)?", "ftp", r"\1 \2"),
    (r"^220[^\r\n]*\bFTP\b", "ftp", ""),
    (r"^220[^\r\n]*\b(Postfix|Exim|Sendmail|Microsoft ESMTP)\b", "smtp", r"\1"),
    (r"^220[^\r\n]*\bE?SMTP\b", "smtp", ""),
    (r"^\+OK", "pop3", ""),
    (r"^\* OK[^\r\n]*\bIMAP", "imap", ""),
    (r"^RFB (\d{3}\.\d{3})", "vnc", r"protocol \1"),
    (r"^.{3}\x00\x0a([\d.]+[^\x00]*)\x00", "mysql", r"MySQL \1"),
    (r"^\xff[\xfb-\xfe]", "telnet", ""),
]

MAX_HOSTS = 65536
CLOSED_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str                 # open | closed | filtered
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Host:
    ip: str
    family: int
    name: str = ""
    up: bool = True
    latency: float | None = None
    ports: list = field(default_factory=list)
    scan_time: float = 0.0
    interrupted: bool = False


@dataclass
class Config:
    ports: list
    timeout: float
    workers: int
    delay: float
    retries: int
    timing: int
    service_scan: bool
    verbose: bool
    show_all: bool
    no_dns: bool


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------
# Argument parsing helpers
# --------------------------------------------------------------------------

def port_spec(text: str) -> list:
    """Parse '22,80,443', '1-1000', '20-25,8000-8100', or '-' (all ports)."""
    if text == "-":
        return list(range(1, 65536))
    ports = []
    try:
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo_s, _, hi_s = part.partition("-")
                lo, hi = int(lo_s or 1), int(hi_s or 65535)
            else:
                lo = hi = int(part)
            if not 1 <= lo <= hi <= 65535:
                raise ValueError
            ports.extend(range(lo, hi + 1))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid port spec {text!r} (use e.g. 22,80,443 or 1-1000 or -)")
    if not ports:
        raise argparse.ArgumentTypeError("no ports specified")
    return list(dict.fromkeys(ports))


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}")
    if value < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return value


def positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}")
    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybershot",
        description="CYBERSHoT Port Scanner - TCP connect scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  cybershot.py scanme.example.com\n"
            "  cybershot.py -p 22,80,443 -sV 192.168.1.10\n"
            "  cybershot.py -p- -T4 10.0.0.5\n"
            "  cybershot.py -sn 192.168.1.0/24\n"
            "  cybershot.py -F -oJ results.json 192.168.1.10,192.168.1.11\n\n"
            "Only scan systems you own or have explicit permission to test."
        ),
    )
    p.add_argument("targets", nargs="+", metavar="target",
                   help="hostname, IP, CIDR range (192.168.1.0/24) or comma-separated list")

    g = p.add_mutually_exclusive_group()
    g.add_argument("-p", "--ports", type=port_spec, metavar="PORTS",
                   help="ports to scan: 22,80,443 | 1-1000 | - (all). Default: 1-1024")
    g.add_argument("-F", "--fast", action="store_true",
                   help="fast scan: ~100 most common ports")
    g.add_argument("--top-ports", type=positive_int, metavar="N",
                   help="scan the N most common ports (list holds ~100)")

    p.add_argument("-sV", dest="service_scan", action="store_true",
                   help="service/version detection (banner grabbing)")
    p.add_argument("-sn", dest="ping_only", action="store_true",
                   help="host discovery only, no port scan")
    p.add_argument("-Pn", dest="skip_discovery", action="store_true",
                   help="skip host discovery, treat all hosts as up")
    p.add_argument("-n", dest="no_dns", action="store_true",
                   help="never do reverse DNS lookups")
    p.add_argument("-T", dest="timing", type=int, choices=range(6), default=3,
                   metavar="0-5", help="timing template (0 slowest/stealthiest, 5 fastest). Default: 3")
    p.add_argument("--timeout", type=positive_float, metavar="SEC",
                   help="override connect timeout from the timing template")
    p.add_argument("--workers", type=positive_int, metavar="N",
                   help="override worker count from the timing template")
    p.add_argument("-r", "--randomize", action="store_true", help="randomize port scan order")
    p.add_argument("--all", dest="show_all", action="store_true",
                   help="list closed/filtered ports too (default: only open, unless very few others)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print open ports as they are discovered")

    p.add_argument("-oN", dest="out_normal", metavar="FILE", help="write normal output to FILE")
    p.add_argument("-oJ", dest="out_json", metavar="FILE", help="write JSON output to FILE")
    p.add_argument("-oG", dest="out_grep", metavar="FILE", help="write greppable output to FILE")
    p.add_argument("--version", action="version", version=f"CYBERSHoT {VERSION}")
    return p


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

def expand_target(token: str) -> list:
    """Return [(ip, hostname_or_empty), ...] for one target token."""
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ScanError(f"invalid CIDR range: {token}")
        if net.num_addresses > MAX_HOSTS:
            raise ScanError(f"{token} is too large (max {MAX_HOSTS} addresses)")
        return [(str(ip), "") for ip in net.hosts()]

    try:
        return [(str(ipaddress.ip_address(token)), "")]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(token, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"cannot resolve {token}")
    infos.sort(key=lambda i: i[0] != socket.AF_INET)      # prefer IPv4
    return [(infos[0][4][0], token)]


def resolve_targets(specs: list) -> tuple:
    hosts, errors, seen = [], [], set()
    for spec in specs:
        for token in spec.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                for ip, name in expand_target(token):
                    if ip not in seen:
                        seen.add(ip)
                        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                        hosts.append(Host(ip=ip, family=family, name=name))
            except ScanError as exc:
                errors.append(str(exc))
    return hosts, errors


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

class RateLimiter:
    """Global minimum interval between probe starts, shared by all workers."""

    def __init__(self, interval: float, stop: threading.Event):
        self.interval = interval
        self.stop = stop
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        if slot > now:
            self.stop.wait(slot - now)


def probe(ip: str, family: int, port: int, timeout: float) -> tuple:
    """One TCP connect probe. Returns (state, rtt_seconds_or_None)."""
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        code = sock.connect_ex((ip, port))
        rtt = time.monotonic() - start
    except OSError:
        return "filtered", None
    finally:
        if sock is not None:
            sock.close()

    if code == 0:
        return "open", rtt
    if code in CLOSED_ERRNOS:          # RST received: host is up, port closed
        return "closed", rtt
    return "filtered", None            # timeout, unreachable, admin-prohibited...


def scan_port(host: Host, port: int, cfg: Config, limiter: RateLimiter,
              stop: threading.Event):
    if stop.is_set():
        return None
    state, rtt = "filtered", None
    for _ in range(cfg.retries + 1):
        limiter.wait()
        if stop.is_set():
            return None
        state, rtt = probe(host.ip, host.family, port, cfg.timeout)
        if state != "filtered":        # only retry ports that gave no answer
            break
    return port, state, rtt


def host_is_up(ip: str, family: int, timeout: float) -> tuple:
    for port in DISCOVERY_PORTS:
        state, rtt = probe(ip, family, port, timeout)
        if state != "filtered":
            return True, rtt
    return False, None


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def discover(hosts: list, cfg: Config, ping: bool) -> None:
    """Host discovery + reverse DNS, run in parallel across hosts."""
    def check(host: Host) -> None:
        if ping:
            host.up, host.latency = host_is_up(host.ip, host.family, min(cfg.timeout, 1.0))
        if host.up and not host.name and not cfg.no_dns:
            host.name = reverse_dns(host.ip)

    pool = ThreadPoolExecutor(max_workers=min(64, len(hosts)))
    try:
        for fut in [pool.submit(check, h) for h in hosts]:
            fut.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


# --------------------------------------------------------------------------
# Service / version detection
# --------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _recv_some(sock, wait: float) -> bytes:
    sock.settimeout(wait)
    try:
        return sock.recv(2048)
    except OSError:                    # includes timeouts and TLS errors
        return b""


def grab_banner(host: Host, port: int, cfg: Config) -> bytes:
    """Connect and read whatever the service says (probing HTTP if it stays silent)."""
    http_probe = (f"HEAD / HTTP/1.0\r\nHost: {host.name or host.ip}\r\n"
                  f"User-Agent: CYBERSHoT/{VERSION}\r\nConnection: close\r\n\r\n").encode()
    sock = None
    data = b""
    try:
        sock = socket.create_connection((host.ip, port), timeout=cfg.timeout)
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=None)
        if port not in HTTP_PORTS:                 # talkative services (SSH, FTP, SMTP...)
            data = _recv_some(sock, min(cfg.timeout, 1.0))
        if not data:                               # silent services (HTTP) need a nudge
            sock.settimeout(cfg.timeout)
            sock.sendall(http_probe)
            data = _recv_some(sock, min(max(cfg.timeout, 1.0), 3.0))
    except OSError:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return data


def _prettify(product: str) -> str:
    """'nginx/1.24.0' -> 'nginx 1.24.0'"""
    return re.sub(r"^([\w.\-]+)/", r"\1 ", product.strip(), count=1)


def identify(port: int, raw: bytes) -> tuple:
    """Return (service, version) from a banner, or (None, '') if unrecognised."""
    text = raw.decode("latin-1")
    if text.startswith("HTTP/"):
        service = "https" if port in TLS_PORTS else "http"
        m = re.search(r"^server:[ \t]*(.+?)[ \t]*\r?$", text, re.I | re.M)
        return service, _prettify(m.group(1)) if m else ""
    for pattern, service, template in SIGNATURES:
        m = re.search(pattern, text, re.S)
        if m:
            return service, m.expand(template).strip()
    return None, ""


def _printable(text: str) -> str:
    return " ".join("".join(c if 32 <= ord(c) < 127 else " " for c in text).split())


def detect_service(host: Host, result: PortResult, cfg: Config, stop: threading.Event) -> None:
    if stop.is_set():
        return
    raw = grab_banner(host, result.port, cfg)
    if not raw:
        return
    text = raw.decode("latin-1")
    result.banner = _printable(text[:300])
    service, version = identify(result.port, raw)
    if service:
        result.service, result.version = service, version
    else:                                          # unknown banner: show its first line
        first = text.splitlines()[0] if text.strip() else ""
        line = _printable(first)[:60]
        result.version = line if len(line) >= 3 else ""


# --------------------------------------------------------------------------
# Scanning a host
# --------------------------------------------------------------------------

class Progress:
    def __init__(self, total: int):
        self.total = max(total, 1)
        self.enabled = sys.stderr.isatty()
        self._last = 0.0

    def update(self, done: int) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self._last < 0.2 and done != self.total:
            return
        self._last = now
        sys.stderr.write(f"\r  Scanning: {done}/{self.total} ports ({done * 100 // self.total}%)   ")
        sys.stderr.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stderr.write("\r" + " " * 50 + "\r")
            sys.stderr.flush()

    def log(self, message: str) -> None:
        self.clear()
        print(message, flush=True)


def scan_host(host: Host, cfg: Config, stop: threading.Event) -> None:
    started = time.monotonic()
    limiter = RateLimiter(cfg.delay, stop)
    progress = Progress(len(cfg.ports))
    rtts = []
    pool = ThreadPoolExecutor(max_workers=cfg.workers)
    try:
        futures = [pool.submit(scan_port, host, p, cfg, limiter, stop) for p in cfg.ports]
        for done, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            if res is None:
                continue
            port, state, rtt = res
            host.ports.append(PortResult(port, state, service_name(port) if state == "open" else ""))
            if rtt is not None:
                rtts.append(rtt)
            if state == "open" and cfg.verbose:
                progress.log(f"Discovered open port {port}/tcp on {host.ip}")
            progress.update(done)

        open_ports = [r for r in host.ports if r.state == "open"]
        if cfg.service_scan and open_ports:
            with ThreadPoolExecutor(max_workers=min(cfg.workers, 32)) as sp:
                list(sp.map(lambda r: detect_service(host, r, cfg, stop), open_ports))
    except KeyboardInterrupt:
        stop.set()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        progress.clear()

    host.ports.sort(key=lambda r: r.port)
    host.interrupted = stop.is_set()
    host.scan_time = time.monotonic() - started
    if rtts:
        best = min(rtts)
        host.latency = best if host.latency is None else min(host.latency, best)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def visible_ports(host: Host, show_all: bool) -> list:
    """Open ports always; closed/filtered only if few or --all."""
    non_open = sum(1 for p in host.ports if p.state != "open")
    if show_all or non_open <= 25:
        return list(host.ports)
    return [p for p in host.ports if p.state == "open"]


def render_table(rows: list, with_version: bool) -> list:
    headers = ["PORT", "STATE", "SERVICE"] + (["VERSION"] if with_version else [])
    table = [headers] + [list(r)[:len(headers)] for r in rows]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(headers))]
    return ["  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip() for row in table]


def host_label(host: Host) -> str:
    return f"{host.name} ({host.ip})" if host.name else host.ip


def render_normal(host: Host, cfg: Config) -> str:
    lines = ["", f"Scan report for {host_label(host)}"]
    lines.append(f"Host is up ({host.latency:.4f}s latency)." if host.latency is not None
                 else "Host is up.")
    shown = visible_ports(host, cfg.show_all)
    shown_nums = {p.port for p in shown}
    hidden = Counter(p.state for p in host.ports if p.port not in shown_nums)
    if hidden:
        lines.append("Not shown: " + ", ".join(f"{n} {s}" for s, n in hidden.most_common()))
    if shown:
        rows = [(f"{p.port}/tcp", p.state, p.service or service_name(p.port), p.version)
                for p in shown]
        lines.extend(render_table(rows, cfg.service_scan))
    if not any(p.state == "open" for p in host.ports):
        lines.append("No open ports found.")
    if host.interrupted:
        lines.append("(scan interrupted - partial results)")
    return "\n".join(lines)


def host_to_dict(host: Host, cfg: Config) -> dict:
    ports = [p for p in host.ports if p.state == "open" or cfg.show_all]
    return {
        "address": host.ip,
        "hostname": host.name or None,
        "status": "up" if host.up else "down",
        "latency_seconds": round(host.latency, 5) if host.latency is not None else None,
        "scan_seconds": round(host.scan_time, 3),
        "interrupted": host.interrupted,
        "counts": dict(Counter(p.state for p in host.ports)),
        "ports": [{
            "port": p.port, "protocol": "tcp", "state": p.state,
            "service": p.service or service_name(p.port),
            "version": p.version, "banner": p.banner,
        } for p in ports],
    }


def render_grepable(host: Host, cfg: Config) -> str:
    head = f"Host: {host.ip} ({host.name})"
    lines = [f"{head}\tStatus: Up"]
    open_ports = [p for p in host.ports if p.state == "open"]
    if open_ports:
        entries = []
        for p in open_ports:
            version = p.version.replace("/", "|")
            entries.append(f"{p.port}/open/tcp//{p.service or service_name(p.port)}//{version}/")
        lines.append(f"{head}\tPorts: " + ", ".join(entries))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main flow
# --------------------------------------------------------------------------

def cap_workers(requested: int) -> int:
    """Stay below the process's open-file limit (Unix)."""
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and soft > 0:
            limit = max(soft - 64, 1)
            if requested > limit:
                print(f"Warning: reducing workers {requested} -> {limit} (open-file limit {soft}; "
                      f"raise with 'ulimit -n')", file=sys.stderr)
                return limit
    except ImportError:
        pass
    return requested


def build_config(args) -> Config:
    if args.ports:
        ports = list(args.ports)
    elif args.fast:
        ports = TOP_PORTS[:100]
    elif args.top_ports:
        ports = TOP_PORTS[:args.top_ports]
    else:
        ports = list(range(1, 1025))
    if args.randomize:
        random.shuffle(ports)

    t = TIMING[args.timing]
    return Config(
        ports=ports,
        timeout=args.timeout or t["timeout"],
        workers=cap_workers(args.workers or t["workers"]),
        delay=t["delay"],
        retries=t["retries"],
        timing=args.timing,
        service_scan=args.service_scan,
        verbose=args.verbose,
        show_all=args.show_all,
        no_dns=args.no_dns,
    )


def write_file(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    except OSError as exc:
        print(f"Warning: could not write {path}: {exc}", file=sys.stderr)


def run(args) -> int:
    cfg = build_config(args)
    stop = threading.Event()
    started_at = datetime.now()
    t0 = time.monotonic()
    chunks = []

    def emit(text: str = "") -> None:
        print(text, flush=True)
        chunks.append(text)

    hosts, errors = resolve_targets(args.targets)
    for err in errors:
        print(f"Warning: {err}", file=sys.stderr)
    if not hosts:
        print("Error: no valid targets", file=sys.stderr)
        return 2

    tname = TIMING[cfg.timing]["name"]
    emit("=" * 70)
    emit(f"CYBERSHoT Port Scanner {VERSION}")
    emit("=" * 70)
    if args.ping_only:
        emit(f"Started {started_at:%Y-%m-%d %H:%M:%S} | {len(hosts)} address(es) | host discovery only")
    else:
        emit(f"Started {started_at:%Y-%m-%d %H:%M:%S} | {len(hosts)} address(es) | "
             f"{len(cfg.ports)} ports | T{cfg.timing} {tname} "
             f"({cfg.workers} workers, {cfg.timeout}s timeout)")

    # Host discovery (skipped with -Pn)
    discover(hosts, cfg, ping=not args.skip_discovery)
    up_hosts = [h for h in hosts if h.up]

    if args.ping_only:
        for h in up_hosts:
            lat = f" ({h.latency:.4f}s latency)" if h.latency is not None else ""
            emit(f"Host {host_label(h)} is up{lat}.")
    elif not up_hosts:
        emit("")
        emit("Host seems down. If it is really up but blocking our probes, try -Pn.")
    else:
        down = len(hosts) - len(up_hosts)
        if down:
            emit(f"{down} host(s) appear down and were skipped (use -Pn to scan them anyway).")
        for h in up_hosts:
            scan_host(h, cfg, stop)
            emit(render_normal(h, cfg))
            if stop.is_set():
                break

    elapsed = time.monotonic() - t0
    scanned = [h for h in up_hosts if h.ports]
    total_open = sum(1 for h in scanned for p in h.ports if p.state == "open")
    emit("")
    if args.ping_only:
        emit(f"Done: {len(hosts)} IP address(es) ({len(up_hosts)} up) scanned in {elapsed:.2f}s")
    else:
        emit(f"Done: {len(hosts)} IP address(es) ({len(up_hosts)} up) scanned in {elapsed:.2f}s"
             f" - {total_open} open port(s) found")
    if stop.is_set():
        emit("Scan was interrupted; results above are partial.")

    # Output files
    command = " ".join(sys.argv)
    if args.out_normal:
        write_file(args.out_normal, "\n".join(chunks))
    if args.out_json:
        doc = {
            "scanner": f"CYBERSHoT {VERSION}",
            "command": command,
            "started": started_at.isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 3),
            "interrupted": stop.is_set(),
            "ports_per_host": len(cfg.ports),
            "hosts": [host_to_dict(h, cfg) for h in up_hosts],
        }
        write_file(args.out_json, json.dumps(doc, indent=2))
    if args.out_grep:
        lines = [f"# CYBERSHoT {VERSION} scan initiated {started_at:%Y-%m-%d %H:%M:%S} as: {command}"]
        lines += [render_grepable(h, cfg) for h in up_hosts]
        lines.append(f"# Done: {len(hosts)} IP address(es) ({len(up_hosts)} up) scanned in {elapsed:.2f}s")
        write_file(args.out_grep, "\n".join(lines))

    if stop.is_set():
        return 130
    return 0 if up_hosts else 1


def main(argv=None) -> int:
    if sys.version_info < (3, 9):
        print("CYBERSHoT requires Python 3.9 or newer", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
