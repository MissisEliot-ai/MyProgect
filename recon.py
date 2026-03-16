#!/usr/bin/env python3
"""
recon.py — Subdomain Enumeration Suite 2026 (Modular)
=====================================================
Автоподгрузка модулей из modules/ — кинул .py, оно работает.

Использование:
  python recon.py -d example.com
  python recon.py -d example.com --keys keys.ini
  python recon.py -d example.com --deep
  python recon.py -d example.com --deep --resolve
  python recon.py -d example.com --list-modules

Зависимости (опционально):
  pip install requests dnspython
"""

import argparse
import configparser
import concurrent.futures
import csv
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# OPTIONAL DEPS
# ─────────────────────────────────────────────────────────────
try:
    import requests as _requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver as _dns_resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# ─────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────
_LOCKS = {"crtsh": threading.Lock()}
VERSION = "1.1"

# ─────────────────────────────────────────────────────────────
# COLORS & LOGGING
# ─────────────────────────────────────────────────────────────
_DEBUG = False
_DEBUG_LOG = None

def c(text, color):
    codes = {"red":"\033[91m","green":"\033[92m","yellow":"\033[93m",
             "blue":"\033[94m","cyan":"\033[96m","gray":"\033[90m",
             "reset":"\033[0m","bold":"\033[1m"}
    return f"{codes.get(color,'')}{text}{codes['reset']}"

def _strip_ansi(text):
    """Remove ANSI color codes for log file."""
    return re.sub(r'\033\[[0-9;]*m', '', str(text))

def log(msg, kind="info"):
    prefix = {"info": c("[+]","green"), "warn": c("[!]","yellow"),
              "err":  c("[-]","red"),  "src":  c("[>]","cyan")}
    line = f"{prefix.get(kind,'[?]')} {msg}"
    print(line, flush=True)
    _write_debug_log(line)

def dbg(msg):
    """Debug print — writes to console (if --debug) AND always to debug.log."""
    if _DEBUG:
        print(f"    [DEBUG] {msg}", flush=True)
    _write_debug_log(f"    [DEBUG] {msg}")

def _write_debug_log(line):
    if _DEBUG_LOG:
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            _DEBUG_LOG.write(f"[{ts}] {_strip_ansi(str(line))}\n")
            _DEBUG_LOG.flush()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────────────────────
def get(url, headers=None, timeout=12, retries=2):
    """GET → (status, text)."""
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    if headers:
        h.update(headers)
    last_err = ""
    for attempt in range(retries):
        try:
            if HAS_REQUESTS:
                r = _requests.get(url, headers=h, timeout=timeout, verify=False, allow_redirects=True)
                if r.status_code != 200:
                    dbg(f"HTTP {r.status_code} ← {url[:100]}")
                return r.status_code, r.text
            else:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    return resp.status, resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            last_err = str(e)
            dbg(f"attempt {attempt+1}/{retries} — {type(e).__name__}: {str(e)[:120]}")
            if attempt < retries - 1:
                time.sleep(1.5)
    return 0, last_err

def get_json(url, headers=None, timeout=12):
    status, body = get(url, headers, timeout)
    if status == 200 and body:
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {}
    return status, {}

def post_json(url, payload, headers=None, timeout=12):
    h = {"User-Agent": "Mozilla/5.0 recon/2026", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        if HAS_REQUESTS:
            r = _requests.post(url, json=payload, headers=h, timeout=timeout, verify=False)
            return r.status_code, r.json() if r.text else {}
        else:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers=h, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read())
    except Exception:
        return 0, {}

# ─────────────────────────────────────────────────────────────
# crt.sh HELPERS (shared lock to avoid rate limit)
# ─────────────────────────────────────────────────────────────
def crtsh_query(params, timeout=60):
    """Query crt.sh with proper encoding via params dict."""
    with _LOCKS["crtsh"]:
        try:
            if HAS_REQUESTS:
                r = _requests.get("https://crt.sh/", params=params,
                                  headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                                  timeout=timeout, verify=False, allow_redirects=True)
                dbg(f"crt.sh → {r.status_code} ({len(r.text)} bytes) ← {r.url[:100]}")
                time.sleep(2)
                if r.status_code == 200 and r.text.strip():
                    return json.loads(r.text)
            else:
                qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
                url = f"https://crt.sh/?{qs}"
                status, body = get(url, timeout=timeout)
                time.sleep(2)
                if status == 200 and body.strip():
                    return json.loads(body)
        except Exception as e:
            dbg(f"crt.sh error: {type(e).__name__}: {str(e)[:120]}")
        time.sleep(2)
    return []

def crtsh_extract(data, domain):
    """Extract subdomains from crt.sh JSON."""
    results = set()
    if not isinstance(data, list):
        return results
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") and name != domain:
                results.add(name)
        cn = entry.get("common_name", "").strip().lower()
        if cn.startswith("*."):
            cn = cn[2:]
        if cn.endswith(f".{domain}") and cn != domain:
            results.add(cn)
    return results

# ─────────────────────────────────────────────────────────────
# DNS HELPERS — multi-resolver + massdns
# ─────────────────────────────────────────────────────────────
RESOLVERS = ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222","8.8.4.4",
             "1.0.0.1","149.112.112.112","208.67.220.220"]

def _candidate_resolver_files():
    """Return resolver file paths in lookup order."""
    root = Path(__file__).parent
    return [
        root / "resolvers.txt",              # legacy location (next to recon.py)
        root / "modules" / "resolvers.txt", # current project layout
    ]


def load_resolvers():
    """Load resolvers from resolvers.txt if it exists in known locations."""
    global RESOLVERS
    for rfile in _candidate_resolver_files():
        if not rfile.exists():
            continue
        loaded = [l.strip() for l in rfile.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if loaded:
            RESOLVERS = loaded
            dbg(f"Loaded {len(loaded)} resolvers from {rfile}")
            return str(rfile)
    dbg("No resolvers.txt found in known locations, using built-in defaults")
    return None

load_resolvers()

import random as _random

def dns_query(qname, rtype):
    """DNS query → list of strings."""
    results = []
    try:
        if HAS_DNSPYTHON:
            r = _dns_resolver.Resolver()
            r.nameservers = [_random.choice(RESOLVERS)]
            r.lifetime = 5
            ans = r.resolve(qname, rtype, lifetime=5)
            results = [str(rr) for rr in ans]
        else:
            import subprocess
            out = subprocess.run(["dig", "+short", rtype, qname],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            results = [l.strip() for l in out.stdout.split("\n") if l.strip()]
    except Exception:
        pass
    return results

def resolve_one(subdomain, timeout=2):
    """Resolve A+AAAA with random resolver, 2 attempts → (subdomain, [ips]) or None."""
    for attempt in range(2):
        try:
            if HAS_DNSPYTHON:
                r = _dns_resolver.Resolver()
                r.nameservers = [_random.choice(RESOLVERS)]
                r.lifetime = timeout
                ips = []
                # A record
                try:
                    answers = r.resolve(subdomain, "A", lifetime=timeout)
                    ips.extend(str(rr) for rr in answers)
                except Exception:
                    pass
                # AAAA record (Fix #8: IPv6)
                try:
                    answers6 = r.resolve(subdomain, "AAAA", lifetime=timeout)
                    ips.extend(str(rr) for rr in answers6)
                except Exception:
                    pass
                if ips:
                    return subdomain, ips
            else:
                ip = socket.gethostbyname(subdomain)
                return subdomain, [ip]
        except Exception:
            pass
    return None

def massdns_resolve(candidates, domain, resolvers_file=None):
    """Bulk resolve via massdns if installed. Returns set of resolved subdomains.
    Falls back to None if massdns not available."""
    if resolvers_file is None:
        for candidate in _candidate_resolver_files():
            if candidate.exists():
                resolvers_file = str(candidate)
                break
    if not resolvers_file or not Path(resolvers_file).exists():
        dbg("massdns skipped: resolvers.txt not found")
        return None

    # Find massdns binary with shared detection logic
    massdns_bin = find_binary("massdns")
    if massdns_bin is None:
        dbg("massdns not found in known tool dirs or PATH")
        return None

    dbg(f"massdns found: {massdns_bin}")

    import tempfile
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for c in candidates:
                f.write(c + "\n")
            input_file = f.name
        output_file = input_file + ".out"
        n_candidates = len(candidates)
        dbg(f"massdns_resolve: {n_candidates} candidates")
        subprocess.run([
            massdns_bin,
            "--resolvers", resolvers_file,
            "--type", "A",
            "--output", "S",
            "--outfile", output_file,
            "--processes", "1",
            "--socket-count", "1",
            "--resolve-count", "3",
            "--flush",
            input_file
        ], timeout=600, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results = set()
        if Path(output_file).exists():
            with open(output_file) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "A":
                        sub = parts[0].rstrip(".")
                        if sub.endswith(f".{domain}") and sub != domain:
                            results.add(sub.lower())
            try: Path(output_file).unlink()
            except OSError: pass
        try: Path(input_file).unlink()
        except OSError: pass
        return results
    except Exception as e:
        dbg(f"massdns error: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# EXTERNAL TOOL DETECTION + INTEGRATION
# ─────────────────────────────────────────────────────────────
def _tool_search_dirs():
    """Directories to scan for external tools (Windows-friendly)."""
    root = Path(__file__).parent
    dirs = [
        root,
        root / "tools",
        root / "bin",
        root / "modules" / "tools",
    ]
    # Optional custom dirs: RECON_TOOLS_DIR="C:\tools;D:\sec" on Windows
    env_dirs = os.environ.get("RECON_TOOLS_DIR", "")
    if env_dirs:
        for raw in env_dirs.split(os.pathsep):
            raw = raw.strip().strip('"')
            if raw:
                dirs.append(Path(raw))
    # keep order, drop duplicates
    seen = set()
    uniq = []
    for d in dirs:
        key = str(d.resolve()) if d.exists() else str(d)
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    return uniq


def find_binary(name):
    """Find binary in project dirs first, then PATH. Returns path or None."""
    exts = [".exe", ".bat", ".cmd", ""] if os.name == "nt" else [""]

    # 1) Project-local locations (portable bundles)
    for d in _tool_search_dirs():
        for ext in exts:
            local = d / (name + ext)
            if local.exists() and local.is_file():
                return str(local)

    # 2) PATH via shutil.which (supports PATHEXT on Windows)
    for ext in exts:
        hit = shutil.which(name + ext)
        if hit:
            return hit
    return None

# Detect all binaries at import time
BIN_DNSX = find_binary("dnsx")
BIN_SUBFINDER = find_binary("subfinder")
BIN_AMASS = find_binary("amass")
BIN_HTTPX = find_binary("httpx")

def dnsx_resolve(subdomains, domain):
    """Bulk resolve via dnsx. Returns {sub: [ips]}. Falls back to None."""
    if not BIN_DNSX or not subdomains:
        return None
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for s in subdomains:
                f.write(s + "\n")
            input_file = f.name
        output_file = input_file + ".dnsx"
        n_subs = len(subdomains)
        dx_timeout = max(300, n_subs // 100)  # ~100 subs/sec
        subprocess.run([
            BIN_DNSX, "-l", input_file, "-a", "-resp",
            "-t", "200", "-retry", "2",
            "-silent", "-no-color",
            "-o", output_file
        ], timeout=dx_timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results = {}
        if Path(output_file).exists():
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Format: "sub.domain.com [1.2.3.4]" — ONE LINE PER IP
                    parts = line.split(" [")
                    if len(parts) >= 2:
                        sub = parts[0].strip().lower()
                        val = parts[-1].rstrip("]").strip()
                        # Skip CNAME results (non-IP like "read.uberflip.com")
                        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
                            continue
                        if sub.endswith("." + domain):
                            # Merge IPs — dnsx outputs one line per IP for same sub
                            if sub not in results:
                                results[sub] = []
                            if val not in results[sub]:
                                results[sub].append(val)
            try: Path(output_file).unlink()
            except OSError: pass
        try: Path(input_file).unlink()
        except OSError: pass
        dbg(f"dnsx resolved {len(results)} hosts")
        return results if results else None
    except Exception as e:
        dbg(f"dnsx error: {e}")
        return None

def run_subfinder(domain):
    """Run subfinder as external source. Returns set of subdomains."""
    if not BIN_SUBFINDER:
        return set()
    try:
        result = subprocess.run(
            [BIN_SUBFINDER, "-d", domain, "-silent", "-no-color", "-all"],
            timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        subs = set()
        for line in result.stdout.decode(errors="ignore").strip().split("\n"):
            line = line.strip().lower()
            if line and line.endswith("." + domain) and line != domain:
                subs.add(line)
        dbg(f"subfinder found {len(subs)} subs")
        return subs
    except Exception as e:
        dbg(f"subfinder error: {e}")
        return set()

def run_amass(domain):
    """Run amass enum. Supports v4 (-passive -o) and v5 (enum + subs -names).
    Returns set of subdomains."""
    if not BIN_AMASS:
        return set()
    import tempfile

    # Detect version from version string (most reliable)
    is_v5 = False
    ver_str = ""
    try:
        vr2 = subprocess.run(
            [BIN_AMASS, "-version"],
            timeout=5, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        ver_str = (vr2.stdout + vr2.stderr).decode(errors="ignore").strip()
        print(f"    [amass] version: {ver_str}")
        # Parse version number: "v5.0.0", "5.0.1", "OWASP Amass v5.0.0" etc.
        ver_match = re.search(r'v?(\d+)\.(\d+)', ver_str)
        if ver_match:
            major = int(ver_match.group(1))
            if major >= 5:
                is_v5 = True
    except Exception:
        pass

    # Fallback: try "subs -h" subcommand probe
    if not is_v5 and not ver_str:
        try:
            vr = subprocess.run(
                [BIN_AMASS, "subs", "-h"],
                timeout=5, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            combined = (vr.stdout + vr.stderr).decode(errors="ignore").lower()
            if "unknown" not in combined and "invalid" not in combined:
                is_v5 = True
        except Exception:
            pass

    subs = set()

    def _parse_lines(text):
        """Extract valid subdomains from text output."""
        found = set()
        for line in text.strip().split("\n"):
            line = line.strip().lower()
            if not line:
                continue
            if " " in line:
                line = line.split()[0]
            if line and line.endswith("." + domain) and line != domain:
                if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', line):
                    found.add(line)
        return found

    try:
        if is_v5:
            # Amass v5: enum stores to DB, then subs extracts
            print(f"    [amass v5] enum -d {domain} ...")
            r1 = subprocess.run(
                [BIN_AMASS, "enum", "-d", domain, "-timeout", "2"],
                timeout=180, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stderr1 = r1.stderr.decode(errors="ignore")[:300]
            stdout1 = r1.stdout.decode(errors="ignore")
            if stderr1:
                dbg(f"amass enum stderr: {stderr1}")

            # Try parsing enum stdout first (some v5 builds output here)
            subs = _parse_lines(stdout1)

            # Try "subs -names -d domain"
            if not subs:
                r2 = subprocess.run(
                    [BIN_AMASS, "subs", "-names", "-d", domain],
                    timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                subs = _parse_lines(r2.stdout.decode(errors="ignore"))
                dbg(f"amass subs -names: {len(subs)} found")

            # Fallback: try "subs -show -d domain"
            if not subs:
                r3 = subprocess.run(
                    [BIN_AMASS, "subs", "-show", "-d", domain],
                    timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                subs = _parse_lines(r3.stdout.decode(errors="ignore"))
                dbg(f"amass subs -show: {len(subs)} found")

            # Fallback: try "subs -d domain" (bare)
            if not subs:
                r4 = subprocess.run(
                    [BIN_AMASS, "subs", "-d", domain],
                    timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                subs = _parse_lines(r4.stdout.decode(errors="ignore"))
                dbg(f"amass subs bare: {len(subs)} found")

        else:
            # Amass v4: enum -passive -d domain -o file
            print(f"    [amass v4] enum -passive -d {domain} ...")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                output_file = f.name
            r1 = subprocess.run(
                [BIN_AMASS, "enum", "-passive", "-d", domain,
                 "-timeout", "2", "-o", output_file],
                timeout=180, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stderr1 = r1.stderr.decode(errors="ignore")[:200]
            if stderr1:
                dbg(f"amass stderr: {stderr1}")
            if Path(output_file).exists():
                with open(output_file) as f:
                    subs = _parse_lines(f.read())
                try: Path(output_file).unlink()
                except OSError: pass
            # Fallback: parse stdout
            if not subs:
                subs = _parse_lines(r1.stdout.decode(errors="ignore"))

        print(f"    [amass] found {len(subs)} subdomains")
        return subs
    except subprocess.TimeoutExpired:
        print(f"    [amass] TIMEOUT (180s)")
        return set()
    except Exception as e:
        print(f"    [amass] ERROR: {type(e).__name__}: {e}")
        return set()

# ─────────────────────────────────────────────────────────────
# SUBDOMAIN CLEANER
# ─────────────────────────────────────────────────────────────
def clean(domain, raw):
    """Extract and normalize valid subdomains from string/list."""
    results = set()
    texts = [raw] if isinstance(raw, str) else raw
    pattern = re.compile(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain),
        re.IGNORECASE
    )
    for text in texts:
        for match in pattern.findall(str(text)):
            sub = _normalize_host(match, domain)
            if sub:
                results.add(sub)
    return results

def _normalize_host(name, domain):
    """Normalize a hostname: lowercase, strip junk, validate, scope check.
    Returns normalized name or None if invalid."""
    if not name or not isinstance(name, str):
        return None
    # Lowercase + strip whitespace, trailing dots, control chars
    name = name.lower().strip().rstrip(".")
    name = re.sub(r'[\x00-\x1f\x7f\s]', '', name)
    # Remove wildcard prefix
    while name.startswith("*."):
        name = name[2:]
    # Remove leading dots
    name = name.lstrip(".")
    # Must end with .domain
    if not name.endswith("." + domain) or name == domain:
        return None
    # Validate: only a-z, 0-9, hyphens, dots. No double dots, no leading/trailing hyphens per label
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', name):
        return None
    if ".." in name:
        return None
    # Max 253 chars total, labels max 63
    if len(name) > 253:
        return None
    for label in name.split("."):
        if len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return None
    return name

# ─────────────────────────────────────────────────────────────
# CONFIG / KEYS
# ─────────────────────────────────────────────────────────────
def load_keys(path):
    keys = {}
    if not path or not Path(path).exists():
        return keys
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if "General" in cfg:
        keys = {k.lower(): v.strip() for k, v in cfg["General"].items() if v.strip()}
    for bad in ("robtex", "otx"):
        if keys.get(bad, "").startswith("http"):
            del keys[bad]
    return keys

def k(keys, *names):
    """Return first non-empty key."""
    for n in names:
        v = keys.get(n.lower(), "")
        if v and not v.startswith("http"):
            return v
    return ""

# ─────────────────────────────────────────────────────────────
# MODULE LOADER
# ─────────────────────────────────────────────────────────────
def load_modules(modules_dir=None):
    """Auto-discover and load all modules from modules/ directory."""
    if modules_dir is None:
        modules_dir = Path(__file__).parent / "modules"
    else:
        modules_dir = Path(modules_dir)

    if not modules_dir.exists():
        log(f"Modules directory not found: {modules_dir}", "err")
        return []

    modules = []
    for f in sorted(modules_dir.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Validate module interface
            if not hasattr(mod, "NAME") or not hasattr(mod, "PHASE") or not hasattr(mod, "run"):
                dbg(f"Skip {f.name}: missing NAME/PHASE/run")
                continue

            modules.append(mod)
        except Exception as e:
            log(f"  Error loading {f.name}: {e}", "err")
            dbg(f"Module load error: {e}")

    # Sort by PHASE then by PRIORITY (lower = first)
    modules.sort(key=lambda m: (getattr(m, "PHASE", 99), getattr(m, "PRIORITY", 50)))
    return modules

# ─────────────────────────────────────────────────────────────
# CONTEXT — shared state between modules
# ─────────────────────────────────────────────────────────────
def make_context(domain, keys, args):
    """Build context dict — the shared brain all modules use."""
    return {
        # Target
        "domain": domain,
        "keys": keys,

        # Results (modules read & write)
        "found_subs": set(),
        "source_map": {},       # {source_name: set(subs)}
        "resolved": {},         # {sub: [ips]}
        "wildcard_ips": set(),
        "hidden_subs": set(),        # SERVFAIL/REFUSED hosts → hidden.txt
        "wordcloud": {},        # {word: count}

        # Config
        "debug": args.debug,
        "deep": args.deep,
        "threads": args.threads,
        "timeout": args.timeout,
        "delay": args.delay,
        "RECON_RECURSIVE_PARENT_MAX": max(50, int(os.environ.get("RECON_RECURSIVE_PARENT_MAX", "300"))),
        "RECON_RECURSIVE_WILDCARD_PARENT_MAX": max(50, int(os.environ.get("RECON_RECURSIVE_WILDCARD_PARENT_MAX", "300"))),
        "RECON_WILDCARD_LOG_LIMIT": max(0, int(os.environ.get("RECON_WILDCARD_LOG_LIMIT", "60"))),

        # Shared utilities — modules use these, no imports needed
        "get": get,
        "get_json": get_json,
        "post_json": post_json,
        "clean": clean,
        "normalize": lambda name: _normalize_host(name, domain),
        "dns_query": dns_query,
        "resolve_one": resolve_one,
        "massdns_resolve": massdns_resolve,
        "dnsx_resolve": dnsx_resolve,
        "run_subfinder": run_subfinder,
        "run_amass": run_amass,
        "RESOLVERS": RESOLVERS,
        "crtsh_query": crtsh_query,
        "crtsh_extract": crtsh_extract,
        "log": log,
        "c": c,
        "k": k,
        "HAS_REQUESTS": HAS_REQUESTS,
        "HAS_DNSPYTHON": HAS_DNSPYTHON,
        "locks": _LOCKS,

        # Imports modules might need
        "re": re,
        "json": json,
        "socket": socket,
        "time": time,
        "threading": threading,
        "concurrent": concurrent.futures,
        "urllib_parse": urllib.parse,
    }

# ─────────────────────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────────────────────
def save_txt(path, subdomains):
    with open(path, "w") as f:
        for s in sorted(subdomains):
            f.write(s + "\n")

def save_csv(path, subdomains, source_map, resolved_map):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["subdomain","sources","resolved","ips"])
        w.writeheader()
        for sub in sorted(subdomains):
            srcs = [s for s, r in source_map.items() if sub in r]
            ips = resolved_map.get(sub, [])
            w.writerow({"subdomain": sub, "sources": "|".join(srcs),
                        "resolved": "yes" if ips else "no", "ips": ",".join(ips)})

def save_json_file(path, domain, subdomains, source_map, resolved_map):
    data = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "total": len(subdomains),
        "resolved": len([s for s in subdomains if resolved_map.get(s)]),
        "subdomains": [
            {"subdomain": sub,
             "sources": [s for s, r in source_map.items() if sub in r],
             "ips": resolved_map.get(sub, [])}
            for sub in sorted(subdomains)
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
BANNER = """
{0}
{1}  {2} — Subdomain Enumeration Suite {3}           {1}
{1}  {4} | auto-modules | Phase 1 + Phase 2          {1}
{5}
""".format(
    c('╔══════════════════════════════════════════════════════════╗','cyan'),
    c('║','cyan'),
    c('recon.py','bold'),
    c('2026','yellow'),
    c('modular','yellow'),
    c('╚══════════════════════════════════════════════════════════╝','cyan'),
)

def main():
    parser = argparse.ArgumentParser(
        description="recon.py — Modular Subdomain Enumeration Suite 2026",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python recon.py -d example.com
  python recon.py -d example.com --keys keys.ini
  python recon.py -d example.com --deep
  python recon.py -d example.com --deep --resolve
  python recon.py -d example.com --list-modules
        """
    )
    parser.add_argument("-d", "--domain", required=False)
    parser.add_argument("--keys", default="keys.ini")
    parser.add_argument("--deep", action="store_true", help="Enable Phase 2 modules")
    parser.add_argument("--probe", action="store_true", help="HTTP probe alive hosts (slow)")
    parser.add_argument("--resolve", action="store_true", help="DNS resolve all results")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--output", default=None)
    parser.add_argument("--format", choices=["txt","csv","json","all"], default="all")
    parser.add_argument("--delay", type=float, default=0.3)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--modules-dir", default=None)
    parser.add_argument("--list-modules", action="store_true")
    parser.add_argument("--only", default=None, help="Run only specific module (by NAME)")
    parser.add_argument("--wordlist", default=None, help="Wordlist for root-level DNS brute (e.g. assetnote 1M)")
    args = parser.parse_args()

    print(BANNER)

    global _DEBUG, _DEBUG_LOG
    _DEBUG = args.debug
    if _DEBUG:
        _debug_path = Path(args.output) / "debug.log" if args.output else Path("debug.log")
        _debug_path.parent.mkdir(parents=True, exist_ok=True)
        _DEBUG_LOG = open(str(_debug_path), "w", encoding="utf-8")
        log(f"  Debug log: {_debug_path}", "info")

    # ── Load modules ──
    modules = load_modules(args.modules_dir)
    if not modules:
        log("No modules found! Check modules/ directory.", "err")
        sys.exit(1)

    # ── List modules ──
    if args.list_modules:
        print(f"{c('Loaded modules:','bold')}\n")
        for mod in modules:
            phase = f"Phase {mod.PHASE}"
            deep = c("--deep","yellow") if getattr(mod, "NEEDS_DEEP", False) else c("always","green")
            desc = getattr(mod, "DESCRIPTION", "")
            print(f"  {c(mod.NAME,'cyan'):<35} {phase:<12} {deep:<20} {c(desc,'gray')}")
        print(f"\n  Total: {len(modules)} modules")
        sys.exit(0)

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    domain = args.domain.lower().strip().strip("/")
    if domain.startswith("www."):
        domain = domain[4:]

    # ── Load keys ──
    keys = load_keys(args.keys)
    filled = [n for n in keys if keys[n] and not keys[n].startswith("http")]

    log(f"Домен: {c(domain,'bold')}", "info")
    log(f"Ключей: {c(str(len(filled)),'cyan')} ({', '.join(filled[:8])}{'...' if len(filled)>8 else ''})", "info")
    log(f"Модулей загружено: {c(str(len(modules)),'cyan')}", "info")

    # ── Detect external tools ──
    tools_found = []
    if BIN_DNSX: tools_found.append("dnsx")
    if BIN_SUBFINDER: tools_found.append("subfinder")
    if BIN_AMASS: tools_found.append("amass")
    if BIN_HTTPX: tools_found.append("httpx")
    if find_binary("massdns"): tools_found.append("massdns")
    if tools_found:
        log(f"Внешние тулзы: {c(', '.join(tools_found),'green')}", "info")
    else:
        log(f"Внешние тулзы: не найдены (используется Python fallback)", "info")

    # ── Build context ──
    ctx = make_context(domain, keys, args)

    # ── Output setup ──
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_prefix = args.output or f"{domain.replace('.','_')}_{ts}"
    Path(out_prefix).parent.mkdir(parents=True, exist_ok=True)

    # ── Run modules — PARALLEL within each phase ──
    _scan_start = time.time()
    phase_groups = {}
    for mod in modules:
        if getattr(mod, "NEEDS_DEEP", False) and not args.deep:
            continue
        if args.only and args.only.lower() != mod.NAME.lower():
            continue
        phase_groups.setdefault(mod.PHASE, []).append(mod)

    for phase_num in sorted(phase_groups.keys()):
        phase_mods = phase_groups[phase_num]
        phase_names = {1: "PASSIVE SOURCES", 2: "ACTIVE ENRICHMENT",
                       3: "MUTATIONS & BRUTE", 4: "VERIFICATION"}
        pname = phase_names.get(phase_num, f"PHASE {phase_num}")
        print(f"\n{c('═'*58,'cyan')}")
        print(f"  {c(f'PHASE {phase_num} — {pname}','bold')}")
        print(f"{c('═'*58,'cyan')}")

        if phase_num == 1:
            # Phase 1: passive sources + subfinder/amass ALL in parallel
            _phase_start = time.time()
            before = len(ctx["found_subs"])

            def _run_mod_p1(mod):
                try:
                    mod.run(ctx)
                    return mod.NAME, None
                except Exception as e:
                    return mod.NAME, e

            futures = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                for mod in phase_mods:
                    futures[ex.submit(_run_mod_p1, mod)] = mod.NAME
                if BIN_SUBFINDER and not args.only:
                    futures[ex.submit(run_subfinder, domain)] = "subfinder"
                if BIN_AMASS and not args.only:
                    futures[ex.submit(run_amass, domain)] = "amass"

                for future in concurrent.futures.as_completed(futures):
                    name_t = futures[future]
                    try:
                        result = future.result()
                        if isinstance(result, set):
                            # Normalize and scope-check external tool results
                            normalized = set()
                            for s in result:
                                n = _normalize_host(s, domain)
                                if n:
                                    normalized.add(n)
                            new_ext = normalized - ctx["found_subs"]
                            if new_ext:
                                ctx["found_subs"].update(new_ext)
                                ctx["source_map"][name_t] = new_ext
                                log(f"  {name_t}: +{c(str(len(new_ext)),'green')} новых", "info")
                            else:
                                log(f"  {name_t}: 0 новых (всего найдено: {len(result)})", "info")
                        elif isinstance(result, tuple):
                            mod_name, err = result
                            if err:
                                log(f"  {mod_name}: CRASH — {type(err).__name__}: {err}", "err")
                    except Exception as e:
                        log(f"  {name_t}: error — {e}", "err")

            after = len(ctx["found_subs"])
            _p1_elapsed = time.time() - _phase_start
            log(f"  Phase 1 итого: {c(str(after),'green')} субдоменов [{_p1_elapsed:.1f}s]", "info")

            # ── Root-level DNS brute with external wordlist ──
            if args.wordlist and Path(args.wordlist).exists():
                wl_path = str(Path(args.wordlist).resolve())
                wl_size_mb = Path(wl_path).stat().st_size / (1024 * 1024)
                log(f"  Wordlist brute: {args.wordlist} ({wl_size_mb:.1f} MB)", "info")

                import tempfile
                log(f"  Building candidates...", "info")
                _build_start = time.time()
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, buffering=8192*16) as tf:
                    with open(wl_path, buffering=8192*16) as wl:
                        for word in wl:
                            word = word.strip()
                            if word and not word.startswith("#"):
                                tf.write(word + "." + domain + "\n")
                    candidates_file = tf.name
                log(f"  Candidates ready ({time.time()-_build_start:.1f}s)", "info")

                wl_found = set()
                est_lines = int(wl_size_mb * 100000)
                wl_timeout = max(300, int(est_lines / 2000))
                resolvers_file = next((str(p) for p in _candidate_resolver_files() if p.exists()), "")
                if not resolvers_file:
                    log(f"  Wordlist brute: resolvers.txt not found, massdns skipped", "warn")

                # === Strategy 1: massdns (OneForAll-style flags) ===
                massdns_bin = find_binary("massdns")
                if massdns_bin and resolvers_file:
                    log(f"  Using massdns (timeout: {wl_timeout}s)...", "info")
                    output_file = candidates_file + ".out"
                    try:
                        import threading

                        proc = subprocess.Popen([
                            massdns_bin,
                            "--resolvers", resolvers_file,
                            "--type", "A",
                            "--output", "S",
                            "--outfile", output_file,
                            "--processes", "1",
                            "--socket-count", "10",
                            "--resolve-count", "3",
                            "--flush",
                            candidates_file
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

                        # Drain stderr in background (prevent buffer deadlock)
                        _massdns_stderr = []
                        def _drain():
                            try:
                                for raw in proc.stderr:
                                    _massdns_stderr.append(raw.decode(errors="ignore").strip())
                            except Exception:
                                pass
                        threading.Thread(target=_drain, daemon=True).start()

                        _start_wl = time.time()
                        while proc.poll() is None:
                            time.sleep(3)
                            elapsed = time.time() - _start_wl
                            if elapsed > wl_timeout:
                                proc.kill()
                                log(f"  massdns: timeout ({wl_timeout}s)", "warn")
                                break
                            # Progress from output file size
                            resolved = 0
                            try:
                                if Path(output_file).exists():
                                    resolved = max(0, int(Path(output_file).stat().st_size / 60))
                            except Exception:
                                pass
                            pct = ""
                            # Try to extract % from massdns stderr
                            for line in reversed(_massdns_stderr[-5:]):
                                m = re.search(r'(\d+\.\d+)%', line)
                                if m:
                                    pct = f" ({m.group(1)}%)"
                                    break
                            print(f"\r  massdns: ~{resolved} found | {elapsed:.0f}s{pct}      ", end="", flush=True)
                        print()

                        # Parse results
                        if Path(output_file).exists():
                            with open(output_file) as f:
                                for line in f:
                                    parts = line.strip().split()
                                    if len(parts) >= 3 and parts[1] == "A":
                                        sub = parts[0].rstrip(".").lower()
                                        n = _normalize_host(sub, domain)
                                        if n and n not in ctx["found_subs"]:
                                            wl_found.add(n)
                            try: Path(output_file).unlink()
                            except OSError: pass

                    except Exception as e:
                        dbg(f"massdns wordlist error: {e}")

                # === Strategy 2: dnsx fallback ===
                elif BIN_DNSX:
                    log(f"  Using dnsx (timeout: {wl_timeout}s)...", "info")
                    output_file = candidates_file + ".dnsx"
                    try:
                        proc = subprocess.Popen([
                            BIN_DNSX, "-l", candidates_file,
                            "-a", "-resp",
                            "-t", "100", "-retry", "2",
                            "-silent", "-no-color",
                            "-o", output_file
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                        _start_wl = time.time()
                        while proc.poll() is None:
                            time.sleep(3)
                            elapsed = time.time() - _start_wl
                            if elapsed > wl_timeout:
                                proc.kill()
                                log(f"  dnsx: timeout ({wl_timeout}s)", "warn")
                                break
                            resolved = 0
                            try:
                                if Path(output_file).exists():
                                    resolved = max(0, int(Path(output_file).stat().st_size / 40))
                            except Exception:
                                pass
                            print(f"\r  dnsx: ~{resolved} found | {elapsed:.0f}s      ", end="", flush=True)
                        print()

                        if Path(output_file).exists():
                            with open(output_file) as f:
                                for line in f:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    sub = line.split(" [")[0].strip().lower() if " [" in line else line.strip().lower()
                                    n = _normalize_host(sub, domain)
                                    if n and n not in ctx["found_subs"]:
                                        wl_found.add(n)
                            try: Path(output_file).unlink()
                            except OSError: pass

                    except Exception as e:
                        dbg(f"dnsx wordlist error: {e}")
                else:
                    log(f"  Wordlist brute: requires massdns or dnsx", "warn")

                # Merge results
                if wl_found:
                    ctx["found_subs"].update(wl_found)
                    ctx["source_map"]["Wordlist Brute"] = wl_found
                    log(f"  Wordlist brute: +{c(str(len(wl_found)),'green')} новых", "info")
                else:
                    log(f"  Wordlist brute: 0 новых", "info")

                try: Path(candidates_file).unlink()
                except OSError: pass

        elif phase_num == 4:
            # Phase 4: resolver runs alone
            _p4_start = time.time()
            for mod in phase_mods:
                try:
                    mod.run(ctx)
                except Exception as e:
                    log(f"  {mod.NAME}: CRASH — {type(e).__name__}: {e}", "err")
            log(f"  Phase 4: [{time.time() - _p4_start:.1f}s]", "info")

        else:
            # Phase 2 & 3: ALL modules in parallel with timing
            before = len(ctx["found_subs"])
            _phase_start = time.time()

            def _run_phase_mod(mod):
                _mod_start = time.time()
                try:
                    mod.run(ctx)
                    elapsed = time.time() - _mod_start
                    return mod.NAME, elapsed, None
                except Exception as e:
                    elapsed = time.time() - _mod_start
                    return mod.NAME, elapsed, e

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(phase_mods)) as ex:
                futs = {ex.submit(_run_phase_mod, mod): mod for mod in phase_mods}
                for future in concurrent.futures.as_completed(futs):
                    name_t, elapsed, err = future.result()
                    if err:
                        log(f"  {name_t}: CRASH ({elapsed:.1f}s) — {type(err).__name__}: {err}", "err")
                    else:
                        log(f"  {name_t}: done ({elapsed:.1f}s)", "info")

            _phase_elapsed = time.time() - _phase_start
            after = len(ctx["found_subs"])
            total_new = after - before
            if total_new > 0:
                log(f"  Phase {phase_num}: +{c(str(total_new),'green')} (всего: {after}) [{_phase_elapsed:.1f}s]", "info")
            else:
                log(f"  Phase {phase_num}: 0 новых [{_phase_elapsed:.1f}s]", "info")

    # Phase 2 hint
    if not args.deep:
        log(f"  Совет: {c('--deep','bold')} для Phase 2 (recursive, webscrape, headers, mutations)", "info")

    # ── RECURSIVE LOOP — BBOT-style feedback (max 2 rounds, 60s cap) ──
    if args.deep:
        import ssl as _ssl
        _start_recurse = time.time()
        MAX_RECURSE_TIME = 60  # seconds total

        for loop_round in range(1, 3):
            if time.time() - _start_recurse > MAX_RECURSE_TIME:
                break

            before_loop = len(ctx["found_subs"])
            resolved_ips = set()
            for sub, ips in ctx["resolved"].items():
                if isinstance(ips, (list, set, tuple)):
                    resolved_ips.update(ips)
                elif isinstance(ips, str) and ips:
                    resolved_ips.add(ips)

            if not resolved_ips:
                break

            print(f"\n{c('═'*58,'cyan')}")
            print(f"  {c(f'RECURSIVE ROUND {loop_round} — {len(resolved_ips)} IPs → SSL + crt.sh','bold')}")
            print(f"{c('═'*58,'cyan')}")

            # 1. SSL cert SAN from unique IPs (fast, parallel)
            new_from_ssl = set()
            ips_to_probe = list(resolved_ips)[:200]  # cap at 200

            def _grab_san(ip):
                found = set()
                try:
                    ctx_ssl = _ssl.create_default_context()
                    ctx_ssl.check_hostname = False
                    ctx_ssl.verify_mode = _ssl.CERT_NONE
                    with socket.create_connection((ip, 443), timeout=2) as sock:
                        with ctx_ssl.wrap_socket(sock) as ssock:
                            cert = ssock.getpeercert(binary_form=False)
                            if cert:
                                for field in cert.get("subjectAltName", []):
                                    if field[0].lower() == "dns":
                                        name = _normalize_host(field[1], domain)
                                        if name:
                                            found.add(name)
                except Exception:
                    pass
                return found

            with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
                for result in concurrent.futures.as_completed(
                    {ex.submit(_grab_san, ip): ip for ip in ips_to_probe}
                ):
                    r = result.result()
                    new_from_ssl.update(r - ctx["found_subs"])

            if new_from_ssl:
                ctx["found_subs"].update(new_from_ssl)
                log(f"  SSL SAN: +{c(str(len(new_from_ssl)),'green')} новых", "info")

            # 2. Quick crt.sh for any new subdomains with 2+ levels (e.g. dev.api.site.com → api.site.com)
            new_parents = set()
            for s in new_from_ssl:
                parts = s.replace("." + domain, "").split(".")
                if len(parts) >= 2:
                    parent = ".".join(parts[1:]) + "." + domain
                    if parent not in ctx["found_subs"]:
                        new_parents.add(parent)

            if new_parents and time.time() - _start_recurse < MAX_RECURSE_TIME:
                crt_new = set()
                for parent in list(new_parents)[:10]:
                    try:
                        crt_results = ctx["crtsh_query"](parent)
                        crt_new.update(crt_results - ctx["found_subs"])
                    except Exception:
                        pass
                if crt_new:
                    ctx["found_subs"].update(crt_new)
                    log(f"  crt.sh recursive: +{c(str(len(crt_new)),'green')} новых", "info")

            # 3. Quick resolve new finds
            new_total = ctx["found_subs"] - set(ctx["resolved"].keys())
            if new_total:
                resolve_one = ctx["resolve_one"]
                resolved_count = 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
                    futs = {ex.submit(resolve_one, s): s for s in new_total}
                    for f in concurrent.futures.as_completed(futs):
                        sub = futs[f]
                        try:
                            ips = f.result()
                            if ips:
                                ctx["resolved"][sub] = ips
                                resolved_count += 1
                        except Exception:
                            pass
                if resolved_count:
                    log(f"  Resolve: {c(str(resolved_count),'green')} новых IP", "info")

            after_loop = len(ctx["found_subs"])
            gained = after_loop - before_loop
            if gained == 0:
                break
            log(f"  Round {loop_round}: +{c(str(gained),'green')} (всего: {after_loop})", "info")

        elapsed_r = time.time() - _start_recurse
        if elapsed_r > 1:
            log(f"  Recursive loop: {elapsed_r:.0f}s", "info")

    all_subs = ctx["found_subs"]
    resolved_map = ctx["resolved"]

    # ── Fix #4: Candidate/verified separation ──
    # Mutation candidates (Phase 3) that didn't resolve = not real subdomains.
    # Keep them only if they resolved. Passive/active sources are always kept.
    MUTATION_SOURCES = {"WordCloud Mutations", "Pattern Predictor"}
    mutation_only = set()
    for src_name in MUTATION_SOURCES:
        subs = ctx["source_map"].get(src_name, set())
        for s in subs:
            # Check if this sub was ONLY found by mutations (not also by passive/active)
            other_sources = [n for n, r in ctx["source_map"].items()
                            if n not in MUTATION_SOURCES and s in r]
            if not other_sources:
                mutation_only.add(s)

    # Remove unresolved mutation-only candidates
    unverified_mutations = mutation_only - set(resolved_map.keys())
    if unverified_mutations:
        all_subs -= unverified_mutations
        dbg(f"Removed {len(unverified_mutations)} unverified mutation candidates")

    log(f"\nВсего субдоменов: {c(str(len(all_subs)),'green')}", "info")

    # ── Save ──
    print(f"\n{c('[ СОХРАНЕНИЕ ]','bold')}")
    out_dir = args.output or domain
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # 1. all.txt — все субдомены
    p_all = os.path.join(out_dir, "all.txt")
    save_txt(p_all, all_subs)
    log(f"  {c(p_all,'cyan')} — {len(all_subs)} субдоменов", "info")

    # 2. alive.txt — резолвятся (DNS)
    alive = {s for s in all_subs if resolved_map.get(s)}
    p_alive = os.path.join(out_dir, "alive.txt")
    save_txt(p_alive, alive)
    log(f"  {c(p_alive,'cyan')} — {len(alive)} DNS alive", "info")

    # 3. dead.txt — не резолвятся
    dead = all_subs - alive
    p_dead = os.path.join(out_dir, "dead.txt")
    save_txt(p_dead, dead)
    log(f"  {c(p_dead,'cyan')} — {len(dead)} DNS dead", "info")

    # 3b. hidden.txt — SERVFAIL/REFUSED (internal infrastructure)
    hidden_subs = ctx.get("hidden_subs", set())
    if hidden_subs:
        p_hidden = os.path.join(out_dir, "hidden.txt")
        save_txt(p_hidden, hidden_subs)
        log(f"  {c(p_hidden,'cyan')} — {len(hidden_subs)} SERVFAIL/REFUSED", "info")

    # 4. http_alive.txt — HTTP probe
    if alive and args.probe:
        print(f"\n{c('[ HTTP PROBE ]','bold')}")
        log(f"  Проверяю {len(alive)} хостов...", "info")
        http_alive = set()
        http_info = {}   # {host: [(status, url), ...]}
        dead_codes = {0, 404, 502, 503, 521, 522, 523, 530}

        # Try httpx first (1000+/min)
        httpx_bin = BIN_HTTPX
        httpx_attempted = False
        httpx_failed = False

        if httpx_bin:
            log(f"  httpx found: {httpx_bin}", "info")
            # Probe top web ports — finds hidden services on 8080, 8443, etc.
            PROBE_PORTS = "80,443,8080,8443,8888,9090,3000,4443,8000"
            log(f"  Ports: {PROBE_PORTS}", "info")

            # Optional safety cap for very large runs
            probe_max = int(os.environ.get("RECON_HTTP_PROBE_MAX", "0"))
            probe_set = list(sorted(alive))
            if probe_max > 0 and len(probe_set) > probe_max:
                log(f"  HTTP probe capped: {probe_max}/{len(probe_set)} hosts", "warn")
                probe_set = probe_set[:probe_max]

            httpx_batch_size = max(1000, int(os.environ.get("RECON_HTTPX_BATCH_SIZE", "50000")))
            httpx_batch_timeout = max(120, int(os.environ.get("RECON_HTTPX_BATCH_TIMEOUT", "600")))
            total_probe = len(probe_set)
            total_batches = (total_probe + httpx_batch_size - 1) // httpx_batch_size

            import tempfile
            try:
                httpx_attempted = True
                for bi in range(total_batches):
                    batch = probe_set[bi*httpx_batch_size:(bi+1)*httpx_batch_size]
                    log(f"  httpx batch {bi+1}/{total_batches}: {len(batch)} hosts", "info")

                    tmp_in = os.path.join(out_dir, f"_probe_in_{bi}.txt")
                    tmp_out = os.path.join(out_dir, f"_probe_out_{bi}.txt")
                    save_txt(tmp_in, batch)

                    # Run WITHOUT -fc — capture ALL responses for http_full
                    subprocess.run([
                        httpx_bin, "-l", tmp_in, "-o", tmp_out,
                        "-t", "100", "-timeout", "3",
                        "-p", PROBE_PORTS,
                        "-sc", "-silent", "-no-color"
                    ], timeout=httpx_batch_timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    if Path(tmp_out).exists():
                        with open(tmp_out) as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                url = line.split(" [")[0].strip() if " [" in line else line
                                status = 0
                                if " [" in line:
                                    try:
                                        status = int(line.split(" [")[1].rstrip("]").strip())
                                    except ValueError:
                                        pass
                                host_part = url.replace("https://", "").replace("http://", "").split("/")[0]
                                host = host_part.split(":")[0]
                                if host.endswith("." + domain) or host == domain:
                                    # ALL go to http_info (for http_full.txt)
                                    http_info.setdefault(host, []).append((status, url))
                                    # Only non-dead go to http_alive
                                    if status and status not in dead_codes:
                                        http_alive.add(url)

                    log(f"  httpx progress: {min((bi+1)*httpx_batch_size, total_probe)}/{total_probe}", "info")
                    for fpath in (tmp_in, tmp_out):
                        try: Path(fpath).unlink()
                        except OSError: pass
            except Exception as e:
                httpx_failed = True
                dbg(f"httpx error: {e}")

        # Fallback: fast HEAD requests, 100 threads, 2s timeout
        # Avoid huge fallback scans when httpx already ran but returned nothing.
        probed_hosts = set(http_info.keys())
        force_head_after_httpx = os.environ.get("RECON_HEAD_PROBE_ON_HTTPX_EMPTY", "0") == "1"
        head_on_httpx_fail = os.environ.get("RECON_HEAD_ON_HTTPX_FAIL", "0") == "1"
        do_head_probe = (not httpx_bin) or (not probed_hosts and (not httpx_attempted or force_head_after_httpx or (httpx_failed and head_on_httpx_fail)))
        if do_head_probe:
            remaining = alive - probed_hosts if probed_hosts else alive

            # Safety: never fan-out to huge HEAD fallback unless explicitly forced.
            head_fallback_total_max = max(0, int(os.environ.get("RECON_HEAD_FALLBACK_TOTAL_MAX", "50000")))
            if httpx_bin and not force_head_after_httpx and head_fallback_total_max > 0 and len(remaining) > head_fallback_total_max:
                log(f"  HEAD fallback skipped: {len(remaining)} hosts is too large (limit {head_fallback_total_max}); use httpx tuning or set RECON_HEAD_PROBE_ON_HTTPX_EMPTY=1", "warn")
                remaining = set()

            head_probe_max = max(0, int(os.environ.get("RECON_HEAD_PROBE_MAX", "5000")))
            if head_probe_max > 0 and len(remaining) > head_probe_max:
                log(f"  HEAD probe capped: {head_probe_max}/{len(remaining)} hosts", "warn")
                remaining = set(sorted(remaining)[:head_probe_max])

            if remaining:
                log(f"  HEAD probe {len(remaining)} hosts (100 threads, 2s timeout)...", "info")

            if HAS_REQUESTS:
                _session = _requests.Session()
                _session.headers.update({"User-Agent": "Mozilla/5.0"})
                _adapter = _requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
                _session.mount("https://", _adapter)
                _session.mount("http://", _adapter)

            def _fast_probe(sub):
                for scheme in ("https", "http"):
                    try:
                        url = f"{scheme}://{sub}"
                        if HAS_REQUESTS:
                            r = _session.head(url, timeout=2, allow_redirects=True)
                            return sub, r.status_code, url
                        else:
                            req = urllib.request.Request(url, method="HEAD",
                                                        headers={"User-Agent": "Mozilla/5.0"})
                            with urllib.request.urlopen(req, timeout=2) as resp:
                                return sub, resp.status, url
                    except Exception:
                        continue
                return sub, 0, ""

            done = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
                futures = {ex.submit(_fast_probe, sub): sub for sub in remaining}
                for future in concurrent.futures.as_completed(futures):
                    done += 1
                    if done % 200 == 0:
                        print(f"\r  {c(str(done),'cyan')}/{len(remaining)} probed, live: {c(str(len(http_alive)),'green')}     ", end="", flush=True)
                    sub, status, url = future.result()
                    if status and status not in dead_codes:
                        http_alive.add(url)
                        http_info.setdefault(sub, []).append((status, url))
            if len(remaining) > 200:
                print()
        elif httpx_bin and not probed_hosts:
            if httpx_failed:
                log("  HEAD fallback skipped after httpx failure (set RECON_HEAD_ON_HTTPX_FAIL=1 to enable)", "warn")
            else:
                log("  HEAD fallback skipped (httpx returned no hosts); set RECON_HEAD_PROBE_ON_HTTPX_EMPTY=1 to force", "warn")

        # http_alive.txt — only good URLs (open in browser)
        p_http = os.path.join(out_dir, "http_alive.txt")
        with open(p_http, "w") as f:
            for url in sorted(http_alive):
                f.write(url + "\n")
        log(f"  {c(p_http,'cyan')} — {c(str(len(http_alive)),'green')} живых URL", "info")

        # http_full.txt — ALL URLs including 502/503 (degraded infra visible)
        p_full = os.path.join(out_dir, "http_full.txt")
        total_urls = 0
        with open(p_full, "w") as f:
            for sub in sorted(http_info.keys()):
                for status, url in http_info[sub]:
                    f.write(f"{sub} [{status}] {url}\n")
                    total_urls += 1
        log(f"  {c(p_full,'cyan')} — {total_urls} URLs (все ответы, включая 5xx)", "info")

        # temp probe files are cleaned per-batch above
    elif alive and not args.probe:
        log(f"  Совет: {c('--probe','bold')} для HTTP проверки alive хостов", "info")

    # ── Stats ──
    print(f"\n{c('═'*58,'cyan')}")
    print(f"  {c('ИТОГ','bold')}")
    print(f"  Домен:              {c(domain,'cyan')}")
    print(f"  Всего субдоменов:   {c(str(len(all_subs)),'green')}")
    if resolved_map:
        print(f"  Резолвятся:         {c(str(len(resolved_map)),'green')}")
    working = sum(1 for s, r in ctx["source_map"].items() if r)
    total_src = len(ctx["source_map"])
    print(f"  Источников:         {c(str(working),'yellow')}/{total_src}")

    top = sorted(ctx["source_map"].items(), key=lambda x: len(x[1]), reverse=True)[:10]
    if top:
        print(f"\n  {c('Топ:','bold')}")
        for src, subs in top:
            if not subs:
                break
            bar = "█" * min(30, len(subs) // max(1, len(all_subs) // 30 + 1))
            print(f"  {src:<30} {c(str(len(subs)),'cyan'):>8}  {c(bar,'green')}")

    _total_time = time.time() - _scan_start
    _mins = int(_total_time // 60)
    _secs = int(_total_time % 60)
    print(f"\n  {c('Время:','bold')}              {_mins}m {_secs}s")
    print(f"{c('═'*58,'cyan')}\n")

    if _DEBUG_LOG:
        _DEBUG_LOG.write(f"\n=== SCAN COMPLETE ===\n")
        _DEBUG_LOG.close()
        log(f"  Debug log saved", "info")


if __name__ == "__main__":
    main()
