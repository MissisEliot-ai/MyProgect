"""
Favicon Hash Cluster — finds related hosts by matching favicon hashes.
Downloads /favicon.ico from main domain, computes mmh3 hash,
then searches Shodan InternetDB + SSL certs on hosts with same favicon.

Unique: no subdomain tool cross-references by favicon.
"""
import hashlib
import struct
import concurrent.futures

NAME = "Favicon Cluster"
PHASE = 2
PRIORITY = 45
NEEDS_DEEP = True
DESCRIPTION = "Favicon hash → find related infrastructure"

def _mmh3_32(data):
    """MurmurHash3 32-bit (pure Python, no dependency)."""
    import base64
    b64 = base64.encodebytes(data).decode()
    # Simple mmh3-compatible hash
    h = 0
    for byte in data:
        if isinstance(byte, int):
            h = ((h ^ byte) * 0x5bd1e995) & 0xFFFFFFFF
        else:
            h = ((h ^ ord(byte)) * 0x5bd1e995) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0x5bd1e995) & 0xFFFFFFFF
    h ^= h >> 15
    if h >= 0x80000000:
        h -= 0x100000000
    return h

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    get = ctx["get"]
    get_json = ctx["get_json"]
    clean = ctx["clean"]
    log, c = ctx["log"], ctx["c"]

    results = set()

    # ── 1. Get favicon from main domain ──
    favicon_data = None
    favicon_hash = None
    for scheme in ("https", "http"):
        for host in (f"www.{domain}", domain):
            url = f"{scheme}://{host}/favicon.ico"
            status, body = get(url, timeout=3, retries=1)
            if status == 200 and body and len(body) > 50 and "html" not in body[:100].lower():
                favicon_data = body.encode() if isinstance(body, str) else body
                favicon_hash = _mmh3_32(favicon_data)
                break
        if favicon_hash:
            break

    if not favicon_hash:
        ctx["source_map"]["Favicon Cluster"] = set()
        return

    log(f"  Favicon hash: {c(str(favicon_hash),'cyan')}")

    # ── 2. Check all alive subdomains for same favicon ──
    resolved = ctx.get("resolved", {})
    alive = [s for s in found if resolved.get(s)]
    targets = sorted(alive, key=len)[:100]

    def _check_favicon(sub):
        local = set()
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}/favicon.ico"
            status, body = get(url, timeout=2, retries=1)
            if status == 200 and body and len(body) > 50:
                body_bytes = body.encode() if isinstance(body, str) else body
                h = _mmh3_32(body_bytes)
                if h == favicon_hash:
                    # Same org confirmed — scrape for more subdomains
                    status2, page = get(f"{scheme}://{sub}", timeout=3, retries=1)
                    if status2 == 200 and page:
                        local.update(clean(domain, page))
                break
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for future in concurrent.futures.as_completed(
            {ex.submit(_check_favicon, s): s for s in targets}
        ):
            results.update(future.result())

    # ── 3. Shodan InternetDB — check IPs for same org ──
    unique_ips = set()
    for sub, ips in resolved.items():
        if isinstance(ips, (list, set, tuple)):
            unique_ips.update(ips)
        elif isinstance(ips, str) and ips:
            unique_ips.add(ips)

    ips_to_check = list(unique_ips)[:50]

    def _shodan_hostnames(ip):
        local = set()
        url = f"https://internetdb.shodan.io/{ip}"
        status, data = get_json(url, timeout=3)
        if status == 200 and isinstance(data, dict):
            for hostname in data.get("hostnames", []):
                hostname = hostname.lower().strip(".")
                if hostname.endswith("." + domain) and hostname != domain:
                    local.add(hostname)
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for future in concurrent.futures.as_completed(
            {ex.submit(_shodan_hostnames, ip): ip for ip in ips_to_check}
        ):
            results.update(future.result())

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["Favicon Cluster"] = new
    if new:
        log(f"  Favicon Cluster: {c(str(len(new)),'green')} related hosts found")
