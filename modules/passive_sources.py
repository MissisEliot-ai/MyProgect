"""
Passive Sources — all passive API sources in one module.
Auto-discovered by recon.py.
"""
import time
import json
import re
import socket
import concurrent.futures
import threading

# crt.sh PostgreSQL — 1 query replaces 4 JSON API calls
# Try psycopg2 first, then pg8000 (pure Python, no compilation)
_PG_DRIVER = None
try:
    import psycopg2
    _PG_DRIVER = "psycopg2"
except ImportError:
    try:
        import pg8000
        _PG_DRIVER = "pg8000"
    except ImportError:
        pass

NAME = "Passive Sources"
PHASE = 1
PRIORITY = 10
NEEDS_DEEP = False
DESCRIPTION = "All passive API sources (CT, DNS, search engines)"
VERSION = "1.2"

# ─────────────────────────────────────────────────────────────
# Module-level context — set by run(), used by source functions
# ─────────────────────────────────────────────────────────────
_ctx = None
def _get(*a, **kw): return _ctx["get"](*a, **kw)
def _get_json(*a, **kw): return _ctx["get_json"](*a, **kw)
def _clean(*a, **kw): return _ctx["clean"](*a, **kw)
def _k(*a): return _ctx["k"](_ctx["keys"], *a)
def _crtsh_query(*a, **kw): return _ctx["crtsh_query"](*a, **kw)
def _crtsh_extract(*a, **kw): return _ctx["crtsh_extract"](*a, **kw)
def _log(*a, **kw): return _ctx["log"](*a, **kw)
def _c(*a, **kw): return _ctx["c"](*a, **kw)
def _dns_query(*a, **kw): return _ctx["dns_query"](*a, **kw)

# ─────────────────────────────────────────────────────────────
# SOURCE FUNCTIONS — each returns set() of subdomains
# ─────────────────────────────────────────────────────────────

def src_crtsh_postgres(domain):
    """crt.sh — tries PostgreSQL first (pg8000/psycopg2), falls back to JSON API.
    Note: crt.sh removed certificate_identity table in 2025, new FTS schema gives fewer results.
    JSON fallback is currently more reliable."""
    if _PG_DRIVER is None:
        return _src_crtsh_json_fallback(domain)

    results = set()
    try:
        if _PG_DRIVER == "psycopg2":
            conn = psycopg2.connect(
                host="crt.sh", port=5432, user="guest",
                dbname="certwatch", connect_timeout=15
            )
            conn.set_session(autocommit=True)
        else:
            conn = pg8000.connect(
                host="crt.sh", port=5432, user="guest",
                database="certwatch", timeout=15
            )
            conn.autocommit = True
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT cai.NAME_VALUE "
            "FROM certificate_and_identities cai "
            "WHERE plainto_tsquery('certwatch', %s) @@ identities(cai.CERTIFICATE) "
            "LIMIT 10000",
            (domain,)
        )
        for row in cur.fetchall():
            name = row[0].strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name.endswith("." + domain) and name != domain:
                results.add(name)
        cur.close()
        conn.close()
        if _ctx and _ctx.get("debug"):
            print("    [DEBUG] crt.sh PostgreSQL (%s): %d subs" % (_PG_DRIVER, len(results)))
    except Exception as e:
        if _ctx and _ctx.get("debug"):
            print("    [DEBUG] crt.sh PostgreSQL failed: %s" % str(e)[:100])

    # Always supplement with JSON API — it often finds more than new FTS schema
    json_results = _src_crtsh_json_fallback(domain)
    combined = results | json_results
    if _ctx and _ctx.get("debug"):
        print("    [DEBUG] crt.sh combined: PG=%d + JSON=%d = %d unique" % (len(results), len(json_results), len(combined)))
    return combined

def _src_crtsh_json_fallback(domain):
    """Fallback: 4 crt.sh JSON API queries if PostgreSQL unavailable."""
    results = set()
    # Main wildcard
    data = _crtsh_query({"q": f"%.{domain}", "output": "json"})
    results.update(_crtsh_extract(data, domain))
    # Identity search
    data2 = _crtsh_query({"Identity": f"%.{domain}", "output": "json", "deduplicate": "Y"})
    results.update(_crtsh_extract(data2, domain))
    # CN search
    data3 = _crtsh_query({"CN": f"%.{domain}", "output": "json"})
    results.update(_crtsh_extract(data3, domain))
    return results

# Keep old functions for anyone referencing them directly
def src_crtsh(domain):
    return src_crtsh_postgres(domain)

def src_crtsh_company(domain):
    data = _crtsh_query({"Identity": f"%.{domain}", "output": "json", "deduplicate": "Y"})
    return _crtsh_extract(data, domain)

def src_crtsh_expired(domain):
    data = _crtsh_query({"q": f"%.{domain}", "output": "json", "exclude": "false"})
    return _crtsh_extract(data, domain)

def src_crtsh_db(domain):
    results = set()
    data1 = _crtsh_query({"q": f"%.{domain}", "output": "json", "deduplicate": "Y"})
    results.update(_crtsh_extract(data1, domain))
    data2 = _crtsh_query({"CN": f"%.{domain}", "output": "json"})
    results.update(_crtsh_extract(data2, domain))
    return results

def src_certspotter_free(domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    status, data = _get_json(url, timeout=15)
    if status != 200 or not isinstance(data, list):
        return set()
    results = set()
    for cert in data:
        for name in cert.get("dns_names", []):
            results.update(_clean(domain, name))
    return results

def src_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    status, body = _get(url, timeout=15)
    if status != 200 or "API count exceeded" in body:
        return set()
    results = set()
    for line in body.strip().split("\n"):
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host.endswith(f".{domain}") and host != domain:
                results.add(host)
    return results

def src_rapiddns(domain):
    url = "https://rapiddns.io/subdomain/{d}?full=1#result".format(d=domain)
    status, body = _get(url, timeout=20)
    if status != 200:
        return set()
    results = set()
    for m in re.finditer(r'<td[^>]*>([\w\.\-]+\.' + re.escape(domain) + r')</td>', body, re.IGNORECASE):
        sub = m.group(1).lower().strip()
        if sub != domain:
            results.add(sub)
    # Also extract from target="_blank" links (more reliable)
    for m in re.finditer(r'_blank["\'][^>]*>([^<]+\.' + re.escape(domain) + r')<', body, re.IGNORECASE):
        sub = m.group(1).lower().strip()
        if sub != domain and sub.endswith("." + domain):
            results.add(sub)
    results.update(_clean(domain, body))
    return results

def src_urlscan(domain):
    results = set()
    search_after = ""
    for _ in range(10):
        url = "https://urlscan.io/api/v1/search/?q=page.domain:{d}&size=100".format(d=domain)
        if search_after:
            url += "&search_after=" + search_after
        status, data = _get_json(url, timeout=15)
        if status != 200 or not data:
            break
        hits = data.get("results", [])
        if not hits:
            break
        for r in hits:
            page = r.get("page", {})
            d = page.get("domain", "")
            if d and d.endswith("." + domain) and d != domain:
                results.add(d.lower())
            results.update(_clean(domain, page.get("url", "")))
            results.update(_clean(domain, r.get("task", {}).get("url", "")))
        if hits and "sort" in hits[-1]:
            search_after = ",".join(str(s) for s in hits[-1]["sort"])
        else:
            break
        if len(hits) < 100:
            break
        time.sleep(0.5)
    return results

def src_wayback(domain):
    results = set()
    # Query 1: URLs with wildcard
    url1 = "https://web.archive.org/cdx/search/cdx?url=*.{d}/*&fl=original&output=text&collapse=urlkey&limit=100000".format(d=domain)
    status, body = _get(url1, timeout=90)
    if status == 200 and body and body.strip():
        results.update(_clean(domain, body))
    # Query 2: matchType=domain — catches subdomains that Query 1 misses
    url2 = "https://web.archive.org/cdx/search/cdx?url=*.{d}&fl=original&output=text&collapse=urlkey&limit=50000&matchType=domain".format(d=domain)
    status2, body2 = _get(url2, timeout=60)
    if status2 == 200 and body2 and body2.strip():
        results.update(_clean(domain, body2))
    return results

def src_commoncrawl(domain):
    status, indexes = _get_json("https://index.commoncrawl.org/collinfo.json", timeout=15)
    if status != 200 or not indexes:
        return set()
    latest = indexes[0].get("cdx-api", "")
    if not latest:
        return set()
    url = f"{latest}?url=*.{domain}&output=json&fl=url&limit=50000"
    status, body = _get(url, timeout=30)
    if status != 200:
        return set()
    results = set()
    for line in body.strip().split("\n"):
        try:
            obj = json.loads(line)
            results.update(_clean(domain, obj.get("url", "")))
        except Exception:
            pass
    return results

def src_otx_free(domain):
    """OTX passive DNS + url_list. Uses API key if available (10x rate limit).
    Aggressive retry on 429. Full pagination."""
    results = set()
    api_key = _k("otx")
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    def _otx_fetch(url, max_retries=4):
        """Fetch with aggressive 429 retry."""
        for attempt in range(max_retries):
            status, data = _get_json(url, headers if headers else None, timeout=30)
            if status == 200:
                return data
            if status == 429:
                wait = min(5 * (attempt + 1), 20)
                if _ctx and _ctx.get("debug"):
                    print(f"    [DEBUG] OTX 429, waiting {wait}s (attempt {attempt+1}/{max_retries})...")
                time.sleep(wait)
                continue
            # Other error — try once more after short pause
            if attempt == 0:
                time.sleep(2)
                continue
            break
        return {}

    # passive_dns — main source, up to 20 pages
    for page in range(1, 21):
        data = _otx_fetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?limit=500&page={page}"
        )
        if not isinstance(data, dict):
            break
        entries = data.get("passive_dns", [])
        if not entries:
            break
        for entry in entries:
            h = entry.get("hostname", "").lower()
            if h.endswith(f".{domain}") and h != domain:
                results.add(h)
        if not data.get("has_next", False):
            break
        time.sleep(1)

    # url_list — extra subdomains from URL patterns, up to 10 pages
    for page in range(1, 11):
        data2 = _otx_fetch(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}"
        )
        if not isinstance(data2, dict):
            break
        entries2 = data2.get("url_list", [])
        if not entries2:
            break
        for entry in entries2:
            results.update(_clean(domain, entry.get("url", "")))
            results.update(_clean(domain, entry.get("hostname", "")))
        if not data2.get("has_next", False):
            break
        time.sleep(1)

    return results

def src_subdomain_center(domain):
    """subdomain.center — has engine parameter we weren't using.
    Try multiple engines for maximum coverage."""
    results = set()
    engines = [None, "1", "2", "3"]  # None = default, 1/2/3 = different clustering engines
    for engine in engines:
        url = "https://api.subdomain.center/?domain={d}".format(d=domain)
        if engine:
            url += "&engine=" + engine
        status, data = _get_json(url, timeout=60)
        if status == 200 and isinstance(data, list) and len(data) > 0:
            for s in data:
                sub = str(s).lower().strip()
                if not sub.endswith("." + domain) or sub == domain:
                    continue
                prefix = sub.replace("." + domain, "")
                if prefix.replace(".", "").isdigit():
                    continue
                results.add(sub)
            if results:
                return results
        time.sleep(3)  # rate limit: 2 req/min
    return results

def src_myssl(domain):
    results = set()
    url = f"https://myssl.com/api/v1/discover_sub_domain?domain={domain}&is_subdomains=true"
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "https://myssl.com/"}
    status, data = _get_json(url, headers, timeout=15)
    if status == 200:
        for item in data.get("data", []):
            sub = item.get("domain", "").lower()
            if sub.endswith(domain) and sub != domain:
                results.add(sub)
    return results

def src_sitemap(domain):
    results = set()
    queue = [f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"]
    visited = set()
    status, rb = _get(f"https://{domain}/robots.txt", timeout=6)
    if status == 200:
        for line in rb.split("\n"):
            if line.lower().startswith("sitemap:"):
                queue.append(line.split(":", 1)[1].strip())
    while queue and len(visited) < 50:
        url = queue.pop(0)
        if url in visited: continue
        visited.add(url)
        results.update(_clean(domain, url))
        status, body = _get(url, timeout=8)
        if status == 200 and body:
            results.update(_clean(domain, body))
            for nested in re.findall(r"<loc>\s*(https?://[^<]+sitemap[^<]*)\s*</loc>", body, re.IGNORECASE):
                if nested not in visited:
                    queue.append(nested)
    return results

def src_robots(domain):
    results = set()
    for scheme in ("https", "http"):
        status, body = _get(f"{scheme}://{domain}/robots.txt", timeout=8)
        if status == 200 and body:
            results.update(_clean(domain, body))
            break
    return results

def src_sslcert(domain):
    import ssl
    results = set()
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((domain, 443), timeout=5)
        with ctx.wrap_socket(conn, server_hostname=domain) as s:
            cert = s.getpeercert()
            for x in cert.get("subject", ()):
                for attr_name, attr_val in x:
                    if attr_name == "commonName":
                        results.update(_clean(domain, attr_val))
            for san_type, san_val in cert.get("subjectAltName", ()):
                if san_type == "DNS":
                    results.update(_clean(domain, san_val))
    except Exception:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            conn2 = socket.create_connection((domain, 443), timeout=5)
            with ctx2.wrap_socket(conn2, server_hostname=domain) as s2:
                der = s2.getpeercert(binary_form=True)
                results.update(_clean(domain, ssl.DER_cert_to_PEM_cert(der)))
        except Exception:
            pass
    return results

def src_csp_header(domain):
    results = set()
    for scheme in ("https", "http"):
        try:
            if _ctx["HAS_REQUESTS"]:
                import requests
                r = requests.get(f"{scheme}://{domain}", timeout=8, verify=False, allow_redirects=True)
                csp = r.headers.get("Content-Security-Policy", "") or r.headers.get("Content-Security-Policy-Report-Only", "")
            else:
                return results
            if csp:
                results.update(_clean(domain, csp))
                break
        except Exception:
            pass
    return results

def src_dnsdumpster(domain):
    if not _ctx["HAS_REQUESTS"]:
        return set()
    results = set()
    try:
        import requests
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0"})
        r = s.get("https://dnsdumpster.com/", timeout=10)
        m = re.search(r'csrfmiddlewaretoken.*?value=["\']([^"\']+)["\']', r.text, re.DOTALL)
        csrf = m.group(1) if m else s.cookies.get("csrftoken", "")
        if csrf:
            resp = s.post("https://dnsdumpster.com/",
                data={"csrfmiddlewaretoken": csrf, "targetip": domain, "user": "free"},
                headers={"Referer": "https://dnsdumpster.com/"}, timeout=15)
            results.update(_clean(domain, resp.text))
    except Exception:
        pass
    return results

def src_mnemonic(domain):
    results = set()
    for query in [domain, f"*.{domain}"]:
        offset = 0
        for _ in range(10):
            url = f"https://api.mnemonic.no/pdns/v3/{query}?limit=1000&offset={offset}"
            status, data = _get_json(url, timeout=20)
            if status != 200 or not isinstance(data, dict):
                break
            entries = data.get("data", [])
            if not entries: break
            for entry in entries:
                for field in ("query", "answer", "hostname", "rrname", "rdata"):
                    val = entry.get(field, "")
                    if val: results.update(_clean(domain, val))
            if data.get("size", 0) < 1000:
                break
            offset += 1000
            time.sleep(0.3)
    return results

def src_robtex(domain):
    results = set()
    status, body = _get(f"https://freeapi.robtex.com/pdns/forward/{domain}", timeout=15)
    if status == 200 and body:
        for line in body.strip().split("\n"):
            if not line.strip(): continue
            try:
                entry = json.loads(line)
                for f in ("rrname", "rdata", "rrvalue"):
                    if entry.get(f): results.update(_clean(domain, entry[f]))
            except Exception:
                pass
    time.sleep(1.5)
    try:
        ip = socket.gethostbyname(domain)
        s2, b2 = _get(f"https://freeapi.robtex.com/pdns/reverse/{ip}", timeout=15)
        if s2 == 200 and b2:
            for line in b2.strip().split("\n"):
                if not line.strip(): continue
                try:
                    entry = json.loads(line)
                    for f in ("rrname", "rdata", "rrvalue"):
                        if entry.get(f): results.update(_clean(domain, entry[f]))
                except Exception:
                    pass
    except Exception:
        pass
    return results

def src_dns_records(domain):
    results = set()
    for rtype in ["MX", "NS", "SOA", "TXT", "CNAME", "AAAA"]:
        for rec in _dns_query(domain, rtype):
            results.update(_clean(domain, rec))
            if rtype == "TXT":
                for m in re.findall(r'(?:include:|redirect=)(\S+)', rec):
                    results.update(_clean(domain, m))
    for prefix in ["_dmarc", "_spf", "_mta-sts", "default._domainkey",
                    "selector1._domainkey", "selector2._domainkey"]:
        sub = f"{prefix}.{domain}"
        recs = _dns_query(sub, "TXT")
        if recs: results.add(sub)
        for rec in recs: results.update(_clean(domain, rec))
        cnames = _dns_query(sub, "CNAME")
        if cnames: results.add(sub)
    return results

def src_shodan_internetdb(domain):
    results = set()
    try:
        ips = list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET)})[:5]
    except Exception:
        return results
    for ip in ips:
        status, data = _get_json(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if status == 200:
            for h in data.get("hostnames", []):
                if h.endswith(domain) and h != domain:
                    results.add(h.lower())
    return results

# ── Search engines ──
def src_sogou(domain):
    results = set()
    for page in range(1, 6):
        url = f"https://www.sogou.com/web?query=site%3A*.{domain}&page={page}"
        status, body = _get(url, timeout=10)
        if status != 200: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        time.sleep(2)
    return results

def src_yahoo(domain):
    results = set()
    for page in range(1, 8):
        b = (page - 1) * 10 + 1
        url = f"https://search.yahoo.com/search?p=site%3A*.{domain}&b={b}&pz=10"
        status, body = _get(url, timeout=10)
        if status != 200: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        time.sleep(2)
    return results

def src_bing(domain):
    results = set()
    first = 0
    for _ in range(10):
        url = f"https://www.bing.com/search?q=site%3A*.{domain}&first={first}&count=10"
        status, body = _get(url, timeout=10)
        if status != 200 or not body: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        if "next" not in body.lower(): break
        first += 10
        time.sleep(1.5)
    return results

# ── Keyed sources ──
def src_virustotal(domain):
    api_key = _k("virustotal")
    if not api_key: return set()
    results = set()
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    while url:
        status, data = _get_json(url, headers)
        if status != 200: break
        for item in data.get("data", []):
            results.add(item.get("id", ""))
        cursor = data.get("meta", {}).get("cursor", "")
        url = (f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
               f"?limit=40&cursor={cursor}") if cursor else None
        time.sleep(0.3)
    return _clean(domain, list(results))

def src_securitytrails(domain):
    api_key = _k("securitytrails")
    if not api_key: return set()
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
    status, data = _get_json(url, headers)
    if status != 200: return set()
    return {f"{sub}.{domain}" for sub in data.get("subdomains", [])}

def src_shodan(domain):
    api_key = _k("shodan")
    if not api_key: return set()
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    status, data = _get_json(url)
    if status != 200: return set()
    return {f"{sub}.{domain}" for sub in data.get("subdomains", [])}

def src_fullhunt(domain):
    api_key = _k("fullhunt")
    if not api_key: return set()
    url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
    status, data = _get_json(url, {"X-API-KEY": api_key})
    if status != 200: return set()
    return _clean(domain, data.get("hosts", []))

def src_chaos(domain):
    api_key = _k("projectdiscovery")
    if not api_key: return set()
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    status, data = _get_json(url, {"Authorization": api_key})
    if status != 200: return set()
    return {f"{s}.{domain}" for s in data.get("subdomains", [])}

def src_whoisxml(domain):
    api_key = _k("whoisxmlapi")
    if not api_key: return set()
    url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={api_key}&domainName={domain}"
    status, data = _get_json(url)
    if status != 200: return set()
    return {r.get("domain","").lower() for r in data.get("result",{}).get("records",[])}

def src_binaryedge(domain):
    api_key = _k("binaryedge")
    if not api_key: return set()
    url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
    status, data = _get_json(url, {"X-Key": api_key})
    if status != 200: return set()
    return _clean(domain, data.get("events", []))

def src_c99(domain):
    api_key = _k("c99")
    if not api_key: return set()
    url = f"https://api.c99.nl/subdomainfinder?key={api_key}&domain={domain}&json"
    status, data = _get_json(url)
    if status != 200: return set()
    return {e.get("subdomain","") for e in data.get("subdomains",[]) if e.get("subdomain")}

def src_otx_key(domain):
    """OTX with API key — just calls src_otx_free which auto-detects key."""
    api_key = _k("otx")
    if not api_key: return set()
    # src_otx_free already uses API key if present
    return src_otx_free(domain)

def src_threatbook(domain):
    api_key = _k("threatbook")
    if not api_key: return set()
    url = f"https://api.threatbook.cn/v3/domain/sub_domains?apikey={api_key}&resource={domain}"
    status, data = _get_json(url)
    if status != 200: return set()
    return {s.lower() for s in data.get("data",{}).get("sub_domains",{}).get("data",[])}

def src_zoomeye(domain):
    api_key = _k("zoomeye")
    if not api_key: return set()
    url = f"https://api.zoomeye.org/web/search?query=hostname%3A*.{domain}&page=1"
    status, data = _get_json(url, {"API-KEY": api_key})
    if status != 200: return set()
    results = set()
    for m in data.get("matches", []):
        results.update(_clean(domain, m.get("rdns", "")))
    return results

def src_spyonweb(domain):
    api_key = _k("spyonweb")
    if not api_key: return set()
    url = f"https://api.spyonweb.com/v1/domain/{domain}?access_token={api_key}"
    status, data = _get_json(url)
    return _clean(domain, str(data)) if status == 200 else set()

def src_hostio(domain):
    api_key = _k("host")
    if not api_key: return set()
    url = f"https://host.io/api/dns/{domain}"
    status, data = _get_json(url, {"Authorization": f"Bearer {api_key}"})
    return _clean(domain, str(data)) if status == 200 else set()

def src_leakix_key(domain):
    api_key = _k("leakix")
    if not api_key: return set()
    url = f"https://leakix.net/search?q=+domain:{domain}&scope=leak,service"
    status, body = _get(url, {"api-key": api_key})
    return _clean(domain, body) if status == 200 else set()

def src_ipinfo(domain):
    api_key = _k("ipinfo")
    if not api_key: return set()
    url = f"https://ipinfo.io/domains/{domain}?token={api_key}"
    status, data = _get_json(url)
    return _clean(domain, str(data)) if status == 200 else set()

def src_bevigil(domain):
    api_key = _k("bevigil")
    if not api_key: return set()
    url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
    status, data = _get_json(url, {"X-Access-Token": api_key})
    if status != 200: return set()
    return {s.lower() for s in data.get("subdomains",[]) if s.endswith(domain) and s != domain}

def src_dnsdb(domain):
    api_key = _k("dnsdb")
    if not api_key: return set()
    url = f"https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{domain}?limit=10000"
    status, body = _get(url, {"X-API-Key": api_key, "Accept": "application/x-ndjson"}, timeout=20)
    if status != 200: return set()
    results = set()
    for line in body.strip().split("\n"):
        try:
            entry = json.loads(line)
            rrname = entry.get("obj",{}).get("rrname","").rstrip(".").lower()
            if rrname.endswith(domain) and rrname != domain:
                results.add(rrname)
        except: pass
    return results

def src_passivedns_cn(domain):
    api_key = _k("passivedns")
    if not api_key: return set()
    url = f"https://api.passivedns.cn/api/v1/query?q={domain}&qtype=1"
    status, data = _get_json(url, {"Authorization": f"Bearer {api_key}"}, timeout=12)
    if status != 200: return set()
    results = set()
    for e in data.get("data",[]):
        results.update(_clean(domain, e.get("qname","")))
    return results

def src_hunter(domain):
    api_key = _k("hunter")
    if not api_key: return set()
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=100"
    status, data = _get_json(url)
    if status != 200: return set()
    results = set()
    for e in data.get("data",{}).get("emails",[]):
        results.update(_clean(domain, e.get("value","")))
    return results

def src_github_search(domain):
    api_key = _k("github")
    if not api_key: return set()
    headers = {"Authorization": f"token {api_key}", "Accept": "application/vnd.github.v3+json"}
    results = set()
    for q in [f'"{domain}" extension:conf', f'"{domain}" extension:yaml', f'site:{domain}']:
        from urllib.parse import quote
        url = f"https://api.github.com/search/code?q={quote(q)}&per_page=100"
        status, data = _get_json(url, headers, timeout=15)
        if status == 200:
            for item in data.get("items",[]):
                results.update(_clean(domain, item.get("html_url","")))
        elif status == 403: break
        time.sleep(2)
    return results

def src_fofa(domain):
    api_key = _k("fofa")
    if not api_key: return set()
    import base64
    query_b64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?key={api_key}&qbase64={query_b64}&fields=host&size=10000"
    status, data = _get_json(url, timeout=20)
    if status != 200: return set()
    results = set()
    for host in data.get("results",[]):
        h = str(host[0] if isinstance(host,list) else host).lower().strip()
        h = re.sub(r"https?://","",h).split("/")[0].split(":")[0]
        if h.endswith(domain) and h != domain:
            results.add(h)
    return results

def src_chinaz_api(domain):
    api_key = _k("chinaz")
    if not api_key: return set()
    url = f"http://api.chinaz.com/api/SubDomain?AuthorizationCode={api_key}&Domain={domain}&PageIndex=1&PageSize=100"
    status, data = _get_json(url, timeout=15)
    if status != 200: return set()
    return {i.get("SubDomain","").lower() for i in data.get("ResultData",[]) if i.get("SubDomain","").endswith(domain)}

def src_github_org(domain):
    api_key = _k("github")
    if not api_key: return set()
    headers = {"Authorization": f"token {api_key}", "Accept": "application/vnd.github.v3+json"}
    results = set()
    org_name = domain.split(".")[0]
    status, data = _get_json(f"https://api.github.com/search/users?q={org_name}+type:org&per_page=5", headers, timeout=15)
    if status != 200: return results
    for org in data.get("items",[])[:3]:
        login = org.get("login","")
        if not login: continue
        s2, repos = _get_json(f"https://api.github.com/orgs/{login}/repos?per_page=100&type=all", headers, timeout=15)
        if s2 != 200: continue
        for repo in repos if isinstance(repos,list) else []:
            results.update(_clean(domain, repo.get("description","") or ""))
            results.update(_clean(domain, repo.get("homepage","") or ""))
    return results

def src_trickest(domain):
    api_key = _k("trickest")
    if not api_key: return set()
    url = f"https://api.trickest.io/solutions/v1/subdomains/?domain={domain}"
    status, data = _get_json(url, {"Authorization": f"Token {api_key}"}, timeout=15)
    if status != 200: return set()
    subs = data.get("subdomains",[]) if isinstance(data,dict) else data
    return {str(s).lower() for s in subs if str(s).lower().endswith(domain) and str(s).lower() != domain}

def src_builtwith(domain):
    api_key = _k("builtwith")
    if not api_key: return set()
    results = set()
    for url in [f"https://api.builtwith.com/v21/api.json?KEY={api_key}&LOOKUP={domain}"]:
        status, data = _get_json(url, timeout=15)
        if status == 200: results.update(_clean(domain, str(data)))
    return results

def src_passivetotal(domain):
    api_key = _k("passivetotal")
    if not api_key: return set()
    import base64
    results = set()
    if ":" in api_key:
        user, key = api_key.split(":",1)
        creds = base64.b64encode(f"{user}:{key}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
    else:
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    for url in [f"https://api.passivetotal.org/v2/enrichment/subdomains?query={domain}"]:
        status, data = _get_json(url, headers, timeout=15)
        if status == 200:
            for rec in data.get("subdomains",[]):
                results.add(f"{rec}.{domain}" if not rec.endswith(domain) else rec)
    return results

def src_certspotter_key(domain):
    api_key = _k("certspotter")
    if not api_key: return set()
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    status, data = _get_json(url, {"Authorization": f"Bearer {api_key}"}, timeout=15)
    if status != 200 or not isinstance(data,list): return set()
    results = set()
    for cert in data:
        for name in cert.get("dns_names",[]):
            results.update(_clean(domain, name))
    return results

def src_netlas(domain):
    """Netlas.io DNS search — 50 req/day free with key."""
    api_key = _k("netlas")
    if not api_key: return set()
    results = set()
    headers = {"X-API-Key": api_key}
    # Count first
    status, count_data = _get_json(
        f"https://app.netlas.io/api/domains_count/?q=*.{domain}", headers, timeout=15)
    if status != 200:
        return results
    total = count_data.get("count", 0)
    if total == 0:
        return results
    # Search with pagination
    limit = min(total, 500)
    for start in range(0, limit, 20):
        url = f"https://app.netlas.io/api/domains/?q=*.{domain}&start={start}&fields=domain&source_type=include"
        status, data = _get_json(url, headers, timeout=15)
        if status != 200 or not isinstance(data, dict):
            break
        for item in data.get("items", []):
            d = item.get("data", {}).get("domain", "").lower().rstrip(".")
            if d and d.endswith(f".{domain}") and d != domain:
                results.add(d)
        _ctx["time"].sleep(0.5)
    return results

# ── Missing sources from old version ──

def src_axfr(domain):
    results = set()
    ns_servers = []
    try:
        ns_servers = [r.rstrip(".") for r in _dns_query(domain, "NS")]
    except Exception:
        pass
    for ns in ns_servers:
        try:
            if _ctx["HAS_DNSPYTHON"]:
                import dns.query, dns.zone
                try:
                    ns_ip = _ctx["socket"].gethostbyname(ns)
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=10))
                    for name, node in zone.nodes.items():
                        fqdn = str(name) + "." + domain if str(name) != "@" else domain
                        results.update(_clean(domain, fqdn.lower()))
                except Exception:
                    pass
        except Exception:
            pass
    return results

def src_nsec_walk(domain):
    results = set()
    if not _ctx["HAS_DNSPYTHON"]:
        return results
    import dns.resolver
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
    except Exception:
        return results
    current = domain
    visited = set()
    for _ in range(500):
        if current in visited: break
        visited.add(current)
        try:
            ans = dns.resolver.resolve(current, "NSEC", lifetime=3)
            for rdata in ans:
                next_name = str(rdata.next_name).rstrip(".").lower()
                results.update(_clean(domain, next_name))
                current = next_name
                break
        except Exception:
            break
    return results

def src_hackertarget_shared(domain):
    url = f"https://api.hackertarget.com/findshareddns/?q={domain}"
    status, body = _get(url, timeout=10)
    return _clean(domain, body) if status == 200 else set()

def src_anubis(domain):
    results = set()
    for url in [f"https://jldc.me/anubis/subdomains/{domain}",
                f"https://jonlu.ca/anubis/subdomains/{domain}"]:
        status, data = _get_json(url, timeout=15)
        if status == 200 and isinstance(data, list) and data:
            results.update(_clean(domain, data))
            break
    return results

def src_arquivo(domain):
    results = set()
    # Try CDX endpoint first (like Wayback)
    url1 = "https://arquivo.pt/wayback/cdx?url=*.{d}&output=json&limit=5000".format(d=domain)
    status, body = _get(url1, timeout=20)
    if status == 200 and body:
        results.update(_clean(domain, body))
    # Also try textsearch
    url2 = "https://arquivo.pt/textsearch?q={d}&maxItems=500".format(d=domain)
    status2, data2 = _get_json(url2, timeout=20)
    if status2 == 200 and isinstance(data2, dict):
        for item in data2.get("response_items", []):
            results.update(_clean(domain, item.get("url", "")))
            results.update(_clean(domain, item.get("originalURL", "")))
    return results

def src_leakix(domain):
    url = f"https://leakix.net/search?q=domain:{domain}&scope=leak"
    status, body = _get(url)
    return _clean(domain, body) if status == 200 else set()

def src_netcraft(domain):
    url = f"https://searchdns.netcraft.com/?restriction=site+contains&host=*.{domain}&lookup=wait..&position=limited"
    status, body = _get(url)
    return _clean(domain, body) if status == 200 else set()

def src_sitedossier(domain):
    """SiteDossier — scrape with pagination, up to 20 pages."""
    results = set()
    for page in range(1, 21):
        for scheme in ("https", "http"):
            url = "{s}://www.sitedossier.com/parentdomain/{d}/{p}".format(s=scheme, d=domain, p=page)
            status, body = _get(url, timeout=15, retries=1)
            if status == 200 and body:
                results.update(_clean(domain, body))
                if "Next page" not in body:
                    return results
                break
        else:
            break
        time.sleep(1)
    return results

def src_yandex(domain):
    results = set()
    for p in range(0, 5):
        url = f"https://yandex.com/search/?text=site%3A*.{domain}&p={p}"
        status, body = _get(url, timeout=10)
        if status != 200: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        time.sleep(2)
    return results

def src_chinaz(domain):
    url = f"http://tool.chinaz.com/subdomain/?domain={domain}"
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "http://tool.chinaz.com/", "Accept-Language": "zh-CN,zh;q=0.9"}
    status, body = _get(url, headers, timeout=15)
    return _clean(domain, body) if status == 200 else set()

def src_ip138(domain):
    url = f"https://site.ip138.com/{domain}/"
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "https://site.ip138.com/", "Accept-Language": "zh-CN,zh;q=0.9"}
    status, body = _get(url, headers, timeout=12)
    return _clean(domain, body) if status == 200 else set()

def src_baidu(domain):
    results = set()
    headers = {"User-Agent": "Mozilla/5.0", "Accept-Language": "zh-CN,zh;q=0.9", "Referer": "https://www.baidu.com/"}
    for pn in range(0, 5):
        url = f"https://www.baidu.com/s?wd=site%3A*.{domain}&pn={pn * 10}&rn=10"
        status, body = _get(url, headers, timeout=10)
        if status != 200: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        time.sleep(2)
    return results

def src_360so(domain):
    results = set()
    for page in range(1, 6):
        url = f"https://www.so.com/s?q=site%3A*.{domain}&pn={page}"
        status, body = _get(url, timeout=10)
        if status != 200: break
        found = _clean(domain, body)
        if not found: break
        results.update(found)
        time.sleep(2)
    return results

def src_subdomainradar(domain):
    url = f"https://subdomainradar.io/api/search?domain={domain}"
    status, data = _get_json(url, timeout=15)
    if status != 200: return set()
    subs = data.get("subdomains", data if isinstance(data, list) else [])
    return {str(s).lower() for s in subs if str(s).lower().endswith(domain) and str(s).lower() != domain}

def src_securitytxt(domain):
    results = set()
    for scheme in ("https", "http"):
        for path in ("/.well-known/security.txt", "/security.txt"):
            status, body = _get(f"{scheme}://{domain}{path}", timeout=8)
            if status == 200 and body and len(body) < 10000:
                results.update(_clean(domain, body))
                return results
    return results

def src_oauth_discovery(domain):
    results = set()
    for path in ["/.well-known/openid-configuration",
                 "/.well-known/oauth-authorization-server",
                 "/oauth2/.well-known/openid-configuration"]:
        status, data = _get_json(f"https://{domain}{path}", timeout=8)
        if status == 200 and isinstance(data, dict):
            results.update(_clean(domain, str(data)))
    return results

def src_postman(domain):
    results = set()
    for qtype in ("collections", "requests"):
        url = f"https://www.postman.com/search?q={domain}&type={qtype}"
        status, body = _get(url, timeout=12)
        if status == 200:
            results.update(_clean(domain, body))
    return results

def src_dnscaa(domain):
    results = set()
    for target in [domain] + [f"{p}.{domain}" for p in ("www","mail","smtp","api")]:
        for rec in _dns_query(target, "CAA"):
            results.update(_clean(domain, rec))
    return results

def src_dnstlsrpt(domain):
    results = set()
    for prefix in ("_smtp._tls", "_mta-sts", "_dmarc", "_report._dmarc"):
        for rec in _dns_query(f"{prefix}.{domain}", "TXT"):
            results.update(_clean(domain, rec))
    return results

def src_dnsbimi(domain):
    results = set()
    for selector in ("default", "brand", "logo", "bimi"):
        for rec in _dns_query(f"{selector}._bimi.{domain}", "TXT"):
            results.update(_clean(domain, rec))
    return results

def src_srv_extended(domain):
    results = set()
    srv_templates = [
        "_sip._tcp","_sip._udp","_sips._tcp","_xmpp-server._tcp","_xmpp-client._tcp",
        "_smtp._tcp","_submission._tcp","_pop3._tcp","_imap._tcp","_imaps._tcp",
        "_autodiscover._tcp","_kerberos._tcp","_ldap._tcp","_gc._tcp",
        "_http._tcp","_https._tcp","_ftp._tcp","_ssh._tcp",
        "_caldav._tcp","_carddav._tcp","_collab-edge._tls",
    ]
    for srv in srv_templates:
        srv_fqdn = f"{srv}.{domain}"
        for rtype in ("SRV", "A", "CNAME"):
            records = _dns_query(srv_fqdn, rtype)
            if records:
                results.add(srv_fqdn)
                for rec in records:
                    results.update(_clean(domain, rec))
    return results

def src_ip_neighbor(domain):
    results = set()
    try:
        import ipaddress
        ip = _ctx["socket"].gethostbyname(domain)
        base = int(ipaddress.ip_address(ip))
        neighbors = [str(ipaddress.ip_address(base + offset)) for offset in range(-16, 17)]
        def rdns(ip_str):
            try: return _ctx["socket"].gethostbyaddr(ip_str)[0]
            except: return None
        with _ctx["concurrent"].ThreadPoolExecutor(max_workers=20) as ex:
            for hostname in ex.map(rdns, neighbors):
                if hostname:
                    results.update(_clean(domain, hostname))
    except Exception:
        pass
    return results

def src_azure_tenant(domain):
    results = set()
    status, data = _get_json(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration", timeout=10)
    if status == 200 and isinstance(data, dict):
        for field in ("issuer","token_endpoint","authorization_endpoint","userinfo_endpoint","jwks_uri"):
            results.update(_clean(domain, data.get(field, "")))
    status2, body2 = _get(f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1", timeout=10)
    if status2 == 200:
        results.update(_clean(domain, body2))
    return results

def src_azure_realm(domain):
    results = set()
    url = f"https://login.microsoftonline.com/common/userrealm?user=test@{domain}&api-version=2.1"
    status, data = _get_json(url, timeout=10)
    if status == 200 and isinstance(data, dict):
        for field in ("DomainName", "AuthURL", "MERIAuthURL"):
            val = data.get(field, "")
            if val: results.update(_clean(domain, str(val)))
    return results

def src_cloudflare_doh(domain):
    results = set()
    headers = {"Accept": "application/dns-json"}
    for qtype in ("A", "AAAA", "CNAME"):
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={qtype}"
        status, data = _get_json(url, headers, timeout=8)
        if status == 200:
            for ans in data.get("Answer", []):
                name = ans.get("name", "").rstrip(".").lower()
                if name.endswith(domain) and name != domain:
                    results.add(name)
                results.update(_clean(domain, ans.get("data", "")))
    return results

# ─────────────────────────────────────────────────────────────
# NEW SOURCES — from BBOT, subfinder, sub3suite
# ─────────────────────────────────────────────────────────────

def src_bufferover(domain):
    """BufferOver — wraps Rapid7 FDNS dataset. Free, no key."""
    results = set()
    for url in ["https://dns.bufferover.run/dns?q=.{d}".format(d=domain),
                "https://tls.bufferover.run/dns?q=.{d}".format(d=domain)]:
        status, data = _get_json(url, timeout=15)
        if status == 200 and isinstance(data, dict):
            for record in data.get("FDNS_A", []) + data.get("RDNS", []) + data.get("Results", []):
                if isinstance(record, str):
                    # Format: "IP,hostname" or just hostname
                    parts = record.split(",")
                    for p in parts:
                        results.update(_clean(domain, p.strip()))
    return results

def src_viewdns(domain):
    """ViewDNS.info reverse IP — finds co-hosted subdomains."""
    results = set()
    try:
        ip = _ctx["socket"].gethostbyname(domain)
    except Exception:
        return results
    url = "https://viewdns.info/reverseip/?host={ip}&t=1".format(ip=ip)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    status, body = _get(url, headers, timeout=15)
    if status == 200 and body:
        results.update(_clean(domain, body))
    return results

def src_duckduckgo(domain):
    """DuckDuckGo search — less aggressive anti-bot than Google."""
    results = set()
    for page in range(0, 5):
        url = "https://html.duckduckgo.com/html/?q=site%3A*.{d}&s={s}".format(d=domain, s=page*30)
        status, body = _get(url, timeout=10)
        if status != 200 or not body:
            break
        found = _clean(domain, body)
        if not found:
            break
        results.update(found)
        time.sleep(2)
    return results

def src_shrewdeye(domain):
    """ShrewdEye — new free source, added in subfinder 2024."""
    url = "https://shrewdeye.app/domains/{d}.txt".format(d=domain)
    status, body = _get(url, timeout=15)
    if status == 200 and body:
        results = set()
        for line in body.strip().split("\n"):
            line = line.strip().lower()
            if line.endswith("." + domain) and line != domain:
                results.add(line)
        results.update(_clean(domain, body))
        return results
    return set()

def src_columbus(domain):
    """Columbus/elmasy — free subdomain aggregator."""
    url = "https://columbus.elmasy.com/api/lookup/{d}".format(d=domain)
    status, data = _get_json(url, timeout=15)
    if status == 200 and isinstance(data, list):
        return {s.lower() for s in data if str(s).lower().endswith("." + domain) and str(s).lower() != domain}
    # Fallback: text format
    status2, body2 = _get("https://columbus.elmasy.com/lookup/{d}".format(d=domain), timeout=15)
    if status2 == 200 and body2:
        return _clean(domain, body2)
    return set()

def src_n45ht(domain):
    """N45HT — sub3suite source, free aggregator."""
    url = "https://api.n45ht.or.id/v1/subdomain-enumeration?domain={d}".format(d=domain)
    status, data = _get_json(url, timeout=15)
    if status == 200 and isinstance(data, dict):
        subs = data.get("subdomains", data.get("data", []))
        if isinstance(subs, list):
            return {s.lower() for s in subs if str(s).lower().endswith("." + domain)}
    return set()

def src_huntermap(domain):
    """Hunter.how (huntermap) — Chinese Shodan-like, free tier."""
    results = set()
    url = 'https://hunter.how/api/web/search?query=domain%3D"{d}"&page=1&page_size=100'.format(d=domain)
    status, data = _get_json(url, timeout=15)
    if status == 200 and isinstance(data, dict):
        for item in data.get("data", {}).get("list", []):
            results.update(_clean(domain, item.get("domain", "")))
            results.update(_clean(domain, item.get("url", "")))
    return results

def src_pgp_keys(domain):
    """PGP Key servers — email addresses in PGP keys contain subdomains."""
    results = set()
    url = "https://keys.openpgp.org/vks/v1/by-email/{d}".format(d=domain)
    status, body = _get(url, timeout=10)
    if status == 200 and body:
        results.update(_clean(domain, body))
    # MIT key server
    url2 = "https://pgp.mit.edu/pks/lookup?search={d}&op=index".format(d=domain)
    status2, body2 = _get(url2, timeout=10)
    if status2 == 200 and body2:
        results.update(_clean(domain, body2))
    return results

def src_github_codesearch(domain):
    """GitHub Code Search — separate from regular search, finds configs/envs."""
    api_key = _k("github")
    if not api_key:
        return set()
    results = set()
    headers = {"Authorization": "token " + api_key, "Accept": "application/vnd.github.v3.text-match+json"}
    queries = [
        '"{d}" in:file'.format(d=domain),
        'filename:.env "{d}"'.format(d=domain),
        'filename:configuration "{d}"'.format(d=domain),
    ]
    for q in queries:
        from urllib.parse import quote
        url = "https://api.github.com/search/code?q={q}&per_page=100".format(q=quote(q))
        status, data = _get_json(url, headers, timeout=15)
        if status == 200 and isinstance(data, dict):
            for item in data.get("items", []):
                # Extract from text_matches
                for tm in item.get("text_matches", []):
                    results.update(_clean(domain, tm.get("fragment", "")))
                results.update(_clean(domain, item.get("html_url", "")))
        elif status == 403:
            break
        time.sleep(3)
    return results

def src_digitorus(domain):
    """Digitorus / certificatedetails.com — another CT source, used by BBOT."""
    url = "https://certificatedetails.com/{d}".format(d=domain)
    status, body = _get(url, timeout=10)
    if status == 200 and body:
        return _clean(domain, body)
    return set()

# ─────────────────────────────────────────────────────────────
# REGISTRY — (name, func, key_names, description)
# ─────────────────────────────────────────────────────────────
REGISTRY = [
    # CT — PostgreSQL replaces 4 JSON API calls, falls back if no psycopg2
    ("crt.sh",           src_crtsh_postgres,   [],               f"PostgreSQL {'(' + _PG_DRIVER + ')' if _PG_DRIVER else '→ JSON fallback'}"),
    ("CertSpotter",      src_certspotter_free, [],               "100/hour free"),
    # Active recon
    ("AXFR ZoneXfer",   src_axfr,             [],               "zone transfer"),
    ("NSEC Walk",        src_nsec_walk,        [],               "DNSSEC zone enum"),
    ("robots.txt",       src_robots,           [],               "Disallow/Sitemap"),
    ("sitemap.xml",      src_sitemap,          [],               "recursive sitemap"),
    ("CSP Header",       src_csp_header,       [],               "Content-Security-Policy"),
    ("SSL Cert SAN",     src_sslcert,          [],               "TLS SAN напрямую"),
    ("DNS Records",      src_dns_records,      [],               "MX/NS/TXT/SRV"),
    ("DNSDumpster",      src_dnsdumpster,      [],               "CSRF scraping"),
    ("security.txt",     src_securitytxt,      [],               "/.well-known/security.txt"),
    ("OIDC Discovery",   src_oauth_discovery,  [],               "openid-configuration"),
    ("Postman Public",   src_postman,          [],               "public workspaces"),
    # Passive DNS — free
    ("HackerTarget",     src_hackertarget,     [],               "100/day"),
    ("HackerTarget shared", src_hackertarget_shared, [],         "shared DNS"),
    ("RapidDNS",         src_rapiddns,         [],               "no key"),
    ("Anubis/jldc.me",   src_anubis,           [],               "no key"),
    ("URLScan.io",       src_urlscan,          [],               "1000/day"),
    ("Wayback CDX",      src_wayback,          [],               "archive.org"),
    ("CommonCrawl",      src_commoncrawl,      [],               "web crawl"),
    ("OTX free",         src_otx_free,         [],               "pdns + url_list"),
    ("subdomain.center", src_subdomain_center, [],               "aggregator (slow)"),
    ("Mnemonic pdns",    src_mnemonic,         [],               "no key"),
    ("Robtex",           src_robtex,           [],               "forward+reverse"),
    ("Arquivo.pt",       src_arquivo,          [],               "PT archive"),
    ("LeakIX free",      src_leakix,           [],               "limited, no key"),
    ("Netcraft",         src_netcraft,         [],               "scraping"),
    ("SiteDossier",      src_sitedossier,      [],               "parentdomain scrape"),
    ("Cloudflare DoH",   src_cloudflare_doh,   [],               "1.1.1.1 DoH"),
    ("Shodan InternetDB",src_shodan_internetdb,[],               "no key"),
    ("BufferOver",       src_bufferover,       [],               "Rapid7 FDNS wrapper"),
    ("ViewDNS.info",     src_viewdns,          [],               "reverse IP"),
    ("DuckDuckGo",       src_duckduckgo,       [],               "site:*.domain"),
    ("ShrewdEye",        src_shrewdeye,        [],               "new free aggregator"),
    ("Columbus",         src_columbus,          [],               "elmasy.com aggregator"),
    ("N45HT",            src_n45ht,            [],               "sub3suite source"),
    ("Hunter.how",       src_huntermap,        [],               "Chinese Shodan"),
    ("PGP Keys",         src_pgp_keys,         [],               "email→subdomains"),
    ("Digitorus",        src_digitorus,        [],               "certificatedetails.com CT"),
    ("SubdomainRadar",   src_subdomainradar,   [],               "subdomainradar.io"),
    ("MySSL.com",        src_myssl,            [],               "CN CT"),
    # DNS extensions
    ("DNS CAA",          src_dnscaa,           [],               "CAA records"),
    ("DNS TLS-RPT",      src_dnstlsrpt,       [],               "TLS-RPT/DMARC"),
    ("DNS BIMI",         src_dnsbimi,          [],               "BIMI records"),
    ("SRV Extended",     src_srv_extended,     [],               "SRV шаблонов"),
    # IP / Cloud
    ("IP Neighbor",      src_ip_neighbor,      [],               "reverse DNS ±16 IP"),
    ("Azure Tenant",     src_azure_tenant,     [],               "onmicrosoft.com"),
    ("Azure Realm",      src_azure_realm,      [],               "UserRealm SSO/ADFS"),
    # Search engines
    ("Sogou Search",     src_sogou,            [],               "site:*.domain"),
    ("Yahoo Search",     src_yahoo,            [],               "site:*.domain"),
    ("Bing Search",      src_bing,             [],               "site:*.domain"),
    ("Yandex Search",    src_yandex,           [],               "site:*.domain"),
    ("Baidu Search",     src_baidu,            [],               "site:*.domain"),
    ("360.so Search",    src_360so,            [],               "so.com"),
    ("ChinaZ",           src_chinaz,           [],               "tool.chinaz.com"),
    ("IP138",            src_ip138,            [],               "site.ip138.com"),
    # Keyed
    ("VirusTotal",       src_virustotal,       ["virustotal"],   "4 req/min free"),
    ("SecurityTrails",   src_securitytrails,   ["securitytrails"],"50/month free"),
    ("Shodan DNS",       src_shodan,           ["shodan"],       "free tier"),
    ("FullHunt",         src_fullhunt,         ["fullhunt"],     "free tier"),
    ("Chaos/PD",         src_chaos,            ["projectdiscovery"],"free w/key"),
    ("WhoisXMLAPI",      src_whoisxml,         ["whoisxmlapi"],  "500/month free"),
    ("BinaryEdge",       src_binaryedge,       ["binaryedge"],   "paid"),
    ("C99",              src_c99,              ["c99"],          "paid"),
    ("AlienVault OTX",   src_otx_key,          ["otx"],          "free w/key"),
    ("ThreatBook",       src_threatbook,       ["threatbook"],   "free tier"),
    ("ZoomEye",          src_zoomeye,          ["zoomeye"],      "free tier"),
    ("SpyOnWeb",         src_spyonweb,         ["spyonweb"],     "paid"),
    ("host.io",          src_hostio,           ["host"],         "free tier"),
    ("LeakIX key",       src_leakix_key,       ["leakix"],       "free w/key"),
    ("IPInfo domains",   src_ipinfo,           ["ipinfo"],       "free w/key"),
    ("BeVigil",          src_bevigil,          ["bevigil"],      "mobile apps"),
    ("Farsight DNSDB",   src_dnsdb,            ["dnsdb"],        "best pdns, paid"),
    ("Passive DNS CN",   src_passivedns_cn,    ["passivedns"],   "passivedns.cn"),
    ("Hunter.io",        src_hunter,           ["hunter"],       "email → subs"),
    ("GitHub Search",    src_github_search,    ["github"],       "code/configs"),
    ("GitHub CodeSearch",src_github_codesearch,["github"],       "env/config files"),
    ("FOFA",             src_fofa,             ["fofa"],         "chinese shodan"),
    ("ChinaZ API",       src_chinaz_api,       ["chinaz"],       "с ключом"),
    ("GitHub Org",       src_github_org,       ["github"],       "org repos"),
    ("Trickest",         src_trickest,         ["trickest"],     "cloud subdomain DB"),
    ("BuiltWith",        src_builtwith,        ["builtwith"],    "tech profile"),
    ("PassiveTotal",     src_passivetotal,     ["passivetotal"], "RiskIQ/MS Defender"),
    ("CertSpotter key",  src_certspotter_key,  ["certspotter"],  "unlimited w/key"),
    ("Netlas.io",        src_netlas,           ["netlas"],       "50/day free"),
]

# ─────────────────────────────────────────────────────────────
# RUN — entry point called by recon.py
# ─────────────────────────────────────────────────────────────
def run(ctx):
    global _ctx
    _ctx = ctx
    domain = ctx["domain"]
    keys = ctx["keys"]
    threads = ctx["threads"]
    delay = ctx["delay"]

    # Split sources
    free = [(n,f,kn,d) for n,f,kn,d in REGISTRY if not kn]
    keyed = [(n,f,kn,d) for n,f,kn,d in REGISTRY if kn and any(_ctx["k"](keys, kname) for kname in kn)]
    nokey = [(n,f,kn,d) for n,f,kn,d in REGISTRY if kn and not any(_ctx["k"](keys, kname) for kname in kn)]

    # Rate-sensitive sources — run FIRST, sequentially (prevents 429)
    rate_sensitive_names = {"OTX free"}
    rate_first = [(n,f,kn,d) for n,f,kn,d in free if n in rate_sensitive_names]
    free_parallel = [(n,f,kn,d) for n,f,kn,d in free if n not in rate_sensitive_names]

    _log(f"  Sources: {len(free)} free | {len(keyed)} keyed | {len(nokey)} no key")

    def run_one(name, func, key_names, desc):
        try:
            result = func(domain)
            result = {r for r in result if r and r != domain and r.endswith(f".{domain}")}
            return name, len(result), result
        except Exception as ex:
            if ctx["debug"]:
                print(f"    [DEBUG] {name}: {type(ex).__name__}: {str(ex)[:120]}")
            return name, 0, set()

    def run_and_print(name, func, key_names, desc):
        n, count, results = run_one(name, func, key_names, desc)
        symbol = _c("✓","green") if count > 0 else _c("·","gray")
        cnt = _c(str(count),"cyan") if count > 0 else _c("0","gray")
        print(f"  {symbol} {n:<30} {cnt} субдоменов")
        return n, count, results

    # ── Rate-sensitive sources FIRST (sequential, with pauses) ──
    print(f"\n{_c('[ RATE-SENSITIVE — запускаем первыми ]','bold')}")
    for n, f, kn, d in rate_first:
        name, count, results = run_and_print(n, f, kn, d)
        ctx["source_map"][name] = results
        ctx["found_subs"].update(results)
        time.sleep(1)

    # ── Free sources — parallel ──
    print(f"\n{_c('[ FREE — без ключей ]','bold')}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(run_and_print, n, f, kn, d) for n,f,kn,d in free_parallel]
        for future in concurrent.futures.as_completed(futures):
            name, count, results = future.result()
            ctx["source_map"][name] = results
            ctx["found_subs"].update(results)
            time.sleep(delay)

    # ── Keyed sources — sequential (rate limits) ──
    if keyed:
        print(f"\n{_c('[ KEYED — ключ есть ]','bold')}")
        for n, f, kn, d in keyed:
            name, count, results = run_and_print(n, f, kn, d)
            ctx["source_map"][name] = results
            ctx["found_subs"].update(results)
            time.sleep(delay)

    # ── No key — just print ──
    if nokey:
        print(f"\n{_c('[ NO KEY — добавь в keys.ini ]','gray')}")
        for n, f, kn, d in nokey:
            print(f"  {_c('—','gray')} {n:<30} {_c('нет ключа: '+','.join(kn),'gray')}")
            ctx["source_map"][n] = set()

    _log(f"  Passive итого: {_c(str(len(ctx['found_subs'])),'green')} уникальных субдоменов")
