"""
Web Scrape + Header Harvest — MERGED for speed.
ONE request per host = headers (CSP, CORS, Location) + body (HTML/JS).
Fully parallel with ThreadPoolExecutor.
"""
import re
import concurrent.futures

NAME = "Web Scrape"
PHASE = 2
PRIORITY = 10
NEEDS_DEEP = True
DESCRIPTION = "Parallel HTTP scrape: headers + HTML + JS"
VERSION = "1.3"

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    get = ctx["get"]
    clean = ctx["clean"]
    log, c = ctx["log"], ctx["c"]

    results = set()
    js_urls = set()

    # Top 50 for full GET (body + headers)
    targets = sorted(found, key=len)[:50]
    if domain not in targets:
        targets.insert(0, domain)
    if f"www.{domain}" not in targets:
        targets.insert(1, f"www.{domain}")

    def _scrape_one(sub):
        local_results = set()
        local_js = set()
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            try:
                status, body = get(url, timeout=3, retries=1)
                if status != 200 or not body:
                    continue
                local_results.update(clean(domain, body))
                for m in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.I):
                    if m.startswith("//"):
                        m = "https:" + m
                    elif m.startswith("/"):
                        m = url.rstrip("/") + m
                    elif not m.startswith("http"):
                        m = url.rstrip("/") + "/" + m
                    local_js.add(m)
                for m in re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I):
                    if len(m) > 20:
                        local_results.update(clean(domain, m))
                break
            except Exception:
                continue
        return local_results, local_js

    # Header-only for hosts 50-200 (stream=True, no body download)
    header_targets = sorted(found, key=len)[50:200]

    def _header_only(sub):
        local_results = set()
        if not ctx["HAS_REQUESTS"]:
            return local_results
        import requests as _req
        for scheme in ("https", "http"):
            try:
                r = _req.get(f"{scheme}://{sub}", timeout=2, verify=False,
                            allow_redirects=False, stream=True,
                            headers={"User-Agent": "Mozilla/5.0"})
                r.close()
                for h in ("Content-Security-Policy", "Content-Security-Policy-Report-Only",
                          "Access-Control-Allow-Origin", "Location",
                          "X-Backend-Server", "X-Forwarded-Host", "X-Served-By"):
                    val = r.headers.get(h, "")
                    if val:
                        local_results.update(clean(domain, val))
                if local_results:
                    break
            except Exception:
                continue
        return local_results

    log(f"  Scraping {len(targets)} hosts + headers on {len(header_targets)} more...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        scrape_futures = {ex.submit(_scrape_one, sub): sub for sub in targets}
        header_futures = {ex.submit(_header_only, sub): sub for sub in header_targets}
        for future in concurrent.futures.as_completed(scrape_futures):
            r, js = future.result()
            results.update(r)
            js_urls.update(js)
        for future in concurrent.futures.as_completed(header_futures):
            results.update(future.result())

    # Parallel JS parsing (top 30)
    js_list = list(js_urls)[:30]
    if js_list:
        log(f"  Parsing {len(js_list)} JS files...")
        dom_re = re.compile(r'["\']([a-zA-Z0-9][\w\-\.]*\.' + re.escape(domain) + r')["\'/\\]')
        url_re = re.compile(r'https?://([a-zA-Z0-9][\w\-\.]*\.' + re.escape(domain) + r')[/"\'\\]')

        def _parse_js(js_url):
            local = set()
            status, body = get(js_url, timeout=3, retries=1)
            if status == 200 and body:
                local.update(clean(domain, body))
                for m in dom_re.findall(body):
                    sub = m.lower().strip()
                    if sub != domain and sub.endswith(f".{domain}"):
                        local.add(sub)
                for m in url_re.findall(body):
                    sub = m.lower().strip()
                    if sub != domain and sub.endswith(f".{domain}"):
                        local.add(sub)
            return local

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for future in concurrent.futures.as_completed(
                {ex.submit(_parse_js, u): u for u in js_list}
            ):
                results.update(future.result())

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["Web Scrape"] = new
    ctx["source_map"]["Header Harvest"] = set()  # merged here
    log(f"  Web+Headers: {c(str(len(new)),'green')} новых")
