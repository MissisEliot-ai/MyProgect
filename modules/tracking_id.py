"""
Tracking ID Correlation — finds related domains via shared analytics/tracking IDs.
Extracts GA/GTM/Adsense/FB Pixel IDs from main domain, then searches for
other domains using the same IDs via builtwith/searchdns.

Unique technique: no other subdomain tool does this.
"""
import re
import concurrent.futures

NAME = "Tracking ID"
PHASE = 2
PRIORITY = 40
NEEDS_DEEP = True
DESCRIPTION = "GA/GTM/Pixel ID → linked domains"

# Tracking ID patterns
TRACKING_PATTERNS = [
    (r'UA-(\d{4,10})-\d{1,4}', 'ga'),           # Google Analytics UA
    (r'G-([A-Z0-9]{8,12})', 'ga4'),              # GA4
    (r'GTM-([A-Z0-9]{5,8})', 'gtm'),             # Google Tag Manager
    (r'AW-(\d{8,12})', 'gads'),                   # Google Ads
    (r'pub-(\d{10,16})', 'adsense'),              # AdSense
    (r'fbq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d{10,20})[\'"]', 'fbpixel'),  # FB Pixel
    (r'mc\.yandex\.ru/watch/(\d{5,10})', 'ym'),   # Yandex Metrika
]

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    get = ctx["get"]
    clean = ctx["clean"]
    log, c = ctx["log"], ctx["c"]

    results = set()
    tracking_ids = {}  # {(type, id): count}

    # ── 1. Extract tracking IDs from known hosts ──
    targets = [domain, f"www.{domain}"] + sorted(found, key=len)[:10]
    seen = set()

    def _extract_ids(sub):
        ids = {}
        if sub in seen:
            return ids
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub}"
            status, body = get(url, timeout=3, retries=1)
            if status == 200 and body:
                for pattern, id_type in TRACKING_PATTERNS:
                    for m in re.findall(pattern, body):
                        ids[(id_type, m)] = sub
                break
        return ids

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(_extract_ids, s): s for s in targets}
        for future in concurrent.futures.as_completed(futures):
            for key, source in future.result().items():
                tracking_ids[key] = source
                seen.add(source)

    if not tracking_ids:
        ctx["source_map"]["Tracking ID"] = set()
        return

    log(f"  Found {c(str(len(tracking_ids)),'cyan')} tracking IDs")

    # ── 2. Search for related domains using same IDs ──
    # Method A: BuiltWith relationships (free, no key)
    for (id_type, id_val), source in list(tracking_ids.items()):
        if id_type == 'ga':
            # Search BuiltWith for same GA ID
            url = "https://builtwith.com/relationships/tag/ua-%s" % id_val
            status, body = get(url, timeout=5, retries=1)
            if status == 200 and body:
                results.update(clean(domain, body))

        elif id_type == 'ga4':
            url = "https://builtwith.com/relationships/tag/g-%s" % id_val
            status, body = get(url, timeout=5, retries=1)
            if status == 200 and body:
                results.update(clean(domain, body))

    # Method B: Search HTML of all found subs for cross-references
    # If sub A has the same GA as sub B, any links in A might reveal more subs
    if tracking_ids:
        main_ids = set(v for (t, v) in tracking_ids.keys())

        def _scan_for_links(sub):
            local = set()
            for scheme in ("https", "http"):
                status, body = get(f"{scheme}://{sub}", timeout=3, retries=1)
                if status == 200 and body:
                    # Check if this host shares a tracking ID
                    for pattern, id_type in TRACKING_PATTERNS:
                        for m in re.findall(pattern, body):
                            if m in main_ids:
                                # Same org — extract all subdomains from this page
                                local.update(clean(domain, body))
                                break
                    break
            return local

        extra_targets = [s for s in sorted(found, key=len)[10:50] if s not in seen]
        if extra_targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
                for future in concurrent.futures.as_completed(
                    {ex.submit(_scan_for_links, s): s for s in extra_targets}
                ):
                    results.update(future.result())

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["Tracking ID"] = new
    if new:
        log(f"  Tracking ID: {c(str(len(new)),'green')} linked domains found")
