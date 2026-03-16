"""
CNAME Chain — resolve CNAME records for all found subdomains.
Discovers hidden infrastructure: CDN hosts, staging aliases, internal balancers.
"""
import concurrent.futures

NAME = "CNAME Chain"
PHASE = 2
PRIORITY = 40
NEEDS_DEEP = True
DESCRIPTION = "CNAME following → hidden infrastructure"

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    clean = ctx["clean"]
    dns_query = ctx["dns_query"]
    log, c = ctx["log"], ctx["c"]

    if not found:
        return

    results = set()
    targets = list(found)[:500]

    def resolve_cname(sub):
        local = set()
        try:
            for rec in dns_query(sub, "CNAME"):
                target = rec.rstrip(".").lower()
                local.update(clean(domain, target))
        except Exception:
            pass
        return local

    log(f"  CNAME resolving {len(targets)} hosts...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(resolve_cname, targets):
            results.update(result)

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["CNAME Chain"] = new
    log(f"  CNAME Chain: {c(str(len(new)),'green')} новых из CNAME records")
