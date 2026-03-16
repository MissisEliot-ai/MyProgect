"""
API Spec Harvester — finds hidden subdomains inside swagger/openapi/graphql specs.
Probes known API documentation paths on alive hosts, extracts server URLs.
These internal endpoints are NEVER published anywhere else.
"""
import re
import concurrent.futures

NAME = "API Spec Harvest"
PHASE = 2
PRIORITY = 35
NEEDS_DEEP = True
DESCRIPTION = "Swagger/OpenAPI/GraphQL → hidden server URLs"
VERSION = "1.2"

# Paths to probe (ordered by likelihood)
SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api/openapi.json",
]

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    get = ctx["get"]
    clean = ctx["clean"]
    log, c = ctx["log"], ctx["c"]

    if not found:
        return

    results = set()
    # Only probe alive hosts (resolved)
    resolved = ctx.get("resolved", {})
    alive = [s for s in found if resolved.get(s)]
    targets = sorted(alive, key=len)[:15]  # top 15

    if not targets:
        targets = sorted(found, key=len)[:5]

    domain_re = re.compile(
        r'https?://([a-zA-Z0-9][\w\-\.]*\.' + re.escape(domain) + r')',
        re.IGNORECASE
    )

    def _probe_host(sub):
        local = set()
        for scheme in ("https", "http"):
            base = f"{scheme}://{sub}"
            fails = 0
            for path in SPEC_PATHS:
                if fails >= 3:
                    break  # 3 misses in a row = no API spec here
                url = base + path
                status, body = get(url, timeout=2, retries=1)
                if status == 0:
                    break  # dead host, skip all paths
                if status != 200 or not body or len(body) < 20:
                    fails += 1
                    continue
                fails = 0  # reset on success

                for m in domain_re.findall(body):
                    sub_found = m.lower().strip(".")
                    if sub_found != domain and sub_found.endswith("." + domain):
                        local.add(sub_found)

                local.update(clean(domain, body))

                if local or len(body) > 100:
                    break
            if local:
                break
        return local

    log(f"  Probing {len(targets)} hosts for API specs...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe_host, sub): sub for sub in targets}
        for future in concurrent.futures.as_completed(futures):
            results.update(future.result())

    # ── GraphQL introspection (separate, lighter) ──
    gql_targets = targets[:5]

    def _probe_graphql(sub):
        local = set()
        for scheme in ("https", "http"):
            dead = False
            for path in ("/graphql", "/api/graphql", "/gql", "/query"):
                if dead:
                    break
                url = f"{scheme}://{sub}{path}"
                status, body = get(url + "?query=%7B__schema%7Btypes%7Bname%7D%7D%7D",
                                  timeout=2, retries=1)
                if status == 0:
                    dead = True
                    continue
                if status == 200 and body and "__schema" in body:
                    local.update(clean(domain, body))
                    break
            if local:
                break
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for future in concurrent.futures.as_completed(
            {ex.submit(_probe_graphql, s): s for s in gql_targets}
        ):
            results.update(future.result())

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["API Spec Harvest"] = new
    if new:
        log(f"  API Specs: {c(str(len(new)),'green')} hidden endpoints found")
