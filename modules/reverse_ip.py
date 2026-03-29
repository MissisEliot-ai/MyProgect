"""
Reverse IP — resolve all found subdomains, collect unique IPs,
then reverse DNS each IP to find more subdomains on shared infrastructure.
"""
import socket
import concurrent.futures

NAME = "Reverse IP"
PHASE = 2
PRIORITY = 50
NEEDS_DEEP = True
DESCRIPTION = "Reverse DNS on all discovered IPs"
VERSION = "1.3"

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    resolve_one = ctx["resolve_one"]
    clean = ctx["clean"]
    get_json = ctx["get_json"]
    log, c = ctx["log"], ctx["c"]

    if not found:
        return

    # Step 1: Resolve subdomains → collect unique IPs (cap at 300)
    targets = list(found)[:300]
    log(f"  Resolving {len(targets)} subs to collect IPs...")
    all_ips = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for result in ex.map(resolve_one, targets):
            if result:
                sub, ips = result
                all_ips.update(ips)
                ctx["resolved"][sub] = ips

    log(f"  Found {c(str(len(all_ips)),'cyan')} unique IPs")

    # Step 2: Reverse DNS on each IP
    results = set()

    def rdns(ip):
        local = set()
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            local.update(clean(domain, hostname))
        except Exception:
            pass
        # Also check Shodan InternetDB (free, no key)
        try:
            status, data = get_json(f"https://internetdb.shodan.io/{ip}", timeout=5)
            if status == 200:
                for h in data.get("hostnames", []):
                    if h.lower().endswith(f".{domain}") and h.lower() != domain:
                        local.add(h.lower())
        except Exception:
            pass
        return local

    log(f"  Reverse DNS on {len(all_ips)} IPs...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for result in ex.map(rdns, list(all_ips)[:100]):
            results.update(result)

    # Step 3: ±16 IP neighbors on primary IPs
    try:
        import ipaddress
        primary_ip = socket.gethostbyname(domain)
        base = int(ipaddress.ip_address(primary_ip))
        neighbors = []
        for offset in range(-16, 17):
            try:
                neighbors.append(str(ipaddress.ip_address(base + offset)))
            except Exception:
                pass

        def rdns_simple(ip):
            try:
                return clean(domain, socket.gethostbyaddr(ip)[0])
            except Exception:
                return set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for result in ex.map(rdns_simple, neighbors):
                results.update(result)
    except Exception:
        pass

    new = results - found
    ctx["found_subs"].update(results)
    ctx["source_map"]["Reverse IP"] = new
    log(f"  Reverse IP: {c(str(len(new)),'green')} новых из reverse DNS")
