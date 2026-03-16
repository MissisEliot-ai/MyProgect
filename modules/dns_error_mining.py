"""
DNS Error Mining — distinguishes NXDOMAIN from SERVFAIL/REFUSED.
NXDOMAIN = domain definitely doesn't exist.
SERVFAIL = server exists but had an error → host IS configured but broken/internal.
REFUSED = server actively refusing → host IS configured but restricted.

These "hidden" hosts are real infrastructure that DNS brute misses.
"""
import concurrent.futures

NAME = "DNS Error Mining"
PHASE = 3
PRIORITY = 20
NEEDS_DEEP = True
DESCRIPTION = "SERVFAIL/REFUSED = hidden hosts that exist"
VERSION = "1.1"

# High-value internal prefixes to probe
INTERNAL_WORDS = [
    "internal", "intranet", "private", "corp", "office",
    "dc", "dc1", "dc2", "ad", "ldap", "kerberos",
    "nas", "san", "nfs", "smb", "ftp-internal",
    "db-master", "db-slave", "db-replica", "primary", "secondary",
    "kafka", "zookeeper", "consul", "vault", "etcd",
    "k8s", "kube", "kubernetes", "docker", "swarm",
    "prometheus", "alertmanager", "loki",
    "jump", "jumpbox", "bastion", "gateway-internal",
    "vpn-internal", "ipsec", "wireguard",
    "build", "deploy", "artifact", "nexus", "sonar",
    "splunk", "elastic-internal", "kibana-internal", "logstash",
    "radius", "tacacs", "ntp-internal", "dns-internal",
    "mgmt", "management", "oob", "ipmi", "ilo", "idrac",
    "dev-internal", "staging-internal", "prod-internal",
    "api-internal", "service", "microservice",
    "cache-internal", "memcached", "redis-internal",
    "queue", "rabbitmq", "activemq",
    "proxy-internal", "lb-internal", "haproxy",
    "backup-internal", "dr", "disaster-recovery",
    "test-internal", "qa-internal", "uat-internal",
    "crm", "erp", "hrm", "jira-internal", "confluence-internal",
]

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    log, c = ctx["log"], ctx["c"]

    if not ctx.get("HAS_DNSPYTHON"):
        ctx["source_map"]["DNS Error Mining"] = set()
        return

    import dns.resolver
    import dns.exception
    import random

    resolvers = ctx.get("RESOLVERS", ["8.8.8.8", "1.1.1.1"])

    # Build candidates: internal words × found parent subs (skip wildcard parents)
    candidates = set()
    parents = set()
    parents.add(domain)
    wildcard_parents = set()
    for sub in found:
        prefix = sub.replace("." + domain, "")
        parts = prefix.split(".")
        if len(parts) == 1:
            parents.add(sub)

    # Quick wildcard check on parents
    wc_ips = ctx.get("wildcard_ips", set())
    for parent in list(parents)[:30]:
        if parent in ctx.get("wildcard_parents", set()):
            wildcard_parents.add(parent)
            continue
        # Check if parent is wildcard by resolving random sub
        import string as _str
        rand = ''.join(random.choices(_str.ascii_lowercase, k=12))
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [random.choice(resolvers)]
            r.timeout = 2
            r.lifetime = 2
            answers = r.resolve(f"{rand}.{parent}", "A")
            if answers:
                wildcard_parents.add(parent)
        except Exception:
            pass

    safe_parents = [p for p in list(parents)[:30] if p not in wildcard_parents]

    for parent in safe_parents:
        for word in INTERNAL_WORDS:
            cand = f"{word}.{parent}" if parent != domain else f"{word}.{domain}"
            if cand not in found:
                candidates.add(cand)

    if wildcard_parents:
        log(f"  Skipped {len(wildcard_parents)} wildcard parents")

    if not candidates:
        ctx["source_map"]["DNS Error Mining"] = set()
        return

    candidates = set(list(candidates)[:3000])
    log(f"  Error mining: probing {c(str(len(candidates)),'cyan')} internal candidates...")

    hidden = set()      # SERVFAIL/REFUSED
    alive_new = set()   # Actually resolves

    def _probe_dns(name):
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [random.choice(resolvers)]
            r.timeout = 2
            r.lifetime = 2
            answers = r.resolve(name, "A")
            ips = [str(a) for a in answers]
            return name, "RESOLVED", ips
        except dns.resolver.NXDOMAIN:
            return name, "NXDOMAIN", []
        except dns.resolver.NoAnswer:
            return name, "NOANSWER", []  # Record exists but no A
        except dns.resolver.NoNameservers:
            return name, "SERVFAIL", []  # Server error = host configured
        except dns.exception.Timeout:
            return name, "TIMEOUT", []
        except Exception as e:
            err = str(e).lower()
            if "refused" in err:
                return name, "REFUSED", []
            return name, "ERROR", []

    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
        futures = {ex.submit(_probe_dns, cand): cand for cand in candidates}
        for future in concurrent.futures.as_completed(futures):
            name, status, ips = future.result()
            if status == "RESOLVED":
                # Filter wildcard
                if ctx.get("wildcard_ips") and set(ips).issubset(ctx["wildcard_ips"]):
                    continue
                alive_new.add(name)
                ctx["resolved"][name] = ips
            elif status in ("SERVFAIL", "REFUSED", "NOANSWER"):
                hidden.add(name)

    # Add resolved to found
    ctx["found_subs"].update(alive_new)

    # Hidden hosts go to SEPARATE storage — NOT found_subs
    # They never resolve, so they inflate dead.txt with garbage
    all_hidden = hidden - found - alive_new
    ctx.setdefault("hidden_subs", set()).update(all_hidden)

    ctx["source_map"]["DNS Error Mining"] = alive_new.copy()

    if alive_new:
        log(f"  Resolved: {c(str(len(alive_new)),'green')} new hosts")
    if all_hidden:
        log(f"  Hidden (SERVFAIL/REFUSED): {c(str(len(all_hidden)),'yellow')} → hidden.txt")
