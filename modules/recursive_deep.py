"""
Recursive Deep — DNS brute on EVERY found subdomain + smart CT.
Found api.hupu.com → brute dev.api.hupu.com, test.api.hupu.com, v2.api.hupu.com
This is what gives BBOT its 20-50% advantage over other tools.
Uses massdns if available, otherwise ThreadPool with multiple resolvers.
"""
import concurrent.futures

NAME = "Recursive Deep"
PHASE = 2
PRIORITY = 20
NEEDS_DEEP = True
DESCRIPTION = "Recursive DNS brute on every subdomain (BBOT-style)"

# High-probability prefixes — short list, maximum hit rate
RECURSIVE_WORDS = [
    "dev","test","staging","stg","stage","qa","uat","prod","pre","beta",
    "api","app","web","admin","backend","frontend","gateway","proxy",
    "internal","int","ext","v2","v3","new","old","alpha",
    "cdn","static","img","assets","media",
    "m","mobile","h5",
    "auth","sso","login","passport",
    "mail","smtp","mx",
    "vpn","remote",
    "db","redis","mongo","elastic",
    "ci","jenkins","gitlab","git",
    "monitor","grafana","status",
    "sandbox","demo","lab","backup",
    "docs","help","support","wiki",
    "pay","billing","shop","store",
]

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    resolve_one = ctx["resolve_one"]
    massdns_resolve = ctx["massdns_resolve"]
    crtsh_query = ctx["crtsh_query"]
    crtsh_extract = ctx["crtsh_extract"]
    log, c = ctx["log"], ctx["c"]

    if not found:
        return

    import random as _rnd
    import string as _str

    # ──────────────────────────────────────────
    # STEP 0: Detect wildcard at each parent level BEFORE brute
    # ──────────────────────────────────────────
    wildcard_parents = set()  # parents with *.parent wildcard
    parents_to_check = set()
    for sub in found:
        depth = sub.replace(f".{domain}", "").count(".")
        if depth >= 2:
            continue
        parents_to_check.add(sub)
    parents_to_check.add(domain)

    # Cap: only check 500 shortest parents (rest are wordlist noise)
    if len(parents_to_check) > 500:
        parents_to_check = set(sorted(parents_to_check, key=len)[:500])

    def _wc_check(parent):
        rand = ''.join(_rnd.choices(_str.ascii_lowercase, k=12))
        r = resolve_one(f"{rand}.{parent}", timeout=2)
        if r:
            # Double-check
            rand2 = ''.join(_rnd.choices(_str.ascii_lowercase, k=14))
            r2 = resolve_one(f"{rand2}.{parent}", timeout=2)
            if r2:
                return parent, set(r[1]) | set(r2[1])
        return parent, None

    log(f"  Wildcard pre-check on {len(parents_to_check)} parents...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for future in concurrent.futures.as_completed(
            {ex.submit(_wc_check, p): p for p in parents_to_check}
        ):
            parent, wc_ips = future.result()
            if wc_ips:
                wildcard_parents.add(parent)
                # Add to ctx for other modules
                ctx.setdefault("wildcard_ips", set()).update(wc_ips)

    if wildcard_parents:
        log(f"  Wildcard parents ({c(str(len(wildcard_parents)),'yellow')}): skipping brute on these", "warn")
        for wp in sorted(wildcard_parents):
            log(f"    *.{wp}", "warn")

    # ──────────────────────────────────────────
    # STEP 1: Build candidates — SKIP wildcard parents
    # ──────────────────────────────────────────
    candidates = set()
    parents = []
    for sub in found:
        depth = sub.replace(f".{domain}", "").count(".")
        if depth >= 2:
            continue
        if sub in wildcard_parents:
            continue
        parents.append(sub)

    # Cap to 500 parents — beyond that, wordlist brute already covers them
    if len(parents) > 500:
        parents = sorted(parents, key=len)[:500]

    for sub in parents:
        for word in RECURSIVE_WORDS:
            candidate = f"{word}.{sub}"
            if candidate not in found:
                candidates.add(candidate)

    log(f"  Recursive brute: {c(str(len(candidates)),'cyan')} candidates (excluded {len(wildcard_parents)} wildcard zones)")

    # ──────────────────────────────────────────
    # STEP 2: Resolve — massdns or ThreadPool
    # ──────────────────────────────────────────
    new_dns = set()

    # Try massdns first (1000x faster)
    massdns_result = massdns_resolve(candidates, domain)

    if massdns_result is not None:
        log(f"  Using massdns — {c(str(len(massdns_result)),'green')} resolved")
        new_dns = massdns_result - found
    else:
        # Fallback: ThreadPool with multiple resolvers
        log(f"  massdns not found, using ThreadPool ({ctx['threads']} threads)...")
        done = 0
        total = len(candidates)
        threads = min(ctx["threads"], 80)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(resolve_one, cand, 2): cand for cand in candidates}
            for future in concurrent.futures.as_completed(futures):
                done += 1
                if done % 500 == 0:
                    print(f"\r  {c(str(done),'cyan')}/{total} bruted, found: {c(str(len(new_dns)),'green')}     ", end="", flush=True)
                result = future.result()
                if result:
                    sub, ips = result
                    # Filter wildcard
                    if ctx["wildcard_ips"] and set(ips).issubset(ctx["wildcard_ips"]):
                        continue
                    if sub not in found:
                        new_dns.add(sub)
                        ctx["resolved"][sub] = ips
        if total > 500:
            print()

    ctx["found_subs"].update(new_dns)
    ctx["source_map"].setdefault("Recursive DNS", set()).update(new_dns)
    log(f"  Recursive DNS brute: {c(str(len(new_dns)),'green')} новых субдоменов")

    # ──────────────────────────────────────────
    # STEP 3: Smart CT — parallel, not sequential
    # ──────────────────────────────────────────
    all_subs = ctx["found_subs"]
    parent_counts = {}
    for sub in all_subs:
        parts = sub.replace(f".{domain}", "").split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[1:]) + f".{domain}"
            parent_counts[parent] = parent_counts.get(parent, 0) + 1

    ct_targets = [p.replace(f".{domain}", "") for p, cnt in parent_counts.items() if cnt >= 2]
    infra = ["api","pay","passport","mail","auth","vpn","cdn","app","m","mobile","admin"]
    for word in infra:
        if f"{word}.{domain}" in all_subs and word not in ct_targets:
            ct_targets.append(word)

    if not ct_targets:
        return

    ct_targets = ct_targets[:10]
    log(f"  Smart CT: {c(str(len(ct_targets)),'cyan')} targets (parallel)")

    new_ct = set()

    def _ct_one(prefix):
        sub_domain = f"{prefix}.{domain}"
        data = crtsh_query({"q": f"%.{sub_domain}", "output": "json", "deduplicate": "Y"}, timeout=15)
        if not data:
            return set()
        return crtsh_extract(data, domain)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(_ct_one, p): p for p in ct_targets}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            new = result - all_subs - new_ct
            if new:
                new_ct.update(new)

    ctx["found_subs"].update(new_ct)
    ctx["source_map"].setdefault("Smart CT", set()).update(new_ct)
    if new_ct:
        log(f"  Smart CT: {c(str(len(new_ct)),'green')} новых")
