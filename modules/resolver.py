"""
Resolver — DNS validation with BBOT-style multi-level wildcard detection.
Checks wildcard at EVERY parent level, not just root.
*.test-main.proginn.com, *.prod.proginn.com etc. are detected and filtered.
"""
import random
import string
import concurrent.futures
import os

NAME = "DNS Resolver"
PHASE = 4
PRIORITY = 10
NEEDS_DEEP = False
DESCRIPTION = "Multi-level wildcard detection + mass DNS resolve"
VERSION = "1.1"

def run(ctx):
    domain = ctx["domain"]
    found = set(ctx["found_subs"])
    resolve_one = ctx["resolve_one"]
    log, c = ctx["log"], ctx["c"]

    if not found:
        return

    # ── 1. Collect all unique parent zones from found subdomains ──
    parents = set()
    parents.add(domain)
    for sub in found:
        parts = sub.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent.endswith("." + domain) or parent == domain:
                parents.add(parent)

    # Cap parents to prevent slowdown with large wordlists
    parent_cap = max(50, int(os.environ.get("RECON_WILDCARD_PARENT_MAX", "500")))
    if len(parents) > parent_cap:
        # Keep shortest (most important) parents
        parents = set(sorted(parents, key=len)[:parent_cap])

    log(f"  Checking {len(parents)} zones for wildcards...")

    # ── 2. Test each parent for wildcard (parallel) ──
    wildcard_map = {}  # {parent: set(ips)}

    def _check_wildcard(parent):
        rand = ''.join(random.choices(string.ascii_lowercase, k=12))
        test_host = f"{rand}.{parent}"
        result = resolve_one(test_host, timeout=3)
        if result:
            return parent, set(result[1])
        return parent, None

    threads = min(200, len(parents))
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_check_wildcard, p): p for p in parents}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 200 == 0:
                print(f"\r  Wildcard probe: {done}/{len(parents)}...     ", end="", flush=True)
            parent, ips = future.result()
            if ips:
                wildcard_map[parent] = ips
    if len(parents) > 200:
        print()

    if wildcard_map:
        # Double-check wildcards with second random query (avoid false positives)
        # Parallelized: sequential confirmation can be very slow on large runs.
        confirmed = {}

        def _confirm_wildcard(item):
            parent, ips1 = item
            rand2 = ''.join(random.choices(string.ascii_lowercase, k=14))
            result2 = resolve_one(f"{rand2}.{parent}", timeout=2)
            if result2:
                ips2 = set(result2[1])
                # Both random queries resolved — confirmed wildcard
                return parent, (ips1 | ips2)
            return parent, None

        items = list(wildcard_map.items())
        threads2 = min(200, len(items))
        done2 = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads2) as ex:
            futures2 = {ex.submit(_confirm_wildcard, item): item[0] for item in items}
            for future in concurrent.futures.as_completed(futures2):
                done2 += 1
                if done2 % 200 == 0:
                    print(f"\r  Confirming wildcards: {done2}/{len(items)}...     ", end="", flush=True)
                parent, merged_ips = future.result()
                if merged_ips:
                    confirmed[parent] = merged_ips
        if len(items) > 200:
            print()

        wildcard_map = confirmed

    if wildcard_map:
        log(f"  Wildcards found at {c(str(len(wildcard_map)),'yellow')} levels:", "warn")
        ctx["wildcard_parents"] = set(wildcard_map.keys())
        wc_log_limit = max(0, int(os.environ.get("RECON_WILDCARD_LOG_LIMIT", "60")))
        shown = 0
        for parent in sorted(wildcard_map.keys()):
            if wc_log_limit and shown >= wc_log_limit:
                break
            log(f"    *.{parent} → {wildcard_map[parent]}", "warn")
            shown += 1
        if wc_log_limit and len(wildcard_map) > wc_log_limit:
            log(f"    ... and {len(wildcard_map) - wc_log_limit} more wildcard parents", "warn")
        # Merge all wildcard IPs for ctx
        all_wc_ips = set()
        for ips in wildcard_map.values():
            all_wc_ips.update(ips)
        ctx["wildcard_ips"] = all_wc_ips
    else:
        log(f"  No wildcards detected ✓")
        ctx["wildcard_ips"] = set()
        ctx["wildcard_parents"] = set()

    # ── 3. Filter already-resolved subs against wildcard parents ──
    def _is_wildcard(sub, ips):
        """Check if subdomain's IPs match any of its parent wildcards."""
        if not wildcard_map:
            return False
        ip_set = set(ips) if isinstance(ips, (list, tuple)) else ({ips} if ips else set())
        # No IP evidence -> cannot confidently classify as wildcard.
        if not ip_set:
            return False
        parts = sub.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in wildcard_map and ip_set.issubset(wildcard_map[parent]):
                return True
        return False

    to_remove = set()
    for sub, ips in list(ctx["resolved"].items()):
        if _is_wildcard(sub, ips):
            to_remove.add(sub)

    if to_remove:
        ctx["found_subs"] -= to_remove
        for sub in to_remove:
            ctx["resolved"].pop(sub, None)
        log(f"  Removed {c(str(len(to_remove)),'yellow')} wildcard subs from resolved")

    # ── 4. Mass resolve remaining — massdns first, dnsx second, ThreadPool last ──
    found = set(ctx["found_subs"])  # refresh after filtering
    unresolved = [s for s in found if s not in ctx["resolved"]]
    if not unresolved:
        log(f"  All {len(found)} subs already resolved")
        return

    log(f"  Resolving {len(unresolved)} remaining subs...")
    resolved_count = 0

    # Try massdns first (fastest for large sets)
    massdns_resolve = ctx.get("massdns_resolve")
    if massdns_resolve and len(unresolved) > 100:
        log(f"  Using massdns for {len(unresolved)} subs...")
        massdns_result = massdns_resolve(unresolved, domain)
        if massdns_result is not None:
            for sub in massdns_result:
                # massdns confirms that hostname resolves, but does not provide
                # trusted IP data in this code path, so keep a marker value.
                ctx["resolved"][sub] = ["massdns"]
                resolved_count += 1
            still_unresolved = [s for s in unresolved if s not in ctx["resolved"]]
            log(f"  massdns: {resolved_count} alive, {len(still_unresolved)} remain")
            unresolved = still_unresolved

    # Try dnsx second (gets actual IPs)
    dnsx_resolve = ctx.get("dnsx_resolve")
    if dnsx_resolve and unresolved:
        dnsx_max_total = max(0, int(os.environ.get("RECON_DNSX_MAX_TOTAL", "120000")))
        if dnsx_max_total and len(unresolved) > dnsx_max_total:
            unresolved = sorted(unresolved, key=len)[:dnsx_max_total]
            log(f"  dnsx capped: {dnsx_max_total} hosts (set RECON_DNSX_MAX_TOTAL=0 to disable)", "warn")

        dnsx_batch_size = max(1000, int(os.environ.get("RECON_DNSX_BATCH_SIZE", "50000")))
        total_dnsx = len(unresolved)
        if total_dnsx > dnsx_batch_size:
            log(f"  Using dnsx for {total_dnsx} subs in batches of {dnsx_batch_size}...")
        else:
            log(f"  Using dnsx for {total_dnsx} subs...")

        remaining_after_dnsx = []
        dnsx_resolved = 0
        batch_no = 0
        total_batches = (total_dnsx + dnsx_batch_size - 1) // dnsx_batch_size

        for i in range(0, total_dnsx, dnsx_batch_size):
            batch_no += 1
            batch = unresolved[i:i + dnsx_batch_size]
            log(f"  dnsx batch {batch_no}/{total_batches}: {len(batch)} hosts", "info")
            dnsx_result = dnsx_resolve(batch, domain) or {}

            for sub in batch:
                ips = dnsx_result.get(sub)
                if not ips:
                    remaining_after_dnsx.append(sub)
                    continue
                if _is_wildcard(sub, ips):
                    ctx["found_subs"].discard(sub)
                    continue
                ctx["resolved"][sub] = ips
                resolved_count += 1
                dnsx_resolved += 1

            log(f"  dnsx progress: {min(i + dnsx_batch_size, total_dnsx)}/{total_dnsx} processed", "info")

        unresolved = remaining_after_dnsx
        if unresolved:
            log(f"  dnsx: +{dnsx_resolved} alive, {len(unresolved)} remain")

    # Fallback: ThreadPool for remaining (small batches only)
    if unresolved and len(unresolved) <= 5000:
        threads = min(200, len(unresolved))
        log(f"  ThreadPool ({threads} threads) for {len(unresolved)} remaining...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(resolve_one, sub): sub for sub in unresolved}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                if done % 500 == 0:
                    print(f"\r  {done}/{len(unresolved)} resolving...     ", end="", flush=True)
                result = future.result()
                if result:
                    sub, ips = result
                    if _is_wildcard(sub, ips):
                        ctx["found_subs"].discard(sub)
                        continue
                    ctx["resolved"][sub] = ips
                    resolved_count += 1
        if len(unresolved) > 500:
            print()
    elif unresolved:
        log(f"  Skipping {len(unresolved)} unresolved (too many for ThreadPool, need massdns/dnsx)")

    alive = len(ctx["resolved"])
    total = len(ctx["found_subs"])
    log(f"  Resolved: {c(str(alive),'green')} alive / {total} total")

    # ── 5. Trusted resolver validation (anti-poisoning) ──
    # Re-check all resolved hosts against 8.8.8.8 and 1.1.1.1
    # Removes DNS-poisoned results from dodgy public resolvers
    TRUSTED = ["8.8.8.8", "1.1.1.1"]
    resolved_hosts = list(ctx["resolved"].keys())
    max_validate = int(os.environ.get("RECON_TRUSTED_VALIDATE_MAX", "5000"))
    if len(resolved_hosts) > max_validate:
        # Large runs can stall for a long time here; validate a representative sample.
        random.shuffle(resolved_hosts)
        log(f"  Trusted validation capped: {max_validate}/{len(ctx['resolved'])} hosts", "warn")
        resolved_hosts = resolved_hosts[:max_validate]
    if len(resolved_hosts) > 3:
        try:
            import dns.resolver as _dns_r
        except ImportError:
            log(f"  Trusted validation skipped (dnspython not installed)")
            return

        log(f"  Validating {len(resolved_hosts)} hosts via trusted resolvers...")

        def _trusted_check(sub):
            for ns in TRUSTED:
                try:
                    r = _dns_r.Resolver()
                    r.nameservers = [ns]
                    r.lifetime = 3
                    answers = r.resolve(sub, "A", lifetime=3)
                    return sub, [str(a) for a in answers]
                except Exception:
                    continue
            return sub, None

        poisoned = set()
        threads = min(200, len(resolved_hosts))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_trusted_check, sub): sub for sub in resolved_hosts}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                done += 1
                if done % 500 == 0:
                    print(f"\r  Validating: {done}/{len(resolved_hosts)}...     ", end="", flush=True)
                sub, trusted_ips = future.result()
                if trusted_ips is None:
                    # Trusted resolvers say NXDOMAIN — was poisoned!
                    poisoned.add(sub)
        if len(resolved_hosts) > 500:
            print()

        if poisoned:
            for sub in poisoned:
                ctx["resolved"].pop(sub, None)
                ctx["found_subs"].discard(sub)
            log(f"  Removed {c(str(len(poisoned)),'yellow')} DNS-poisoned results", "warn")
        else:
            log(f"  Trusted validation: all clean ✓")
