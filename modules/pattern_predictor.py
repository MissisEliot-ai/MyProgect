"""
Pattern Predictor — predicts subdomains from numeric/structural patterns.
No API calls, pure math + DNS resolve.

Found dev1, dev2, dev3 → predicts dev4..dev20
Found us-east-1.api → predicts eu-west-1.api, ap-southeast-1.api
Found backup-20240101 → predicts backup-20240201, backup-20240301
"""
import re
import concurrent.futures

NAME = "Pattern Predictor"
PHASE = 3
PRIORITY = 15
NEEDS_DEEP = True
DESCRIPTION = "Predict subdomains from numeric/structural patterns"
VERSION = "1.2"

# Cloud region patterns (AWS, Azure, GCP style)
CLOUD_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ap-south-1", "sa-east-1", "ca-central-1", "me-south-1",
    "eastus", "westus", "westus2", "centralus", "northeurope", "westeurope",
    "southeastasia", "eastasia", "japaneast", "japanwest",
    "australiaeast", "brazilsouth", "koreacentral",
]

def run(ctx):
    domain = ctx["domain"]
    found = ctx["found_subs"]
    resolve_one = ctx["resolve_one"]
    massdns_resolve = ctx["massdns_resolve"]
    log, c = ctx["log"], ctx["c"]

    if len(found) < 3:
        return

    candidates = set()

    # ── 1. Numeric sequences: dev1→dev2..dev20 ──
    num_re = re.compile(r'^(.+?)(\d+)(\..*)?$')
    groups = {}  # prefix → set of numbers
    for sub in found:
        prefix_part = sub.replace("." + domain, "")
        m = num_re.match(prefix_part)
        if m:
            base, num_str, suffix = m.group(1), m.group(2), m.group(3) or ""
            key = (base, suffix)
            groups.setdefault(key, set()).add(int(num_str))

    for (base, suffix), numbers in groups.items():
        if len(numbers) < 2:
            continue
        min_n, max_n = min(numbers), max(numbers)
        # Cap: max 50 predictions per group, max range 200
        range_end = min(max_n + 15, min_n + 200)
        group_count = 0
        for n in range(min_n, range_end):
            if group_count >= 50:
                break
            if n not in numbers:
                cand = f"{base}{n}{suffix}.{domain}"
                if cand not in found:
                    candidates.add(cand)
                    group_count += 1
            if len(candidates) >= 3000:
                break
        if len(candidates) >= 3000:
            break

    log(f"  Numeric patterns: {c(str(len(candidates)),'cyan')} candidates")

    # ── 2. Cloud region expansion ──
    region_cands = set()
    for sub in found:
        prefix = sub.replace("." + domain, "")
        for region in CLOUD_REGIONS:
            if region in prefix:
                # Found a region pattern, try all other regions
                for other in CLOUD_REGIONS:
                    if other != region:
                        new_prefix = prefix.replace(region, other)
                        cand = f"{new_prefix}.{domain}"
                        if cand not in found and cand not in candidates:
                            region_cands.add(cand)
                break

    if region_cands:
        log(f"  Cloud regions: {c(str(len(region_cands)),'cyan')} candidates")
        candidates.update(region_cands)

    # ── 3. Date patterns: backup-20240101 → next months ──
    date_re = re.compile(r'(\d{4})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])')
    date_cands = set()
    for sub in found:
        prefix = sub.replace("." + domain, "")
        m = date_re.search(prefix)
        if m:
            year, month = int(m.group(1)), int(m.group(2))
            for dy in range(-1, 3):
                for dm in range(1, 13):
                    ny = year + dy
                    if 2020 <= ny <= 2026:
                        new_date = f"{ny}{dm:02d}01"
                        new_prefix = prefix[:m.start()] + new_date + prefix[m.end():]
                        cand = f"{new_prefix}.{domain}"
                        if cand not in found and cand not in candidates:
                            date_cands.add(cand)

    if date_cands:
        # Limit date candidates
        date_cands = set(list(date_cands)[:200])
        log(f"  Date patterns: {c(str(len(date_cands)),'cyan')} candidates")
        candidates.update(date_cands)

    # ── 4. Letter sequences: node-a, node-b → node-c..node-f ──
    letter_re = re.compile(r'^(.+?)-([a-z])$')
    letter_groups = {}
    for sub in found:
        prefix = sub.replace("." + domain, "")
        m = letter_re.match(prefix)
        if m:
            base = m.group(1)
            letter_groups.setdefault(base, set()).add(m.group(2))

    for base, letters in letter_groups.items():
        if len(letters) < 2:
            continue
        for ch in "abcdefghijklmnop":
            if ch not in letters:
                cand = f"{base}-{ch}.{domain}"
                if cand not in found:
                    candidates.add(cand)

    if not candidates:
        return

    # Cap at 3000
    candidates = set(list(candidates)[:3000])
    log(f"  Total predictions: {c(str(len(candidates)),'cyan')}")

    # ── Resolve ──
    new_found = set()
    massdns_result = massdns_resolve(candidates, domain)
    if massdns_result is not None:
        new_found = massdns_result - found
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
            futures = {ex.submit(resolve_one, cand): cand for cand in candidates}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    sub, ips = result
                    if ctx.get("wildcard_ips") and set(ips).issubset(ctx["wildcard_ips"]):
                        continue
                    if sub not in found:
                        new_found.add(sub)
                        ctx["resolved"][sub] = ips

    ctx["found_subs"].update(new_found)
    ctx["source_map"]["Pattern Predictor"] = new_found
    if new_found:
        log(f"  Pattern Predictor: {c(str(len(new_found)),'green')} новых")
