"""
WordCloud Engine — BBOT-style adaptive word extraction + smart mutations.
Uses wordninja NLP for splitting compound words (pip install wordninja).
Falls back to basic split if wordninja not installed.
"""
import re
import json
import concurrent.futures
from pathlib import Path

NAME = "WordCloud Mutations"
PHASE = 3
PRIORITY = 10
NEEDS_DEEP = True
DESCRIPTION = "BBOT-style WordCloud + NLP mutations"
VERSION = "1.1"

# Try wordninja — NLP-based word splitting (BBOT's secret weapon)
try:
    import wordninja
    _HAS_WORDNINJA = True
except ImportError:
    _HAS_WORDNINJA = False

def _split_word(word):
    """Split compound words using wordninja NLP or fallback.
    mobileapi → [mobile, api], footballnews → [football, news]."""
    parts = set()
    # Split on separators first
    for sep in ("-", "_", "."):
        if sep in word:
            for p in word.split(sep):
                if len(p) > 1:
                    parts.add(p)
                    # Also NLP-split each part
                    if _HAS_WORDNINJA and len(p) > 4:
                        for w in wordninja.split(p):
                            if len(w) > 1:
                                parts.add(w)
            return parts

    # wordninja NLP split — the killer feature
    if _HAS_WORDNINJA and len(word) > 4:
        ninja_parts = wordninja.split(word)
        if len(ninja_parts) > 1:
            for p in ninja_parts:
                if len(p) > 1:
                    parts.add(p)

    # CamelCase split
    camel = re.findall(r'[a-z]+|[A-Z][a-z]*', word)
    if len(camel) > 1:
        for p in camel:
            if len(p) > 1:
                parts.add(p.lower())

    # Number split: www2 → [www], api3 → [api]
    num_split = re.match(r'^([a-z]+)(\d+)$', word)
    if num_split:
        base = num_split.group(1)
        if len(base) > 1:
            parts.add(base)

    # If nothing split, add the whole word
    if not parts:
        parts.add(word)

    return parts

def _build_cloud(found_subs, domain):
    """Build word frequency cloud from all found subdomains."""
    cloud = {}
    # Snapshot to avoid "set changed size during iteration" when Phase 3 modules
    # run in parallel and mutate ctx["found_subs"].
    for sub in list(found_subs):
        # Strip domain suffix
        prefix = sub.replace(f".{domain}", "")
        # Split each level
        for level in prefix.split("."):
            if len(level) < 2:
                continue
            # Add whole level
            cloud[level] = cloud.get(level, 0) + 1
            # Add split parts
            for part in _split_word(level):
                if len(part) > 1:
                    cloud[part] = cloud.get(part, 0) + 1
    return cloud

def _generate_mutations(cloud, found_subs, domain):
    """Generate mutation candidates from WordCloud."""
    candidates = set()
    existing_prefixes = set()
    for sub in list(found_subs):
        prefix = sub.replace(f".{domain}", "")
        existing_prefixes.add(prefix)

    # Get top words (most frequent)
    top_words = sorted(cloud.items(), key=lambda x: -x[1])[:60]

    # DevOps suffixes/prefixes
    devops_suffixes = [
        "-dev","-test","-staging","-stg","-qa","-uat","-prod","-beta",
        "-alpha","-canary","-preview","-demo","-sandbox","-lab",
        "-internal","-int","-ext","-api","-app","-web","-admin",
        "-backend","-frontend","-gateway","-proxy","-cdn","-cache",
        "-v2","-v3","-new","-old","-backup","-bak","-dr","-hot",
        "2","3","4","1",
    ]
    devops_prefixes = [
        "dev-","test-","staging-","stage-","stg-","qa-","uat-","prod-",
        "pre-","beta-","alpha-","internal-","new-","old-","v2-","api-",
    ]

    for word, count in top_words:
        if word in existing_prefixes:
            # Word already exists as subdomain — mutate it
            for suf in devops_suffixes:
                c = f"{word}{suf}"
                if c not in existing_prefixes:
                    candidates.add(c)
            for pre in devops_prefixes:
                c = f"{pre}{word}"
                if c not in existing_prefixes:
                    candidates.add(c)

        # Number mutations: found api2 → try api3, api4, api5
        num_match = re.match(r'^([a-z]+?)(\d+)$', word)
        if num_match:
            base, num = num_match.group(1), int(num_match.group(2))
            for n in range(max(0, num-2), num+5):
                c = f"{base}{n}"
                if c not in existing_prefixes:
                    candidates.add(c)

    # Cross-combinations of top words (Amass-style permutations)
    top_15 = [w for w, _ in top_words[:15]]
    for w1 in top_15:
        for w2 in top_15:
            if w1 != w2:
                for combo in [f"{w1}-{w2}", f"{w1}{w2}", f"{w2}-{w1}", f"{w2}{w1}"]:
                    if combo not in existing_prefixes and len(combo) < 30:
                        candidates.add(combo)

    # Amass-style: permute existing multi-part names
    # bbs-sit → sit-bbs, bbssit, sitbbs
    for prefix in existing_prefixes:
        if "-" in prefix:
            parts = prefix.split("-")
            if len(parts) == 2:
                a, b = parts
                for perm in [f"{b}-{a}", f"{a}{b}", f"{b}{a}"]:
                    if perm not in existing_prefixes:
                        candidates.add(perm)

    return candidates

def run(ctx):
    domain = ctx["domain"]
    # Snapshot shared set (other Phase 3 modules run concurrently)
    found = set(ctx["found_subs"])
    resolve_one = ctx["resolve_one"]
    log, c_fn = ctx["log"], ctx["c"]

    if not found:
        return

    # Build WordCloud
    cloud = _build_cloud(found, domain)
    ctx["wordcloud"] = cloud

    log(f"  WordCloud: {c_fn(str(len(cloud)),'cyan')} unique words extracted" +
        (f" (wordninja NLP: on)" if _HAS_WORDNINJA else f" (wordninja: off, pip install wordninja)"))

    # Show top words
    top = sorted(cloud.items(), key=lambda x: -x[1])[:15]
    if ctx["debug"]:
        for word, count in top:
            print(f"    {word}: {count}")

    # Generate mutations
    candidates = _generate_mutations(cloud, found, domain)
    log(f"  Mutations generated: {c_fn(str(len(candidates)),'cyan')} candidates")

    if not candidates:
        return

    # DNS brute force mutations — massdns if available, else ThreadPool
    to_check = [f"{c}.{domain}" for c in list(candidates)[:3000]]
    log(f"  Brute-forcing {len(to_check)} mutations...")

    new_found = set()

    # Try massdns first
    massdns_result = ctx["massdns_resolve"](to_check, domain)
    if massdns_result is not None:
        new_found = massdns_result - found
        log(f"  massdns: {c_fn(str(len(new_found)),'green')} resolved")
    else:
        # Fallback: ThreadPool
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(resolve_one, sub): sub for sub in to_check}
            for future in concurrent.futures.as_completed(futures):
                done += 1
                if done % 200 == 0:
                    print(f"\r  {c_fn(str(done),'cyan')}/{len(to_check)} checked, found: {c_fn(str(len(new_found)),'green')}     ", end="", flush=True)
                result = future.result()
                if result:
                    sub, ips = result
                    if sub not in found:
                        new_found.add(sub)
                        ctx["resolved"][sub] = ips
        print()

    ctx["found_subs"].update(new_found)
    ctx["source_map"]["WordCloud Mutations"] = new_found
    log(f"  WordCloud: {c_fn(str(len(new_found)),'green')} новых из smart mutations")

    # Save WordCloud for persistence
    cloud_dir = Path("wordclouds")
    cloud_dir.mkdir(exist_ok=True)
    cloud_file = cloud_dir / f"{domain.replace('.','_')}.json"
    try:
        # Merge with existing if present
        existing = {}
        if cloud_file.exists():
            existing = json.loads(cloud_file.read_text())
        for word, count in cloud.items():
            existing[word] = existing.get(word, 0) + count
        cloud_file.write_text(json.dumps(existing, indent=2, ensure_ascii=False))
        log(f"  WordCloud saved: {c_fn(str(cloud_file),'cyan')}")
    except Exception:
        pass
