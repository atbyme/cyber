import json
import re
import logging
from typing import Dict, List, Optional, Set
from collections import defaultdict, Counter

logger = logging.getLogger("sys.cleaner")

# ──────────────────────────────────────────────
# RESEARCH-GRADE DATA VERIFICATION ENGINE
# ──────────────────────────────────────────────
# Every threat entry goes through:
#   1. Text cleaning & normalization
#   2. False positive filtering
#   3. Scoring (type, CVSS, IOCs, depth)
#   4. Cross-source verification (same IP/domain seen by 2+ sources = verified)
#   5. Confidence scoring (0-100) for research accuracy
#   6. Deduplication (merge identical records)
#   7. Research metadata tagging

# Source reputation scores (how reliable is each source historically)
SOURCE_REPUTATION = {
    "nvd": 95, "cisa_kev": 95, "malwarebazaar": 92, "threatfox": 90,
    "urlhaus": 88, "alienvault": 85, "spamhaus": 85, "feodo": 83,
    "sslbl": 80, "greynoise": 80, "abuseipdb": 78, "shodan_db": 75,
    "phishstats": 72, "openphish": 70, "ransomware_tracker": 70,
    "emerging_threats": 68, "blocklist": 65, "cybercrime": 62,
    "bambenek": 60, "botvrij": 58, "threatview": 55, "threatminer": 50,
    "crtsh": 45, "vxvault": 40, "openrime": 35, "malpedia": 30,
    "yaraify": 25, "triage": 25, "hybrid_analysis": 25,
    "urlscan": 20, "reddit_cyber": 15, "hackernews": 12,
    "arxiv_cyber": 10, "bleepingcomputer": 10, "thehackernews": 10,
}

# Source reliability tiers for research confidence
SOURCE_TIER = {
    90: "A+", 85: "A", 80: "A-", 75: "B+", 70: "B", 65: "B-",
    60: "C+", 55: "C", 50: "C-", 40: "D", 30: "E", 20: "F", 10: "F-"
}


def get_source_tier(source: str) -> str:
    rep = SOURCE_REPUTATION.get(source, 30)
    for cutoff, tier in sorted(SOURCE_TIER.items(), reverse=True):
        if rep >= cutoff:
            return tier
    return "F"


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def remove_urls(text: str) -> str:
    return re.sub(r"https?://\S+", "", text)


def remove_non_ascii(text: str) -> str:
    return re.sub(r"[^\x00-\x7F]+", " ", text)


def clean_text(text: str) -> str:
    if not text or not isinstance(text, str):
        return ""
    text = strip_html(text)
    text = remove_urls(text)
    text = remove_non_ascii(text)
    text = normalize_whitespace(text)
    return text


MIN_DESC_LENGTH = 10
MAX_DESC_LENGTH = 5000


def is_valid_entry(entry: Dict) -> bool:
    text = entry.get("description") or entry.get("name") or entry.get("ioc") or entry.get("url") or ""
    if not text:
        return True
    if isinstance(text, str) and len(text) > MAX_DESC_LENGTH:
        entry["description"] = text[:MAX_DESC_LENGTH]
    return True


def is_noise(text: str) -> bool:
    noise_patterns = [
        r"^\s*$",
        r"^[0-9\s]+$",
        r"^(N/A|n/a|NA|na|None|null|undefined|-)$",
        r"^(TBD|tbd|TODO|todo)$",
        r"^(localhost|127\.0\.0\.1|0\.0\.0\.0)$",
        r"^[a-zA-Z0-9]{50,}$",
    ]
    for pat in noise_patterns:
        if re.match(pat, text.strip()):
            return True
    return False


def is_known_false_positive(entry: Dict) -> bool:
    text = str(entry.get("ioc", "") or entry.get("url", "") or entry.get("description", ""))
    false_patterns = [
        r"^0\.0\.0\.0",
        r"^127\.\d+",
        r"^192\.168\.",
        r"^10\.\d+",
        r"^172\.1[6-9]\.",
        r"^172\.2[0-9]\.",
        r"^172\.3[0-1]\.",
        r"^::1$",
        r"^test[.-]",
        r"^example\.",
        r"^internal\.",
        r"^localhost",
    ]
    for pat in false_patterns:
        if re.match(pat, text, re.IGNORECASE):
            return True
    return False


def has_valid_ip(text: str) -> Optional[str]:
    m = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", text.strip())
    if m:
        return m.group()
    return None


def has_valid_domain(text: str) -> Optional[str]:
    m = re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", text.strip())
    if m and len(text.strip()) > 3:
        return m.group()
    return None


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


# ──────────────────────────────────────────────
# CROSS-SOURCE VERIFICATION
# ──────────────────────────────────────────────
# This is the AI verification engine: it tracks every IP/domain seen by each source
# and determines which entries are verified by multiple independent sources.
# Entries verified by 2+ sources get "verified" flag and higher confidence.

_verification_cache = {}  # {ioc_or_url: set_of_sources}
_source_ioc_map = defaultdict(set)  # {source: {iocs}}


def reset_verification_cache():
    _verification_cache.clear()
    _source_ioc_map.clear()


def register_entry(entry: Dict):
    """Register an entry's IOCs with their source for cross-verification."""
    source = entry.get("source", "unknown")
    ioc = entry.get("ioc", "")
    url = entry.get("url", "")
    key = ioc or url or ""
    if key and source:
        if key not in _verification_cache:
            _verification_cache[key] = set()
        _verification_cache[key].add(source)
        _source_ioc_map[source].add(key)


def get_verification_status(ioc_or_url: str) -> dict:
    """Check how many sources have seen this IOC/URL and their reputation."""
    sources = _verification_cache.get(ioc_or_url, set())
    if not sources:
        return {"verified": False, "source_count": 0, "sources": [], "confidence": 0}
    reps = [SOURCE_REPUTATION.get(s, 30) for s in sources]
    avg_rep = sum(reps) / len(reps) if reps else 0
    confidence = min(95, int(avg_rep * 0.6 + len(sources) * 8))
    return {
        "verified": len(sources) >= 2,
        "source_count": len(sources),
        "sources": list(sources),
        "confidence": confidence,
        "avg_source_reputation": int(avg_rep),
    }


def score_entry(entry: Dict, verification: Optional[dict] = None) -> int:
    score = 0
    etype = entry.get("type", "")
    source = entry.get("source", "")

    # Type priority
    type_scores = {"cve": 100, "exploit": 90, "ioc": 80, "botnet": 75, "malicious_ssl": 70,
                   "malicious_url": 60, "phishing_url": 55, "malware_url": 50, "pulse": 40,
                   "cert": 30, "crawl_result": 25}
    score += type_scores.get(etype, 10)

    # CVSS bonus
    cvss = entry.get("cvss_score")
    if cvss:
        try:
            cvss_f = float(cvss)
            if cvss_f >= 9.0: score += 50
            elif cvss_f >= 7.0: score += 30
            elif cvss_f >= 4.0: score += 15
            else: score += 5
        except:
            pass

    # Has IOCs
    if entry.get("ioc"):
        score += 20
        if source == "spamhaus": score += 10

    # Has URL
    if entry.get("url"): score += 15

    # Has malware name
    if entry.get("malware"): score += 25

    # Has threat type
    if entry.get("threat_type"): score += 10

    # Description depth
    desc = entry.get("description", "")
    if isinstance(desc, str):
        if len(desc) > 200: score += 20
        elif len(desc) > 50: score += 10

    # Tags
    tags = entry.get("tags", [])
    if tags: score += len(tags) * 5

    # Source reputation bonus (research-grade)
    source_rep = SOURCE_REPUTATION.get(source, 30)
    score += source_rep // 10

    # Cross-source verification bonus
    if verification and verification.get("verified"):
        score += 30  # Verified by 2+ sources = major confidence boost
        score += verification.get("confidence", 0) // 5

    return score


def deduplicate(entries: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for e in entries:
        dedup_key = str(e.get("id", "")) or str(e.get("ioc", "")) or str(e.get("url", "")) or e.get("name", "") or str(e.get("cn", ""))
        if dedup_key and dedup_key not in seen:
            seen.add(dedup_key)
            unique.append(e)
    return unique


def filter_and_clean(entries: List[Dict]) -> List[Dict]:
    cleaned = []
    for entry in entries:
        if "description" in entry:
            entry["description"] = clean_text(entry["description"])
            if is_noise(entry["description"]):
                entry["description"] = ""
        if "name" in entry:
            entry["name"] = clean_text(entry["name"])
        if is_known_false_positive(entry):
            continue
        if is_valid_entry(entry):
            # Register for cross-source verification
            register_entry(entry)
            # Get verification status
            ioc = entry.get("ioc", "")
            url = entry.get("url", "")
            verification = get_verification_status(ioc or url) if (ioc or url) else None
            # Score with verification
            entry["score"] = score_entry(entry, verification)
            # Add research metadata
            if verification:
                entry["verified"] = verification.get("verified", False)
                entry["confidence"] = verification.get("confidence", 0)
                entry["source_count"] = verification.get("source_count", 1)
                entry["avg_source_rep"] = verification.get("avg_source_reputation", 0)
                entry["source_tier"] = get_source_tier(entry.get("source", ""))
                if verification.get("verified"):
                    entry["research_flag"] = "VERIFIED_CROSS_SOURCE"
            else:
                entry["confidence"] = min(80, SOURCE_REPUTATION.get(entry.get("source", ""), 30) + 10)
                entry["source_tier"] = get_source_tier(entry.get("source", ""))
            cleaned.append(entry)

    cleaned = deduplicate(cleaned)
    cleaned.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Keep high-value entries (score >= 15) but keep at least some
    high_value = [e for e in cleaned if e.get("score", 0) >= 10]
    if high_value:
        cleaned = high_value

    # Log verification stats for research
    verified_count = sum(1 for e in cleaned if e.get("verified"))
    total = len(cleaned)
    logger.info(
        f"Cleaner: {len(entries)} -> {total} entries "
        f"[{verified_count} verified by 2+ sources, "
        f"{total - verified_count} single-source]"
    )
    return cleaned


def format_for_training(entries: List[Dict]) -> List[Dict]:
    samples = []
    for entry in entries:
        source = entry.get("source", "unknown")
        etype = entry.get("type", "unknown")
        desc = entry.get("description") or entry.get("name") or ""
        ioc = entry.get("ioc", "")
        url = entry.get("url", "")
        cvss = entry.get("cvss_score")
        verified = entry.get("verified", False)
        confidence = entry.get("confidence", 0)

        # Build research-quality metadata string
        meta = f"Source: {source} (Tier: {entry.get('source_tier', '?')})"
        if verified:
            meta += f" | VERIFIED by {entry.get('source_count', 1)} sources"
        meta += f" | Confidence: {confidence}/100"
        if entry.get("avg_source_rep"):
            meta += f" | Avg Source Rep: {entry['avg_source_rep']}"

        if etype == "cve":
            instruction = f"Analyze this CVE: {entry.get('id', '')}"
            response = f"CVE {entry.get('id', '')}: {desc}" + (f"\nCVSS: {cvss}" if cvss else "") + f"\n{meta}"
        elif etype in ("ioc", "botnet", "malicious_ssl"):
            instruction = f"Analyze this IOC: {ioc}"
            response = f"IOC: {ioc}\nType: {entry.get('threat_type', etype)}\nMalware: {entry.get('malware', 'unknown')}\n{meta}"
        elif etype in ("malicious_url", "phishing_url", "malware_url"):
            instruction = f"Analyze this malicious URL: {url}"
            response = f"Malicious URL: {url}\nType: {etype}\n{meta}"
        elif etype == "exploit":
            instruction = f"Analyze this exploit: {entry.get('id', '')}"
            response = f"Exploit: {entry.get('id', '')}\nDesc: {desc}\nDate: {entry.get('date_added', '')}\n{meta}"
        elif etype == "cert":
            instruction = f"Analyze this certificate: {entry.get('cn', '')}"
            response = f"Certificate: {entry.get('cn', '')}\nIssuer: {entry.get('issuer', '')}\n{meta}"
        elif etype == "crawl_result":
            keywords = ", ".join(entry.get("threat_keywords", [])[:10])
            instruction = f"Analyze this crawled page: {entry.get('url', '')}"
            response = f"URL: {entry.get('url', '')}\nThreats: {keywords}\nScore: {entry.get('threat_score', 0)}\n{meta}"
        else:
            instruction = f"Analyze this threat: {desc[:80]}"
            response = f"Threat: {desc}\nTags: {', '.join(entry.get('tags', []))}\n{meta}"

        samples.append({
            "instruction": instruction,
            "response": response,
            "source": source,
            "score": entry.get("score", 0),
            "confidence": confidence,
            "verified": verified,
        })
    return samples
