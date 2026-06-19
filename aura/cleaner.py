import json
import re
import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger("AURA.Cleaner")


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


def score_entry(entry: Dict) -> int:
    score = 0
    etype = entry.get("type", "")
    source = entry.get("source", "")

    # Type priority
    type_scores = {"cve": 100, "exploit": 90, "ioc": 80, "botnet": 75, "malicious_ssl": 70,
                   "malicious_url": 60, "phishing_url": 55, "malware_url": 50, "pulse": 40, "cert": 30, "crawl_result": 25}
    score += type_scores.get(etype, 10)

    # CVSS bonus
    cvss = entry.get("cvss_score")
    if cvss:
        try:
            cvss_f = float(cvss)
            if cvss_f >= 9.0:
                score += 50
            elif cvss_f >= 7.0:
                score += 30
            elif cvss_f >= 4.0:
                score += 15
            else:
                score += 5
        except:
            pass

    # Has IOCs
    if entry.get("ioc"):
        score += 20
        if source == "spamhaus":
            score += 10

    # Has URL
    if entry.get("url"):
        score += 15

    # Has malware name
    if entry.get("malware"):
        score += 25

    # Has threat type description
    if entry.get("threat_type"):
        score += 10

    # Description length
    desc = entry.get("description", "")
    if isinstance(desc, str) and len(desc) > 50:
        score += 10
    elif isinstance(desc, str) and len(desc) > 200:
        score += 20

    # Tags
    tags = entry.get("tags", [])
    if tags:
        score += len(tags) * 5

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
            entry["score"] = score_entry(entry)
            cleaned.append(entry)
    cleaned = deduplicate(cleaned)
    cleaned.sort(key=lambda x: x.get("score", 0), reverse=True)

    # Keep only high-value entries (score >= 10) but keep at least some
    high_value = [e for e in cleaned if e.get("score", 0) >= 10]
    if high_value:
        cleaned = high_value

    logger.info(f"Cleaned: {len(entries)} -> {len(cleaned)} entries (scored, deduped, noise removed)")
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

        if etype == "cve":
            instruction = f"Analyze this CVE: {entry.get('id', '')}"
            response = f"CVE {entry.get('id', '')}: {desc}" + (f"\nCVSS: {cvss}" if cvss else "") + f"\nSource: {source}"
        elif etype in ("ioc", "botnet", "malicious_ssl"):
            instruction = f"Analyze this IOC: {ioc}"
            response = f"IOC: {ioc}\nType: {entry.get('threat_type', etype)}\nMalware: {entry.get('malware', 'unknown')}\nSource: {source}"
        elif etype in ("malicious_url", "phishing_url", "malware_url"):
            instruction = f"Analyze this malicious URL: {url}"
            response = f"Malicious URL: {url}\nType: {etype}\nSource: {source}"
        elif etype == "exploit":
            instruction = f"Analyze this exploit: {entry.get('id', '')}"
            response = f"Exploit: {entry.get('id', '')}\nDesc: {desc}\nDate: {entry.get('date_added', '')}\nSource: {source}"
        elif etype == "cert":
            instruction = f"Analyze this certificate: {entry.get('cn', '')}"
            response = f"Certificate: {entry.get('cn', '')}\nIssuer: {entry.get('issuer', '')}\nSource: {source}"
        elif etype == "crawl_result":
            keywords = ", ".join(entry.get("threat_keywords", [])[:10])
            instruction = f"Analyze this crawled page: {entry.get('url', '')}"
            response = f"URL: {entry.get('url', '')}\nThreats: {keywords}\nScore: {entry.get('threat_score', 0)}\nSource: web_crawl"
        else:
            instruction = f"Analyze this threat: {desc[:80]}"
            response = f"Threat: {desc}\nTags: {', '.join(entry.get('tags', []))}\nSource: {source}"

        samples.append({"instruction": instruction, "response": response, "source": source, "score": entry.get("score", 0)})
    return samples
