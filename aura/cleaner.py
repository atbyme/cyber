import re
import logging
from typing import Dict, List, Optional

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


MIN_DESC_LENGTH = 20
MAX_DESC_LENGTH = 5000


def is_valid_entry(entry: Dict) -> bool:
    text = entry.get("description") or entry.get("name") or ""
    if len(text) < MIN_DESC_LENGTH:
        return False
    if len(text) > MAX_DESC_LENGTH:
        entry["description"] = text[:MAX_DESC_LENGTH]
    return True


def is_noise(text: str) -> bool:
    noise_patterns = [
        r"^\s*$",
        r"^[0-9\s]+$",
        r"^(N/A|n/a|NA|na|None|null|undefined|-)$",
        r"^(TBD|tbd|TODO|todo)$",
    ]
    for pat in noise_patterns:
        if re.match(pat, text.strip()):
            return True
    return False


def deduplicate(entries: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for e in entries:
        dedup_key = str(e.get("id", "")) or str(e.get("ioc", "")) or str(e.get("url", "")) or e.get("name", "")
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
        if is_valid_entry(entry):
            cleaned.append(entry)
    cleaned = deduplicate(cleaned)
    logger.info(f"Cleaned: {len(entries)} -> {len(cleaned)} entries after filter+dedup")
    return cleaned


def format_for_training(entries: List[Dict]) -> List[Dict]:
    samples = []
    for entry in entries:
        source = entry.get("source", "unknown")
        etype = entry.get("type", "unknown")
        desc = entry.get("description") or entry.get("name") or ""
        ioc = entry.get("ioc", "")
        cvss = entry.get("cvss_score")

        if etype == "cve":
            instruction = f"Analyze this CVE threat: {entry.get('id', '')}"
            response = f"CVE {entry.get('id', '')}: {desc}"
            if cvss:
                response += f"\nCVSS Score: {cvss}"
            response += f"\nSource: {source}"
        elif etype == "ioc":
            instruction = f"Analyze this threat indicator: {ioc}"
            response = f"Indicator: {ioc}\nThreat: {entry.get('threat_type', 'unknown')}\nMalware: {entry.get('malware', 'unknown')}\nSource: {source}"
        else:
            instruction = f"Analyze this cyber threat: {entry.get('name', desc[:80])}"
            response = f"Threat: {desc}\nTags: {', '.join(entry.get('tags', []))}\nSource: {source}"

        samples.append({"instruction": instruction, "response": response, "source": source})
    return samples
