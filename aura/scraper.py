import json
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

from .config import DATA_DIR, get

logger = logging.getLogger("AURA.Scraper")
ua = UserAgent()


def _cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def _cached_or_fetch(url: str, ttl_hours: int = 6) -> Optional[dict]:
    cache_file = DATA_DIR / f"{_cache_key(url)}.json"
    if cache_file.exists():
        age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
        if age < timedelta(hours=ttl_hours):
            with open(cache_file) as f:
                return json.load(f)
    try:
        headers = {"User-Agent": ua.random}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json() if "application/json" in resp.headers.get("Content-Type", "") else {"raw": resp.text}
        with open(cache_file, "w") as f:
            json.dump(data, f)
        return data
    except Exception as e:
        logger.warning(f"Fetch failed for {url}: {e}")
        return None


def scrape_nvd(cves_since_days: int = 7) -> List[Dict]:
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        + urlencode({"pubStartDate": (datetime.utcnow() - timedelta(days=cves_since_days)).strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 50})
    )
    data = _cached_or_fetch(url)
    if not data or "vulnerabilities" not in data:
        return []
    results = []
    for item in data["vulnerabilities"]:
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(version):
                cvss = metrics[version][0].get("cvssData", {}).get("baseScore")
                break
        results.append({
            "id": cve.get("id"),
            "description": desc,
            "cvss_score": cvss,
            "published": cve.get("published"),
            "source": "nvd",
            "type": "cve",
        })
    logger.info(f"Scraped {len(results)} CVEs from NVD")
    return results


def scrape_threatfox() -> List[Dict]:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    try:
        headers = {"User-Agent": ua.random}
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning(f"ThreatFox fetch failed: {e}")
        return []
    results = []
    for ioc in data.get("data", []):
        results.append({
            "ioc": ioc.get("ioc"),
            "threat_type": ioc.get("threat_type_desc"),
            "malware": ioc.get("malware"),
            "first_seen": ioc.get("first_seen"),
            "source": "threatfox",
            "type": "ioc",
        })
    logger.info(f"Scraped {len(results)} IOCs from ThreatFox")
    return results


def scrape_alienvault_otx(limit: int = 20) -> List[Dict]:
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={limit}"
    data = _cached_or_fetch(url)
    if not data or "results" not in data:
        return []
    results = []
    for pulse in data["results"]:
        results.append({
            "name": pulse.get("name"),
            "description": pulse.get("description"),
            "tags": [t.get("name") for t in pulse.get("tags", [])],
            "created": pulse.get("created"),
            "source": "alienvault_otx",
            "type": "threat_pulse",
        })
    logger.info(f"Scraped {len(results)} pulses from AlienVault OTX")
    return results


def scrape_urlhaus() -> List[Dict]:
    url = "https://urlhaus.abuse.ch/downloads/text_recent/"
    try:
        headers = {"User-Agent": ua.random}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        lines = resp.text.strip().split("\n")
    except Exception as e:
        logger.warning(f"URLhaus fetch failed: {e}")
        return []
    results = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append({
            "url": line,
            "source": "urlhaus",
            "type": "malicious_url",
        })
    logger.info(f"Scraped {len(results)} URLs from URLhaus")
    return results


def scrape_cyber_threats() -> List[Dict]:
    all_data = []
    all_data.extend(scrape_nvd())
    all_data.extend(scrape_threatfox())
    all_data.extend(scrape_alienvault_otx())
    all_data.extend(scrape_urlhaus())
    logger.info(f"Total scraped: {len(all_data)} threat entries")
    return all_data
