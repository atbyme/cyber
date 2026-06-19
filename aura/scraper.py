import json
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests
from fake_useragent import UserAgent

from .config import DATA_DIR

logger = logging.getLogger("AURA.Scraper")
ua = UserAgent()

THREAT_SOURCES = {
    "nvd": "NVD CVEs",
    "threatfox": "ThreatFox IOCs",
    "alienvault_otx": "AlienVault OTX",
    "urlhaus": "URLhaus Malicious URLs",
    "phishtank": "PhishTank Phishing",
    "cisa_kev": "CISA Known Exploited Vulns",
    "feodo": "Feodo Tracker Botnets",
    "sslblacklist": "SSL Blacklist",
    "cyberfeed": "CyberFeed RSS",
    "greynoise": "GreyNoise Quick",
    "crt_sh": "Certificate Transparency",
}


def _cache_get(key: str, max_age_min: int = 5) -> Optional[any]:
    cf = DATA_DIR / f"{key}.cache"
    if cf.exists():
        age = datetime.now() - datetime.fromtimestamp(cf.stat().st_mtime)
        if age < timedelta(minutes=max_age_min):
            with open(cf) as f:
                return json.load(f)
    return None


def _cache_set(key: str, data: any):
    cf = DATA_DIR / f"{key}.cache"
    DATA_DIR.mkdir(exist_ok=True)
    with open(cf, "w") as f:
        json.dump(data, f)


def _fetch_json(url: str, method: str = "GET", payload: dict = None, max_age: int = 5) -> Optional[any]:
    key = hashlib.md5(url.encode()).hexdigest()
    cached = _cache_get(key, max_age)
    if cached:
        return cached
    try:
        h = {"User-Agent": ua.random, "Accept": "application/json"}
        if method == "POST":
            r = requests.post(url, json=payload, headers=h, timeout=20)
        else:
            r = requests.get(url, headers=h, timeout=20)
        r.raise_for_status()
        data = r.json()
        _cache_set(key, data)
        return data
    except Exception as e:
        logger.debug(f"Fetch fail [{url[:50]}]: {e}")
        return None


def _fetch_text(url: str, max_age: int = 5) -> Optional[str]:
    key = "txt_" + hashlib.md5(url.encode()).hexdigest()
    cached = _cache_get(key, max_age)
    if cached:
        return cached["text"]
    try:
        r = requests.get(url, headers={"User-Agent": ua.random}, timeout=20)
        r.raise_for_status()
        text = r.text
        _cache_set(key, {"text": text})
        return text
    except Exception as e:
        logger.debug(f"Text fetch fail [{url[:50]}]: {e}")
        return None


def scrape_nvd() -> List[Dict]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({
        "pubStartDate": (datetime.utcnow() - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    })
    data = _fetch_json(url, max_age=30)
    if not data or "vulnerabilities" not in data:
        return []
    results = []
    for item in data["vulnerabilities"]:
        cve = item.get("cve", {})
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metrics.get(ver):
                cvss = metrics[ver][0].get("cvssData", {}).get("baseScore")
                break
        results.append({"id": cve.get("id"), "description": desc, "cvss_score": cvss, "published": cve.get("published"), "source": "nvd", "type": "cve"})
    return results


def scrape_threatfox() -> List[Dict]:
    data = _fetch_json("https://threatfox-api.abuse.ch/api/v1/", "POST", {"query": "get_iocs", "days": 1}, max_age=3)
    if not data:
        return []
    return [{"ioc": i.get("ioc"), "threat_type": i.get("threat_type_desc"), "malware": i.get("malware"), "first_seen": i.get("first_seen"), "source": "threatfox", "type": "ioc"} for i in data.get("data", [])]


def scrape_alienvault() -> List[Dict]:
    data = _fetch_json("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", max_age=15)
    if not data or "results" not in data:
        return []
    return [{"name": p.get("name"), "description": p.get("description"), "tags": [t.get("name") for t in p.get("tags", [])], "created": p.get("created"), "source": "alienvault_otx", "type": "threat_pulse"} for p in data["results"]]


def scrape_urlhaus() -> List[Dict]:
    text = _fetch_text("https://urlhaus.abuse.ch/downloads/text_recent/", max_age=3)
    if not text:
        return []
    return [{"url": line.strip(), "source": "urlhaus", "type": "malicious_url"} for line in text.split("\n") if line.strip() and not line.startswith("#")][:100]


def scrape_phishtank() -> List[Dict]:
    text = _fetch_text("https://data.phishtank.com/data/online-valid.csv", max_age=10)
    if not text:
        return []
    results = []
    for line in text.split("\n")[1:81]:
        parts = line.split(",")
        if len(parts) >= 2:
            results.append({"url": parts[1].strip('"'), "source": "phishtank", "type": "phishing_url"})
    return results


def scrape_cisa_kev() -> List[Dict]:
    data = _fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", max_age=60)
    if not data or "vulnerabilities" not in data:
        return []
    return [{"id": v.get("cveID"), "description": v.get("shortDescription"), "date_added": v.get("dateAdded"), "source": "cisa_kev", "type": "known_exploit"} for v in data["vulnerabilities"]]


def scrape_feodo() -> List[Dict]:
    text = _fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", max_age=5)
    if not text:
        return []
    return [{"ioc": line.strip(), "source": "feodo", "type": "botnet_c2"} for line in text.split("\n") if line.strip() and not line.startswith("#")]


def scrape_sslblacklist() -> List[Dict]:
    text = _fetch_text("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", max_age=10)
    if not text:
        return []
    return [{"ioc": line.strip(), "source": "sslblacklist", "type": "malicious_ssl"} for line in text.split("\n") if line.strip() and not line.startswith("#")]


def scrape_crtsh() -> List[Dict]:
    data = _fetch_json("https://crt.sh/?q=%25&output=json&limit=30", max_age=30)
    if not data:
        return []
    return [{"id": c.get("id"), "issuer": c.get("issuer_name"), "cn": c.get("common_name"), "not_after": c.get("not_after"), "source": "crt_sh", "type": "certificate"} for c in data if isinstance(c, dict)]


def scrape_cyberfeed() -> List[Dict]:
    try:
        h = {"User-Agent": ua.random}
        r = requests.get("https://cyberfeed.io/feed", headers=h, timeout=10)
        if r.status_code == 200:
            items = r.json().get("items", []) if "application/json" in r.headers.get("Content-Type", "") else []
            return [{"title": i.get("title"), "description": i.get("description"), "source": "cyberfeed", "type": "news"} for i in items[:20]]
    except:
        pass
    return []


def scrape_all() -> List[Dict]:
    all_data = []
    scrapers = [
        ("threatfox", scrape_threatfox),
        ("urlhaus", scrape_urlhaus),
        ("phishtank", scrape_phishtank),
        ("feodo", scrape_feodo),
        ("sslblacklist", scrape_sslblacklist),
        ("alienvault", scrape_alienvault),
        ("nvd", scrape_nvd),
        ("cisa_kev", scrape_cisa_kev),
        ("crtsh", scrape_crtsh),
        ("cyberfeed", scrape_cyberfeed),
    ]
    for name, fn in scrapers:
        try:
            data = fn()
            if data:
                all_data.extend(data)
                logger.info(f"  {name}: {len(data)} items")
        except Exception as e:
            logger.debug(f"  {name} failed: {e}")
    logger.info(f"Total: {len(all_data)} threats from {len(THREAT_SOURCES)} sources")
    return all_data


def get_source_stats(data: List[Dict]) -> Dict[str, int]:
    s = {}
    for item in data:
        src = item.get("source", "unknown")
        s[src] = s.get(src, 0) + 1
    return s
