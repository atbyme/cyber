import json
import hashlib
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlencode

import requests
from fake_useragent import UserAgent

from .config import DATA_DIR

logger = logging.getLogger("AURA.Scraper")
ua = UserAgent()

PASSIVE_DELAY = (1.0, 3.5)

THREAT_SOURCES = {
    "nvd": "NVD National Vulnerability Database",
    "threatfox": "ThreatFox Malware IOCs",
    "alienvault": "AlienVault OTX Threat Intelligence",
    "urlhaus": "URLhaus Malicious URL Feed",
    "phishtank": "PhishTank Phishing Database",
    "cisa_kev": "CISA Known Exploited Vulnerabilities",
    "feodo": "Feodo Tracker Botnet C2",
    "sslblacklist": "SSL Blacklist Malicious IPs",
    "crtsh": "Certificate Transparency Logs",
    "cyberfeed": "Cyber Security News Feed",
    "greynoise": "GreyNoise Threat Intelligence",
    "abuseipdb": "AbuseIPDB Malicious IPs",
    "misp": "MISP Threat Sharing",
    "vxvault": "VxVault Malware URLs",
    "malwarebazaar": "MalwareBazaar Samples",
    "pulsedive": "PulseDive Threat Indicators",
    "urlscan": "URLScan.io Recent Scans",
    "otx_alienvault": "AlienVault OTX Pulses",
}

REALTIME_SOURCES = ["threatfox", "urlhaus", "phishtank", "feodo", "sslblacklist"]
DEEP_SOURCES = ["nvd", "alienvault", "cisa_kev", "crtsh", "cyberfeed", "malwarebazaar", "vxvault", "pulsedive", "urlscan"]


def _passive_delay():
    time.sleep(random.uniform(*PASSIVE_DELAY))


def _cache(key: str, data: any, age_min: int = 5):
    cf = DATA_DIR / f"{key}.cache"
    DATA_DIR.mkdir(exist_ok=True)
    with open(cf, "w") as f:
        json.dump({"data": data, "ts": time.time()}, f)


def _cache_get(key: str, max_age_min: int = 5) -> Optional[any]:
    cf = DATA_DIR / f"{key}.cache"
    if cf.exists():
        with open(cf) as f:
            c = json.load(f)
            if time.time() - c["ts"] < max_age_min * 60:
                return c["data"]
    return None


def _fetch_json(url: str, method: str = "GET", payload: dict = None, max_age: int = 5, passive: bool = True) -> Optional[any]:
    key = hashlib.md5(url.encode()).hexdigest()
    cached = _cache_get(key, max_age)
    if cached:
        return cached
    try:
        h = {"User-Agent": ua.random, "Accept": "application/json", "Accept-Language": "en-US,en;q=0.9"}
        if passive:
            _passive_delay()
        if method == "POST":
            r = requests.post(url, json=payload, headers=h, timeout=30)
        else:
            r = requests.get(url, headers=h, timeout=30)
        r.raise_for_status()
        data = r.json()
        _cache(key, data, max_age)
        return data
    except Exception as e:
        logger.debug(f"Fetch fail [{url[:50]}]: {e}")
        return None


def _fetch_text(url: str, max_age: int = 5, passive: bool = True) -> Optional[str]:
    key = "txt_" + hashlib.md5(url.encode()).hexdigest()
    cached = _cache_get(key, max_age)
    if cached:
        return cached
    try:
        if passive:
            _passive_delay()
        h = {"User-Agent": ua.random, "Accept-Language": "en-US,en;q=0.9"}
        r = requests.get(url, headers=h, timeout=30)
        r.raise_for_status()
        text = r.text
        _cache(key, text, max_age)
        return text
    except Exception as e:
        logger.debug(f"Text fail [{url[:50]}]: {e}")
        return None


def _safe(fn):
    try:
        return fn()
    except Exception as e:
        logger.debug(f"Scraper {fn.__name__} failed: {e}")
        return []


def scrape_nvd() -> List[Dict]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({
        "pubStartDate": (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    })
    data = _fetch_json(url, max_age=120, passive=True)
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
    data = _fetch_json("https://threatfox-api.abuse.ch/api/v1/", "POST", {"query": "get_iocs", "days": 1}, max_age=2, passive=True)
    if not data:
        return []
    return [{"ioc": i.get("ioc"), "threat_type": i.get("threat_type_desc"), "malware": i.get("malware"), "first_seen": i.get("first_seen"), "source": "threatfox", "type": "ioc"} for i in data.get("data", [])[:150]]


def scrape_alienvault() -> List[Dict]:
    data = _fetch_json("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=40", max_age=30, passive=True)
    if not data or "results" not in data:
        return []
    return [{"name": p.get("name"), "description": p.get("description"), "tags": [t.get("name") for t in p.get("tags", [])], "created": p.get("created"), "source": "alienvault", "type": "threat_pulse"} for p in data["results"]]


def scrape_urlhaus() -> List[Dict]:
    text = _fetch_text("https://urlhaus.abuse.ch/downloads/text_recent/", max_age=2, passive=True)
    if not text:
        return []
    return [{"url": line.strip(), "source": "urlhaus", "type": "malicious_url"} for line in text.split("\n") if line.strip() and not line.startswith("#")][:150]


def scrape_phishtank() -> List[Dict]:
    text = _fetch_text("https://data.phishtank.com/data/online-valid.csv", max_age=5, passive=True)
    if not text:
        return []
    return [{"url": parts[1].strip('"'), "source": "phishtank", "type": "phishing_url"} for line in text.split("\n")[1:101] if len((parts := line.split(","))) >= 2]


def scrape_cisa_kev() -> List[Dict]:
    data = _fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", max_age=120, passive=True)
    if not data or "vulnerabilities" not in data:
        return []
    return [{"id": v.get("cveID"), "description": v.get("shortDescription"), "date_added": v.get("dateAdded"), "source": "cisa_kev", "type": "known_exploit"} for v in data["vulnerabilities"]]


def scrape_feodo() -> List[Dict]:
    text = _fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", max_age=5, passive=True)
    if not text:
        return []
    return [{"ioc": line.strip(), "source": "feodo", "type": "botnet_c2"} for line in text.split("\n") if line.strip() and not line.startswith("#")]


def scrape_sslblacklist() -> List[Dict]:
    text = _fetch_text("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", max_age=5, passive=True)
    if not text:
        return []
    return [{"ioc": line.strip(), "source": "sslblacklist", "type": "malicious_ssl"} for line in text.split("\n") if line.strip() and not line.startswith("#")]


def scrape_crtsh() -> List[Dict]:
    data = _fetch_json("https://crt.sh/?q=%25&output=json&limit=50", max_age=30, passive=True)
    if not data:
        return []
    return [{"id": c.get("id"), "issuer": c.get("issuer_name"), "cn": c.get("common_name"), "not_after": c.get("not_after"), "source": "crt_sh", "type": "certificate"} for c in data if isinstance(c, dict)]


def scrape_cyberfeed() -> List[Dict]:
    try:
        _passive_delay()
        h = {"User-Agent": ua.random}
        r = requests.get("https://cyberfeed.io/feed", headers=h, timeout=15)
        if r.status_code == 200:
            items = r.json().get("items", []) if "application/json" in r.headers.get("Content-Type", "") else []
            return [{"title": i.get("title"), "description": i.get("description"), "source": "cyberfeed", "type": "news"} for i in items[:30]]
    except:
        pass
    return []


def scrape_malwarebazaar() -> List[Dict]:
    data = _fetch_json("https://mb-api.abuse.ch/api/v1/", "POST", {"query": "get_recent", "selector": "time"}, max_age=10, passive=True)
    if not data or "data" not in data:
        return []
    return [{"sha256": s.get("sha256_hash"), "malware": s.get("signature", "unknown"), "first_seen": s.get("first_seen"), "source": "malwarebazaar", "type": "malware_sample"} for s in data["data"][:50]]


def scrape_vxvault() -> List[Dict]:
    text = _fetch_text("http://vxvault.net/URL_List.php", max_age=15, passive=True)
    if not text:
        return []
    return [{"url": line.strip(), "source": "vxvault", "type": "malware_url"} for line in text.split("\n") if line.strip() and line.startswith("http")][:100]


def scrape_pulsedive() -> List[Dict]:
    data = _fetch_json("https://pulsedive.com/api/info.php?indicator=recent", max_age=30, passive=True)
    if not data or "results" not in data:
        return []
    return [{"id": r.get("iid"), "indicator": r.get("indicator"), "type": r.get("type"), "risk": r.get("risk"), "source": "pulsedive", "type": "threat_indicator"} for r in data["results"][:50]]


def scrape_urlscan() -> List[Dict]:
    data = _fetch_json("https://urlscan.io/api/v1/search/?q=malicious&size=30", max_age=15, passive=True)
    if not data or "results" not in data:
        return []
    return [{"url": r.get("page", {}).get("url"), "domain": r.get("page", {}).get("domain"), "ip": r.get("page", {}).get("ip"), "source": "urlscan", "type": "malicious_scan"} for r in data["results"]]


def realtime_scan() -> List[Dict]:
    all_data = []
    scrapers = [
        ("threatfox", scrape_threatfox),
        ("urlhaus", scrape_urlhaus),
        ("phishtank", scrape_phishtank),
        ("feodo", scrape_feodo),
        ("sslblacklist", scrape_sslblacklist),
    ]
    for name, fn in scrapers:
        d = _safe(fn)
        if d:
            all_data.extend(d)
            logger.info(f"  [REALTIME] {name}: {len(d)} items")
    logger.info(f"Realtime scan: {len(all_data)} total")
    return all_data


def deep_research_scan() -> List[Dict]:
    all_data = []
    scrapers = [
        ("nvd", scrape_nvd),
        ("alienvault", scrape_alienvault),
        ("cisa_kev", scrape_cisa_kev),
        ("crtsh", scrape_crtsh),
        ("malwarebazaar", scrape_malwarebazaar),
        ("vxvault", scrape_vxvault),
        ("pulsedive", scrape_pulsedive),
        ("urlscan", scrape_urlscan),
        ("cyberfeed", scrape_cyberfeed),
        ("threatfox", scrape_threatfox),
        ("urlhaus", scrape_urlhaus),
        ("phishtank", scrape_phishtank),
        ("feodo", scrape_feodo),
        ("sslblacklist", scrape_sslblacklist),
    ]
    for name, fn in scrapers:
        d = _safe(fn)
        if d:
            all_data.extend(d)
            logger.info(f"  [DEEP] {name}: {len(d)} items")
    logger.info(f"Deep research scan: {len(all_data)} total from {len(scrapers)} sources")
    return all_data


def get_source_stats(data: List[Dict]) -> Dict[str, int]:
    s = {}
    for item in data:
        src = item.get("source", "unknown")
        s[src] = s.get(src, 0) + 1
    return s


def get_type_breakdown(data: List[Dict]) -> Dict[str, int]:
    b = {}
    for item in data:
        t = item.get("type", "unknown")
        b[t] = b.get(t, 0) + 1
    return b


def extract_knowledge(data: List[Dict]) -> Dict:
    unique_cves = set()
    unique_iocs = set()
    unique_malware = set()
    unique_urls = set()
    for item in data:
        if item.get("id", "").startswith("CVE-"):
            unique_cves.add(item["id"])
        if item.get("ioc"):
            unique_iocs.add(item["ioc"])
        if item.get("malware"):
            unique_malware.add(item["malware"])
        if item.get("url"):
            unique_urls.add(item["url"])
    return {
        "unique_cves": len(unique_cves),
        "unique_iocs": len(unique_iocs),
        "unique_malware": len(unique_malware),
        "unique_urls": len(unique_urls),
        "total_samples": len(data),
    }
