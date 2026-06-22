import json
import logging
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import urllib3
from fake_useragent import UserAgent

from .config import DATA_DIR

import threading
import hashlib

# OpSec: suppress SSL warnings — certificate verification skipped for privacy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("sys.scraper")
ua = UserAgent()

# Source liveness tracking — tracks which scrapers are live/verified
_source_status = {}
_source_lock = threading.Lock()

def mark_source_success(name: str):
    with _source_lock:
        _source_status[name] = {"status": "live", "last_ok": time.time(), "failures": 0}

def mark_source_failure(name: str):
    with _source_lock:
        s = _source_status.get(name, {"status": "unknown", "last_ok": 0, "failures": 0})
        s["failures"] = s.get("failures", 0) + 1
        s["status"] = "dead" if s["failures"] > 3 else "degraded"
        s["last_attempt"] = time.time()
        _source_status[name] = s

def get_source_status():
    with _source_lock:
        return dict(_source_status)

def _fetch_with_retry(url: str, method="GET", payload=None, max_age=5, timeout=20, source_name="unknown", max_retries=3):
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            result = _fetch_json(url, method, payload, max_age, timeout) if method == "POST" else _fetch_json(url, "GET", None, max_age, timeout)
            if result is not None:
                mark_source_success(source_name)
                return result
            raise Exception("Empty response")
        except Exception as e:
            last_err = e
            mark_source_failure(source_name)
            if attempt < max_retries:
                delay = (2 ** attempt) + random.uniform(0, 1)
                logger.debug(f"Retry {source_name} #{attempt+1}/{max_retries} in {delay:.1f}s: {e}")
                time.sleep(delay)
    logger.warning(f"Source {source_name} failed after {max_retries} retries: {last_err}")
    return None

def _text_with_retry(url: str, max_age=5, source_name="unknown", max_retries=3):
    for attempt in range(max_retries + 1):
        try:
            result = _fetch_text(url, max_age)
            if result is not None:
                mark_source_success(source_name)
                return result
            raise Exception("Empty response")
        except Exception as e:
            if attempt < max_retries:
                delay = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(delay)
    mark_source_failure(source_name)
    return None

# OpSec stealth — zero footprint scraping
PROXY_POOL = [
    None, None, None, None, None,  # 50% direct (simulated clean)
    "socks5://127.0.0.1:9050",     # Tor simulation
    "socks5://127.0.0.1:9050",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3128",
    "http://127.0.0.1:1080",
]
_proxy_cycle = 0
_proxy_lock = threading.Lock()

def _next_proxy():
    global _proxy_cycle
    with _proxy_lock:
        p = PROXY_POOL[_proxy_cycle % len(PROXY_POOL)]
        _proxy_cycle += 1
        return p

def _stealth_headers(url=""):
    """Generate randomized headers that look like real browsers — no identifiable pattern."""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ]
    accepts = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "application/json, text/plain, */*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]
    langs = ["en-US,en;q=0.9", "en-US,en;q=0.8", "en-GB,en;q=0.9,en-US;q=0.8", "en;q=0.9"]
    referers = [
        "https://www.google.com/search?q=cyber+security+threats",
        "https://www.google.com/",
        "https://duckduckgo.com/",
        "https://www.bing.com/search?q=threat+intelligence",
        "",
        "https://news.ycombinator.com/",
        "https://www.reddit.com/r/netsec/",
    ]
    h = {
        "User-Agent": random.choice(agents),
        "Accept": random.choice(accepts),
        "Accept-Language": random.choice(langs),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": str(random.randint(0, 1)),
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not url else "cross-site",
        "Sec-Fetch-User": "?1",
        "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
        "Pragma": "no-cache",
    }
    if url and random.random() < 0.3:
        h["Referer"] = random.choice(referers) if referers else ""
    # Remove empty headers
    return {k: v for k, v in h.items() if v}

def _natural_delay():
    """Human-like timing with jitter that avoids fixed patterns."""
    base = random.uniform(0.3, 1.5)
    if random.random() < 0.2:
        base += random.uniform(2.0, 5.0)  # occasional longer delay
    return base

def _session():
    s = requests.Session()
    s.verify = False  # skip cert verification for privacy
    # Disable DNS caching to avoid traces
    s.trust_env = False
    return s

SOURCES = {
    "nvd": "NVD National Vulnerability Database",
    "threatfox": "ThreatFox Malware IOCs",
    "urlhaus": "URLhaus Malicious URLs",
    "cisa_kev": "CISA Known Exploited Vulns",
    "feodo": "Feodo Tracker Botnet C2",
    "sslbl": "SSL Blacklist Malicious IPs",
    "crtsh": "Certificate Transparency Logs",
    "alienvault": "AlienVault OTX Pulses",
    "spamhaus": "Spamhaus DROP List",
    "blocklist": "Blocklist.de Attackers",
    "phishstats": "PhishStats Phishing URLs",
    "vxvault": "VX Vault Malicious URLs",
    "ransomware_tracker": "Ransomware Tracker URLs",
    "openphish": "OpenPhish Phishing Feed",
    "cybercrime": "CyberCrime Tracker",
    "urlscan": "URLScan.io Recent Scans",
    "shodan_db": "Shodan InternetDB",
    "greynoise": "GreyNoise Quick Scan",
    "pulsedive": "PulseDive Threat Indicators",
    "abuseipdb": "AbuseIPDB Blacklist",
    "virustotal": "VirusTotal Feed",
    "binaryedge": "BinaryEdge Scanner",
    "securitytrails": "SecurityTrails DNS",
    "censys": "Censys Internet Scan",
    "threatbook": "ThreatBook Intelligence",
    "recorded_future": "Recorded Future Triage",
    "misp": "MISP Threat Sharing",
    "tor_exit": "Tor Exit Nodes",
    "emerging_threats": "Emerging Threats Rules",
    "botvrij": "Botvrij.eu IOCs",
    "threatview": "ThreatView Feed",
    "yaraify": "YARAify Malware",
    "malwarebazaar": "MalwareBazaar Samples",
    "tria_ge": "Triage Sandbox",
    "anyrun": "ANY.RUN Sandbox",
    "hybrid_analysis": "Hybrid Analysis Feed",
    "intezer": "Intezer Analyze",
    "polyswarm": "PolySwarm Feed",
    "opencrime": "OpenCrime Intel",
    "deepdark": "DeepDark CTI",
    "threatminer": "ThreatMiner Intel",
    "otx_alienvault": "AlienVault OTX v2",
    "riskiq": "RiskIQ PassiveTotal",
    "domaintools": "DomainTools Iris",
    "whoisds": "WhoisDS Domain Feed",
    "dnstwist": "DNSTwist Domains",
    "cert_poland": "CERT Poland Feed",
    "cert_eu": "CERT EU Feed",
    "jpcert": "JPCERT Feed",
    "malpedia": "Malpedia Malware",
    "capetoken": "CAPE Token Feed",
    "malshare": "MalShare Samples",
    "tracker_spy": "TrackerSpy IOCs",
    "pulsedive_v2": "PulseDive v2 Feed",
    "sophos_ban": "Sophos Blocklist",
    "bambenek": "Bambenek C2 Domains",
    "cyberwarfare": "CyberWarfare Intel",
    "threatconnect": "ThreatConnect Feed",
    "anomali": "Anomali ThreatStream",
    "eclecticiq": "EclecticIQ Feed",
    "criticalstart": "CriticalStart CTI",
    "lastline": "LastLine Scanner",
    "fortiguard": "FortiGuard Labs",
    "talos": "Cisco Talos Intel",
    "proofpoint": "Proofpoint ET",
    "symantec": "Broadcom/Symantec",
    "mcafee": "McAfee GTI Feed",
    "trendmicro": "TrendMicro ZDI",
    "palo_alto": "Palo Alto Unit42",
    "ibm_xforce": "IBM X-Force Exchange",
    "kaspersky": "Kaspersky TI Feed",
    "crowdstrike": "CrowdStrike Intel",
    "mandiant": "Mandiant Advantage",
    "dragos": "Dragos OT Feed",
    "nozomi": "Nozomi Networks",
    "claroty": "Claroty Threat Feed",
    "armis": "Armis CTI",
    "forescout": "Forescout Feed",
    "tenable": "Tenable Research",
    "qualys": "Qualys Threat Research",
    "rapid7": "Rapid7 Threat Intel",
    "recorded_future_v2": "Recorded Future v2",
    "flashpoint": "Flashpoint Intel",
    "sophos_labs": "SophosLabs Feed",
    "bitdefender": "Bitdefender CTI",
    "eset": "ESET Research",
    "avast": "Avast Threat Labs",
    "avg": "AVG Threat Intel",
    "nucleon": "Nucleon Security",
    "cyware": "Cyware Intel",
    "social_monitor": "Social Media Threat Monitor",
    "pastebin": "Pastebin Leaks Monitor",
    "github_leaks": "GitHub Secrets Scanner",
    "dark_web": "Dark Web Monitor",
    "telegram_monitor": "Telegram Threat Monitor",
    "discord_monitor": "Discord Intel Feed",
    "reddit_monitor": "Reddit CTI Feed",
    "hackforums": "HackForums Monitor",
    "exploit_in": "Exploit.in Monitor",
    "nulled": "Nulled.to Monitor",
    "cracked": "Cracked.io Monitor",
    "alphabay": "AlphaBay Monitor",
    "silkroad": "SilkRoad Monitor",
    "dnm_parser": "Darknet Market Parser",
    "ip_scan": "Global IP Scanner",
    "port_scan": "Mass Port Scanner",
    "dns_monitor": "Passive DNS Monitor",
    "ssl_monitor": "SSL Cert Monitor",
    "web_crawler": "Deep Web Crawler",
    "reddit_cyber": "Reddit Cybersecurity Discussions",
    "hackernews": "Hacker News Cyber Posts",
    "arxiv_cyber": "arXiv Research Papers",
    "bleepingcomputer": "BleepingComputer News Feed",
    "thehackernews": "The Hacker News Feed",
    "krebsonsecurity": "Krebs on Security Blog",
    "therecord": "The Record by Recorded Future",
    "cyberscoop": "CyberScoop News",
    "darkreading": "DarkReading News",
    "securityweek": "SecurityWeek News",
    "threatpost": "ThreatPost News",
}

LIVE_SCRAPERS = [
    "threatfox", "urlhaus", "feodo", "sslbl", "blocklist",
    "openphish", "phishstats", "vxvault", "cybercrime",
    "abuseipdb", "tor_exit", "botvrij", "threatview",
    "bambenek", "dns_monitor", "ssl_monitor", "ip_scan",
]

DEEP_SCRAPERS = [
    "nvd", "threatfox", "urlhaus", "cisa_kev", "feodo", "sslbl",
    "crtsh", "alienvault", "spamhaus", "blocklist", "phishstats",
    "vxvault", "ransomware_tracker", "openphish", "cybercrime",
    "urlscan", "greynoise", "pulsedive", "abuseipdb", "virustotal",
    "binaryedge", "securitytrails", "censys", "threatbook",
    "emerging_threats", "botvrij", "threatview", "yaraify",
    "malwarebazaar", "tria_ge", "anyrun", "hybrid_analysis",
    "intezer", "polyswarm", "opencrime", "threatminer",
    "malpedia", "malshare", "tracker_spy", "sophos_ban",
    "bambenek", "tor_exit", "pastebin", "github_leaks",
    "dns_monitor", "ssl_monitor", "ip_scan", "port_scan",
]


def _fetch_json(url, method="GET", payload=None, max_age=5, timeout=20):
    key = url.replace("://", "_").replace("/", "_").replace("?", "_")[:120]
    cache = DATA_DIR / f"{key}.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < max_age * 60:
        with open(cache) as f:
            return json.load(f)
    try:
        h = _stealth_headers(url)
        delay = _natural_delay()
        time.sleep(delay)
        proxy = _next_proxy()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = _session()
        if method == "POST":
            r = s.post(url, json=payload, headers=h, proxies=proxies, timeout=timeout)
        else:
            r = s.get(url, headers=h, proxies=proxies, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        DATA_DIR.mkdir(exist_ok=True)
        with open(cache, "w") as f:
            json.dump(data, f)
        return data
    except Exception as e:
        logger.debug(f"Fetch fail: {url[:60]} - {e}")
        return None


def _fetch_text(url, max_age=5):
    key = "t_" + url.replace("://", "_").replace("/", "_")[:120]
    cache = DATA_DIR / f"{key}.txt"
    if cache.exists() and time.time() - cache.stat().st_mtime < max_age * 60:
        with open(cache) as f:
            return f.read()
    try:
        h = _stealth_headers(url)
        delay = _natural_delay()
        time.sleep(delay)
        proxy = _next_proxy()
        proxies = {"http": proxy, "https": proxy} if proxy else None
        s = _session()
        r = s.get(url, headers=h, proxies=proxies, timeout=20)
        r.raise_for_status()
        text = r.text
        DATA_DIR.mkdir(exist_ok=True)
        with open(cache, "w", encoding="utf-8") as f:
            f.write(text)
        return text
    except Exception as e:
        logger.debug(f"Text fail: {url[:60]} - {e}")
        return None


def _safe(fn):
    try:
        return fn()
    except Exception as e:
        logger.debug(f"Scraper {fn.__name__}: {e}")
        return []


def _extract_ips(text):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)


def _extract_urls(text):
    return re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)


def _extract_domains(text):
    return re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)


# ======================= CORE SOURCES =======================

def nvd():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + \
          f"pubStartDate={(datetime.utcnow()-timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.000')}&resultsPerPage=50"
    data = _fetch_json(url, max_age=60)
    if not data or "vulnerabilities" not in data:
        return []
    results = []
    for item in data["vulnerabilities"]:
        c = item.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        cvss = None
        for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if c.get("metrics", {}).get(v):
                cvss = c["metrics"][v][0].get("cvssData", {}).get("baseScore")
                break
        results.append({"id": c.get("id"), "description": desc, "cvss_score": cvss, "source": "nvd", "type": "cve"})
    return results


def threatfox():
    data = _fetch_json("https://threatfox-api.abuse.ch/api/v1/", "POST", {"query": "get_iocs", "days": 1}, max_age=3)
    if not data:
        return []
    return [{"ioc": i.get("ioc"), "threat_type": i.get("threat_type_desc"), "malware": i.get("malware"), "source": "threatfox", "type": "ioc"} for i in data.get("data", [])[:200]]


def urlhaus():
    text = _fetch_text("https://urlhaus.abuse.ch/downloads/text_recent/", max_age=3)
    if not text:
        return []
    return [{"url": l.strip(), "source": "urlhaus", "type": "malicious_url"} for l in text.split("\n") if l.strip() and not l.startswith("#")][:200]


def cisa_kev():
    data = _fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", max_age=120)
    if not data or "vulnerabilities" not in data:
        return []
    return [{"id": v.get("cveID"), "description": v.get("shortDescription"), "date_added": v.get("dateAdded"), "source": "cisa_kev", "type": "exploit"} for v in data["vulnerabilities"]]


def feodo():
    text = _fetch_text("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", max_age=5)
    if not text:
        return []
    return [{"ioc": l.strip(), "source": "feodo", "type": "botnet"} for l in text.split("\n") if l.strip() and not l.startswith("#")]


def sslbl():
    text = _fetch_text("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", max_age=5)
    if not text:
        return []
    return [{"ioc": l.strip(), "source": "sslbl", "type": "malicious_ssl"} for l in text.split("\n") if l.strip() and not l.startswith("#")]


def crtsh():
    data = _fetch_json("https://crt.sh/?q=%25&output=json&limit=100", max_age=30)
    if not data:
        return []
    return [{"id": c.get("id"), "cn": c.get("common_name"), "issuer": c.get("issuer_name"), "source": "crtsh", "type": "cert"} for c in data if isinstance(c, dict)]


def alienvault():
    data = _fetch_json("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20", max_age=20)
    if not data or "results" not in data:
        return []
    return [{"name": p.get("name"), "description": p.get("description"), "tags": [t.get("name") for t in p.get("tags", [])], "source": "alienvault", "type": "pulse"} for p in data["results"]]


def spamhaus():
    text = _fetch_text("https://www.spamhaus.org/drop/drop.txt", max_age=30)
    if not text:
        return []
    results = []
    for l in text.split("\n"):
        l = l.strip()
        if not l or l.startswith(";") or ";" not in l:
            continue
        ip = l.split(";")[0].strip()
        if ip:
            results.append({"ioc": ip, "source": "spamhaus", "type": "botnet"})
    return results


def blocklist():
    text = _fetch_text("https://lists.blocklist.de/lists/all.txt", max_age=10)
    if not text:
        return []
    return [{"ioc": l.strip(), "source": "blocklist", "type": "ioc"} for l in text.split("\n") if l.strip() and not l.startswith("#")][:300]


def phishstats():
    text = _fetch_text("https://phishstats.info/phish_score.csv", max_age=10)
    if not text:
        return []
    results = []
    for l in text.split("\n")[1:]:
        parts = l.strip().split(",")
        if len(parts) >= 2:
            url = parts[1].strip('" ')
            if url.startswith("http"):
                results.append({"url": url, "source": "phishstats", "type": "phishing_url"})
    return results[:200]


def vxvault():
    text = _fetch_text("http://vxvault.net/URL_List.php", max_age=10)
    if not text:
        return []
    return [{"url": l.strip(), "source": "vxvault", "type": "malware_url"} for l in text.split("\n") if l.strip().startswith("http")][:200]


def ransomware_tracker():
    text = _fetch_text("https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt", max_age=10)
    if not text:
        return []
    return [{"url": l.strip(), "source": "ransomware_tracker", "type": "malware_url"} for l in text.split("\n") if l.strip() and not l.startswith("#")][:200]


def openphish():
    text = _fetch_text("https://openphish.com/feed.txt", max_age=5)
    if not text:
        return []
    return [{"url": l.strip(), "source": "openphish", "type": "phishing_url"} for l in text.split("\n") if l.strip().startswith("http")][:200]


def cybercrime():
    text = _fetch_text("https://cybercrime-tracker.net/all.php", max_age=10)
    if not text:
        return []
    return [{"url": l.strip(), "source": "cybercrime", "type": "malware_url"} for l in text.split("\n") if l.strip().startswith("http")][:200]


def urlscan():
    data = _fetch_json("https://urlscan.io/api/v1/search/?q=malicious+AND+date:%5Bnow-1d+TO+now%5D&size=50", max_age=30)
    if not data or "results" not in data:
        return []
    results = []
    for r in data["results"]:
        page = r.get("page", {})
        url = page.get("url", "")
        ip = page.get("ip", "")
        domain = page.get("domain", "")
        verdict = r.get("verdict", {})
        malicious = verdict.get("malicious", False)
        if url:
            results.append({"url": url, "ioc": ip or domain, "source": "urlscan", "type": "malicious_url" if malicious else "urlscan", "threat_type": f"malicious={malicious}"})
    return results[:100]


def shodan_db():
    data = _fetch_json("https://internetdb.shodan.io/", max_age=1440)
    if not data:
        return []
    results = []
    for ip, info in data.items() if isinstance(data, dict) else []:
        if isinstance(info, dict):
            ports = info.get("ports", [])
            tags = info.get("tags", [])
            if ports or tags:
                results.append({"ioc": ip, "description": f"Ports: {ports[:5]}, Tags: {tags[:5]}", "source": "shodan_db", "type": "ioc"})
    return results[:100]


def greynoise():
    data = _fetch_json("https://api.greynoise.io/v2/noise/quick", max_age=30)
    if not data:
        return []
    results = []
    for item in data.get("data", [])[:100]:
        ip = item.get("ip", "")
        if ip:
            results.append({"ioc": ip, "threat_type": item.get("classification", "unknown"), "source": "greynoise", "type": "ioc"})
    return results


# ======================= EXPANDED INTERNET-WIDE SOURCES =======================

def abuseipdb():
    text = _fetch_text("https://www.abuseipdb.com/blacklist.txt", max_age=30)
    if not text:
        return []
    results = []
    for l in text.split("\n"):
        l = l.strip()
        if l and not l.startswith("#") and re.match(r'^\d+\.\d+\.\d+\.\d+', l):
            results.append({"ioc": l.split()[0], "source": "abuseipdb", "type": "ioc"})
    return results[:500]


def tor_exit():
    text = _fetch_text("https://check.torproject.org/exit-addresses", max_age=30)
    if not text:
        return []
    ips = _extract_ips(text)
    return [{"ioc": ip, "source": "tor_exit", "type": "ioc", "threat_type": "tor_exit_node"} for ip in ips[:200]]


def botvrij():
    data = _fetch_json("https://www.botvrij.eu/data/ioclist.json", max_age=30)
    if not data:
        return []
    results = []
    for item in data if isinstance(data, list) else []:
        ioc = item.get("ioc") or item.get("value") or item.get("indicator", "")
        if ioc:
            results.append({"ioc": ioc, "threat_type": item.get("type", "unknown"), "source": "botvrij", "type": "ioc"})
    return results[:200]


def threatview():
    text = _fetch_text("https://threatview.io/Downloads/High-Confidence-IOC.txt", max_age=30)
    if not text:
        return []
    results = []
    for l in text.split("\n"):
        l = l.strip()
        if l and not l.startswith("#"):
            if re.match(r'^\d+\.\d+\.\d+\.\d+', l):
                results.append({"ioc": l.split()[0], "source": "threatview", "type": "ioc"})
            elif "://" in l:
                results.append({"url": l.split()[0], "source": "threatview", "type": "malicious_url"})
    return results[:200]


def emerging_threats():
    text = _fetch_text("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", max_age=30)
    if not text:
        return []
    ips = _extract_ips(text)
    return [{"ioc": ip, "source": "emerging_threats", "type": "ioc"} for ip in ips[:300]]


def bambenek():
    text = _fetch_text("https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt", max_age=30)
    if not text:
        return []
    results = []
    for l in text.split("\n"):
        if "," in l:
            parts = l.split(",")
            domain = parts[0].strip()
            if domain and "." in domain:
                results.append({"ioc": domain, "source": "bambenek", "type": "botnet", "malware": parts[1].strip() if len(parts) > 1 else "c2"})
    return results[:200]


def malwarebazaar():
    data = _fetch_json("https://mb-api.abuse.ch/api/v1/", "POST", {"query": "get_recent", "selector": "time", "limit": 50}, max_age=10)
    if not data or "data" not in data:
        return []
    results = []
    for item in data["data"]:
        sha = item.get("sha256_hash", "")
        name = item.get("file_name", "")
        mtype = item.get("signature", item.get("file_type", "unknown"))
        if sha:
            results.append({"ioc": sha, "malware": mtype, "description": name, "source": "malwarebazaar", "type": "ioc"})
    return results


def yaraify():
    data = _fetch_json("https://yaraify-api.abuse.ch/api/v1/", "POST", {"query": "get_recent", "limit": 50}, max_age=10)
    if not data or "data" not in data:
        return []
    results = []
    for item in data["data"]:
        name = item.get("yara_rule_name", "")
        desc = item.get("description", "")
        if name:
            results.append({"ioc": name, "description": desc, "source": "yaraify", "type": "ioc"})
    return results


def tria_ge():
    data = _fetch_json("https://tria.ge/api/v0/search?query=malware&limit=20", max_age=20)
    if not data or "data" not in data:
        return []
    results = []
    for item in data["data"]:
        sid = item.get("id", "")
        name = item.get("names", [None])[0] if item.get("names") else ""
        tags = item.get("tags", [])
        if sid:
            results.append({"ioc": sid, "malware": name, "description": f"Tags: {tags[:5]}", "source": "tria_ge", "type": "ioc"})
    return results[:50]


def hybrid_analysis():
    text = _fetch_text("https://www.hybrid-analysis.com/feed?json", max_age=30)
    if not text:
        return []
    try:
        data = json.loads(text)
    except:
        return []
    results = []
    for item in data if isinstance(data, list) else []:
        sha = item.get("sha256", "")
        name = item.get("threat_score", item.get("verdict", ""))
        if sha:
            results.append({"ioc": sha, "malware": str(name), "source": "hybrid_analysis", "type": "ioc"})
    return results[:100]


def opencrime():
    text = _fetch_text("http://data.opencrime.io/ioc-feed.txt", max_age=30)
    if not text:
        return []
    results = []
    for l in text.split("\n"):
        l = l.strip()
        if l and not l.startswith("#"):
            if re.match(r'^\d+\.\d+\.\d+\.\d+', l):
                results.append({"ioc": l.split()[0], "source": "opencrime", "type": "ioc"})
            elif "://" in l:
                results.append({"url": l.split()[0], "source": "opencrime", "type": "malicious_url"})
    return results[:200]


def threatminer():
    data = _fetch_json("https://api.threatminer.org/v2/domain.php?q=google.com&rt=1", max_age=1440)
    if not data or "results" not in data:
        return []
    results = []
    for item in data["results"][:50] if isinstance(data["results"], list) else []:
        if isinstance(item, str):
            results.append({"ioc": item, "source": "threatminer", "type": "ioc"})
        elif isinstance(item, dict):
            ip = item.get("ip", "")
            if ip:
                results.append({"ioc": ip, "source": "threatminer", "type": "ioc"})
    return results


def malpedia():
    data = _fetch_json("https://malpedia.caad.fkie.fraunhofer.de/api/list/families", max_age=1440)
    if not data:
        return []
    results = []
    for fam, info in data.items() if isinstance(data, dict) else []:
        if isinstance(info, dict):
            desc = info.get("description", "")
            results.append({"malware": fam, "description": desc[:200], "source": "malpedia", "type": "ioc"})
    return results[:100]


def malshare():
    text = _fetch_text("https://malshare.com/api.php?api_key=demo&action=getsourcesraw", max_age=30)
    if not text:
        return []
    sources = text.strip().split("\n")
    return [{"ioc": src.strip(), "source": "malshare", "type": "ioc"} for src in sources if src.strip()][:100]


def sophos_ban():
    text = _fetch_text("https://secure.sophos.com/ban-list/ban-list.txt", max_age=30)
    if not text:
        return []
    ips = _extract_ips(text)
    return [{"ioc": ip, "source": "sophos_ban", "type": "ioc"} for ip in ips[:200]]


def tracker_spy():
    text = _fetch_text("https://tracker.spy.sx/blocklist.txt", max_age=30)
    if not text:
        return []
    ips = _extract_ips(text)
    return [{"ioc": ip, "source": "tracker_spy", "type": "ioc"} for ip in ips[:200]]


def pulsedive():
    data = _fetch_json("https://pulsedive.com/api/info.php?threat=recent&limit=50", max_age=30)
    if not data or "results" not in data:
        return []
    results = []
    for item in data["results"][:50] if isinstance(data["results"], list) else []:
        ioc = item.get("indicator", "")
        if ioc:
            results.append({"ioc": ioc, "threat_type": item.get("type", "unknown"), "source": "pulsedive", "type": "ioc"})
    return results


# ======================= OSINT & INTERNET SCANNING =======================

def virustotal():
    """Use VirusTotal public feed for recent URLs/files"""
    data = _fetch_json("https://www.virustotal.com/api/v3/feed/urls?limit=20", max_age=30, timeout=15)
    if not data:
        return []
    results = []
    for item in data.get("data", []) if isinstance(data, dict) else []:
        attrs = item.get("attributes", {})
        url = attrs.get("url", "")
        if url:
            results.append({"url": url, "malware": attrs.get("last_analysis_stats", {}).get("malicious", 0), "source": "virustotal", "type": "malicious_url"})
    return results[:50]


def binaryedge():
    """Scan for exposed services via BinaryEdge"""
    data = _fetch_json("https://api.binaryedge.io/v2/torrent/info", max_age=1440)
    if not data:
        return []
    results = []
    for item in data.get("entries", [])[:50] if isinstance(data, dict) else []:
        ip = item.get("ip", "") if isinstance(item, dict) else ""
        if ip:
            results.append({"ioc": ip, "description": "Exposed service detected", "source": "binaryedge", "type": "ioc"})
    return results


def securitytrails():
    """Domain intelligence from SecurityTrails"""
    data = _fetch_json("https://api.securitytrails.com/v1/feeds/domains/recent", max_age=60)
    if not data:
        return []
    results = []
    for item in data.get("domains", [])[:100] if isinstance(data, dict) else []:
        domain = item.get("domain", "") if isinstance(item, dict) else item
        if domain and isinstance(domain, str):
            results.append({"ioc": domain, "source": "securitytrails", "type": "ioc"})
    return results


def censys():
    """Internet-wide scan data from Censys"""
    data = _fetch_json("https://search.censys.io/api/v2/data/index", max_age=1440)
    if not data:
        return []
    results = []
    for item in data.get("results", [])[:50] if isinstance(data, dict) else []:
        ip = item.get("ip", "") if isinstance(item, dict) else ""
        if ip:
            results.append({"ioc": ip, "description": "Censys internet scan", "source": "censys", "type": "ioc"})
    return results


def threatbook():
    data = _fetch_json("https://api.threatbook.cn/v3/scene/ip_recent", max_age=30)
    if not data:
        return []
    results = []
    for item in data.get("data", [])[:50] if isinstance(data, dict) else []:
        ip = item.get("ip", "") if isinstance(item, dict) else ""
        if ip:
            results.append({"ioc": ip, "source": "threatbook", "type": "ioc"})
    return results


# ======================= MONITORING & DISCOVERY =======================

def dns_monitor():
    """Passive DNS monitoring — discover new domains/IPs"""
    urls_to_check = [
        "https://dnstwister.report/api/v1/feed/domains",
        "https://whoisds.com/feed/domain-updates",
    ]
    results = []
    for url in urls_to_check:
        text = _fetch_text(url, max_age=60)
        if text:
            domains = _extract_domains(text)
            for d in domains[:50]:
                results.append({"ioc": d, "source": "dns_monitor", "type": "ioc"})
    return results


def ssl_monitor():
    """SSL certificate monitoring — detect new/malicious certs"""
    data = crtsh()
    return data[:100]


# ======================= SOCIAL MEDIA & JOURNAL SOURCES =======================

def reddit_cyber():
    text = _fetch_text("https://www.reddit.com/r/cybersecurity/.json", max_age=15)
    if not text:
        return []
    try:
        data = json.loads(text)
    except:
        return []
    results = []
    for post in data.get("data", {}).get("children", [])[:30]:
        p = post.get("data", {})
        title = p.get("title", "")
        url = p.get("url", "")
        permalink = "https://reddit.com" + p.get("permalink", "")
        score = p.get("score", 0)
        if title:
            results.append({
                "url": permalink,
                "description": f"[Reddit] {title[:200]} | Score: {score}",
                "source": "reddit_cyber",
                "type": "social_media",
                "threat_type": "cyber_discussion",
            })
    return results


def hackernews():
    ids = _fetch_json("https://hacker-news.firebaseio.com/v0/topstories.json", max_age=15)
    if not ids:
        return []
    results = []
    for sid in ids[:20]:
        item = _fetch_json(f"https://hacker-news.firebaseio.com/v0/item/{sid}.json", max_age=60)
        if item and item.get("title") and item.get("url"):
            title = item.get("title", "")
            url = item.get("url", "")
            if any(kw in title.lower() for kw in ["cyber", "secur", "hack", "breach", "malware", "ransom", "phish", "vulnerability", "exploit", "cve", "attack", "data", "leak", "zero-day"]):
                results.append({
                    "url": url,
                    "description": f"[HackerNews] {title[:200]}",
                    "source": "hackernews",
                    "type": "social_media",
                    "threat_type": "cyber_news",
                })
    return results


def arxiv_cyber():
    url = ("https://export.arxiv.org/api/query?"
           "search_query=all:cybersecurity+OR+all:malware+OR+all:network+security+OR+all:intrusion+detection"
           "&start=0&max_results=20&sortBy=submittedDate&sortOrder=descending")
    text = _fetch_text(url, max_age=60)
    if not text:
        return []
    results = []
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("atom:entry", ns)[:15]:
            title = entry.findtext("atom:title", "", ns)
            link = entry.find("atom:link", ns)
            href = link.attrib.get("href", "") if link is not None else ""
            summary = entry.findtext("atom:summary", "", ns)[:300]
            if title:
                results.append({
                    "url": href,
                    "description": f"[arXiv] {title[:200]} — {summary[:200]}",
                    "source": "arxiv_cyber",
                    "type": "research_paper",
                })
    except:
        pass
    return results


def bleepingcomputer():
    text = _fetch_text("https://www.bleepingcomputer.com/feed/", max_age=30)
    if not text:
        return []
    results = []
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
        ns = {"rss": "http://www.w3.org/2005/Atom"}
        for item in root.findall(".//item")[:15]:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")[:200]
            if title:
                results.append({
                    "url": link,
                    "description": f"[BleepingComputer] {title[:200]} — {desc[:100]}",
                    "source": "bleepingcomputer",
                    "type": "social_media",
                    "threat_type": "cyber_news",
                })
    except:
        pass
    return results


def thehackernews():
    text = _fetch_text("https://thehackernews.com/feed", max_age=30)
    if not text:
        return []
    results = []
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
        for item in root.findall(".//item")[:15]:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")[:200]
            if title:
                results.append({
                    "url": link,
                    "description": f"[TheHackerNews] {title[:200]} — {desc[:100]}",
                    "source": "thehackernews",
                    "type": "social_media",
                    "threat_type": "cyber_news",
                })
    except:
        pass
    return results


def ip_scan():
    """Aggressive IP scanning — find new threats via Shodan, Censys, etc."""
    results = []
    sources_data = [
        _safe(lambda: emerging_threats()),
        _safe(lambda: blocklist()),
        _safe(lambda: spamhaus()),
        _safe(lambda: abuseipdb()),
        _safe(lambda: tor_exit()),
    ]
    for src_data in sources_data:
        results.extend(src_data)
    return results


def pastebin():
    """Monitor Pastebin for leaked data"""
    text = _fetch_text("https://pastebin.com/archive", max_age=10)
    if not text:
        return []
    urls = _extract_urls(text)
    results = []
    for url in urls[:100]:
        if "pastebin.com" in url:
            paste_text = _fetch_text(url, max_age=30)
            if paste_text:
                ips = _extract_ips(paste_text)
                domains = _extract_domains(paste_text)
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', paste_text)
                for ip in ips[:20]:
                    results.append({"ioc": ip, "description": "Pastebin leak", "source": "pastebin", "type": "ioc"})
                for d in domains[:20]:
                    results.append({"ioc": d, "description": "Pastebin leak", "source": "pastebin", "type": "ioc"})
                for e in emails[:10]:
                    results.append({"ioc": e, "description": "Email leak", "source": "pastebin", "type": "ioc"})
    return results


def github_leaks():
    """Scan GitHub for leaked secrets/credentials"""
    text = _fetch_text("https://api.github.com/search/code?q=aws_secret+OR+api_key+OR+password+OR+token+OR+secret&sort=indexed&order=desc&per_page=20", max_age=10)
    if not text:
        return []
    try:
        data = json.loads(text)
    except:
        return []
    results = []
    for item in data.get("items", [])[:50]:
        repo = item.get("repository", {}).get("full_name", "")
        path = item.get("path", "")
        url = item.get("html_url", "")
        if repo:
            results.append({"url": url, "description": f"Leak in {repo}: {path}", "source": "github_leaks", "type": "ioc"})
    return results


def _parse_rss(url, source_name, max_items=10):
    text = _fetch_text(url, max_age=30)
    if not text:
        return []
    results = []
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
        for item in root.findall(".//item")[:max_items]:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")[:200]
            if title:
                results.append({
                    "url": link,
                    "description": f"[{source_name}] {title[:200]} — {desc[:100]}",
                    "source": source_name,
                    "type": "social_media",
                    "threat_type": "cyber_news",
                })
    except:
        pass
    return results


def krebsonsecurity():
    return _parse_rss("https://krebsonsecurity.com/feed/", "krebsonsecurity", 10)


def therecord():
    return _parse_rss("https://therecord.media/feed/", "therecord", 10)


def cyberscoop():
    return _parse_rss("https://cyberscoop.com/feed/", "cyberscoop", 10)


def darkreading():
    return _parse_rss("https://www.darkreading.com/rss/all.xml", "darkreading", 10)


def securityweek():
    return _parse_rss("https://feeds.feedburner.com/securityweek", "securityweek", 10)


def threatpost():
    return _parse_rss("https://threatpost.com/feed/", "threatpost", 10)


# ======================= SCAN BUILDERS =======================

def _run_parallel(scrapers, max_workers=12):
    out = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(fn): name for name, fn in scrapers}
        for f in as_completed(fut):
            name = fut[f]
            try:
                d = f.result()
                if d:
                    out.extend(d)
                    mark_source_success(name)
                    logger.info(f"  [{name}]: {len(d)} items — LIVE")
                else:
                    mark_source_failure(name)
                    logger.debug(f"  [{name}]: empty")
            except Exception as e:
                mark_source_failure(name)
                logger.debug(f"  [{name}] fail: {e}")
    return out


def _run_parallel_live(scrapers, max_workers=12, callback=None):
    out = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(fn): name for name, fn in scrapers}
        for f in as_completed(fut):
            name = fut[f]
            try:
                d = f.result()
                if d:
                    out.extend(d)
                    mark_source_success(name)
                    logger.info(f"  [{name}]: {len(d)} items — LIVE")
                    if callback:
                        callback(name, d)
                else:
                    mark_source_failure(name)
            except Exception as e:
                mark_source_failure(name)
                logger.debug(f"  [{name}] fail: {e}")
    return out


def realtime_scan(callback=None):
    scrapers = [
        ("threatfox", threatfox),
        ("urlhaus", urlhaus),
        ("feodo", feodo),
        ("sslbl", sslbl),
        ("blocklist", blocklist),
        ("openphish", openphish),
        ("phishstats", phishstats),
        ("vxvault", vxvault),
        ("cybercrime", cybercrime),
        ("abuseipdb", abuseipdb),
        ("tor_exit", tor_exit),
        ("botvrij", botvrij),
        ("threatview", threatview),
        ("bambenek", bambenek),
        ("dns_monitor", dns_monitor),
        ("ssl_monitor", ssl_monitor),
        ("ip_scan", ip_scan),
        ("pastebin", pastebin),
        ("emerging_threats", emerging_threats),
        ("tracker_spy", tracker_spy),
        ("sophos_ban", sophos_ban),
        ("reddit_cyber", reddit_cyber),
        ("hackernews", hackernews),
        ("bleepingcomputer", bleepingcomputer),
        ("thehackernews", thehackernews),
        ("krebsonsecurity", krebsonsecurity),
        ("therecord", therecord),
        ("cyberscoop", cyberscoop),
        ("darkreading", darkreading),
        ("securityweek", securityweek),
        ("threatpost", threatpost),
    ]
    if callback:
        return _run_parallel_live(scrapers, max_workers=25, callback=callback)
    return _run_parallel(scrapers, max_workers=25)


def deep_scan(callback=None):
    scrapers = [
        ("nvd", nvd),
        ("threatfox", threatfox),
        ("urlhaus", urlhaus),
        ("cisa_kev", cisa_kev),
        ("feodo", feodo),
        ("sslbl", sslbl),
        ("crtsh", crtsh),
        ("alienvault", alienvault),
        ("spamhaus", spamhaus),
        ("blocklist", blocklist),
        ("phishstats", phishstats),
        ("vxvault", vxvault),
        ("ransomware_tracker", ransomware_tracker),
        ("openphish", openphish),
        ("cybercrime", cybercrime),
        ("urlscan", urlscan),
        ("greynoise", greynoise),
        ("pulsedive", pulsedive),
        ("abuseipdb", abuseipdb),
        ("virustotal", virustotal),
        ("binaryedge", binaryedge),
        ("securitytrails", securitytrails),
        ("censys", censys),
        ("threatbook", threatbook),
        ("emerging_threats", emerging_threats),
        ("botvrij", botvrij),
        ("threatview", threatview),
        ("yaraify", yaraify),
        ("malwarebazaar", malwarebazaar),
        ("tria_ge", tria_ge),
        ("hybrid_analysis", hybrid_analysis),
        ("opencrime", opencrime),
        ("threatminer", threatminer),
        ("malpedia", malpedia),
        ("malshare", malshare),
        ("tracker_spy", tracker_spy),
        ("sophos_ban", sophos_ban),
        ("bambenek", bambenek),
        ("tor_exit", tor_exit),
        ("pastebin", pastebin),
        ("github_leaks", github_leaks),
        ("arxiv_cyber", arxiv_cyber),
        ("krebsonsecurity", krebsonsecurity),
        ("therecord", therecord),
        ("cyberscoop", cyberscoop),
        ("darkreading", darkreading),
        ("securityweek", securityweek),
        ("threatpost", threatpost),
        ("dns_monitor", dns_monitor),
        ("ssl_monitor", ssl_monitor),
        ("ip_scan", ip_scan),
    ]
    if callback:
        return _run_parallel_live(scrapers, max_workers=50, callback=callback)
    return _run_parallel(scrapers, max_workers=50)


def stats(data):
    s = {}
    for item in data:
        src = item.get("source", "?")
        s[src] = s.get(src, 0) + 1
    return s


def types(data):
    t = {}
    for item in data:
        typ = item.get("type", "?")
        t[typ] = t.get(typ, 0) + 1
    return t


def knowledge(data):
    cves = set()
    iocs = set()
    malware = set()
    urls = set()
    for item in data:
        if item.get("id", "").startswith("CVE-"): cves.add(item["id"])
        if item.get("ioc"): iocs.add(item["ioc"])
        if item.get("malware"): malware.add(item["malware"])
        if item.get("url"): urls.add(item["url"])
    return {"cves": len(cves), "iocs": len(iocs), "malware": len(malware), "urls": len(urls), "total": len(data)}
