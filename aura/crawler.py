import json
import logging
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

logger = logging.getLogger("AURA.Crawler")
ua = UserAgent()

THREAT_KEYWORDS = [
    "malware", "cve-", "exploit", "phishing", "ransomware", "trojan",
    "backdoor", "0day", "shellcode", "botnet", "ddos", "vulnerability",
    "payload", "injection", "xss", "sql injection", "credential",
    "spyware", "keylogger", "rootkit", "worm", "dropper", "loader",
    "infostealer", "rat", "c2", "command and control", "ioc",
    "indicator of compromise", "threat", "attack", "breach", "leak",
    "darknet", "dark web", "hacker", "cyber", "security advisory",
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r'https?://[^\s"\'<>]+')


def extract_links(html: str, base_url: str) -> List[str]:
    links = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("http"):
                links.append(href)
            elif href.startswith("/") or href.startswith("?"):
                links.append(urljoin(base_url, href))
    except:
        for m in URL_RE.findall(html):
            links.append(m)
    return links


def extract_threat_indicators(html: str, url: str) -> Dict:
    text = html.lower()
    found = [kw for kw in THREAT_KEYWORDS if kw in text]
    ips = list(IP_RE.findall(text))
    domains = [d for d in DOMAIN_RE.findall(text) if len(d) > 3 and not d.startswith(".")]
    urls = URL_RE.findall(text)
    return {
        "threat_keywords": found,
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "urls": list(set(urls)),
    }


def crawl_page(url: str, depth: int = 1, max_pages: int = 50, visited: Optional[Set] = None) -> List[Dict]:
    if visited is None:
        visited = set()
    results = []
    to_visit = [(url, 0)]

    while to_visit and len(results) < max_pages:
        current_url, current_depth = to_visit.pop(0)
        if current_url in visited or len(results) >= max_pages:
            continue
        visited.add(current_url)

        try:
            headers = {"User-Agent": ua.random, "Accept": "text/html,application/xhtml+xml"}
            time.sleep(random.uniform(0.3, 1.5))
            r = requests.get(current_url, headers=headers, timeout=10, allow_redirects=True)
            if r.status_code != 200:
                continue

            indicators = extract_threat_indicators(r.text, current_url)
            has_threats = len(indicators["threat_keywords"]) > 0 or len(indicators["ips"]) > 0 or len(indicators["domains"]) > 0

            result = {
                "url": current_url,
                "status": r.status_code,
                "depth": current_depth,
                "content_length": len(r.text),
                "title": extract_title(r.text),
                "threat_keywords": indicators["threat_keywords"],
                "ips_found": len(indicators["ips"]),
                "domains_found": len(indicators["domains"]),
                "urls_found": len(indicators["urls"]),
                "has_threats": has_threats,
                "threat_score": len(indicators["threat_keywords"]) + len(indicators["ips"]) + len(indicators["domains"]),
                "source": "web_crawl",
                "type": "crawl_result",
            }
            results.append(result)

            if has_threats and current_depth < depth and len(results) < max_pages:
                links = extract_links(r.text, current_url)
                for link in links[:20]:
                    if link not in visited:
                        to_visit.append((link, current_depth + 1))

            if len(results) % 10 == 0:
                logger.info(f"  CRAWL progress: {len(results)} pages, depth={current_depth}")

        except Exception as e:
            logger.debug(f"Crawl skip {current_url[:60]}: {e}")

    return results


def extract_title(html: str) -> str:
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def extract_targets(threats: List[Dict], max_urls: int = 200, max_domains: int = 500) -> tuple:
    urls = set()
    domains = set()
    ips = set()
    for item in threats:
        for f in ("url", "ioc", "description", "instruction", "response"):
            v = item.get(f, "")
            if isinstance(v, str):
                for u in URL_RE.findall(v):
                    urls.add(u)
                for d in DOMAIN_RE.findall(v):
                    if len(d) > 3 and not d.startswith("."):
                        domains.add(d)
                for ip in IP_RE.findall(v):
                    ips.add(ip)
    return list(urls)[:max_urls], list(domains)[:max_domains]


def crawl_targets(urls: List[str], domains: List[str], max_workers: int = 20, max_pages: int = 200) -> List[Dict]:
    all_results = []
    targets = urls + [f"https://{d}" for d in domains]
    random.shuffle(targets)
    targets = targets[:max_pages]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(crawl_page, t, depth=1, max_pages=5): t for t in targets}
        for f in as_completed(fut):
            try:
                results = f.result()
                all_results.extend(results)
            except Exception as e:
                logger.debug(f"Crawl batch fail: {e}")

    # Sort by threat score descending, deduplicate by URL
    seen = set()
    unique = []
    for r in sorted(all_results, key=lambda x: x.get("threat_score", 0), reverse=True):
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)

    logger.info(f"Crawler: {len(targets)} targets → {len(all_results)} pages → {len(unique)} unique (threat filtered)")
    return unique


def format_crawl_for_training(crawl_results: List[Dict]) -> List[Dict]:
    samples = []
    for r in crawl_results:
        if not r.get("has_threats"):
            continue
        keywords = ", ".join(r.get("threat_keywords", [])[:10])
        instruction = f"Analyze this crawled threat page: {r['url']}"
        response = f"URL: {r['url']}\nTitle: {r.get('title', '')}\nThreat Indicators: {keywords}\nThreat Score: {r.get('threat_score', 0)}\nIPs Found: {r.get('ips_found', 0)}\nDomains Found: {r.get('domains_found', 0)}\nSource: web_crawl"
        samples.append({"instruction": instruction, "response": response, "source": "web_crawl"})
    return samples
