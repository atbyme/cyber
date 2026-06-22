import asyncio
import json
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from fake_useragent import UserAgent

from .config import DATA_DIR

logger = logging.getLogger("sys.scanner")
ua = UserAgent()

HEADERS = {"User-Agent": ua.random, "Accept": "application/json"}


def _run_cmd(cmd: List[str], timeout: int = 15) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
        return r.stdout
    except Exception as e:
        logger.debug(f"CMD fail {' '.join(cmd[:2])}: {e}")
        return None


def _fetch_json(url: str, max_age: int = 30) -> Optional[dict]:
    key = "ps_" + url.replace("://", "_").replace("/", "_")[:120]
    cache = DATA_DIR / f"{key}.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < max_age * 60:
        with open(cache) as f:
            return json.load(f)
    try:
        time.sleep(0.5)
        r = requests.get(url, headers={"User-Agent": ua.random}, timeout=15)
        r.raise_for_status()
        data = r.json()
        DATA_DIR.mkdir(exist_ok=True)
        with open(cache, "w") as f:
            json.dump(data, f)
        return data
    except Exception as e:
        logger.debug(f"Fetch fail: {url[:60]} - {e}")
        return None


def resolve_dns(domain: str) -> Dict:
    result = {"domain": domain, "ips": [], "ns": [], "mx": [], "txt": []}
    try:
        result["ips"] = list(set(info[4][0] for info in socket.getaddrinfo(domain, 80)))
    except:
        pass
    out = _run_cmd(["nslookup", "-type=ns", domain])
    if out:
        result["ns"] = re.findall(r"nameserver\s*=\s*(\S+)", out.lower()) or re.findall(r"nameserver\s+(\S+)", out)
    out = _run_cmd(["nslookup", "-type=mx", domain])
    if out:
        result["mx"] = re.findall(r"mx\s+preference\s*=\s*\d+,\s*mx\s*=\s*(\S+)", out.lower()) or re.findall(r"mail exchanger\s*=\s*(\S+)", out)
    return result


def passive_dns(domain: str) -> Dict:
    result = {"domain": domain, "subdomains": [], "historical_ips": []}
    data = _fetch_json(f"https://crt.sh/?q=%25.{domain}&output=json&limit=100", max_age=60)
    if data and isinstance(data, list):
        subs = set()
        for c in data:
            name = c.get("common_name", "")
            if name and name.endswith(domain) and name != domain:
                subs.add(name)
        result["subdomains"] = sorted(subs)[:50]
    return result


def whois_lookup(target: str) -> Dict:
    result = {"target": target, "registrar": "", "creation": "", "expiry": "", "org": "", "emails": []}
    out = _run_cmd(["whois", target])
    if out:
        for pat, key in [(r"Registrar:\s*(.+)", "registrar"), (r"Creation Date:\s*(.+)", "creation"),
                         (r"Registry Expiry Date:\s*(.+)", "expiry"), (r"OrgName:\s*(.+)", "org"),
                         (r"Registrant Organization:\s*(.+)", "org"),
                         (r"Registrant Email:\s*(\S+)", "emails")]:
            m = re.search(pat, out, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                if key == "emails":
                    result["emails"].append(val)
                else:
                    result[key] = val
    return result


def ssl_certificate(domain: str, port: int = 443) -> Dict:
    result = {"domain": domain, "port": port, "cn": "", "issuer": "", "valid_from": "", "valid_to": "", "alt_names": []}
    out = _run_cmd(["openssl", "s_client", "-connect", f"{domain}:{port}", "-servername", domain, "-tlsextdebug"], timeout=10)
    if not out:
        return result
    result["cn"] = re.search(r"subject=\s*CN\s*=\s*(\S+)", out)
    result["cn"] = result["cn"].group(1) if result["cn"] else ""
    result["issuer"] = re.search(r"issuer=\s*CN\s*=\s*(\S+)", out)
    result["issuer"] = result["issuer"].group(1) if result["issuer"] else ""
    m = re.search(r"notBefore=(.+)", out)
    result["valid_from"] = m.group(1).strip() if m else ""
    m = re.search(r"notAfter=(.+)", out)
    result["valid_to"] = m.group(1).strip() if m else ""
    alts = re.findall(r"DNS:(\S+)", out)
    result["alt_names"] = list(set(alts))[:20]
    return result


def http_headers(domain: str) -> Dict:
    result = {"domain": domain, "status": 0, "server": "", "tech": [], "security_headers": {}}
    try:
        r = requests.get(f"https://{domain}", headers={"User-Agent": ua.random}, timeout=10, allow_redirects=True)
        result["status"] = r.status_code
        result["server"] = r.headers.get("Server", "")
        h = dict(r.headers)
        sec = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection", "Referrer-Policy"]
        for s in sec:
            if h.get(s):
                result["security_headers"][s] = h[s]
        if "X-Powered-By" in h:
            result["tech"].append(h["X-Powered-By"])
    except Exception as e:
        logger.debug(f"HTTP fail: {domain} - {e}")
    return result


def shodan_internetdb(ip: str) -> Dict:
    data = _fetch_json(f"https://internetdb.shodan.io/{ip}", max_age=120)
    if data:
        return {"ip": ip, "ports": data.get("ports", []), "tags": data.get("tags", []), "vulns": data.get("vulns", []), "hostnames": data.get("hostnames", [])}
    return {"ip": ip}


def check_threat_intel(ioc: str) -> Dict:
    result = {"ioc": ioc, "malicious": False, "sources": {}}
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "search_ioc", "search_term": ioc},
                          headers={"User-Agent": ua.random}, timeout=10)
        if r.status_code == 200 and r.json().get("data"):
            result["malicious"] = True
            result["sources"]["threatfox"] = True
    except:
        pass
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ioc}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get("vulns"):
                result["malicious"] = True
                result["sources"]["shodan"] = d.get("vulns")
    except:
        pass
    return result


def scan_target(target: str, deep: bool = False) -> Dict:
    result = {"target": target, "timestamp": datetime.now(timezone.utc).isoformat()}
    is_ip = bool(target.replace(".", "").isdigit())
    is_domain = "." in target and not target.startswith("http")

    if is_ip:
        result["dns_reverse"] = resolve_dns(target) if deep else {}
        result["shodan"] = shodan_internetdb(target)
        result["threat"] = check_threat_intel(target)
    elif is_domain:
        result["dns"] = resolve_dns(target)
        result["passive_dns"] = passive_dns(target) if deep else {}
        result["whois"] = whois_lookup(target)
        result["ssl"] = ssl_certificate(target) if deep else {}
        result["http"] = http_headers(target)
        result["threat"] = check_threat_intel(target)
    return result


def batch_passive_scan(targets: List[str], deep: bool = False, max_workers: int = 20) -> List[Dict]:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(scan_target, t, deep): t for t in targets[:100]}
        for f in as_completed(fut):
            try:
                results.append(f.result())
            except:
                pass
    return results


def extract_intel_from_scan(scan_results: List[Dict]) -> List[Dict]:
    samples = []
    for r in scan_results:
        target = r["target"]
        threat = r.get("threat", {})
        malicious = threat.get("malicious", False)
        sources = list(threat.get("sources", {}).keys())

        is_ip = target.replace(".", "").isdigit()
        ports = []
        vulns = []
        if is_ip and r.get("shodan"):
            ports = r["shodan"].get("ports", [])
            vulns = r["shodan"].get("vulns", [])

        if malicious or vulns or ports:
            instruction = f"Passive scan target: {target}"
            lines = [f"Target: {target}"]
            if is_ip:
                if ports:
                    lines.append(f"Open Ports: {', '.join(map(str, ports[:20]))}")
                if vulns:
                    lines.append(f"Vulnerabilities: {', '.join(vulns[:10])}")
            else:
                dns = r.get("dns", {})
                if dns.get("ips"):
                    lines.append(f"IPs: {', '.join(dns['ips'][:5])}")
                whois = r.get("whois", {})
                if whois.get("registrar"):
                    lines.append(f"Registrar: {whois['registrar']}")
                http = r.get("http", {})
                if http.get("server"):
                    lines.append(f"Server: {http['server']}")
                if http.get("security_headers"):
                    lines.append(f"Security Headers: {len(http['security_headers'])} present")
                subs = r.get("passive_dns", {}).get("subdomains", [])
                if subs:
                    lines.append(f"Subdomains: {len(subs)} discovered")
            if malicious:
                lines.append(f"Threat Intel: Malicious ({', '.join(sources)})")
            lines.append("Source: passive_scan")
            samples.append({"instruction": instruction, "response": "\n".join(lines), "source": "passive_scan"})
    return samples
