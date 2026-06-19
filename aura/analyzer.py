import json
import logging
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import requests
from fake_useragent import UserAgent

logger = logging.getLogger("AURA.Analyzer")
ua = UserAgent()


def resolve_dns(domain: str) -> Dict[str, Any]:
    result = {"domain": domain, "ips": [], "records": {}}
    try:
        result["ips"] = list(set(
            info[4][0] for info in socket.getaddrinfo(domain, 80)
        ))
    except Exception as e:
        logger.debug(f"DNS resolution failed for {domain}: {e}")
    return result


def whois_lookup(target: str) -> Optional[Dict]:
    try:
        import whois
        w = whois.whois(target)
        return {
            "domain": target,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "org": w.org,
            "country": w.country,
        }
    except ImportError:
        logger.debug("python-whois not installed, skipping WHOIS")
        return None
    except Exception as e:
        logger.debug(f"WHOIS lookup failed for {target}: {e}")
        return None


def check_threat_intel(ioc: str) -> Dict[str, Any]:
    result = {"ioc": ioc, "malicious": False, "sources": {}}
    try:
        resp = requests.get(
            f"https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            headers={"User-Agent": ua.random},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data"):
                result["malicious"] = True
                result["sources"]["threatfox"] = data["data"]
    except Exception as e:
        logger.debug(f"Threat intel check failed for {ioc}: {e}")
    return result


def analyze_ip(ip: str) -> Dict[str, Any]:
    result = {"ip": ip, "hostname": None, "threat": None, "open_ports": []}
    try:
        result["hostname"] = socket.gethostbyaddr(ip)[0]
    except:
        pass
    threat = check_threat_intel(ip)
    if threat.get("malicious"):
        result["threat"] = threat
    return result


def analyze_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    result = {
        "url": url,
        "domain": parsed.netloc,
        "path": parsed.path,
        "params": parsed.query,
    }
    dns_info = resolve_dns(parsed.netloc)
    result["dns"] = dns_info
    whois_info = whois_lookup(parsed.netloc)
    if whois_info:
        result["whois"] = whois_info
    threat = check_threat_intel(parsed.netloc)
    if threat.get("malicious"):
        result["threat"] = threat
    return result


def digital_footprint(target: str) -> Dict[str, Any]:
    result = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "analysis": {},
    }
    if target.replace(".", "").isdigit():
        result["analysis"]["ip"] = analyze_ip(target)
    elif "." in target and not target.startswith("http"):
        result["analysis"]["domain"] = analyze_url(f"https://{target}")
    elif target.startswith("http"):
        result["analysis"]["url"] = analyze_url(target)
    else:
        result["analysis"]["ioc"] = check_threat_intel(target)
    return result


def scan_ports(host: str, ports: List[int] = None) -> List[Dict]:
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                results.append({"port": port, "state": "open"})
        except:
            pass
    return results
