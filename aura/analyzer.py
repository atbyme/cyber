import json
import logging
import re
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from fake_useragent import UserAgent

logger = logging.getLogger("AURA.Analyzer")
ua = UserAgent()

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_ips(data: List[Dict]) -> Set[str]:
    ips = set()
    for item in data:
        for f in ("ioc", "url", "description", "response"):
            v = item.get(f, "")
            if isinstance(v, str):
                ips.update(IP_RE.findall(v))
    return ips


def extract_domains(data: List[Dict]) -> Set[str]:
    domains = set()
    for item in data:
        for f in ("ioc", "url", "description", "response"):
            v = item.get(f, "")
            if isinstance(v, str):
                for m in DOMAIN_RE.findall(v):
                    if not m.startswith(".") and len(m) > 3:
                        domains.add(m)
    return domains


def resolve_dns(domain: str) -> Dict[str, Any]:
    result = {"domain": domain, "ips": [], "records": {}}
    try:
        result["ips"] = list(set(
            info[4][0] for info in socket.getaddrinfo(domain, 80)
        ))
    except Exception as e:
        logger.debug(f"DNS fail: {domain} - {e}")
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
        return None
    except Exception as e:
        logger.debug(f"WHOIS fail: {target} - {e}")
        return None


def check_threatfox(ioc: str) -> Dict[str, Any]:
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "search_ioc", "search_term": ioc},
                          headers={"User-Agent": ua.random}, timeout=10)
        if r.status_code == 200 and r.json().get("data"):
            return {"malicious": True, "source": "threatfox", "data": r.json()["data"]}
    except:
        pass
    return {"malicious": False}


def check_virustotal(ioc: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/search?query={ioc}",
                         headers={"User-Agent": ua.random, "x-apikey": "dummy"}, timeout=5)
        if r.status_code != 401:
            return {"malicious": r.status_code == 200, "source": "virustotal"}
    except:
        pass
    return {"malicious": False}


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"https://www.abuseipdb.com/check/{ip}/json",
                         headers={"User-Agent": ua.random, "Key": "dummy"}, timeout=5)
        if r.status_code == 200:
            d = r.json()
            return {"malicious": d.get("abuseConfidenceScore", 0) > 50, "source": "abuseipdb", "score": d.get("abuseConfidenceScore", 0)}
    except:
        pass
    return {"malicious": False}


def check_threat_intel(ioc: str) -> Dict[str, Any]:
    result = {"ioc": ioc, "malicious": False, "sources": {}}
    for fn in [check_threatfox, check_virustotal, check_abuseipdb]:
        r = fn(ioc)
        if r.get("malicious"):
            result["malicious"] = True
            result["sources"][r.get("source", "?")] = r
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
    result = {"url": url, "domain": parsed.netloc, "path": parsed.path, "params": parsed.query}
    dns = resolve_dns(parsed.netloc)
    result["dns"] = dns
    whois = whois_lookup(parsed.netloc)
    if whois:
        result["whois"] = whois
    threat = check_threat_intel(parsed.netloc)
    if threat.get("malicious"):
        result["threat"] = threat
    return result


def digital_footprint(target: str) -> Dict[str, Any]:
    result = {"target": target, "timestamp": datetime.utcnow().isoformat(), "analysis": {}}
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


def batch_analyze(threats: List[Dict], max_items=20) -> List[Dict]:
    ips = extract_ips(threats)
    domains = extract_domains(threats)
    targets = list(ips | domains)[:max_items]
    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        fut = {ex.submit(digital_footprint, t): t for t in targets}
        for f in as_completed(fut):
            try:
                results.append(f.result())
            except:
                pass
    return results


def check_breaches(email: str) -> List[Dict]:
    """Check known breaches for an email address"""
    results = []
    try:
        r = requests.get(f"https://api.xposedornot.com/v1/check-email?email={email}",
                         headers={"User-Agent": ua.random}, timeout=5)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, dict) and d.get("breaches"):
                for b in d["breaches"]:
                    results.append({"email": email, "breach": b.get("Name") or b.get("name", "unknown"),
                                    "date": b.get("Date") or b.get("date", "unknown")})
    except:
        pass
    return results


def company_intelligence(company: str) -> Dict:
    """Full company recon: WHOIS, DNS, SSL, Shodan, subdomains, ports, breaches"""
    result = {"company": company, "timestamp": datetime.utcnow().isoformat(), "domains": [], "threats": [], "open_ports": [], "breaches": [], "samples": 0}

    domains_found = set()
    base = company.lower().replace(" ", "").replace("'", "").replace(".com", "").replace(".io", "")
    for tld in [".com", ".io", ".org", ".net", ".co", ".ai", ".app", ".dev", ".tech"]:
        domains_found.add(base + tld)
        domains_found.add(company.lower().replace(" ", "-") + tld)

    domain_results = []
    for domain in list(domains_found)[:8]:
        try:
            dns = resolve_dns(domain)
            w = whois_lookup(domain)
            threat = check_threat_intel(domain)
            entry = {"domain": domain, "ips": dns.get("ips", [])}
            if w and w.get("registrar"):
                entry["whois"] = w
            if threat.get("malicious"):
                entry["malicious"] = True
                result["threats"].append({"domain": domain, "source": "threatfox+shodan"})
            domain_results.append(entry)
            for ip in dns.get("ips", [])[:3]:
                try:
                    sd = requests.get(f"https://internetdb.shodan.io/{ip}", headers={"User-Agent": ua.random}, timeout=5)
                    if sd.status_code == 200:
                        sd_d = sd.json()
                        if sd_d.get("ports"):
                            for p in sd_d["ports"]:
                                result["open_ports"].append({"ip": ip, "port": p})
                        if sd_d.get("vulns"):
                            result["threats"].append({"ip": ip, "vulns": sd_d["vulns"], "source": "shodan"})
                except:
                    pass
        except:
            pass

    try:
        first_domain = domain_results[0]["domain"] if domain_results else base + ".com"
    except:
        first_domain = base + ".com"

    breach_emails = [
        f"admin@{first_domain}",
        f"info@{first_domain}",
        f"security@{first_domain}",
        f"contact@{first_domain}",
    ]
    for email in breach_emails:
        try:
            result["breaches"].extend(check_breaches(email))
        except:
            pass

    try:
        ct_r = requests.get(f"https://crt.sh/?q=%25.{first_domain}&output=json&limit=50", headers={"User-Agent": ua.random}, timeout=10)
        if ct_r.status_code == 200:
            for c in ct_r.json() if isinstance(ct_r.json(), list) else []:
                cn = c.get("common_name", "") if isinstance(c, dict) else ""
                if cn and not any(d["domain"] == cn for d in domain_results):
                    domain_results.append({"domain": cn, "subdomain": True})
    except:
        pass

    result["domains"] = domain_results
    result["total_domains"] = len(domain_results)
    result["total_ports"] = len(result["open_ports"])
    result["total_threats"] = len(result["threats"])
    result["total_breaches"] = len(result["breaches"])
    result["samples"] = result["total_domains"] + result["total_ports"] + result["total_threats"] + result["total_breaches"]
    logger.info(f"Company intel for {company}: {result['total_domains']} domains, {result['total_ports']} ports, {result['total_threats']} threats, {result['total_breaches']} breaches")
    return result
