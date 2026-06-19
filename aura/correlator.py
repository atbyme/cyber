import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("AURA.Correlator")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_all_iocs(threats: List[Dict]) -> Dict[str, Set[str]]:
    iocs = {"ips": set(), "domains": set(), "urls": set(), "cves": set(), "malware": set()}
    for t in threats:
        for f in ("ioc", "url", "description", "instruction", "response"):
            v = t.get(f, "")
            if isinstance(v, str):
                for ip in IP_RE.findall(v):
                    iocs["ips"].add(ip)
                for d in DOMAIN_RE.findall(v):
                    if len(d) > 3:
                        iocs["domains"].add(d)
                for u in re.findall(r'https?://[^\s"\'<>]+', v):
                    iocs["urls"].add(u)
        if t.get("id", "").startswith("CVE-"):
            iocs["cves"].add(t["id"])
        if t.get("malware"):
            iocs["malware"].add(t["malware"])
    return iocs


def cross_reference(threats: List[Dict]) -> Dict:
    """Find IPs that appear in multiple sources, malware families, etc."""
    ip_sources = defaultdict(set)
    ip_malware = defaultdict(set)
    ip_types = defaultdict(set)
    source_counts = Counter()
    type_counts = Counter()
    malware_counts = Counter()

    for t in threats:
        src = t.get("source", "?")
        etype = t.get("type", "?")
        malware = t.get("malware", "")
        source_counts[src] += 1
        type_counts[etype] += 1
        if malware:
            malware_counts[malware] += 1

        ioc = t.get("ioc", "")
        if ioc and IP_RE.match(ioc):
            ip_sources[ioc].add(src)
            ip_types[ioc].add(etype)
            if malware:
                ip_malware[ioc].add(malware)

    # Find IPs appearing in 2+ sources (high confidence threats)
    multi_source_ips = {ip: srcs for ip, srcs in ip_sources.items() if len(srcs) >= 2}

    # Find top malware families
    top_malware = malware_counts.most_common(20)

    # Find top sources
    top_sources = source_counts.most_common(30)

    return {
        "multi_source_ips": dict(multi_source_ips),
        "multi_source_count": len(multi_source_ips),
        "top_malware": top_malware,
        "top_sources": top_sources,
        "total_unique_ips": len(ip_sources),
        "total_unique_malware": len(malware_counts),
        "source_distribution": dict(source_counts.most_common()),
        "type_distribution": dict(type_counts.most_common()),
    }


def find_threat_clusters(threats: List[Dict]) -> List[Dict]:
    """Find groups of related threats (same IP, same malware, etc.)"""
    ip_threats = defaultdict(list)
    malware_threats = defaultdict(list)
    source_threats = defaultdict(list)

    for t in threats:
        ioc = t.get("ioc", "")
        if ioc and IP_RE.match(ioc):
            ip_threats[ioc].append(t)
        mal = t.get("malware", "")
        if mal:
            malware_threats[mal].append(t)
        src = t.get("source", "")
        if src:
            source_threats[src].append(t)

    clusters = []

    # IP clusters (IPs associated with multiple threats)
    for ip, related in sorted(ip_threats.items(), key=lambda x: -len(x[1])):
        if len(related) >= 2:
            types = set(t.get("type") for t in related)
            sources = set(t.get("source") for t in related)
            malwares = set(t.get("malware") for t in related if t.get("malware"))
            clusters.append({
                "type": "ip_cluster",
                "key": ip,
                "threat_count": len(related),
                "sources": list(sources),
                "threat_types": list(types),
                "malware": list(malwares),
            })

    return sorted(clusters, key=lambda x: -x["threat_count"])[:50]


def generate_research_insights(threats: List[Dict], history: List[Dict]) -> List[Dict]:
    """Generate insights about threat trends and patterns."""
    insights = []
    correlation = cross_reference(threats)

    if correlation["multi_source_count"] > 0:
        insights.append({
            "type": "high_confidence",
            "message": f"{correlation['multi_source_count']} IPs confirmed malicious by 2+ sources",
            "count": correlation["multi_source_count"],
        })

    if correlation["top_malware"]:
        top = correlation["top_malware"][0]
        insights.append({
            "type": "top_malware",
            "message": f"Most active malware: {top[0]} ({top[1]} occurrences)",
            "malware": top[0],
            "count": top[1],
        })

    if correlation["total_unique_ips"] > 0:
        insights.append({
            "type": "coverage",
            "message": f"{correlation['total_unique_ips']} unique malicious IPs tracked across {len(correlation['top_sources'])} sources",
            "count": correlation["total_unique_ips"],
        })

    # Trending: compare with history
    if history:
        last = history[-1].get("total", 0) if isinstance(history[-1], dict) else 0
        current = len(threats)
        if current > last:
            insights.append({
                "type": "trending_up",
                "message": f"Threat volume increasing: {current} vs {last} in last cycle",
                "current": current,
                "previous": last,
            })

    return insights
